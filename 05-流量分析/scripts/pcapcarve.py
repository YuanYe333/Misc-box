# -*- coding: utf-8 -*-
"""
pcapcarve.py -- 从 pcap / pcapng 里把明文传输的内容掏出来。

为什么需要
==========
CTF 流量题给的几乎都是 .pcap / .pcapng。装了 Wireshark 当然能看，但：
  * 很多机器没装、或者 tshark 不在 PATH 里；
  * 题目要的是「把那几个 HTTP 响应体 / FTP 传输的文件 / Telnet 里敲的东西
    弄出来」，图形界面一条条点很慢；
  * 批量题（一次给几十个 pcap）根本没法手点。

本脚本自己解析 pcap 和 pcapng 的二进制格式（不依赖 scapy / dpkt / pyshark），
按 TCP 四元组分流、重组双向数据，然后做协议识别与内容提取。

能做什么
========
  * 两种容器：经典 pcap（含纳秒版魔数）与 pcapng（SHB/IDB/EPB/SPB/旧 PB，
    逐 section 判断字节序）。
  * 三种链路层：Ethernet（含 VLAN/QinQ 标签）、Raw IP、Linux SLL / SLL2、
    DLT_NULL 回环。
  * IPv4 / IPv6，IPv4 分片重组（支持重叠，按先到先得填充）。
  * TCP 流重组：乱序、重传、重复包都能拼回正确内容（序号回绕只能告警）。
  * 内容提取：HTTP 请求/响应（Content-Length、chunked、gzip 都会解开）、
    FTP 控制命令、Telnet 明文（会剥掉 IAC 协商字节）、SMTP / POP3 会话，
    以及任意 TCP 流的原始 payload。

用法
====
    python -X utf8 pcapcarve.py 题目.pcap --list
    python -X utf8 pcapcarve.py 题目.pcap
    python -X utf8 pcapcarve.py 题目.pcap --stream 3
    python -X utf8 pcapcarve.py 题目.pcap --follow 3 -o 会话.txt
    python -X utf8 pcapcarve.py 题目.pcap -o 全部内容.txt --force

已知限制
========
  * 只处理 TCP。UDP 请用同目录的 dnsdump.py（DNS）或直接看 Wireshark。
  * 加密流量（TLS）解不出来——本脚本只捞明文。
  * IP 分片按「先到先得」合并重叠区；如果两个分片在同一偏移给出不同数据，
    以先到的为准，不做 Wireshark 那种启发式裁决。
  * TCP 序号回绕只做告警：跨 2^32 边界的大流可能拼接错位。
  * 不做 TCP 的 SACK / 窗口分析，也不处理隧道里再套的协议。
  * 流序号按「该四元组第一次出现的顺序」编号，从 1 开始，与 tshark 的 0 基不同。
"""

import argparse
import gzip
import os
import re
import socket
import struct
import sys
import zlib

# ---------------------------------------------------------------- 常量

PCAP_MAGIC = {
    0xA1B2C3D4: ("<", 1000000.0),   # 小端，微秒
    0xD4C3B2A1: (">", 1000000.0),   # 大端，微秒
    0xA1B23C4D: ("<", 1000000000.0),  # 小端，纳秒
    0x4D3CB2A1: (">", 1000000000.0),  # 大端，纳秒
}

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
VLAN_TYPES = (0x8100, 0x88A8, 0x9100)

PROTO_TCP = 6
PROTO_UDP = 17

# 单包上限，防止坏文件把内存吃光
MAX_PACKET_LEN = 16 * 1024 * 1024


class PcapError(Exception):
    """pcap / pcapng 格式错误。"""


# ---------------------------------------------------------------- 容器解析

def _parse_tsresol(opts, endian):
    """从 IDB 的选项里取 if_tsresol（默认微秒）。"""
    res = 1000000.0
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack(endian + "HH", opts[i:i + 4])
        if code == 0:
            break
        val = opts[i + 4:i + 4 + ln]
        if code == 9 and len(val) >= 1:
            v = val[0]
            # 最高位为 1 表示 2 的负幂，否则是 10 的负幂
            res = float(2 ** (v & 0x7F)) if (v & 0x80) else float(10 ** v)
        i += 4 + ((ln + 3) & ~3)
    return res


def _iter_pcap(fh, endian, res, linktype):
    idx = 0
    while True:
        hdr = fh.read(16)
        if not hdr:
            return
        if len(hdr) < 16:
            raise PcapError("pcap 包记录头被截断（还差 %d 字节）" % (16 - len(hdr)))
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", hdr)
        if incl > MAX_PACKET_LEN:
            raise PcapError("包长度异常 (%d 字节)，文件可能损坏或不是 pcap" % incl)
        data = fh.read(incl)
        if len(data) < incl:
            raise PcapError("最后一个包被截断：需要 %d 字节，实际只有 %d 字节"
                            % (incl, len(data)))
        idx += 1
        yield (idx, ts_sec + ts_frac / res, linktype, data)


def _iter_pcapng(fh):
    """按块结构遍历 pcapng。每个 section 可以有自己的字节序。

    块布局：type(4) + total_length(4) + body(...) + total_length(4)。
    第一个块（SHB）的字节序只能靠 body 开头的 Byte-Order Magic 判断，
    所以 SHB 要先读 8 字节头、再读 4 字节 BOM、才能解析长度。
    """
    endian = "<"
    linktypes = []
    tsres = []
    idx = 0
    while True:
        pos = fh.tell()
        head8 = fh.read(8)
        if not head8:
            return
        if len(head8) < 8:
            raise PcapError("pcapng 块头被截断（文件偏移 %d）" % pos)

        if head8[:4] == b"\x0a\x0d\x0d\x0a":
            bom = fh.read(4)
            if len(bom) < 4:
                raise PcapError("pcapng SHB 被截断（文件偏移 %d）" % pos)
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                raise PcapError("pcapng SHB 的字节序标识错误（文件偏移 %d）" % pos)
            blen = struct.unpack(endian + "I", head8[4:8])[0]
            if blen < 16 or blen % 4 != 0:
                raise PcapError("pcapng SHB 块长度异常 %d（文件偏移 %d）" % (blen, pos))
            rest = fh.read(blen - 12)
            if len(rest) < blen - 12:
                raise PcapError("pcapng SHB 被截断（文件偏移 %d）" % pos)
            tail = struct.unpack(endian + "I", rest[-4:])[0]
            if tail != blen:
                raise PcapError("pcapng 块尾长度 %d 与块头 %d 不一致（文件偏移 %d）"
                                % (tail, blen, pos))
            linktypes = []
            tsres = []
            continue

        btype, blen = struct.unpack(endian + "II", head8)
        if blen < 12 or blen % 4 != 0:
            raise PcapError("pcapng 块长度异常 %d（文件偏移 %d）" % (blen, pos))
        rest = fh.read(blen - 8)
        if len(rest) < blen - 8:
            raise PcapError("pcapng 块被截断（文件偏移 %d，块长 %d）" % (pos, blen))
        if len(rest) < 4:
            raise PcapError("pcapng 块太短（文件偏移 %d）" % pos)
        tail = struct.unpack(endian + "I", rest[-4:])[0]
        if tail != blen:
            raise PcapError("pcapng 块尾长度 %d 与块头 %d 不一致（文件偏移 %d）"
                            % (tail, blen, pos))
        content = rest[:-4]

        if btype == 0x00000001:            # Interface Description Block
            if len(content) < 8:
                raise PcapError("pcapng IDB 太短（文件偏移 %d）" % pos)
            lt = struct.unpack(endian + "H", content[:2])[0]
            linktypes.append(lt)
            tsres.append(_parse_tsresol(content[8:], endian))

        elif btype == 0x00000006:          # Enhanced Packet Block
            if len(content) < 20:
                raise PcapError("pcapng EPB 太短（文件偏移 %d）" % pos)
            iface, tsh, tsl, cap, _orig = struct.unpack(endian + "IIIII", content[:20])
            if iface >= len(linktypes):
                raise PcapError("pcapng EPB 引用了不存在的接口 %d（文件偏移 %d）"
                                % (iface, pos))
            if cap > MAX_PACKET_LEN:
                raise PcapError("包长度异常 (%d 字节)（文件偏移 %d）" % (cap, pos))
            pkt = content[20:20 + cap]
            if len(pkt) < cap:
                raise PcapError("pcapng EPB 包数据被截断（文件偏移 %d）" % pos)
            idx += 1
            ts = ((tsh << 32) | tsl) / tsres[iface]
            yield (idx, ts, linktypes[iface], pkt)

        elif btype == 0x00000003:          # Simple Packet Block
            if len(content) < 4:
                raise PcapError("pcapng SPB 太短（文件偏移 %d）" % pos)
            if not linktypes:
                raise PcapError("pcapng SPB 出现在 IDB 之前（文件偏移 %d）" % pos)
            idx += 1
            yield (idx, 0.0, linktypes[0], content[4:])

        elif btype == 0x00000002:          # 旧版 Packet Block
            if len(content) < 20:
                raise PcapError("pcapng PB 太短（文件偏移 %d）" % pos)
            iface, _drops = struct.unpack(endian + "HH", content[:4])
            _tsh, _tsl, cap, _orig = struct.unpack(endian + "IIII", content[4:20])
            if iface >= len(linktypes):
                raise PcapError("pcapng PB 引用了不存在的接口 %d" % iface)
            idx += 1
            yield (idx, 0.0, linktypes[iface], content[20:20 + cap])

        # 其它块（NRB / ISB / 自定义）直接跳过


def read_packets(path):
    """统一入口：返回 (包序号, 时间戳, 链路类型, 原始字节) 的迭代器。"""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if len(head) < 4:
            raise PcapError("文件太小（%d 字节），不是有效的 pcap/pcapng" % len(head))
        magic_le = struct.unpack("<I", head)[0]
        fh.seek(0)
        if magic_le == 0x0A0D0D0A:
            for item in _iter_pcapng(fh):
                yield item
            return
        if magic_le not in PCAP_MAGIC:
            raise PcapError("无法识别的文件魔数 0x%08X，既不是 pcap 也不是 pcapng"
                            % magic_le)
        endian, res = PCAP_MAGIC[magic_le]
        gh = fh.read(24)
        if len(gh) < 24:
            raise PcapError("pcap 全局头被截断（需要 24 字节，实际 %d）" % len(gh))
        _magic, _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(
            endian + "IHHiIII", gh)
        for item in _iter_pcap(fh, endian, res, linktype):
            yield item


# ---------------------------------------------------------------- 链路层 / 网络层

def ipv4_str(raw):
    return ".".join(str(b) for b in raw)


def ipv6_str(raw):
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return ":".join("%02x%02x" % (raw[i], raw[i + 1]) for i in range(0, 16, 2))


def decode_link(linktype, data):
    """剥链路层头，返回 (ethertype, 上层字节)；认不出返回 None。"""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        et = struct.unpack(">H", data[12:14])[0]
        off = 14
        # VLAN / QinQ：标签可以叠好几层
        while et in VLAN_TYPES and len(data) >= off + 4:
            et = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        return et, data[off:]

    if linktype == LINKTYPE_RAW:
        if not data:
            return None
        ver = data[0] >> 4
        if ver == 4:
            return ETH_IPV4, data
        if ver == 6:
            return ETH_IPV6, data
        return None

    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        return struct.unpack(">H", data[14:16])[0], data[16:]

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None
        return struct.unpack(">H", data[0:2])[0], data[20:]

    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        fam = struct.unpack("<I", data[:4])[0]
        if fam == 2:
            return ETH_IPV4, data[4:]
        if fam in (10, 24, 28, 30):
            return ETH_IPV6, data[4:]
        return None

    return None


def decode_ipv4(data):
    """返回 (src, dst, proto, ident, frag_off, more_frags, payload)。"""
    if len(data) < 20:
        return None
    if data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total = struct.unpack(">H", data[2:4])[0]
    # total 为 0 是网卡 TSO 卸载留下的坑，此时只能信实际长度
    if total < ihl or total > len(data):
        total = len(data)
    ident = struct.unpack(">H", data[4:6])[0]
    fo = struct.unpack(">H", data[6:8])[0]
    more = bool(fo & 0x2000)
    off = (fo & 0x1FFF) * 8
    proto = data[9]
    src = ipv4_str(data[12:16])
    dst = ipv4_str(data[16:20])
    return src, dst, proto, ident, off, more, data[ihl:total]


def decode_ipv6(data):
    if len(data) < 40:
        return None
    if data[0] >> 4 != 6:
        return None
    plen = struct.unpack(">H", data[4:6])[0]
    nh = data[6]
    src = ipv6_str(data[8:24])
    dst = ipv6_str(data[24:40])
    payload = data[40:40 + plen] if plen else data[40:]
    # 跳过常见的扩展头（逐跳/路由/目的选项）
    guard = 0
    while nh in (0, 43, 60) and len(payload) >= 8 and guard < 8:
        nxt = payload[0]
        hlen = (payload[1] + 1) * 8
        if hlen <= 0 or hlen > len(payload):
            break
        payload = payload[hlen:]
        nh = nxt
        guard += 1
    return src, dst, nh, payload


def feed_fragment(table, key, off, more, payload):
    """把一片 IPv4 分片塞进表里；凑齐了返回完整 payload，否则 None。"""
    entry = table.setdefault(key, {"parts": {}, "end": None})
    entry["parts"][off] = payload
    if not more:
        entry["end"] = off + len(payload)
    total = entry["end"]
    if total is None:
        return None
    buf = bytearray()
    pos = 0
    for o in sorted(entry["parts"]):
        chunk = entry["parts"][o]
        if o > pos:
            return None             # 中间还有洞
        if o + len(chunk) > pos:
            buf.extend(chunk[pos - o:])
            pos = o + len(chunk)
    if pos < total:
        return None
    return bytes(buf[:total])


def new_stats():
    """统计字典的统一构造，保证 iter_l3 用到的键一定存在。"""
    return {
        "packets": 0, "linktypes": set(), "unknown_link": 0,
        "bad_ip": 0, "other_l3": 0, "frag_done": 0, "tcp_pkts": 0,
    }


def _bump(stats, key, n=1):
    """容忍调用方传进来的 stats 只关心部分字段。"""
    stats[key] = stats.get(key, 0) + n


def iter_l3(packets, stats):
    """把链路层包解成 (序号, 时间戳, src, dst, proto, 上层字节)。"""
    frags = {}
    lt_set = stats.get("linktypes")
    if lt_set is None:
        lt_set = set()
        stats["linktypes"] = lt_set
    for idx, ts, linktype, data in packets:
        lt_set.add(linktype)
        r = decode_link(linktype, data)
        if r is None:
            _bump(stats, "unknown_link")
            continue
        et, payload = r
        if et == ETH_IPV4:
            r2 = decode_ipv4(payload)
            if r2 is None:
                _bump(stats, "bad_ip")
                continue
            src, dst, proto, ident, off, more, pl = r2
            if more or off:
                key = (src, dst, ident, proto)
                done = feed_fragment(frags, key, off, more, pl)
                if done is None:
                    continue
                frags.pop(key, None)
                pl = done
                _bump(stats, "frag_done")
            yield idx, ts, src, dst, proto, pl
        elif et == ETH_IPV6:
            r2 = decode_ipv6(payload)
            if r2 is None:
                _bump(stats, "bad_ip")
                continue
            src, dst, proto, pl = r2
            yield idx, ts, src, dst, proto, pl
        else:
            _bump(stats, "other_l3")


def decode_tcp(data):
    """返回 (sport, dport, seq, ack, flags, payload)。"""
    if len(data) < 20:
        return None
    sp, dp, seq, ack = struct.unpack(">HHII", data[:12])
    doff = (data[12] >> 4) * 4
    if doff < 20 or doff > len(data):
        return None
    flags = data[13]
    return sp, dp, seq, ack, flags, data[doff:]


# ---------------------------------------------------------------- TCP 流

def norm_endpoints(ep):
    """把 (a, b) 规范成有序对，返回 (有序端点对, 本包方向 0/1)。"""
    a, b = ep
    if a <= b:
        return (a, b), 0
    return (b, a), 1


class Flow(object):
    """一条双向 TCP 流。"""

    def __init__(self, endpoints, index):
        self.endpoints = endpoints          # ((ip,port),(ip,port)) 已排序
        self.index = index
        self.segs = []                      # [(dir, seq, payload)] 抓包顺序
        self.dupe = set()                   # (dir, seq, len) 用来识别完全重复包

    def add(self, direction, seq, payload):
        if not payload:
            return
        key = (direction, seq, len(payload))
        if key in self.dupe:
            return                          # 完全一样的重传包，丢掉即可
        self.dupe.add(key)
        self.segs.append((direction, seq, payload))

    def byte_count(self, direction):
        return sum(len(p) for d, _s, p in self.segs if d == direction)


# 单条流单方向允许的最大重组跨度。超过就说明序号根本对不上
# （典型是序号回绕、或者抓包里混进了别的连接），此时宁可报错也不能
# 去分配一个 GB 级的缓冲区 —— 那会直接吃光内存。
MAX_REASSEMBLY_SPAN = 64 * 1024 * 1024


def _signed32(delta):
    """把 32 位无符号差值解释成有符号，用于判断「早/晚」。"""
    delta &= 0xFFFFFFFF
    if delta >= 0x80000000:
        return delta - 0x100000000
    return delta


def reassemble_dir(segments):
    """把同一方向的分段按序号拼起来。

    做法：先以第一个抓到的分段为参照算出所有分段的相对偏移，再整体平移到
    「最小偏移 = 0」。基准必须取最小序号而不是第一个抓到的包 —— 否则乱序时
    抓包里先出现的中段会被当成起点，前面那半截数据直接丢掉。
    之后只往「还没被写过」的位置写：乱序天然正确，重传/重复包自动跳过，
    重叠分段按先到先得。
    返回 (数据, 空洞字节数, 告警列表)。
    """
    if not segments:
        return b"", 0, []
    ref = segments[0][1]
    notes = []
    offsets = []
    for _d, seq, _p in segments:
        offsets.append(_signed32(seq - ref))
    base = min(offsets)
    span = max(offsets) - base
    if span > MAX_REASSEMBLY_SPAN:
        # 别硬拼：跨度大到这个程度，序号关系已经不可信了。
        # 直接把所有 payload 按抓包顺序接起来，并明确告诉用户这是退化的结果。
        notes.append("序号跨度 %d 字节，远超合理范围（疑似序号回绕/混杂连接），"
                     "已退化为「按抓包顺序拼接」，内容可能错位" % span)
        blob = b"".join(p for _d, _s, p in segments)
        return blob, 0, notes
    if span > 0x40000000:
        notes.append("序号跨度异常大（>1GB），疑似序号回绕，拼接结果可能错位")

    buf = bytearray()
    mask = bytearray()
    for (d, seq, payload), off in zip(segments, offsets):
        if not payload:
            continue
        delta = off - base
        end = delta + len(payload)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
            mask.extend(b"\x00" * (end - len(mask)))
        i = delta
        while i < end:
            if mask[i]:
                i += 1
                continue
            j = i
            while j < end and not mask[j]:
                j += 1
            buf[i:j] = payload[i - delta:j - delta]
            mask[i:j] = b"\x01" * (j - i)
            i = j
    gaps = mask.count(0) if len(mask) == len(buf) else 0
    if gaps:
        notes.append("重组后仍有 %d 字节空洞（抓包不完整）" % gaps)
    return bytes(buf), gaps, notes


# ---------------------------------------------------------------- 内容识别

HTTP_REQ_RE = re.compile(rb"^([A-Z]{3,7})[ \t]+(\S+)[ \t]+HTTP/(\d\.\d)")
HTTP_RESP_RE = re.compile(rb"^HTTP/(\d\.\d)[ \t]+(\d{3})")

PORT_HINTS = {
    21: "FTP", 20: "FTP-data", 23: "Telnet", 25: "SMTP", 110: "POP3",
    143: "IMAP", 80: "HTTP", 8080: "HTTP", 8000: "HTTP", 3128: "HTTP",
    8888: "HTTP", 443: "TLS", 22: "SSH",
}


def to_text(data):
    """把字节尽力解成可读文本（按 utf-8 / gb18030 / latin-1 依次尝试）。"""
    for enc in ("utf-8", "gb18030"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "replace")


def http_split(data):
    """拆出 (头部, 体)；找不到空行分隔返回 None。"""
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = data.find(sep)
        if i >= 0:
            return data[:i], data[i + len(sep):]
    return None


def parse_headers(head):
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    first = lines[0] if lines else b""
    hdrs = {}
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, v = ln.split(b":", 1)
        key = k.strip().lower().decode("latin-1", "replace")
        if key not in hdrs:
            hdrs[key] = v.strip().decode("latin-1", "replace")
    return first, hdrs


def dechunk(body):
    """解 HTTP/1.1 chunked 编码。"""
    out = bytearray()
    i = 0
    n = len(body)
    while i < n:
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        line = body[i:j].split(b";")[0].strip()
        try:
            size = int(line, 16)
        except ValueError:
            break
        if size == 0:
            break
        start = j + 2
        out.extend(body[start:start + size])
        i = start + size + 2
    return bytes(out)


def decode_body(body, hdrs):
    """按 Content-Encoding / Transfer-Encoding 把响应体还原成原始内容。"""
    if not body:
        return body, []
    notes = []
    te = (hdrs.get("transfer-encoding") or "").lower()
    if "chunked" in te:
        body = dechunk(body)
        notes.append("chunked 已解码")
    ce = (hdrs.get("content-encoding") or "").lower()
    if "gzip" in ce:
        try:
            body = gzip.decompress(body)
            notes.append("gzip 已解压")
        except (OSError, EOFError, zlib.error):
            notes.append("gzip 解压失败（数据可能不完整）")
    elif "deflate" in ce:
        try:
            body = zlib.decompress(body)
            notes.append("deflate 已解压")
        except zlib.error:
            try:
                body = zlib.decompress(body, -15)
                notes.append("deflate(raw) 已解压")
            except zlib.error:
                notes.append("deflate 解压失败")
    cl = hdrs.get("content-length")
    if cl:
        try:
            want = int(cl)
            if 0 <= want < len(body):
                body = body[:want]
                notes.append("按 Content-Length 截断")
        except ValueError:
            pass
    return body, notes


def strip_telnet(data):
    """剥掉 Telnet 的 IAC 协商序列，只留用户真正敲的字符。"""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b != 0xFF:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        cmd = data[i + 1]
        if cmd == 0xFF:                 # 转义的字面 0xFF
            out.append(0xFF)
            i += 2
        elif cmd in (0xFB, 0xFC, 0xFD, 0xFE):   # WILL/WONT/DO/DONT + 选项
            i += 3
        elif cmd == 0xFA:               # SB ... IAC SE
            j = data.find(b"\xff\xf0", i + 2)
            i = (j + 2) if j >= 0 else n
        else:
            i += 2
    return bytes(out)


def classify(flow):
    """判断这条流是什么协议：先看内容，再看端口。"""
    c2s = reassemble_dir([(d, s, p) for d, s, p in flow.segs if d == 0])[0]
    s2c = reassemble_dir([(d, s, p) for d, s, p in flow.segs if d == 1])[0]
    if HTTP_REQ_RE.match(c2s[:64]) or HTTP_RESP_RE.match(c2s[:32]):
        return "HTTP"
    if HTTP_RESP_RE.match(s2c[:32]) or HTTP_REQ_RE.match(s2c[:64]):
        return "HTTP"
    p0 = flow.endpoints[0][1]
    p1 = flow.endpoints[1][1]
    for p in (p1, p0):
        hint = PORT_HINTS.get(p)
        if hint and hint not in ("HTTP",):
            return hint
    for p in (p1, p0):
        hint = PORT_HINTS.get(p)
        if hint:
            return hint
    return "TCP"


FTP_CMDS = (b"USER ", b"PASS ", b"RETR ", b"STOR ", b"LIST", b"PASV", b"PORT ",
            b"TYPE ", b"CWD ", b"PWD", b"QUIT", b"SYST", b"NLST", b"SIZE ")


def looks_like_ftp(data):
    head = data[:400]
    return any(c in head for c in FTP_CMDS)


# ---------------------------------------------------------------- 输出

def safe_setup():
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass


class Out(object):
    """统一收集输出，最后一次性打到 stdout 或写文件。"""

    def __init__(self, path, force, limit):
        self.path = path
        self.force = force
        self.limit = limit
        self.buf = []

    def line(self, s=""):
        self.buf.append(s)

    def flush(self):
        text = "\n".join(self.buf) + "\n"
        if self.path:
            p = os.path.abspath(self.path)
            if os.path.exists(p) and not self.force:
                raise SystemExit("错误：输出文件已存在，加 --force 才覆盖：%s" % p)
            parent = os.path.dirname(p)
            if parent and not os.path.isdir(parent):
                raise SystemExit("错误：输出目录不存在：%s" % parent)
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            sys.stderr.write("已写入 %s（%d 字节）\n"
                             % (p, len(text.encode("utf-8"))))
        else:
            sys.stdout.write(text)


def fmt_bytes(n):
    if n < 1024:
        return "%dB" % n
    if n < 1024 * 1024:
        return "%.1fKB" % (n / 1024.0)
    return "%.1fMB" % (n / 1024.0 / 1024.0)


def ep_str(ep):
    ip, port = ep
    if ":" in ip:
        return "[%s]:%d" % (ip, port)
    return "%s:%d" % (ip, port)


def dump_stream(out, flow, kind, limit):
    c2s = reassemble_dir([(d, s, p) for d, s, p in flow.segs if d == 0])
    s2c = reassemble_dir([(d, s, p) for d, s, p in flow.segs if d == 1])
    a = ep_str(flow.endpoints[0])
    b = ep_str(flow.endpoints[1])
    out.line("=" * 70)
    out.line("流 #%d  %s -> %s  [%s]" % (flow.index, a, b, kind))
    out.line("=" * 70)

    for title, (data, gaps, notes), direction in (
            ("A -> B", c2s, 0), ("B -> A", s2c, 1)):
        if not data:
            continue
        out.line("")
        out.line("--- %s：%d 字节%s ---" % (title, len(data),
                                         "，%d 字节空洞" % gaps if gaps else ""))
        for note in notes:
            out.line("  [!] %s" % note)
        if direction == 0 and kind == "HTTP":
            emit_http(out, data, limit, is_request=True)
        elif direction == 1 and kind == "HTTP":
            emit_http(out, data, limit, is_request=False)
        elif kind == "Telnet":
            body = strip_telnet(data)
            emit_text(out, body, limit, note="已剥掉 Telnet IAC 协商字节")
        elif kind == "FTP" or (kind == "TCP" and looks_like_ftp(data)):
            emit_text(out, data, limit, note="FTP 控制通道")
        else:
            emit_text(out, data, limit)


def emit_http(out, data, limit, is_request):
    parts = http_split(data)
    if parts is None:
        emit_text(out, data, limit, note="不像完整的 HTTP（没有头/体分隔）")
        return
    head, body = parts
    first, hdrs = parse_headers(head)
    out.line(to_text(head))
    out.line("")
    if not body:
        out.line("（无请求体/响应体）")
        return
    decoded, notes = decode_body(body, hdrs)
    tag = "请求体" if is_request else "响应体"
    extra = ("（%s）" % "，".join(notes)) if notes else ""
    out.line("[%s %d 字节 -> %d 字节%s]" % (tag, len(body), len(decoded), extra))
    emit_text(out, decoded, limit)


def emit_text(out, data, limit, note=None):
    if note:
        out.line("(%s)" % note)
    shown = data
    if limit and len(shown) > limit:
        shown = shown[:limit]
        out.line("(只显示前 %d 字节，共 %d 字节；用 --limit 调整)" % (limit, len(data)))
    text = to_text(shown)
    # 去掉行尾 \r，避免在 Windows 上显示成方块
    out.line(text.replace("\r\n", "\n").replace("\r", "\n"))
    if not text.endswith("\n"):
        out.line("")


def follow_stream(out, flow, limit):
    a = ep_str(flow.endpoints[0])
    b = ep_str(flow.endpoints[1])
    out.line("=" * 70)
    out.line("跟随流 #%d  %s <-> %s （按抓包顺序，>>> 是 A->B，<<< 是 B->A）"
             % (flow.index, a, b))
    out.line("=" * 70)
    used = 0
    for direction, _seq, payload in flow.segs:
        if limit and used >= limit:
            out.line("...（已达 --limit 上限，后续省略）")
            break
        arrow = ">>>" if direction == 0 else "<<<"
        chunk = payload
        if limit and used + len(chunk) > limit:
            chunk = chunk[:max(0, limit - used)]
        used += len(chunk)
        text = to_text(chunk).replace("\r\n", "\n").replace("\r", "\n")
        out.line("%s %s" % (arrow, text))


# ---------------------------------------------------------------- 主流程

def collect(path):
    stats = new_stats()
    flows = {}
    order = []
    for idx, _ts, src, dst, proto, pl in iter_l3(read_packets(path), stats):
        stats["packets"] += 1
        if proto != PROTO_TCP:
            continue
        r = decode_tcp(pl)
        if r is None:
            continue
        stats["tcp_pkts"] += 1
        sp, dp, seq, _ack, _flags, payload = r
        key, direction = norm_endpoints(((src, sp), (dst, dp)))
        flow = flows.get(key)
        if flow is None:
            flow = Flow(key, len(order) + 1)
            flows[key] = flow
            order.append(flow)
        flow.add(direction, seq, payload)
    return order, stats


def usage(prog):
    print("pcapcarve.py -- 从 pcap/pcapng 里提取明文传输内容（纯标准库，不需要 scapy/tshark）")
    print("")
    print("用法：")
    print("  python -X utf8 %s 题目.pcap --list          先列出所有 TCP 流" % prog)
    print("  python -X utf8 %s 题目.pcap                 提取全部明文内容" % prog)
    print("  python -X utf8 %s 题目.pcap --stream 3      只看第 3 条流" % prog)
    print("  python -X utf8 %s 题目.pcap --follow 3      按时间顺序跟随第 3 条流" % prog)
    print("  python -X utf8 %s 题目.pcap -o 结果.txt     把结果写文件" % prog)
    print("")
    print("支持：经典 pcap / pcapng；Ethernet / Raw IP / Linux SLL(SLL2) / NULL；")
    print("      IPv4(含分片重组) / IPv6；HTTP(含 chunked、gzip) / FTP / Telnet /")
    print("      SMTP / POP3 / 任意 TCP 流 payload。")
    print("")
    print("选项：")
    print("  --list        只列流清单，不打印内容")
    print("  --stream N    只输出第 N 条流（N 从 1 开始，见 --list）")
    print("  --follow N    按抓包顺序交错显示第 N 条流的双向数据")
    print("  -o FILE       结果写入文件（已存在需 --force）")
    print("  --force       允许覆盖已存在的输出文件")
    print("  --limit N     单段最多显示多少字节（默认 200000，0 表示不限）")
    print("")
    print("例子：")
    print("  python -X utf8 %s capture.pcapng --list" % prog)
    print("  python -X utf8 %s capture.pcap --stream 2 -o http.txt" % prog)


def main():
    safe_setup()
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--stream", type=int, default=None)
    ap.add_argument("--follow", type=int, default=None)
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--limit", type=int, default=200000)
    try:
        args = ap.parse_args()
    except SystemExit:
        return 2

    prog = os.path.basename(sys.argv[0]) or "pcapcarve.py"
    if args.help or not args.pcap:
        usage(prog)
        return 0

    path = os.path.abspath(args.pcap)
    if not os.path.isfile(path):
        sys.stderr.write("错误：文件不存在或不是普通文件：%s\n" % path)
        return 1

    try:
        flows, stats = collect(path)
    except PcapError as exc:
        sys.stderr.write("错误：%s\n" % exc)
        sys.stderr.write("提示：确认这是 pcap/pcapng；可以用 file 命令或看文件头魔数。\n")
        return 1
    except (IOError, OSError) as exc:
        sys.stderr.write("错误：读取失败：%s\n" % exc)
        return 1
    except struct.error as exc:
        sys.stderr.write("错误：文件结构异常（%s），可能已损坏或被截断\n" % exc)
        return 1

    try:
        out = Out(args.output, args.force, args.limit)
    except SystemExit as exc:
        sys.stderr.write("%s\n" % exc)
        return 1

    if not flows:
        sys.stderr.write("没有找到任何 TCP 流（文件里可能只有 UDP/ARP/非 IP 流量）。\n")
        sys.stderr.write("包的链路类型：%s\n" % sorted(stats["linktypes"]))
        return 1

    kinds = {}
    for flow in flows:
        kinds[flow.index] = classify(flow)

    if args.list:
        out.line("共 %d 个包，%d 条 TCP 流" % (stats["packets"], len(flows)))
        out.line("%-4s %-46s %-9s %s" % ("#", "端点 (A <-> B)", "协议", "字节数 A->B / B->A"))
        out.line("-" * 96)
        for flow in flows:
            out.line("%-4d %-46s %-9s %d / %d" % (
                flow.index,
                "%s <-> %s" % (ep_str(flow.endpoints[0]), ep_str(flow.endpoints[1])),
                kinds[flow.index],
                flow.byte_count(0), flow.byte_count(1)))
        out.flush()
        return 0

    targets = []
    if args.stream is not None or args.follow is not None:
        want = args.stream if args.stream is not None else args.follow
        if want < 1 or want > len(flows):
            sys.stderr.write("错误：流序号 %d 超出范围（本文件共 %d 条流，编号 1..%d）\n"
                             % (want, len(flows), len(flows)))
            sys.stderr.write("先用 --list 看看有哪些流。\n")
            return 2
        targets = [flows[want - 1]]

    if args.follow is not None:
        for flow in targets:
            follow_stream(out, flow, args.limit)
        out.flush()
        return 0

    if args.stream is not None:
        for flow in targets:
            dump_stream(out, flow, kinds[flow.index], args.limit)
        out.flush()
        return 0

    out.line("共 %d 个包，%d 条 TCP 流；链路类型 %s"
             % (stats["packets"], len(flows), sorted(stats["linktypes"])))
    if stats["frag_done"]:
        out.line("（其中 %d 个 IPv4 分片组被重组）" % stats["frag_done"])
    out.line("")
    for flow in flows:
        dump_stream(out, flow, kinds[flow.index], args.limit)
        out.line("")
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
