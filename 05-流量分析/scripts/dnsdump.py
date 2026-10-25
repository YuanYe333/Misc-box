# -*- coding: utf-8 -*-
"""
dnsdump.py -- 把 pcap 里的 DNS 查询/响应全导出来，并识别 DNS 隧道。

为什么需要
==========
DNS 题在 CTF 里是固定套路：要么「把域名全列出来看有没有奇怪的」，要么
「域名前缀是 base32/base64 分片，拼起来解码」。用 Wireshark 看能看，但：
  * 几百条查询要手工翻，眼睛会瞎；
  * 隧道流量里「哪几条可疑」需要量化判断，靠肉眼没有标准；
  * 导出成 CSV 才能丢进 Excel/脚本做二次处理。

本脚本自己解析 pcap/pcapng（复用同目录 pcapcarve.py 的容器解析），
把 UDP/TCP 53 的 DNS 报文解出来，按域名做统计，用多条特征打分找隧道。

能做什么
========
  * 解析 DNS 查询与响应：A / AAAA / CNAME / TXT / MX / NS / PTR / SOA / SRV。
  * 支持 UDP 53 与 TCP 53（含 TCP 上的 2 字节长度前缀）。
  * 导出每条查询/响应，可按域名聚合统计（次数、平均长度、NXDOMAIN 比例）。
  * 隧道特征识别（打分制，不是拍脑袋）：
      - 超长子域名（>40 字符）
      - 标签字符集像 base32 / base64 / hex
      - 高频查询（同一根域名被查很多次）
      - TXT 记录异常（超长、高熵、像编码）
      - 大量 NXDOMAIN
  * --tunnel 只输出可疑项；--csv 输出 CSV。

用法
====
    python -X utf8 dnsdump.py 题目.pcap
    python -X utf8 dnsdump.py 题目.pcap --tunnel
    python -X utf8 dnsdump.py 题目.pcap --csv -o dns.csv
    python -X utf8 dnsdump.py 题目.pcap --csv --tunnel

已知限制
========
  * 只认标准 DNS（端口 53）。DoH / DoT / mDNS 5353 / LLMNR 不处理。
  * DNS over TCP 只处理「一个 TCP 段里装完整报文」的常见情况；
    跨段的长报文会拼接，但极端分片不做重排。
  * 隧道打分是启发式，会有误报。分数只代表「值得看一眼」，不是判决。
  * 不做 DNS 报文压缩指针的循环防护以外的完整性校验（循环指针会被截断）。
"""

import argparse
import base64
import csv
import io
import math
import os
import re
import struct
import sys

# 复用同目录 pcapcarve 的容器/链路层解析，避免两份重复实现
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from pcapcarve import (PcapError, read_packets, iter_l3, decode_tcp,
                           PROTO_TCP, PROTO_UDP, safe_setup)
except ImportError:                                     # pragma: no cover
    sys.stderr.write("错误：找不到同目录的 pcapcarve.py（DNS 解析复用了它的 pcap 读取）\n")
    raise SystemExit(1)


# ---------------------------------------------------------------- DNS 报文解析

QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT",
    43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
    255: "ANY", 257: "CAA",
}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}


class DnsError(Exception):
    pass


def read_name(buf, off, depth=0):
    """解域名，支持压缩指针。返回 (名字, 新偏移)。"""
    if depth > 20:
        raise DnsError("域名压缩指针层数过深（疑似循环）")
    labels = []
    pos = off
    jumped = False
    new_off = off
    while True:
        if pos >= len(buf):
            raise DnsError("域名越过报文末尾")
        ln = buf[pos]
        if ln == 0:
            pos += 1
            if not jumped:
                new_off = pos
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise DnsError("压缩指针被截断")
            ptr = ((ln & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                new_off = pos + 2
            jumped = True
            if ptr >= len(buf):
                raise DnsError("压缩指针越界")
            pos = ptr
            depth += 1
            if depth > 20:
                raise DnsError("域名压缩指针层数过深（疑似循环）")
            continue
        if ln & 0xC0:
            raise DnsError("不支持的标签类型 0x%02X" % ln)
        pos += 1
        if pos + ln > len(buf):
            raise DnsError("域名标签被截断")
        labels.append(buf[pos:pos + ln])
        pos += ln
        if not jumped:
            new_off = pos
    try:
        name = ".".join(l.decode("ascii") for l in labels)
    except UnicodeDecodeError:
        name = ".".join(l.decode("latin-1") for l in labels)
    return name, new_off


def parse_rdata(buf, off, rdlen, rtype):
    """把 rdata 解成便于阅读的字符串。"""
    raw = buf[off:off + rdlen]
    if len(raw) < rdlen:
        raise DnsError("rdata 被截断")
    try:
        if rtype == 1 and rdlen == 4:
            return ".".join(str(b) for b in raw)
        if rtype == 28 and rdlen == 16:
            return ":".join("%02x%02x" % (raw[i], raw[i + 1]) for i in range(0, 16, 2))
        if rtype in (2, 5, 12):
            nm, _ = read_name(buf, off)
            return nm
        if rtype == 15:
            if rdlen < 3:
                return raw.hex()
            nm, _ = read_name(buf, off + 2)
            return "%d %s" % (struct.unpack(">H", raw[:2])[0], nm)
        if rtype == 16:
            out = []
            i = 0
            while i < len(raw):
                ln = raw[i]
                out.append(raw[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            return "".join(out)
        if rtype == 6:
            mname, p = read_name(buf, off)
            rname, p = read_name(buf, p)
            if p + 20 <= off + rdlen:
                serial = struct.unpack(">I", buf[p:p + 4])[0]
                return "%s %s serial=%d" % (mname, rname, serial)
            return "%s %s" % (mname, rname)
        if rtype == 33:
            if rdlen < 7:
                return raw.hex()
            prio, weight, port = struct.unpack(">HHH", raw[:6])
            tgt, _ = read_name(buf, off + 6)
            return "%d %d %d %s" % (prio, weight, port, tgt)
    except DnsError:
        pass
    if not raw:
        return ""
    # 兜底：能当可打印文本就当文本，否则给 hex
    printable = sum(1 for b in raw if 32 <= b < 127)
    if printable / float(len(raw)) > 0.9:
        return raw.decode("latin-1")
    return "0x" + raw.hex()


def parse_dns(buf):
    """解析一条 DNS 报文，返回 dict 或 None（不是 DNS 就返回 None）。"""
    if len(buf) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    off = 12
    questions = []
    for _ in range(qd):
        try:
            name, off = read_name(buf, off)
        except DnsError:
            break
        if off + 4 > len(buf):
            break
        qtype, qclass = struct.unpack(">HH", buf[off:off + 4])
        off += 4
        questions.append({"name": name, "qtype": qtype, "qclass": qclass})

    answers = []
    for _ in range(an + ns + ar):
        try:
            name, off = read_name(buf, off)
        except DnsError:
            break
        if off + 10 > len(buf):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        try:
            val = parse_rdata(buf, off, rdlen, rtype)
        except DnsError:
            val = ""
        off += rdlen
        answers.append({"name": name, "type": rtype, "ttl": ttl, "value": val})

    return {
        "txid": txid, "qr": qr, "opcode": opcode, "rcode": rcode,
        "questions": questions, "answers": answers,
    }


def collect_dns(path):
    """遍历 pcap，抽出所有 DNS 报文。"""
    stats = {"packets": 0, "dns": 0, "bad": 0, "tcp": 0, "udp": 0}
    records = []
    tcp_assembler = {}          # (src, sport, dst, dport) -> [seq, bytearray]

    for idx, _ts, src, dst, proto, pl in iter_l3(read_packets(path), stats):
        stats["packets"] += 1
        if proto == PROTO_UDP:
            if len(pl) < 8:
                continue
            sp, dp, _ln = struct.unpack(">HHH", pl[:6])
            if 53 not in (sp, dp):
                continue
            stats["udp"] += 1
            msg = parse_dns(pl[8:])
            if msg is None:
                stats["bad"] += 1
                continue
            stats["dns"] += 1
            msg["src"] = src
            msg["dst"] = dst
            msg["sport"] = sp
            msg["dport"] = dp
            msg["pkt"] = idx
            records.append(msg)

        elif proto == PROTO_TCP:
            r = decode_tcp(pl)
            if r is None:
                continue
            sp, dp, seq, _ack, _flags, payload = r
            if 53 not in (sp, dp):
                continue
            stats["tcp"] += 1
            if not payload:
                continue
            key = (src, sp, dst, dp)
            slot = tcp_assembler.get(key)
            if slot is None:
                slot = [seq, bytearray()]
                tcp_assembler[key] = slot
            slot[1].extend(payload)
            # TCP 上的 DNS 前面有 2 字节长度前缀
            data = bytes(slot[1])
            while len(data) >= 2:
                want = struct.unpack(">H", data[:2])[0]
                if len(data) < 2 + want:
                    break
                msg = parse_dns(data[2:2 + want])
                data = data[2 + want:]
                if msg is None:
                    stats["bad"] += 1
                    continue
                stats["dns"] += 1
                msg["src"] = src
                msg["dst"] = dst
                msg["sport"] = sp
                msg["dport"] = dp
                msg["pkt"] = idx
                records.append(msg)
            slot[1] = bytearray(data)
    return records, stats


# ---------------------------------------------------------------- 隧道特征

B32_RE = re.compile(r"^[A-Z2-7]+=*$")
B32L_RE = re.compile(r"^[a-z2-7]+=*$")
B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
B64U_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# 常见二级域名后缀里常出现的「正常」标签，命中就不算可疑
NORMAL_TLD_HINT = ("www", "mail", "smtp", "pop", "ns1", "ns2", "mx", "api",
                   "cdn", "static", "img", "assets", "login", "auth", "vpn")


def shannon(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(s))
    return -sum((c / total) * math.log(c / total, 2) for c in counts.values())


def label_kind(label):
    """判断一个域名标签像什么编码。返回 (类型, 是否可信)。"""
    n = len(label)
    if n < 8:
        return None, False
    if HEX_RE.match(label) and n % 2 == 0 and any(c.isdigit() for c in label):
        # 纯十六进制但很短、或者全是 0-9 的，多半是版本号/编号
        if n >= 16:
            return "hex", True
        return "hex", False
    up = label.upper()
    if B32L_RE.match(label) and n >= 16:
        try:
            pad = (-len(up)) % 8
            raw = base64.b32decode(up + "=" * pad)
            if all(32 <= b < 127 or b in (9, 10, 13) for b in raw) and raw:
                return "base32", True
        except Exception:                                # noqa: BLE001
            pass
        return "base32?", False
    if B32_RE.match(up) and n >= 16:
        return "base32", True
    for name, rx in (("base64", B64_RE), ("base64url", B64U_RE)):
        if rx.match(label) and n >= 16:
            has_up = any(c.isupper() for c in label)
            has_low = any(c.islower() for c in label)
            has_dig = any(c.isdigit() for c in label)
            # 三种字符都有的长标签才像 base64；全小写英文单词不算
            if has_up and has_low and has_dig:
                return name, True
    return None, False


def root_domain(name):
    """粗暴取最后两级作为「根域名」，够用来聚合。"""
    parts = [p for p in name.split(".") if p]
    if len(parts) <= 2:
        return name
    return ".".join(parts[-2:])


def tunnel_score(rec, domain_stats, total_queries):
    """给一条查询打隧道嫌疑分。返回 (分数, 原因列表)。"""
    reasons = []
    score = 0.0
    q = rec["questions"][0] if rec["questions"] else None
    if not q:
        return 0.0, reasons
    name = q["name"].rstrip(".")
    labels = [l for l in name.split(".") if l]

    # 1) 超长子域名
    if labels:
        longest = max(len(l) for l in labels)
        if longest >= 60:
            score += 3
            reasons.append("最长标签 %d 字符（≥60）" % longest)
        elif longest >= 40:
            score += 2
            reasons.append("最长标签 %d 字符（≥40）" % longest)
        elif longest >= 24:
            score += 1
            reasons.append("最长标签 %d 字符（≥24）" % longest)

    # 2) 编码样式的标签
    enc_hits = []
    for lab in labels[:-2] if len(labels) > 2 else labels:
        kind, strong = label_kind(lab)
        if kind and strong:
            enc_hits.append((lab, kind))
    if enc_hits:
        score += 3
        kinds = sorted(set(k for _l, k in enc_hits))
        reasons.append("%d 个标签像 %s" % (len(enc_hits), "/".join(kinds)))

    # 3) 高频
    st = domain_stats.get(root_domain(name))
    if st and st["count"] >= 30:
        score += 2
        reasons.append("根域名 %s 被查 %d 次" % (root_domain(name), st["count"]))
    elif st and st["count"] >= 10:
        score += 1
        reasons.append("根域名 %s 被查 %d 次" % (root_domain(name), st["count"]))

    # 4) TXT 异常
    for ans in rec["answers"]:
        if ans["type"] != 16:
            continue
        val = ans["value"]
        if len(val) >= 64:
            score += 2
            reasons.append("TXT 记录长 %d 字符" % len(val))
        ent = shannon(val)
        if len(val) >= 32 and ent >= 4.2:
            score += 2
            reasons.append("TXT 记录熵 %.2f（像编码/加密数据）" % ent)
        for pat, nm in ((B64_RE, "base64"), (B32_RE, "base32"), (HEX_RE, "hex")):
            v = val.split(":")[-1].strip()
            if len(v) >= 24 and pat.match(v):
                score += 2
                reasons.append("TXT 内容像 %s" % nm)
                break

    # 5) NXDOMAIN
    if rec["qr"] and rec["rcode"] == 3:
        if st and st["count"] >= 5:
            nx = st["nxdomain"] / float(st["count"])
            if nx >= 0.7:
                score += 2
                reasons.append("根域名 %s 的 NXDOMAIN 占比 %.0f%%"
                               % (root_domain(name), nx * 100))
            else:
                score += 1
                reasons.append("NXDOMAIN")

    # 正常服务标签命中就减分，避免把 www/static 之类误判
    if any(l.lower() in NORMAL_TLD_HINT for l in labels):
        score -= 1.5

    # 单次查询且标签不长：几乎不可能是隧道
    if st and st["count"] <= 2 and not enc_hits:
        score -= 1
    return score, reasons


def build_stats(records):
    """按根域名聚合统计。"""
    stats = {}
    for rec in records:
        if not rec["questions"]:
            continue
        name = rec["questions"][0]["name"].rstrip(".")
        root = root_domain(name)
        st = stats.setdefault(root, {
            "count": 0, "queries": 0, "responses": 0, "nxdomain": 0,
            "labels": [], "qtypes": set(), "names": set(), "txt": 0,
        })
        st["count"] += 1
        if rec["qr"]:
            st["responses"] += 1
        else:
            st["queries"] += 1
        if rec["rcode"] == 3:
            st["nxdomain"] += 1
        st["names"].add(name)
        st["qtypes"].add(rec["questions"][0]["qtype"])
        for lab in name.split("."):
            if lab:
                st["labels"].append(lab)
        for ans in rec["answers"]:
            if ans["type"] == 16:
                st["txt"] += 1
    return stats


# ---------------------------------------------------------------- 输出

def fmt_rec(rec):
    q = rec["questions"][0] if rec["questions"] else None
    name = q["name"].rstrip(".") if q else "(无问题段)"
    qtype = QTYPE_NAMES.get(q["qtype"], str(q["qtype"])) if q else "-"
    direction = "响应" if rec["qr"] else "查询"
    rcode = RCODE_NAMES.get(rec["rcode"], str(rec["rcode"]))
    ans = ""
    if rec["answers"]:
        parts = []
        for a in rec["answers"][:4]:
            tn = QTYPE_NAMES.get(a["type"], str(a["type"]))
            v = a["value"]
            if len(v) > 80:
                v = v[:80] + "..."
            parts.append("%s=%s" % (tn, v))
        ans = "  -> " + "; ".join(parts)
        if len(rec["answers"]) > 4:
            ans += " (+%d)" % (len(rec["answers"]) - 4)
    return "#%-5d %s %-6s %-9s %s%s" % (
        rec["pkt"], direction, qtype, rcode, name, ans)


def try_decode_payload(data):
    """把拼好的字符串尝试各种解码，返回 [(方法, 结果字节)]。"""
    outs = []
    s = data.strip()
    if not s:
        return outs

    # hex
    if HEX_RE.match(s) and len(s) % 2 == 0:
        try:
            outs.append(("hex", bytes.fromhex(s)))
        except ValueError:
            pass

    # base32（容忍缺失的 padding 和大小写）
    up = s.upper().replace(" ", "")
    if B32_RE.match(up):
        for pad in range(0, 9):
            try:
                raw = base64.b32decode(up + "=" * pad)
                if raw:
                    outs.append(("base32", raw))
                    break
            except Exception:                            # noqa: BLE001
                continue

    # base64 / base64url
    for name, cand in (("base64", s), ("base64url", s.replace("-", "+").replace("_", "/"))):
        for pad in range(0, 5):
            try:
                raw = base64.b64decode(cand + "=" * pad, validate=False)
                if raw:
                    outs.append((name, raw))
                    break
            except Exception:                            # noqa: BLE001
                continue

    # 去重（同一结果只留最先出现的）
    seen = set()
    uniq = []
    for name, raw in outs:
        if raw in seen:
            continue
        seen.add(raw)
        uniq.append((name, raw))
    return uniq


def printable_ratio(raw):
    """可打印字符占比，用来判断解码结果是不是「有意义的数据」。"""
    if not raw:
        return 0.0
    ok = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    return ok / float(len(raw))


def decode_tunnels(scored, threshold):
    """按「根域名 + 标签类型」分组，把可疑标签按出现顺序拼接。

    必须按类型分组：同一个域名下可能既有 base32 段又有 base64 段
    （甚至不同工具产生的噪声），混在一起拼出来的东西谁也解不开。
    """
    groups = {}
    for rec, sc, _reasons in scored:
        if sc < threshold:
            continue
        q = rec["questions"][0] if rec["questions"] else None
        if not q:
            continue
        name = q["name"].rstrip(".")
        labels = [l for l in name.split(".") if l]
        if len(labels) < 2:
            continue
        root = root_domain(name)
        # 去掉根域名的两级，剩下的就是隧道数据部分
        data_labels = labels[:-2] if len(labels) > 2 else labels[:-1]
        kind = None
        picked = []
        for lab in data_labels:
            k, strong = label_kind(lab)
            if strong:
                if kind is None:
                    kind = k
                picked.append(lab)
        if not picked:
            continue
        # 归一到「家族」：base64 / base64url 视为一类
        family = "base64" if kind in ("base64", "base64url") else kind
        key = (root, family)
        g = groups.setdefault(key, {"root": root, "kind": family,
                                    "parts": [], "order": []})
        g["parts"].append("".join(picked))
        g["order"].append(rec["pkt"])

    return groups


def usage(prog):
    print("dnsdump.py -- 导出 pcap 里的 DNS 查询/响应，并识别 DNS 隧道特征")
    print("")
    print("用法：")
    print("  python -X utf8 %s 题目.pcap            列出所有 DNS 记录" % prog)
    print("  python -X utf8 %s 题目.pcap --tunnel   只输出可疑（隧道）项" % prog)
    print("  python -X utf8 %s 题目.pcap --decode   把隧道数据拼回来并解码" % prog)
    print("  python -X utf8 %s 题目.pcap --stats    按根域名聚合统计" % prog)
    print("  python -X utf8 %s 题目.pcap --csv -o dns.csv" % prog)
    print("")
    print("隧道特征：超长子域名 / base32-base64-hex 样式标签 / 高频查询 /")
    print("          TXT 记录异常 / 大量 NXDOMAIN。")
    print("")
    print("选项：")
    print("  --tunnel      只输出得分达标的可疑项（默认阈值 4）")
    print("  --threshold N 调整可疑阈值（默认 4）")
    print("  --decode      按根域名把可疑标签按出现顺序拼接，自动试 base32/base64/hex")
    print("  --stats       输出按根域名的聚合统计")
    print("  --csv         输出 CSV（列：序号,方向,类型,rcode,域名,应答）")
    print("  --limit N     最多输出多少条明细（默认 0 表示全部）")
    print("  -o FILE       写入文件（已存在需 --force）")
    print("  --force       允许覆盖已存在的输出文件")
    print("")
    print("例子：")
    print("  python -X utf8 %s dns.pcap --tunnel" % prog)
    print("  python -X utf8 %s dns.pcap --decode" % prog)
    print("  python -X utf8 %s dns.pcap --csv -o 结果.csv --force" % prog)


def main():
    safe_setup()
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--tunnel", action="store_true")
    ap.add_argument("--decode", action="store_true")
    ap.add_argument("--threshold", type=float, default=4.0)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--csv", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--force", action="store_true")
    try:
        args = ap.parse_args()
    except SystemExit:
        return 2

    prog = os.path.basename(sys.argv[0]) or "dnsdump.py"
    if args.help or not args.pcap:
        usage(prog)
        return 0

    path = os.path.abspath(args.pcap)
    if not os.path.isfile(path):
        sys.stderr.write("错误：文件不存在或不是普通文件：%s\n" % path)
        return 1

    try:
        records, stats = collect_dns(path)
    except PcapError as exc:
        sys.stderr.write("错误：%s\n" % exc)
        sys.stderr.write("提示：确认这是 pcap/pcapng；DNS 题通常是 UDP 53。\n")
        return 1
    except (IOError, OSError) as exc:
        sys.stderr.write("错误：读取失败：%s\n" % exc)
        return 1
    except struct.error as exc:
        sys.stderr.write("错误：文件结构异常（%s），可能已损坏或被截断\n" % exc)
        return 1

    if not records:
        sys.stderr.write("没有找到任何 DNS 报文（本脚本只认端口 53 的 UDP/TCP）。\n")
        sys.stderr.write("共读了 %d 个包。\n" % stats["packets"])
        return 1

    dstat = build_stats(records)

    # 逐条打分
    scored = []
    for rec in records:
        sc, reasons = tunnel_score(rec, dstat, len(records))
        scored.append((rec, sc, reasons))

    rows = scored
    if args.tunnel:
        rows = [r for r in scored if r[1] >= args.threshold]
    if args.limit and args.limit > 0:
        rows = rows[:args.limit]

    # ---- CSV
    if args.csv:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["序号", "方向", "qtype", "rcode", "域名", "应答", "隧道分", "原因"])
        for rec, sc, reasons in rows:
            q = rec["questions"][0] if rec["questions"] else None
            w.writerow([
                rec["pkt"],
                "response" if rec["qr"] else "query",
                QTYPE_NAMES.get(q["qtype"], str(q["qtype"])) if q else "",
                RCODE_NAMES.get(rec["rcode"], str(rec["rcode"])),
                q["name"].rstrip(".") if q else "",
                " | ".join("%s=%s" % (QTYPE_NAMES.get(a["type"], a["type"]), a["value"])
                           for a in rec["answers"]),
                "%.1f" % sc,
                "; ".join(reasons),
            ])
        text = buf.getvalue()
    else:
        lines = []
        lines.append("共 %d 个包，其中 DNS 报文 %d 条（UDP %d / TCP %d）"
                     % (stats["packets"], stats["dns"], stats["udp"], stats["tcp"]))
        lines.append("")

        if args.stats or not args.tunnel:
            lines.append("== 按根域名聚合（前 15）==")
            lines.append("%-32s %6s %6s %8s %5s" %
                         ("根域名", "查询", "响应", "NXDOMAIN", "唯一名"))
            lines.append("-" * 70)
            top = sorted(dstat.items(), key=lambda kv: kv[1]["count"], reverse=True)
            for root, st in top[:15]:
                lines.append("%-32s %6d %6d %8d %5d" % (
                    root[:32], st["queries"], st["responses"], st["nxdomain"],
                    len(st["names"])))
            lines.append("")

        if args.tunnel:
            lines.append("== 可疑 DNS 隧道项（阈值 %.1f，共 %d 条）=="
                         % (args.threshold, len(rows)))
        else:
            lines.append("== DNS 记录明细（共 %d 条）==" % len(rows))
        lines.append("")
        if not rows:
            lines.append("（没有达到阈值的项）")
        for rec, sc, reasons in rows:
            lines.append(fmt_rec(rec))
            if reasons:
                lines.append("        隧道分 %.1f：%s" % (sc, "；".join(reasons)))
        text = "\n".join(lines) + "\n"

    # ---- --decode：把隧道数据拼回来
    if args.decode:
        lines = []
        lines.append("共 %d 个包，其中 DNS 报文 %d 条" % (stats["packets"], stats["dns"]))
        lines.append("")
        groups = decode_tunnels(scored, args.threshold)
        if not groups:
            lines.append("没有找到可拼接的隧道数据。")
            lines.append("（阈值 %.1f；可用 --threshold 调低试试）" % args.threshold)
        else:
            lines.append("== 隧道数据拼接与解码（阈值 %.1f，%d 个根域名）=="
                         % (args.threshold, len(groups)))
            lines.append("")
            for key in sorted(groups, key=lambda k: (min(groups[k]["order"]), k[0], k[1])):
                g = groups[key]
                joined = "".join(g["parts"])
                lines.append("根域名: %s   类型: %s" % (g["root"], g["kind"] or "?"))
                lines.append("  分段数: %d  拼接长度: %d"
                             % (len(g["parts"]), len(joined)))
                lines.append("  拼接内容: %s" % (joined[:120] + ("..." if len(joined) > 120 else "")))
                decs = try_decode_payload(joined)
                if not decs:
                    lines.append("  [解码] 没有成功的解码方式（可能不是标准 base32/64/hex）")
                else:
                    shown = 0
                    for name, raw in decs:
                        ratio = printable_ratio(raw)
                        if ratio < 0.7:
                            continue
                        try:
                            txt = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            txt = raw.decode("latin-1")
                        if len(txt) > 200:
                            txt = txt[:200] + "..."
                        lines.append("  [%s] %s" % (name, txt))
                        shown += 1
                    if shown == 0:
                        lines.append("  [解码] 解出来了但都不是可读文本（可能被压缩/加密）")
                lines.append("")
        text = "\n".join(lines) + "\n"
        if args.output:
            p = os.path.abspath(args.output)
            if os.path.exists(p) and not args.force:
                sys.stderr.write("错误：输出文件已存在，加 --force 才覆盖：%s\n" % p)
                return 1
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            sys.stderr.write("已写入 %s\n" % p)
        else:
            sys.stdout.write(text)
        return 0

    if args.output:
        p = os.path.abspath(args.output)
        if os.path.exists(p) and not args.force:
            sys.stderr.write("错误：输出文件已存在，加 --force 才覆盖：%s\n" % p)
            return 1
        parent = os.path.dirname(p)
        if parent and not os.path.isdir(parent):
            sys.stderr.write("错误：输出目录不存在：%s\n" % parent)
            return 1
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        sys.stderr.write("已写入 %s（%d 字节）\n" % (p, len(text.encode("utf-8"))))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
