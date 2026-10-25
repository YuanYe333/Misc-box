# -*- coding: utf-8 -*-
"""
tcpextract.py -- 按 TCP 流重组双向数据并导出成文件。

为什么需要
==========
「把这条 TCP 流导出来」是流量题最常做的一步。Wireshark 的
Follow TCP Stream 能用，但：
  * 要一条条点，几十条流就很烦；
  * 它把双向数据混在一个窗口里，想分别拿到「客户端发的」和「服务端发的」
    还得手动切；
  * 导出后还要按文件类型再分拣。

本脚本按 (src_ip, src_port, dst_ip, dst_port) 四元组分流，双向分别重组，
每条流导出两个文件：`stream_N_client.txt` 和 `stream_N_server.txt`。

能做什么
========
  * 乱序：按序号重排，不依赖抓包顺序。
  * 重传 / 重复包：同一序号同一内容的包只写一次。
  * 部分重叠：按「先到先得」填充，后到的重叠部分丢弃。
  * 序号回绕：检测到跨度异常时给出警告（见「已知限制」）。
  * --list 列出所有流；--stream N 导出单条；--all 全导到目录。
  * 自动判断哪个端点是「客户端」（发起 SYN 的一方），命名不搞反。

用法
====
    python -X utf8 tcpextract.py 题目.pcap --list
    python -X utf8 tcpextract.py 题目.pcap --stream 2 -o 导出目录
    python -X utf8 tcpextract.py 题目.pcap --all -o 导出目录

已知限制（重要，别指望它比 Wireshark 强）
==========================================
  * **序号回绕只告警、不真正处理**。超过 4GB 的流会跨 2^32 边界，
    本脚本能发现「跨度异常大」并打印警告，但拼接结果可能错位。
    真遇到这种题请用 tshark 的 follow,tcp,raw。
  * **不做 TCP 重组的「确认号驱动」**。本脚本以序号为准，不跟踪 ACK，
    因此不区分「发送方重传了但接收方没收到」这类语义，只保证字节顺序对。
  * **空洞不猜测**。抓包丢了的字节会如实留下 0x00 并统计空洞数，
    不会假装数据完整。空洞位置在 stderr 里报出来。
  * **不做 TLS 解密**。加密流的 payload 就是密文，导出来也是密文。
  * **不处理 IP 分片以外的重组**（IP 分片由 pcapcarve 的解析层处理）。
  * **流序号从 1 开始**，按四元组首次出现顺序编号，与 tshark 的 0 基不同。
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from pcapcarve import (PcapError, read_packets, iter_l3, decode_tcp,
                           norm_endpoints, reassemble_dir, new_stats,
                           safe_setup, ep_str, PROTO_TCP)
except ImportError:                                     # pragma: no cover
    sys.stderr.write("错误：找不到同目录的 pcapcarve.py（复用它的 pcap 读取与重组）\n")
    raise SystemExit(1)

TCP_SYN = 0x02
TCP_FIN = 0x01
TCP_RST = 0x04


class Stream(object):
    """一条双向 TCP 流。"""

    def __init__(self, endpoints, index):
        self.endpoints = endpoints
        self.index = index
        self.segs = []          # [(dir, seq, payload)]
        self.dupe = set()
        self.client = None      # 0 或 1：哪个端点先发 SYN
        self.syn_seq = [None, None]
        self.wrap_warned = False

    def add(self, direction, seq, payload, flags):
        if flags & TCP_SYN and not (flags & 0x10):
            # 纯 SYN（不带 ACK）来自客户端
            if self.syn_seq[direction] is None:
                self.syn_seq[direction] = seq
            if self.client is None:
                self.client = direction
        if not payload:
            return
        key = (direction, seq, len(payload))
        if key in self.dupe:
            return
        self.dupe.add(key)
        self.segs.append((direction, seq, payload))

    def dir_data(self, direction):
        return [(d, s, p) for d, s, p in self.segs if d == direction]

    def byte_count(self, direction):
        return sum(len(p) for d, _s, p in self.segs if d == direction)

    def client_side(self):
        """返回客户端在 endpoints 里的下标（默认 0）。"""
        return self.client if self.client is not None else 0


def collect(path):
    stats = new_stats()
    streams = {}
    order = []
    for idx, _ts, src, dst, proto, pl in iter_l3(read_packets(path), stats):
        stats["packets"] += 1
        if proto != PROTO_TCP:
            continue
        r = decode_tcp(pl)
        if r is None:
            continue
        stats["tcp_pkts"] += 1
        sp, dp, seq, _ack, flags, payload = r
        key, direction = norm_endpoints(((src, sp), (dst, dp)))
        st = streams.get(key)
        if st is None:
            st = Stream(key, len(order) + 1)
            streams[key] = st
            order.append(st)
        st.add(direction, seq, payload, flags)
    return order, stats


def stream_report(st):
    """计算一条流的双向重组结果 + 告警。"""
    out = []
    for direction in (0, 1):
        data, gaps, notes = reassemble_dir(st.dir_data(direction))
        # 序号回绕的额外判断：相邻分段跨过 2^32 边界
        segs = st.dir_data(direction)
        if len(segs) >= 2:
            seqs = [s for _d, s, _p in segs]
            span = max(seqs) - min(seqs)
            if span > 0x80000000:
                notes.append("序号跨度超过 2^31，极可能有回绕（结果可能错位）")
        out.append((data, gaps, notes))
    return out


def safe_name(ep):
    ip, port = ep
    s = "%s_%d" % (ip.replace(":", "-").replace(".", "_"), port)
    return s


def usage(prog):
    print("tcpextract.py -- 按 TCP 流重组双向数据并导出成文件")
    print("")
    print("用法：")
    print("  python -X utf8 %s 题目.pcap --list            列出所有 TCP 流" % prog)
    print("  python -X utf8 %s 题目.pcap --stream 2 -o 目录  导出第 2 条流" % prog)
    print("  python -X utf8 %s 题目.pcap --all -o 目录       导出全部流" % prog)
    print("  python -X utf8 %s 题目.pcap --stream 2         只打印不落盘" % prog)
    print("")
    print("导出文件名：stream_N_client.txt / stream_N_server.txt")
    print("（客户端 = 先发 SYN 的那一方；认不出就按地址排序的第一个算客户端）")
    print("")
    print("选项：")
    print("  --list        只列流清单")
    print("  --stream N    导出第 N 条流（N 从 1 开始）")
    print("  --all         导出全部流")
    print("  -o DIR        输出目录（不存在会自动创建）")
    print("  --force       允许覆盖已存在的文件")
    print("  --limit N     单方向最多导出多少字节（默认 0 = 不限）")
    print("")
    print("例子：")
    print("  python -X utf8 %s cap.pcap --all -o 导出" % prog)
    print("  python -X utf8 %s cap.pcap --stream 1 -o 导出 --force" % prog)


def main():
    safe_setup()
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--stream", type=int, default=None)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    try:
        args = ap.parse_args()
    except SystemExit:
        return 2

    prog = os.path.basename(sys.argv[0]) or "tcpextract.py"
    if args.help or not args.pcap:
        usage(prog)
        return 0

    path = os.path.abspath(args.pcap)
    if not os.path.isfile(path):
        sys.stderr.write("错误：文件不存在或不是普通文件：%s\n" % path)
        return 1

    try:
        streams, stats = collect(path)
    except PcapError as exc:
        sys.stderr.write("错误：%s\n" % exc)
        return 1
    except (IOError, OSError) as exc:
        sys.stderr.write("错误：读取失败：%s\n" % exc)
        return 1
    except struct.error as exc:
        sys.stderr.write("错误：文件结构异常（%s），可能已损坏或被截断\n" % exc)
        return 1

    if not streams:
        sys.stderr.write("没有找到任何 TCP 流（文件里可能只有 UDP/ARP/非 IP 流量）。\n")
        return 1

    if args.list:
        print("共 %d 个包，%d 条 TCP 流" % (stats["packets"], len(streams)))
        print("%-4s %-48s %-12s %s" % ("#", "客户端 -> 服务端", "端口", "字节 客/服"))
        print("-" * 96)
        for st in streams:
            ci = st.client_side()
            a = st.endpoints[ci]
            b = st.endpoints[1 - ci]
            print("%-4d %-48s %-12s %d / %d" % (
                st.index, "%s -> %s" % (ep_str(a), ep_str(b)),
                "%d->%d" % (a[1], b[1]),
                st.byte_count(ci), st.byte_count(1 - ci)))
        return 0

    if args.stream is None and not args.all:
        sys.stderr.write("错误：需要 --list、--stream N 或 --all 之一。\n")
        sys.stderr.write("例：python -X utf8 %s 题目.pcap --list\n" % prog)
        return 2

    targets = []
    if args.stream is not None:
        if args.stream < 1 or args.stream > len(streams):
            sys.stderr.write("错误：流序号 %d 超出范围（本文件共 %d 条流，编号 1..%d）\n"
                             % (args.stream, len(streams), len(streams)))
            return 2
        targets = [streams[args.stream - 1]]
    else:
        targets = streams

    outdir = None
    if args.output:
        outdir = os.path.abspath(args.output)
        if os.path.exists(outdir) and not os.path.isdir(outdir):
            sys.stderr.write("错误：-o 指向的是文件而不是目录：%s\n" % outdir)
            return 1
        if not os.path.isdir(outdir):
            try:
                os.makedirs(outdir)
            except OSError as exc:
                sys.stderr.write("错误：无法创建输出目录 %s（%s）\n" % (outdir, exc))
                return 1

    written = 0
    for st in targets:
        reports = stream_report(st)
        ci = st.client_side()
        # reports[0] 是 endpoints[0] 方向；按 client 下标映射到 client/server
        pairs = [
            ("client", reports[ci]),
            ("server", reports[1 - ci]),
        ]
        for role, (data, gaps, notes) in pairs:
            for note in notes:
                sys.stderr.write("流 #%d %s 方向：%s\n" % (st.index, role, note))
            if not data:
                continue
            if args.limit and args.limit > 0 and len(data) > args.limit:
                data = data[:args.limit]
            if outdir is None:
                sys.stdout.write("=== 流 #%d %s 方向（%d 字节%s）===\n"
                                 % (st.index, role, len(data),
                                    "，%d 字节空洞" % gaps if gaps else ""))
                sys.stdout.write(data.decode("latin-1").replace("\r\n", "\n"))
                sys.stdout.write("\n")
                continue
            name = "stream_%d_%s.txt" % (st.index, role)
            p = os.path.join(outdir, name)
            if os.path.exists(p) and not args.force:
                sys.stderr.write("错误：文件已存在，加 --force 才覆盖：%s\n" % p)
                return 1
            try:
                with open(p, "wb") as fh:
                    fh.write(data)
            except (IOError, OSError) as exc:
                sys.stderr.write("错误：写入失败 %s（%s）\n" % (p, exc))
                return 1
            written += 1
            sys.stderr.write("已导出 %s（%d 字节%s）\n"
                             % (p, len(data), "，%d 字节空洞" % gaps if gaps else ""))

    if outdir is not None:
        sys.stderr.write("共导出 %d 个文件到 %s\n" % (written, outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
