# -*- coding: utf-8 -*-
"""
strings.py -- 增强版 strings：多编码提取 + 正则过滤。

为什么需要
==========
系统自带的 strings（Sysinternals 版）只认 ASCII，遇到 UTF-16LE
（Windows 程序里的字符串几乎都是 UTF-16）就完全瞎了。CTF 里经常
要在内存转储、PE 文件、图片里找 flag，只搜 ASCII 会漏掉一半。

本脚本同时扫 ASCII / UTF-8 / UTF-16LE / UTF-16BE 四种编码，
并支持正则过滤、按最短长度过滤、只输出命中行。

用法
====
    python -X utf8 strings.py 文件.bin
    python -X utf8 strings.py 文件.bin -m 6              # 最短 6 字符
    python -X utf8 strings.py 文件.bin -r "flag\\{.*?\\}"  # 正则过滤
    python -X utf8 strings.py 文件.bin --enc utf16       # 只扫 UTF-16LE
    python -X utf8 strings.py 文件.bin --with-offset     # 显示偏移

已知限制
========
    * 只提取「连续可打印字符」，被拆散的数据需要先解密/解压；
    * UTF-16 扫描基于字节模式，可能产生少量误报（相邻字节巧合）；
    * 不处理 GBK 等双字节编码（可用 -r 配合其他工具）。
"""

import argparse
import re
import sys
from pathlib import Path

# 可打印 ASCII：0x20-0x7E，外加 tab
ASCII_PRINTABLE = set(range(0x20, 0x7F)) | {0x09}


def extract_ascii(data, minlen):
    """提取连续可打印 ASCII 串，返回 [(偏移, 字符串)]。"""
    out = []
    start = None
    for i, b in enumerate(data):
        if b in ASCII_PRINTABLE:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= minlen:
                out.append((start, data[start:i].decode("latin-1")))
            start = None
    if start is not None and len(data) - start >= minlen:
        out.append((start, data[start:].decode("latin-1")))
    return out


def extract_utf16(data, minlen, little=True):
    """提取 UTF-16 串。

    做法：按 2 字节步进，判断「可打印字符的伙伴字节是 0」。
    LE 时字符在低字节、高位为 0；BE 时反之。

    关键：UTF-16 数据在文件里**不一定 2 字节对齐**（前面多了一个奇数字节
    就会整体错位）。所以两种奇偶相位都要扫，否则会漏掉一半的串 ——
    更糟的是会被另一种字节序「错位凑巧」命中，给出错误标注。
    """
    out = []
    n = len(data) - 1
    for phase in (0, 1):
        i = phase
        while i < n:
            start = None
            chars = []
            j = i
            while j < n:
                lo = data[j] if little else data[j + 1]
                hi = data[j + 1] if little else data[j]
                if hi == 0 and lo in ASCII_PRINTABLE:
                    if start is None:
                        start = j
                    chars.append(chr(lo))
                    j += 2
                else:
                    break
            if start is not None and len(chars) >= minlen:
                out.append((start, "".join(chars)))
                i = j
            else:
                i += 2
    return out


def extract_utf8_cjk(data, minlen):
    """提取包含 CJK 的 UTF-8 串（中文题常见）。

    逐字节尝试解码：遇到能解出中文的连续区段就收集。
    """
    out = []
    i = 0
    n = len(data)
    while i < n:
        # 找 UTF-8 三字节序列的起始（0xE4-0xE9 是 CJK 常见首字节）
        if 0xE4 <= data[i] <= 0xE9 and i + 3 <= n:
            start = i
            chars = []
            j = i
            while j + 3 <= n:
                b = data[j]
                if 0xE4 <= b <= 0xE9:
                    try:
                        ch = data[j:j + 3].decode("utf-8")
                    except UnicodeDecodeError:
                        break
                    chars.append(ch)
                    j += 3
                elif b in ASCII_PRINTABLE:
                    chars.append(chr(b))
                    j += 1
                else:
                    break
            if len(chars) >= minlen:
                out.append((start, "".join(chars)))
                i = j
                continue
        i += 1
    return out


def main():
    ap = argparse.ArgumentParser(
        description="增强版 strings：ASCII/UTF-8/UTF-16 多编码提取 + 正则过滤",
        add_help=True,
    )
    ap.add_argument("target", nargs="?", help="要扫描的文件")
    ap.add_argument("-m", "--min-len", type=int, default=4, help="最短字符串长度（默认 4）")
    ap.add_argument("-r", "--regex", help="只输出匹配这个正则的字符串")
    ap.add_argument("--enc", default="all",
                    choices=["all", "ascii", "utf16", "utf16be", "cjk"],
                    help="扫描哪些编码（默认 all）")
    ap.add_argument("--with-offset", action="store_true", help="显示每条的字节偏移")
    ap.add_argument("--max", type=int, default=0, help="最多输出多少条（0 = 不限）")
    args = ap.parse_args()

    if not args.target:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 strings.py 文件.bin")
        print("  python -X utf8 strings.py 文件.bin -m 6")
        print('  python -X utf8 strings.py 文件.bin -r "flag\\{.*\\}"')
        print("  python -X utf8 strings.py 文件.bin --enc utf16 --with-offset")
        print("")
        print("提示：Windows 程序里的字符串多是 UTF-16LE，只搜 ASCII 会漏。")
        return 0

    p = Path(args.target)
    if not p.is_file():
        print("[错误] 文件不存在: %s" % p, file=sys.stderr)
        return 1
    try:
        data = p.read_bytes()
    except OSError as exc:
        print("[错误] 无法读取: %s" % exc, file=sys.stderr)
        return 1
    if not data:
        print("[错误] 文件为空", file=sys.stderr)
        return 1

    print("扫描: %s  (%d 字节)" % (p.name, len(data)))
    print("")

    results = []      # [(偏移, 编码名, 字符串)]
    if args.enc in ("all", "ascii"):
        for off, s in extract_ascii(data, args.min_len):
            results.append((off, "ascii", s))
    # 先扫 UTF-16LE（Windows/CTF 最常见），再扫 BE。
    # 若同一字符串 BE 也命中，说明是错位巧合，不该覆盖 LE 的结论。
    if args.enc in ("all", "utf16"):
        for off, s in extract_utf16(data, args.min_len, little=True):
            results.append((off, "utf16le", s))
    if args.enc in ("all", "utf16be"):
        for off, s in extract_utf16(data, args.min_len, little=False):
            results.append((off, "utf16be", s))
    if args.enc in ("all", "cjk"):
        for off, s in extract_utf8_cjk(data, max(args.min_len, 2)):
            results.append((off, "cjk", s))

    # 去重（同一偏移同一字符串可能被多编码扫到）
    # 注意：UTF-16LE 的英文串在「按 BE 解析」时也可能凑巧成立，
    # 所以同一字符串若同时被 LE 和 BE 命中，保留 LE（更常见）。
    seen = set()
    uniq = []
    for off, enc, s in results:
        key = (s, enc)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((off, enc, s))
    # 去重：同一段文本可能被两种字节序同时命中（错位凑巧）。
    # 择优规则：保留「更长」的那个（更长的说明没被截断），
    # 长度相同则优先 utf16le（Windows 环境更常见）。
    by_text = {}
    for off, enc, s in uniq:
        prev = by_text.get(s)
        if prev is None:
            by_text[s] = (off, enc, s)
            continue
        p_off, p_enc, p_s = prev
        if len(s) > len(p_s):
            by_text[s] = (off, enc, s)
        elif len(s) == len(p_s) and enc == "utf16le":
            by_text[s] = (off, enc, s)
    uniq = list(by_text.values())
    # 再去一次「前缀重复」：短的被长的包含就丢掉短的
    final = []
    for off, enc, s in uniq:
        if any(len(s) < len(t) and s in t for _, _, t in uniq):
            continue
        final.append((off, enc, s))
    uniq = final

    # 正则过滤
    if args.regex:
        try:
            pat = re.compile(args.regex)
        except re.error as exc:
            print("[错误] 正则不合法: %s" % exc, file=sys.stderr)
            return 1
        uniq = [r for r in uniq if pat.search(r[2])]
        print("正则过滤: %s" % args.regex)
        print("")

    # 按偏移排序
    uniq.sort(key=lambda x: x[0])

    if not uniq:
        print("没有提取到符合条件的字符串。")
        print("建议：")
        print("  - 降低 -m（最短长度）")
        print("  - 数据可能被压缩/加密，先用 filetype.py 判断，再解压/解密")
        return 0

    total = len(uniq)
    show = uniq if args.max <= 0 else uniq[:args.max]
    for off, enc, s in show:
        if args.with_offset:
            print("0x%08X  [%-7s] %s" % (off, enc, s))
        else:
            print(s)

    print("")
    print("共 %d 条" % total, end="")
    if args.max > 0 and total > args.max:
        print("（只显示前 %d 条）" % args.max)
    else:
        print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
