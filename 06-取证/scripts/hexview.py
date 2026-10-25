# -*- coding: utf-8 -*-
"""
hexview.py -- 十六进制查看器（带 ASCII 侧栏、偏移跳转、字符串搜索）。

为什么需要
==========
改文件头、找隐藏数据、确认某处偏移到底是什么，都需要直接看字节。
系统自带的 certutil/format-hex 不好用，HxD 要装，而很多时候只是想
「看一眼这 64 字节」或「搜一下 flag 在哪」。

本脚本提供：
  * 标准 hexdump 布局（偏移 + 16 字节 hex + ASCII 侧栏）；
  * 按偏移直接跳转（-o 0x100）；
  * 按十六进制字节串搜索（-s 504b0304）；
  * 按文本搜索（-t flag）；
  * 只看某一段（-o 偏移 -n 长度）。

用法
====
    python -X utf8 hexview.py 文件.bin                  # 看开头 256 字节
    python -X utf8 hexview.py 文件.bin -o 0x100 -n 512  # 从 0x100 看 512 字节
    python -X utf8 hexview.py 文件.bin -s 504b0304      # 搜 ZIP 头
    python -X utf8 hexview.py 文件.bin -t flag          # 搜文本

已知限制
========
    * 只读，不能修改文件（改字节请用专门的编辑器）；
    * 超大文件搜索会全量读入内存（几百 MB 以内没问题）。
"""

import argparse
import sys
from pathlib import Path

BYTES_PER_LINE = 16


def parse_offset(text):
    """支持 0x 前缀、纯十进制、带下划线的写法。"""
    t = str(text).strip().replace("_", "")
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def hexdump(data, base_offset=0, limit=None):
    """打印标准 hexdump。"""
    if limit is not None:
        data = data[:limit]
    for i in range(0, len(data), BYTES_PER_LINE):
        chunk = data[i:i + BYTES_PER_LINE]
        hexpart = " ".join("%02X" % b for b in chunk)
        # 补齐到固定宽度，让 ASCII 侧栏对齐
        hexpart = hexpart.ljust(BYTES_PER_LINE * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        print("%08X  %s  |%s|" % (base_offset + i, hexpart, ascii_part))


def find_bytes(data, needle):
    """返回所有匹配偏移。"""
    out = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + 1
    return out


def context_view(data, offsets, radius=32):
    """在匹配点前后各取 radius 字节展示。"""
    for off in offsets:
        s = max(0, off - radius)
        e = min(len(data), off + radius)
        print("--- 匹配于 0x%X（展示 0x%X - 0x%X）---" % (off, s, e))
        hexdump(data[s:e], s)
        print("")


def main():
    ap = argparse.ArgumentParser(
        description="十六进制查看器：看字节、跳偏移、搜字节/文本",
        add_help=True,
    )
    ap.add_argument("target", nargs="?", help="要查看的文件")
    ap.add_argument("-o", "--offset", default="0", help="起始偏移（支持 0x100）")
    ap.add_argument("-n", "--length", type=int, default=256, help="显示字节数（默认 256）")
    ap.add_argument("-s", "--search-hex", help="搜索十六进制字节串，如 504b0304")
    ap.add_argument("-t", "--search-text", help="搜索文本（UTF-8 / Latin-1）")
    ap.add_argument("--all", action="store_true", help="显示所有匹配（默认最多 20 处）")
    args = ap.parse_args()

    if not args.target:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 hexview.py 文件.bin")
        print("  python -X utf8 hexview.py 文件.bin -o 0x100 -n 512")
        print("  python -X utf8 hexview.py 文件.bin -s 504b0304")
        print("  python -X utf8 hexview.py 文件.bin -t flag")
        print("")
        print("提示：改文件头前先用 filetype.py 确认它原本是什么类型。")
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

    print("文件: %s  (%d 字节 = 0x%X)" % (p.name, len(data), len(data)))
    print("")

    # 搜索模式
    needle = None
    label = None
    if args.search_hex:
        try:
            needle = bytes.fromhex(args.search_hex.replace(" ", ""))
        except ValueError:
            print("[错误] -s 不是合法的十六进制串: %s" % args.search_hex, file=sys.stderr)
            return 1
        label = "十六进制 %s" % args.search_hex
    elif args.search_text:
        needle = args.search_text.encode("utf-8")
        label = "文本 %r" % args.search_text
        # UTF-16LE 也顺手搜一下（Windows 文本常见）
        alt = args.search_text.encode("utf-16-le")

    if needle is not None:
        offsets = find_bytes(data, needle)
        if not offsets and args.search_text and alt != needle:
            offsets = find_bytes(data, alt)
            if offsets:
                label += "（按 UTF-16LE 匹配）"
        print("搜索: %s" % label)
        if not offsets:
            print("没有找到。")
            print("提示：二进制数据可能被压缩或加密，直接搜文本是搜不到的。")
            return 0
        print("找到 %d 处匹配。" % len(offsets))
        print("")
        show = offsets if args.all else offsets[:20]
        context_view(data, show)
        if not args.all and len(offsets) > 20:
            print("（只显示前 20 处，加 --all 看全部）")
        return 0

    # 普通查看模式
    try:
        offset = parse_offset(args.offset)
    except ValueError:
        print("[错误] -o 偏移不合法: %s" % args.offset, file=sys.stderr)
        return 1

    if offset < 0 or offset >= len(data):
        print("[错误] 偏移 0x%X 超出文件范围（0 - 0x%X）" % (offset, len(data)), file=sys.stderr)
        return 1

    remaining = len(data) - offset
    n = min(args.length, remaining)
    print("显示 0x%X - 0x%X（%d 字节，文件剩余 %d 字节）" % (offset, offset + n, n, remaining))
    print("")
    hexdump(data[offset:offset + n], offset)

    if offset + n < len(data):
        print("")
        print("还有 %d 字节未显示，用 -n 加大或 -o 跳转。" % (len(data) - offset - n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
