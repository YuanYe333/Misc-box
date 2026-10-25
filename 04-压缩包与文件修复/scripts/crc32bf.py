# -*- coding: utf-8 -*-
"""
crc32bf.py -- CRC32 反推缺失字节（小范围爆破）。

为什么需要
==========
CTF 里常出现「文件被挖掉几个字节，但 CRC 还在」的题：
  * PNG 的 IHDR 被改了宽高，需要重新算 CRC 才能被解码器接受；
  * 一个已知 CRC32 的短串，缺 1~4 个字符，要求还原；
  * ZIP 条目 CRC 已知但内容缺失。

CRC32 是线性的，理论上可以用矩阵求逆直接解出任意长度缺失；
但实现复杂、容易出错。本脚本采用**暴力枚举**（限 4 字节以内），
简单可靠，4 字节以内速度可接受。

用法
====
    # 已知 5 字节内容，缺最后 2 字节，目标 CRC = 0x12345678
    python -X utf8 crc32bf.py --prefix "AB" --crc 0x12345678 --len 2

    # 从字符集里找（默认可见 ASCII）
    python -X utf8 crc32bf.py --prefix "flag{" --crc 0xdeadbeef --len 3 --charset lower

    # 修 PNG 的 IHDR：直接给文件，自动定位并修正
    python -X utf8 crc32bf.py --fix-png 坏图.png -o 修好.png

已知限制
========
    * 暴力枚举：4 字节 95^4 ≈ 8100 万，要跑几分钟；5 字节以上不建议；
    * 只支持 CRC32（IEEE 多项式 0xEDB88320），不支持 CRC16/CRC64；
    * --fix-png 只能修 CRC，不能修「数据本身被改坏」的情况。
"""

import argparse
import binascii
import itertools
import struct
import sys
import time
import zlib
from pathlib import Path

CHARSETS = {
    "printable": [chr(c) for c in range(0x20, 0x7F)],
    "lower": list("abcdefghijklmnopqrstuvwxyz"),
    "upper": list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    "digit": list("0123456789"),
    "alnum": list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
    "hex": list("0123456789abcdef"),
    "flag": list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-"),
}


def crc32_of(data):
    return binascii.crc32(data) & 0xFFFFFFFF


def brute(prefix, length, target, charset):
    """在 charset^length 空间里找让 crc32(prefix + guess) == target 的组合。"""
    space = len(charset) ** length
    print("搜索空间: %d^%d = %d 种组合" % (len(charset), length, space))
    if space > 200000000:
        print("[拒绝] 搜索空间超过 2 亿，太慢了。", file=sys.stderr)
        print("建议：缩短 --len，或换更小的 --charset。", file=sys.stderr)
        return None

    pre = prefix.encode("latin-1", "replace")
    start = time.time()
    tried = 0
    found = None
    # 用 itertools.product 生成组合；每 100 万次报一次进度
    for combo in itertools.product(charset, repeat=length):
        tried += 1
        cand = "".join(combo)
        if crc32_of(pre + cand.encode("latin-1", "replace")) == target:
            found = cand
            break
        if tried % 1000000 == 0:
            elapsed = time.time() - start
            rate = tried / elapsed if elapsed else 0
            print("  已试 %d / %d (%.0f%%)  %.0f 次/秒" %
                  (tried, space, tried * 100.0 / space, rate))
    elapsed = time.time() - start
    print("共试 %d 次，耗时 %.1f 秒" % (tried, elapsed))
    return found


def png_chunks(blob):
    """遍历 PNG 块，返回 [(类型, 数据起始, 数据长度, CRC位置)]。"""
    if blob[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    chunks = []
    pos = 8
    while pos + 12 <= len(blob):
        try:
            (length,) = struct.unpack(">I", blob[pos:pos + 4])
        except struct.error:
            break
        ctype = blob[pos + 4:pos + 8]
        data_start = pos + 8
        crc_pos = data_start + length
        if crc_pos + 4 > len(blob):
            break
        chunks.append((ctype.decode("latin-1"), data_start, length, crc_pos))
        if ctype == b"IEND":
            break
        pos = crc_pos + 4
    return chunks


def fix_png(blob, out_path):
    """重算所有块的 CRC 并写出。"""
    chunks = png_chunks(blob)
    if chunks is None:
        print("[错误] 不是 PNG（文件头不对）", file=sys.stderr)
        return False

    print("PNG 块列表:")
    bad = 0
    new = bytearray(blob)
    for ctype, dstart, dlen, crc_pos in chunks:
        data = blob[dstart:dstart + dlen]
        actual = crc32_of(ctype.encode("latin-1") + data)
        stored = struct.unpack(">I", blob[crc_pos:crc_pos + 4])[0]
        ok = actual == stored
        print("  %-6s 长度 %-6d CRC %08X %s" %
              (ctype, dlen, stored, "正常" if ok else "-> 应为 %08X 【需修】" % actual))
        if not ok:
            bad += 1
            struct.pack_into(">I", new, crc_pos, actual)

    if bad == 0:
        print("")
        print("所有块 CRC 都正确，无需修复。")
        print("如果图片仍打不开，问题不在 CRC，可能是宽高或数据被改坏。")
        return False

    print("")
    print("共 %d 个块 CRC 需要修复。" % bad)
    if not out_path:
        print("加 -o 文件名 才能写出修复结果。")
        return True

    target = Path(out_path)
    target.write_bytes(bytes(new))
    print("已写出: %s" % target)
    print("")
    print("验证：")
    try:
        # 检查 IHDR 宽高是否合理
        for ctype, dstart, dlen, crc_pos in png_chunks(bytes(new)):
            if ctype == "IHDR" and dlen >= 8:
                w, h = struct.unpack(">II", bytes(new)[dstart:dstart + 8])
                print("  IHDR 宽高: %d x %d" % (w, h))
                if w == 0 or h == 0 or w > 100000 or h > 100000:
                    print("  [警告] 宽高看起来不合理，可能 IHDR 数据本身被改过")
                break
        print("  CRC 已全部重算，可以再试打开。")
    except Exception as exc:  # noqa: BLE001
        print("  验证时出错: %s" % exc)
    return True


def main():
    ap = argparse.ArgumentParser(
        description="CRC32 反推缺失字节 / 修复 PNG 块 CRC",
        add_help=True,
    )
    ap.add_argument("--prefix", default="", help="已知的前缀内容")
    ap.add_argument("--crc", help="目标 CRC32（0x 开头或十进制）")
    ap.add_argument("--len", type=int, default=2, help="缺失字节数（默认 2）")
    ap.add_argument("--charset", default="printable",
                    help="字符集: printable/lower/upper/digit/alnum/hex/flag，或直接给字符")
    ap.add_argument("--fix-png", dest="fix_png", help="修复指定 PNG 的所有块 CRC")
    ap.add_argument("-o", "--output", help="修复后另存为这个文件")
    args = ap.parse_args()

    if args.fix_png:
        p = Path(args.fix_png)
        if not p.is_file():
            print("[错误] 文件不存在: %s" % p, file=sys.stderr)
            return 1
        blob = p.read_bytes()
        ok = fix_png(blob, args.output)
        return 0 if ok else 1

    if not args.crc:
        ap.print_help()
        print("")
        print("例子：")
        print('  python -X utf8 crc32bf.py --prefix "AB" --crc 0x12345678 --len 2')
        print('  python -X utf8 crc32bf.py --prefix "flag{" --crc 0xdeadbeef --len 3 --charset alnum')
        print("  python -X utf8 crc32bf.py --fix-png 坏图.png -o 修好.png")
        print("")
        print("说明：CRC32 是线性的，理论上可解任意长度；这里用暴力枚举，")
        print("      所以限制在 4 字节以内（2 字节瞬间出结果）。")
        return 0

    try:
        target = int(args.crc, 0) & 0xFFFFFFFF
    except ValueError:
        print("[错误] --crc 不是合法数字: %s" % args.crc, file=sys.stderr)
        return 1

    if args.len < 1:
        print("[错误] --len 至少为 1", file=sys.stderr)
        return 1
    if args.len > 4:
        print("[警告] --len > 4 会非常慢，请确认。", file=sys.stderr)

    charset = CHARSETS.get(args.charset)
    if charset is None:
        charset = list(args.charset)
    if not charset:
        print("[错误] 字符集为空", file=sys.stderr)
        return 1

    print("前缀: %r" % args.prefix)
    print("目标 CRC32: 0x%08X" % target)
    print("")

    found = brute(args.prefix, args.len, target, charset)
    print("")
    if found is None:
        print("没有找到匹配的 %d 字节。可能：" % args.len)
        print("  - 缺失字节不在这个字符集里")
        print("  - 缺失长度不对（试试 --len 1 / 3）")
        print("  - 目标 CRC 记错了")
        return 1

    full = args.prefix + found
    print("找到: %r" % found)
    print("完整内容: %r" % full)
    print("校验: crc32 = 0x%08X (目标 0x%08X)" % (crc32_of(full.encode("latin-1", "replace")), target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
