# -*- coding: utf-8 -*-
"""
filecarve.py -- 从裸数据里「雕」出文件（binwalk 的轻量替代）。

为什么需要
==========
镜像文件、内存转储、被截断的压缩包、或者一张图片尾部塞进去的一整段 ZIP，
都需要「在一大坨字节里找出哪些位置是文件的开始，然后切出来」。

binwalk 很强但要装一堆依赖；本脚本只做最实用的部分：
按文件头魔数找起点，按对应格式的结束标记找终点，切出完整文件。

用法
====
    python -X utf8 filecarve.py 镜像.bin
    python -X utf8 filecarve.py 镜像.bin -o 输出目录
    python -X utf8 filecarve.py 图片.png --tail          # 只看尾部附加数据

已知限制
========
    * 只雕「自带明确结束标记」的格式（PNG/JPG/GIF/ZIP/GZIP/PDF/7z 等）；
    * 没有长度字段又没结束标记的（如原始 PE 段）不雕，只报位置；
    * 一个文件被分成两段时会各雕一半，需要人工拼接。
"""

import argparse
import os
import struct
import sys
import zlib
from pathlib import Path

# ---------------------------------------------------------------- 格式定义
# (名称, 扩展名, 起始魔数, 结束魔数, 说明)
# 结束魔数为 None 表示「用长度字段计算」或「只能报位置」
SIGNATURES = [
    ("PNG", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", "PNG 图片"),
    ("GIF", ".gif", b"GIF89a", b"\x00\x3b", "GIF89a 图片"),
    ("GIF", ".gif", b"GIF87a", b"\x00\x3b", "GIF87a 图片"),
    ("JPEG", ".jpg", b"\xff\xd8\xff", b"\xff\xd9", "JPEG 图片"),
    ("ZIP", ".zip", b"PK\x03\x04", b"PK\x05\x06", "ZIP 归档（以中央目录结尾为界）"),
    ("RAR4", ".rar", b"Rar!\x1a\x07\x00", None, "RAR 4 归档"),
    ("RAR5", ".rar", b"Rar!\x1a\x07\x01\x00", None, "RAR 5 归档"),
    ("7Z", ".7z", b"7z\xbc\xaf\x27\x1c", None, "7-Zip 归档"),
    ("GZIP", ".gz", b"\x1f\x8b\x08", None, "gzip 压缩流"),
    ("BZIP2", ".bz2", b"BZh", None, "bzip2 压缩流"),
    ("PDF", ".pdf", b"%PDF-", b"%%EOF", "PDF 文档"),
    ("FLAC", ".flac", b"fLaC", None, "FLAC 音频"),
    ("OGG", ".ogg", b"OggS", None, "Ogg 容器"),
    ("SQLITE", ".sqlite", b"SQLite format 3\x00", None, "SQLite 数据库"),
    ("ELF", ".elf", b"\x7fELF", None, "ELF 可执行"),
    ("PE", ".exe", b"MZ", None, "PE 可执行（只报位置）"),
]

# 有结束标记的，从结尾魔数往后多切几个字节保证完整。
# 注意：多数格式的结束魔数本身就已经覆盖到「文件最后一个字节」，此时 slack 必须为 0，
# 否则会把后面的无关数据一起切进来（PNG 曾因此多切 4~8 字节）。
TAIL_SLACK = {
    "PNG": 0,       # IEND(4) + CRC(4) 都在魔数里
    "JPEG": 0,      # EOI 就是最后 2 字节
    "GIF": 0,       # trailer 2 字节
    "ZIP": 0,       # 交给 zip_end 精确计算
    "PDF": 0,       # %%EOF 之后可能还有换行，宁可少切也不要污染
}


def find_all(blob, needle):
    """返回 needle 在 blob 中所有出现位置。"""
    out = []
    start = 0
    while True:
        idx = blob.find(needle, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + 1
    return out


def zip_end(blob, start):
    """ZIP 的结尾：找到最后一个 EOCD（PK\\x05\\x06），加上它声明的注释长度。"""
    eocd = b"PK\x05\x06"
    pos = blob.rfind(eocd)
    if pos < start:
        return None
    # EOCD 结构：4 sig + 18 固定 + 2 注释长度
    if pos + 22 > len(blob):
        return len(blob)
    (comment_len,) = struct.unpack("<H", blob[pos + 20:pos + 22])
    return min(len(blob), pos + 22 + comment_len)


def gzip_end(blob, start):
    """gzip 结尾：ISIZE 之后 8 字节。用 zlib 解压来判断真实结束位置。"""
    try:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        dec.decompress(blob[start:])
        consumed = len(blob[start:]) - len(dec.unused_data)
        return start + consumed
    except zlib.error:
        return None


def carve_one(blob, start, name, end_magic):
    """给一个起点，算出终点。返回 (end_offset, 是否完整)。"""
    if name == "ZIP":
        e = zip_end(blob, start)
        return (e, e is not None) if e else (None, False)
    if name == "GZIP":
        e = gzip_end(blob, start)
        return (e, True) if e else (None, False)
    if end_magic:
        idx = blob.find(end_magic, start)
        if idx < 0:
            return None, False
        e = idx + len(end_magic) + TAIL_SLACK.get(name, 0)
        return min(e, len(blob)), True
    # 没有结束标记的：雕到下一个魔数出现处，或者文件尾
    return len(blob), False


def scan(blob):
    """扫描所有格式，返回 [(偏移, 名称, 扩展名, 说明, 终点, 完整)]。"""
    found = []
    seen = set()
    for name, ext, start_magic, end_magic, desc in SIGNATURES:
        for off in find_all(blob, start_magic):
            # MZ 太短太常见，会命中大量假阳性，要求后面有 PE 头
            if name == "PE":
                if blob[off + 0x3C:off + 0x40] and len(blob) > off + 0x40:
                    pe_off = struct.unpack("<I", blob[off + 0x3C:off + 0x40])[0]
                    if blob[off + pe_off:off + pe_off + 4] != b"PE\x00\x00":
                        continue
                else:
                    continue
            if (off, name) in seen:
                continue
            seen.add((off, name))
            end, complete = carve_one(blob, off, name, end_magic)
            found.append((off, name, ext, desc, end, complete))
    found.sort(key=lambda x: x[0])
    return found


def main():
    ap = argparse.ArgumentParser(
        description="按魔数从裸数据中雕刻出内嵌文件（binwalk 轻量替代）",
        add_help=True,
    )
    ap.add_argument("target", nargs="?", help="要扫描的文件")
    ap.add_argument("-o", "--output", help="把雕出的文件写到这个目录")
    ap.add_argument("--tail", action="store_true", help="只显示第一个文件结束之后的附加数据")
    ap.add_argument("--min-size", type=int, default=16, help="小于这个字节数的片段不雕（默认 16）")
    args = ap.parse_args()

    if not args.target:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 filecarve.py 镜像.bin")
        print("  python -X utf8 filecarve.py 镜像.bin -o 输出目录")
        print("  python -X utf8 filecarve.py 图片.png --tail")
        print("")
        print("提示：先跑 filetype.py 确认外层类型，再决定要不要雕。")
        return 0

    p = Path(args.target)
    if not p.is_file():
        print("[错误] 文件不存在: %s" % p, file=sys.stderr)
        return 1
    blob = p.read_bytes()
    if not blob:
        print("[错误] 文件为空", file=sys.stderr)
        return 1

    print("扫描: %s  (%d 字节)" % (p.name, len(blob)))
    print("")

    found = scan(blob)

    if args.tail:
        # 找第一个「完整」的文件，报告它之后还有什么
        first_complete = None
        for off, name, ext, desc, end, complete in found:
            if complete and end and end < len(blob):
                first_complete = (off, name, end)
                break
        if not first_complete:
            print("没有发现「文件结束后仍有剩余数据」的情况。")
            return 0
        off, name, end = first_complete
        tail = blob[end:]
        print("首个完整文件: %s @ 0x%X，结束于 0x%X" % (name, off, end))
        print("其后的附加数据: %d 字节" % len(tail))
        print("")
        if not tail:
            return 0
        print("附加数据开头 64 字节:")
        print(tail[:64].hex(" "))
        print("")
        inner = scan(tail)
        if inner:
            print("附加数据里还藏着：")
            for o2, n2, e2, d2, end2, c2 in inner[:10]:
                print("  +0x%X  %s  %s" % (o2, n2, d2))
        else:
            print("附加数据里没有再识别出已知文件格式（可能是加密数据或纯文本）。")
        return 0

    if not found:
        print("没有识别出任何已知文件头。")
        print("建议：可能是加密/压缩数据，或格式不在本脚本支持范围内。")
        return 0

    print("== 发现的文件头 ==")
    for off, name, ext, desc, end, complete in found:
        if end is None:
            print("  0x%-8X  %-8s  %s  (无法确定结尾)" % (off, name, desc))
        else:
            size = end - off
            flag = "完整" if complete else "不完整"
            print("  0x%-8X  %-8s  %-4s  %8d 字节  %s" % (off, name, flag, size, desc))
    print("")

    if not args.output:
        print("加 -o 目录 可以把这些片段实际切出来。")
        return 0

    outdir = Path(args.output)
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("[错误] 无法创建输出目录 %s: %s" % (outdir, exc), file=sys.stderr)
        return 1

    n = 0
    for off, name, ext, desc, end, complete in found:
        if end is None or end - off < args.min_size:
            continue
        n += 1
        fname = "%s_0x%08X%s" % (name.lower(), off, ext)
        target = outdir / fname
        target.write_bytes(blob[off:end])
        print("  写出 %s  (%d 字节)" % (fname, end - off))

    print("")
    print("共雕出 %d 个文件到 %s" % (n, outdir))
    if n:
        print("提示：雕出的文件先跑 filetype.py 验证完整性。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
