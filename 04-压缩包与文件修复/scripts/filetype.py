# -*- coding: utf-8 -*-
"""
filetype.py -- 魔数识别：不看扩展名，只看文件内容判断它到底是什么。

为什么需要
==========
CTF 里最常见的第一个坑就是「扩展名骗人」：一个叫 `flag.txt` 的东西其实是 PNG，
一个叫 `hint.jpg` 的其实是 ZIP，或者反过来 —— 图片头被人改成了别的类型。
只看扩展名会一路错下去，而改错扩展名又可能让工具链全线失败。

本脚本按文件头魔数（magic bytes）识别真实类型，并和扩展名做对比，
明确告诉你「它是什么」「它叫什么名字」「两者是否一致」。

用法
====
    python -X utf8 filetype.py 可疑文件
    python -X utf8 filetype.py 目录/ -r
    python -X utf8 filetype.py -f 1.png 2.zip          # 只看魔数 hex

已知限制
========
    * 魔数是「开头几个字节」，精心构造的文件可以让它撒谎；
    * 不带文件头的格式（纯文本、shellcode）只能靠启发式；
    * 分卷压缩包（.z01/.z02）的魔数和主包不同，已单独处理。
"""

import argparse
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------- 魔数表
# 顺序有意义：越具体的排越前（避免 ZIP 的 PK\x03\x04 被更泛的规则先匹配）。
# 每项: (魔数 bytes, 偏移, 类型名, 说明)
MAGIC = [
    # --- 图片 ---
    (b"\x89PNG\r\n\x1a\n", 0, "PNG", "PNG 图片"),
    (b"\xff\xd8\xff", 0, "JPEG", "JPEG 图片"),
    (b"GIF87a", 0, "GIF", "GIF87a 图片"),
    (b"GIF89a", 0, "GIF", "GIF89a 图片"),
    (b"BM", 0, "BMP", "Windows 位图"),
    (b"II*\x00", 0, "TIFF", "TIFF 图片（小端）"),
    (b"MM\x00*", 0, "TIFF", "TIFF 图片（大端）"),
    (b"RIFF", 0, "RIFF", "RIFF 容器（WAV/AVI/WebP，看第 9-12 字节）"),
    (b"\x00\x00\x01\x00", 0, "ICO", "Windows 图标"),
    (b"8BPS", 0, "PSD", "Photoshop 文档"),
    (b"\xff\x0a", 0, "JPEG_XL", "JPEG XL"),
    (b"qoif", 0, "QOI", "QOI 图片"),
    # --- 压缩/归档 ---
    (b"PK\x03\x04", 0, "ZIP", "ZIP 归档（本地文件头）"),
    (b"PK\x05\x06", 0, "ZIP_EMPTY", "空 ZIP 归档（只有中央目录结尾）"),
    (b"PK\x07\x08", 0, "ZIP_SPANNED", "分卷 ZIP 归档"),
    (b"Rar!\x1a\x07\x00", 0, "RAR4", "RAR 4.x 归档"),
    (b"Rar!\x1a\x07\x01\x00", 0, "RAR5", "RAR 5.x 归档"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7Z", "7-Zip 归档"),
    (b"\x1f\x8b", 0, "GZIP", "gzip 压缩流"),
    (b"BZh", 0, "BZIP2", "bzip2 压缩流"),
    (b"\xfd7zXZ\x00", 0, "XZ", "xz 压缩流"),
    (b"\x28\xb5\x2f\xfd", 0, "ZSTD", "zstd 压缩流"),
    (b"ustar", 257, "TAR", "POSIX tar 归档（偏移 257）"),
    (b"!<arch>\n", 0, "AR", "ar / deb 归档"),
    (b"MSCF", 0, "CAB", "Windows CAB 归档"),
    # --- 文档 ---
    (b"%PDF-", 0, "PDF", "PDF 文档"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE2", "OLE2 复合文档（老 doc/xls/ppt）"),
    (b"{\\rtf", 0, "RTF", "RTF 文档"),
    # --- 可执行 ---
    (b"MZ", 0, "PE", "Windows PE 可执行"),
    (b"\x7fELF", 0, "ELF", "Linux ELF 可执行"),
    (b"\xca\xfe\xba\xbe", 0, "MACHO_FAT", "Mach-O 通用二进制"),
    (b"\xcf\xfa\xed\xfe", 0, "MACHO64", "Mach-O 64 位"),
    (b"\xce\xfa\xed\xfe", 0, "MACHO32", "Mach-O 32 位"),
    (b"dex\n", 0, "DEX", "Android DEX"),
    # --- 多媒体 ---
    (b"fLaC", 0, "FLAC", "FLAC 音频"),
    (b"OggS", 0, "OGG", "Ogg 容器"),
    (b"ID3", 0, "MP3_ID3", "MP3（带 ID3 标签）"),
    (b"\x1a\x45\xdf\xa3", 0, "MKV", "Matroska / WebM"),
    (b"FLV\x01", 0, "FLV", "Flash 视频"),
    (b"\x00\x00\x00\x18ftyp", 0, "MP4", "MP4 / MOV（ftyp box）"),
    # --- 磁盘/取证 ---
    (b"KDMV", 0, "VMDK", "VMware 磁盘"),
    (b"QFI\xfb", 0, "QCOW", "QEMU QCOW 镜像"),
    (b"conectix", 0, "VHD", "Hyper-V VHD"),
    (b"SQLite format 3\x00", 0, "SQLITE", "SQLite 数据库"),
    (b"\x53\x51\x4c\x69\x74\x65", 0, "SQLITE", "SQLite 数据库"),
    # --- 其它 ---
    (b"-----BEGIN", 0, "PEM", "PEM 证书/密钥（文本）"),
    (b"\x1f\x9d", 0, "COMPRESS", "Unix compress"),
    (b"\x00\x00\x00\x0cjP  ", 0, "JP2", "JPEG 2000"),
]

# 扩展名 -> 期望类型（用于一致性判断）
EXT_EXPECT = {
    ".png": {"PNG"}, ".jpg": {"JPEG"}, ".jpeg": {"JPEG"},
    ".gif": {"GIF"}, ".bmp": {"BMP"}, ".tif": {"TIFF"}, ".tiff": {"TIFF"},
    ".zip": {"ZIP", "ZIP_EMPTY", "ZIP_SPANNED"},
    ".rar": {"RAR4", "RAR5"}, ".7z": {"7Z"},
    ".gz": {"GZIP"}, ".bz2": {"BZIP2"}, ".xz": {"XZ"}, ".tar": {"TAR"},
    ".pdf": {"PDF"}, ".rtf": {"RTF"},
    ".exe": {"PE"}, ".dll": {"PE"}, ".sys": {"PE"},
    ".elf": {"ELF"}, ".so": {"ELF"},
    ".mp3": {"MP3_ID3", "MP3_RAW"}, ".flac": {"FLAC"}, ".ogg": {"OGG"},
    ".mp4": {"MP4"}, ".mkv": {"MKV"},
    ".db": {"SQLITE"}, ".sqlite": {"SQLITE"},
    ".doc": {"OLE2"}, ".xls": {"OLE2"}, ".ppt": {"OLE2"},
    ".jar": {"ZIP"}, ".apk": {"ZIP"},
    # 文本类：内容必须「没有魔数」才算一致。如果 .txt 里其实是 PNG，
    # 那就是最典型的「扩展名骗人」，必须报出来而不是跳过判断。
    ".txt": set(), ".md": set(), ".log": set(), ".csv": set(),
    ".json": set(), ".xml": set(), ".html": set(), ".htm": set(),
    ".py": set(), ".ps1": set(), ".bat": set(), ".sh": set(), ".c": set(),
}

# 这些类型本身就是纯文本，魔数表里没有对应项
TEXTY = {"PEM"}


def sniff(blob):
    """返回 [(类型, 说明)]，按魔数表顺序第一个命中的为主判定。"""
    hits = []
    for magic, off, name, desc in MAGIC:
        if len(blob) >= off + len(magic) and blob[off:off + len(magic)] == magic:
            hits.append((name, desc))
    # RIFF 再细分
    if hits and hits[0][0] == "RIFF" and len(blob) >= 12:
        sub = blob[8:12]
        if sub == b"WAVE":
            hits[0] = ("WAV", "WAV 音频")
        elif sub == b"AVI ":
            hits[0] = ("AVI", "AVI 视频")
        elif sub == b"WEBP":
            hits[0] = ("WEBP", "WebP 图片")
    # MP3 裸流（无 ID3）
    if not hits and len(blob) >= 2 and blob[0] == 0xFF and (blob[1] & 0xE0) == 0xE0:
        hits.append(("MP3_RAW", "MP3 裸流（无 ID3 标签）"))
    return hits


def check_consistency(ext, kinds):
    """扩展名与真实类型是否一致。返回 (状态, 说明)。"""
    ext = ext.lower()
    actual = {k for k, _ in kinds}

    if ext not in EXT_EXPECT:
        # 未知扩展名：只要内容有明确魔数，就提醒一句「可能不是这个后缀」
        if actual:
            return "unknown", "扩展名未登记，但内容是 %s" % "/".join(sorted(actual))
        return "unknown", "扩展名不在已知表里，内容也没有魔数"

    expected = EXT_EXPECT[ext]

    # 文本类扩展名：内容不该有魔数
    if not expected:
        if not actual or actual <= TEXTY:
            return "ok", "一致（纯文本）"
        return "mismatch", "扩展名说 %s，内容其实是 %s" % (ext, "/".join(sorted(actual)))

    if not actual:
        return "bad", "内容没有任何已知魔数（可能是纯文本或已损坏）"
    if actual & expected:
        return "ok", "一致"
    return "mismatch", "扩展名说 %s，内容其实是 %s" % (ext, "/".join(sorted(actual)))


def read_head(path, size=512):
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError as exc:
        print("[错误] 无法读取 %s: %s" % (path, exc), file=sys.stderr)
        return b""


def inspect(path, verbose=True):
    p = Path(path)
    if not p.is_file():
        print("[错误] 不是文件: %s" % p, file=sys.stderr)
        return False
    blob = read_head(p)
    if not blob:
        print("[错误] 文件为空或读不出来: %s" % p, file=sys.stderr)
        return False

    kinds = sniff(blob)
    ext = p.suffix
    status, note = check_consistency(ext, kinds)

    if verbose:
        size = p.stat().st_size
        print("文件: %s  (%d 字节)" % (p.name, size))
        if kinds:
            for name, desc in kinds[:3]:
                print("  真实类型: %s  -- %s" % (name, desc))
        else:
            print("  真实类型: 未知（开头 16 字节: %s）" % blob[:16].hex(" "))
        print("  扩展名  : %s" % (ext or "(无)"))

        if status == "ok":
            print("  一致性  : 一致")
        elif status == "mismatch":
            print("  一致性  : 【不一致】%s" % note)
            print("            → 建议按真实类型改名再交给工具处理")
        elif status == "bad":
            print("  一致性  : 无法判断（%s）" % note)
        else:
            print("  一致性  : %s" % note)
        print("")
    return True


def main():
    ap = argparse.ArgumentParser(
        description="按魔数识别文件真实类型，并检查扩展名是否骗人",
        add_help=True,
    )
    ap.add_argument("paths", nargs="*", help="一个或多个文件/目录")
    ap.add_argument("-r", "--recursive", action="store_true", help="递归子目录")
    ap.add_argument("-f", "--hex", action="store_true", help="额外打印开头 32 字节的 hex")
    args = ap.parse_args()

    if not args.paths:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 filetype.py 可疑文件")
        print("  python -X utf8 filetype.py 题目目录 -r")
        print("")
        print("提示：CTF 里先跑这个，再看扩展名决定用哪个工具，能少走很多弯路。")
        return 0

    targets = []
    for raw in args.paths:
        p = Path(raw)
        if p.is_dir():
            it = p.rglob("*") if args.recursive else p.glob("*")
            targets.extend(sorted(x for x in it if x.is_file()))
        else:
            targets.append(p)

    if not targets:
        print("[错误] 没有找到任何文件", file=sys.stderr)
        return 1

    bad = 0
    for t in targets:
        if not inspect(t):
            bad += 1
            continue
        if args.hex:
            blob = read_head(t, 32)
            print("  hex: %s" % blob.hex(" "))
            print("")

    if len(targets) > 1:
        print("共检查 %d 个文件，读取失败 %d 个。" % (len(targets), bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
