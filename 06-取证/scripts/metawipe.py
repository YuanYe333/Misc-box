# -*- coding: utf-8 -*-
"""
metawipe.py -- 元数据体检与清除（图片 / 文档）。

为什么需要
==========
两个方向的需求：
  1. **取证方向**：一张图片里可能藏着 GPS 坐标、拍摄设备、编辑软件、
     甚至缩略图（缩略图常常是原图的完整副本，能还原被裁剪掉的内容）。
     做 CTF 或取证时要能把这些全挖出来。
  2. **隐私方向**：发图前要去掉 GPS、设备序列号等敏感信息。

本脚本不依赖 exiftool（虽然工具箱里有），纯标准库解析最常见的格式：
  * JPEG：EXIF（APP1）、XMP、ICC、注释（COM）；
  * PNG：tEXt/zTXt/iTXt、eXIf、tIME、pHYs；
  * GIF：注释扩展块。

用法
====
    python -X utf8 metawipe.py 图片.jpg               # 体检，列出所有元数据
    python -X utf8 metawipe.py 图片.jpg --strip -o 干净.jpg   # 清除并另存

已知限制
========
    * 只处理 JPEG/PNG/GIF 的元数据段，不解析 EXIF 内部的每个 tag
      （只提取常用的 Make/Model/DateTime/GPS 等）；
    * --strip 只删元数据段，不动图像数据，所以画质无损；
    * 不处理 HEIC/RAW/PDF（这些用 exiftool）。
"""

import argparse
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------- JPEG

# EXIF 里我们关心的 tag
EXIF_TAGS = {
    0x010F: "厂商 (Make)",
    0x0110: "型号 (Model)",
    0x0112: "方向 (Orientation)",
    0x0131: "软件 (Software)",
    0x0132: "修改时间 (DateTime)",
    0x9003: "原始拍摄时间 (DateTimeOriginal)",
    0x9004: "数字化时间 (DateTimeDigitized)",
    0x8825: "GPS 信息指针",
    0xA002: "图像宽度",
    0xA003: "图像高度",
    0x9286: "用户注释",
    0x010E: "图像描述",
    0x8298: "版权",
    0x013B: "作者 (Artist)",
}

GPS_TAGS = {
    0: "GPS 版本",
    1: "纬度参考 (N/S)",
    2: "纬度",
    3: "经度参考 (E/W)",
    4: "经度",
    5: "海拔参考",
    6: "海拔",
    7: "时间戳",
    29: "拍摄日期",
}


def parse_ifd(blob, base, offset, tag_table, label, out, depth=0):
    """解析一个 IFD（Image File Directory）。"""
    if depth > 3:
        return
    pos = base + offset
    if pos + 2 > len(blob):
        return
    try:
        (count,) = struct.unpack("<H", blob[pos:pos + 2])
    except struct.error:
        return
    pos += 2
    for i in range(count):
        entry = pos + i * 12
        if entry + 12 > len(blob):
            break
        try:
            tag, typ, cnt = struct.unpack("<HHI", blob[entry:entry + 8])
        except struct.error:
            break
        val_bytes = blob[entry + 8:entry + 12]
        name = tag_table.get(tag)
        if name is None:
            continue
        value = read_exif_value(blob, typ, cnt, val_bytes, base)
        if value is not None:
            out.append((label, name, value))
        # GPS IFD 指针要递归进去
        if tag == 0x8825:
            try:
                (sub_off,) = struct.unpack("<I", val_bytes)
                parse_ifd(blob, base, sub_off, GPS_TAGS, "GPS", out, depth + 1)
            except struct.error:
                pass


def read_exif_value(blob, typ, cnt, val_bytes, base):
    """按 EXIF 类型读出值。"""
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
    size = sizes.get(typ)
    if size is None:
        return None
    total = size * cnt
    if total <= 4:
        data = val_bytes[:total]
    else:
        try:
            (off,) = struct.unpack("<I", val_bytes)
        except struct.error:
            return None
        start = base + off
        data = blob[start:start + total]
    if typ == 2:      # ASCII
        return data.rstrip(b"\x00").decode("utf-8", "replace")
    if typ in (3, 4):
        fmt = "<%dH" % cnt if typ == 3 else "<%dI" % cnt
        try:
            vals = struct.unpack(fmt, data[:total])
        except struct.error:
            return None
        return vals[0] if len(vals) == 1 else vals
    if typ in (5, 10):  # 有理数
        fmt = "<%dI" % (cnt * 2)
        try:
            vals = struct.unpack(fmt, data[:total])
        except struct.error:
            return None
        out = []
        for i in range(0, len(vals), 2):
            den = vals[i + 1]
            out.append(vals[i] / den if den else 0)
        return out[0] if len(out) == 1 else out
    if typ == 7:      # undefined（如缩略图）
        return "<%d 字节二进制>" % len(data)
    return None


def jpeg_segments(blob):
    """遍历 JPEG 段，返回 [(标记, 起始, 长度)]。"""
    segs = []
    pos = 2      # 跳过 SOI
    while pos + 4 <= len(blob):
        if blob[pos] != 0xFF:
            break
        marker = blob[pos + 1]
        if marker == 0xD9:   # EOI
            segs.append((marker, pos, 2))
            break
        if marker == 0xDA:   # SOS 之后是压缩数据，无法按段解析
            segs.append((marker, pos, 2))
            break
        try:
            (length,) = struct.unpack(">H", blob[pos + 2:pos + 4])
        except struct.error:
            break
        segs.append((marker, pos, length + 2))
        pos += 2 + length
    return segs


def inspect_jpeg(blob):
    """返回 (findings, strip_ranges)。"""
    findings = []
    strip = []
    segs = jpeg_segments(blob)
    for marker, pos, length in segs:
        data = blob[pos + 4:pos + length] if length > 4 else b""
        if marker == 0xE1 and data[:6] == b"Exif\x00\x00":
            findings.append(("EXIF", "APP1 段", "%d 字节" % len(data)))
            tiff = pos + 4 + 6      # Exif\0\0 之后是 TIFF 头
            base = tiff
            if blob[base:base + 2] in (b"II", b"MM"):
                little = blob[base:base + 2] == b"II"
                if little:
                    try:
                        (ifd0,) = struct.unpack("<I", blob[base + 4:base + 8])
                        tmp = []
                        parse_ifd(blob, base, ifd0, EXIF_TAGS, "EXIF", tmp)
                        findings.extend(tmp)
                        # 检查缩略图
                        if any("GPS" in f[0] for f in findings):
                            pass
                        if b"\xff\xd8\xff" in data:
                            findings.append(("EXIF", "内嵌缩略图", "可能是原图副本！"))
                    except struct.error:
                        pass
            strip.append((pos, length))
        elif marker == 0xE1 and data[:4] == b"http":
            findings.append(("XMP", "XMP 元数据段", "存在"))
            strip.append((pos, length))
        elif marker == 0xE2:
            findings.append(("ICC", "色彩配置文件", "%d 字节" % len(data)))
            strip.append((pos, length))
        elif marker == 0xFE:
            txt = data.rstrip(b"\x00").decode("latin-1", "replace")
            findings.append(("COM", "注释", repr(txt[:200])))
            strip.append((pos, length))
    return findings, strip


# ---------------------------------------------------------------- PNG

def png_chunks(blob):
    """遍历 PNG 块。返回 [(类型, 起始, 数据长度)]。"""
    if blob[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    chunks = []
    pos = 8
    while pos + 12 <= len(blob):
        try:
            (length,) = struct.unpack(">I", blob[pos:pos + 4])
        except struct.error:
            break
        ctype = blob[pos + 4:pos + 8].decode("latin-1")
        chunks.append((ctype, pos, length))
        if ctype == "IEND":
            break
        pos += 12 + length
    return chunks


def inspect_png(blob):
    """返回 (findings, strip)。findings 统一为 (分组, 名称, 值) 三元组。"""
    findings = []
    strip = []
    chunks = png_chunks(blob)
    if chunks is None:
        return findings, strip
    for ctype, pos, length in chunks:
        data = blob[pos + 8:pos + 8 + length]
        if ctype in ("tEXt", "zTXt", "iTXt"):
            try:
                key = data.split(b"\x00")[0].decode("latin-1")
            except Exception:  # noqa: BLE001
                key = "?"
            # 未压缩的 tEXt 可以直接读出值
            value = ""
            if ctype == "tEXt" and b"\x00" in data:
                value = data.split(b"\x00", 1)[1].decode("latin-1", "replace")
            findings.append((ctype, "文本块 %r" % key,
                             (value or "(压缩)") + " [%d 字节]" % length))
            # PNG 块总长 = 4(长度) + 4(类型) + length(数据) + 4(CRC)
            strip.append((pos, length + 12))
        elif ctype == "eXIf":
            findings.append(("eXIf", "EXIF 块", "%d 字节" % length))
            strip.append((pos, length + 12))
        elif ctype == "tIME":
            if length >= 7:
                y, mo, d, h, mi, s = struct.unpack(">HBBBBB", data[:7])
                findings.append(("tIME", "最后修改时间",
                                 "%04d-%02d-%02d %02d:%02d:%02d" % (y, mo, d, h, mi, s)))
            strip.append((pos, length + 12))
        elif ctype == "pHYs":
            if length >= 9:
                x, y, unit = struct.unpack(">IIB", data[:9])
                findings.append(("pHYs", "物理尺寸", "%dx%d 单位=%d" % (x, y, unit)))
            strip.append((pos, length + 12))
    return findings, strip


# ---------------------------------------------------------------- GIF

def inspect_gif(blob):
    findings = []
    strip = []
    if blob[:6] not in (b"GIF87a", b"GIF89a"):
        return findings, strip
    pos = 13
    # 跳过全局调色板
    packed = blob[10]
    if packed & 0x80:
        pos += 3 * (2 ** ((packed & 0x07) + 1))
    while pos < len(blob):
        b = blob[pos]
        if b == 0x3B:      # trailer
            break
        if b == 0x21:      # 扩展块
            label = blob[pos + 1] if pos + 1 < len(blob) else 0
            if label == 0xFE:   # 注释
                start = pos
                p = pos + 2
                text = b""
                while p < len(blob) and blob[p] != 0:
                    n = blob[p]
                    text += blob[p + 1:p + 1 + n]
                    p += 1 + n
                findings.append(("COM", "注释", repr(text.decode("latin-1", "replace")[:200])))
                strip.append((start, p + 1 - start))
                pos = p + 1
            else:
                # 跳过其他扩展
                p = pos + 2
                while p < len(blob) and blob[p] != 0:
                    p += 1 + blob[p]
                pos = p + 1
        elif b == 0x2C:    # 图像描述符
            packed = blob[pos + 9] if pos + 9 < len(blob) else 0
            p = pos + 10
            if packed & 0x80:
                p += 3 * (2 ** ((packed & 0x07) + 1))
            p += 1      # LZW 最小码长
            while p < len(blob) and blob[p] != 0:
                p += 1 + blob[p]
            pos = p + 1
        else:
            break
    return findings, strip


# ---------------------------------------------------------------- 主流程

def inspect(path):
    blob = path.read_bytes()
    if blob[:2] == b"\xff\xd8":
        kind, fn = "JPEG", inspect_jpeg
    elif blob[:8] == b"\x89PNG\r\n\x1a\n":
        kind, fn = "PNG", inspect_png
    elif blob[:6] in (b"GIF87a", b"GIF89a"):
        kind, fn = "GIF", inspect_gif
    else:
        return None, None, None
    findings, strip = fn(blob)
    return kind, findings, strip


def do_strip(blob, strip, kind):
    """删掉指定段，保留其余字节。"""
    if not strip:
        return blob
    # 按起始位置排序，逐段删除
    out = bytearray()
    last = 0
    for pos, length in sorted(strip):
        out += blob[last:pos]
        last = pos + length
    out += blob[last:]
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(
        description="元数据体检与清除（JPEG/PNG/GIF）",
        add_help=True,
    )
    ap.add_argument("target", nargs="?", help="要检查的图片")
    ap.add_argument("--strip", action="store_true", help="清除元数据（需配 -o）")
    ap.add_argument("-o", "--output", help="清除后另存为这个文件")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    args = ap.parse_args()

    if not args.target:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 metawipe.py 图片.jpg")
        print("  python -X utf8 metawipe.py 图片.jpg --strip -o 干净.jpg")
        print("")
        print("提示：CTF 里 EXIF 的缩略图常藏原图，--strip 会一并删掉。")
        return 0

    p = Path(args.target)
    if not p.is_file():
        print("[错误] 文件不存在: %s" % p, file=sys.stderr)
        return 1

    kind, findings, strip = inspect(p)
    if kind is None:
        print("[错误] 不支持的格式（只支持 JPEG/PNG/GIF）", file=sys.stderr)
        print("提示：其它格式请用 exiftool。", file=sys.stderr)
        return 1

    print("文件: %s  (%d 字节)" % (p.name, p.stat().st_size))
    print("格式: %s" % kind)
    print("")

    if findings:
        print("== 发现的元数据 ==")
        for group, name, value in findings:
            show = value if not isinstance(value, str) else value
            if isinstance(show, str) and len(show) > 120:
                show = show[:120] + "..."
            print("  [%s] %s: %s" % (group, name, show))
        print("")
        print("共 %d 项元数据，涉及 %d 个数据段。" % (len(findings), len(strip)))
    else:
        print("没有发现元数据。")
        print("")

    # 隐私提醒
    sensitive = [f for f in findings
                 if any(k in f[1] for k in ("GPS", "纬度", "经度", "厂商", "型号", "软件"))]
    if sensitive:
        print("== 隐私提醒 ==")
        print("  发现可能暴露隐私的字段（GPS/设备/软件信息）。")
        print("  对外分享前建议用 --strip 清除。")
        print("")

    if not args.strip:
        if strip:
            print("加 --strip -o 输出文件 可以清除上面这些元数据段。")
        return 0

    if not args.output:
        print("[错误] --strip 需要同时指定 -o 输出文件", file=sys.stderr)
        return 1

    target = Path(args.output)
    if target.exists() and not args.force:
        print("[错误] 输出文件已存在：%s（加 --force 覆盖）" % target, file=sys.stderr)
        return 1

    blob = p.read_bytes()
    cleaned = do_strip(blob, strip, kind)
    target.write_bytes(cleaned)

    print("已清除元数据并写出: %s" % target)
    print("  原始大小: %d 字节" % len(blob))
    print("  清除后  : %d 字节（减少 %d）" % (len(cleaned), len(blob) - len(cleaned)))
    print("")

    # 验证
    kind2, findings2, _ = inspect(target)
    if kind2 is None:
        print("[警告] 清除后文件格式无法识别，可能损坏了！", file=sys.stderr)
        print("       建议保留原文件，不要使用输出文件。", file=sys.stderr)
        return 1
    if findings2:
        print("验证：仍有 %d 项元数据残留（可能在不支持清除的段里）。" % len(findings2))
        for g, n, v in findings2[:5]:
            print("  [%s] %s" % (g, n))
    else:
        print("验证：元数据已全部清除，图像数据未改动。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
