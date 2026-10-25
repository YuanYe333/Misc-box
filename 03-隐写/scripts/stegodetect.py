# -*- coding: utf-8 -*-
"""
stegodetect.py -- 隐写总检：一条命令扫完「这个文件哪里不对劲」。

为什么需要
==========
CTF 拿到一个图片/音频/压缩包，常规流程是 binwalk 一遍、exiftool 看一遍、
再拖进 Stegsolve 点一遍 —— 三四个工具来回切，还容易漏。而且最容易被
忽略的恰恰是「文件尾多出几 KB」这种简单手法。

本脚本把常见的「结构性异常」一次性列出来，并且**按置信度分优先级**：
高置信度的（文件尾有附加数据、内嵌 ZIP/RAR、PNG 块异常）排在前面，
低置信度的（尺寸可疑、熵偏高）排在后面并明确标注「仅供参考」。

检查项
======
  1. 文件尾附加数据：PNG 的 IEND 之后 / JPEG 的 EOI 之后 / BMP 声明大小之后
  2. 容器结构异常：PNG 块顺序与未知块、JPEG 段异常、BMP 头字段矛盾
  3. 文件大小 vs 像素数据量：声明尺寸算出来的应有大小和实际差多少
  4. 内嵌 ZIP / RAR / 7z / gzip（不管藏在哪里，按魔数扫）
  5. 文本型隐写痕迹：文件尾的可打印串、flag{ 直接命中
  6. --diff a.png b.png：两图逐像素对比，输出差异图 + 差异统计

用法
====
    python -X utf8 stegodetect.py 图.png
    python -X utf8 stegodetect.py 目录/ -r
    python -X utf8 stegodetect.py --diff 原图.png 可疑.png -o 差异.png
    python -X utf8 stegodetect.py 图.png --tail-dump -o tail.bin

已知限制
========
    * 只做「结构层」判断，不做统计型隐写分析（RS 分析、卡方攻击等）。
      它不会告诉你「这张图用了 LSB」，只会告诉你「文件结构有问题」。
    * 尾部数据只做启发式提取，不保证切得准（长度头可能是加密的）。
    * --diff 要求两张图尺寸一致；不一致只报告尺寸差异，不强行对齐。
"""

import argparse
import math
import struct
import sys
import zlib
from pathlib import Path

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# 优先级：1 = 高置信度结论，2 = 值得一看，3 = 仅供参考（噪音多）
P_HIGH, P_MID, P_LOW = 1, 2, 3
P_LABEL = {1: "[高]", 2: "[中]", 3: "[低]"}

MAGICS = (
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"BM", "BMP"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"RIFF", "RIFF(WAV/AVI)"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP(空)"),
    (b"PK\x07\x08", "ZIP(分卷)"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"%PDF", "PDF"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/EXE"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"OggS", "OGG"),
    (b"ID3", "MP3(ID3)"),
    (b"fLaC", "FLAC"),
)

# 内嵌扫描时这些是「有意思」的容器（说明文件里套了东西）
EMBED_MAGICS = (
    (b"PK\x03\x04", "ZIP"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"%PDF", "PDF"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"\xff\xd8\xff\xe0\x00\x10JFIF", "JPEG(JFIF)"),
    (b"GIF89a", "GIF"),
)


class ScanError(Exception):
    """给用户看的错误。"""


# ==================================================================== 通用工具

def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = float(len(data))
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log(p, 2)
    return h


def printable_ratio(data):
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / float(len(data))


def detect_magic(data):
    for magic, name in MAGICS:
        if data.startswith(magic):
            return name
    return None


def hexdump(data, width=16, maxlen=512):
    lines = []
    chunk = data[:maxlen]
    for i in range(0, len(chunk), width):
        part = chunk[i:i + width]
        hexpart = " ".join("%02x" % b for b in part)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in part)
        lines.append("%08x  %-*s  |%s|" % (i, width * 3 - 1, hexpart, text))
    if len(data) > maxlen:
        lines.append("... 共 %d 字节，仅显示前 %d" % (len(data), maxlen))
    return "\n".join(lines)


def preview(data, maxlen=200):
    """尽量当文本显示，否则 hexdump 前若干字节。"""
    if not data:
        return "(空)"
    if printable_ratio(data[:512]) >= 0.85:
        try:
            t = data.decode("utf-8")
        except UnicodeDecodeError:
            t = data.decode("gb18030", "replace")
        if len(t) > maxlen:
            t = t[:maxlen] + "...(截断)"
        return t
    return hexdump(data, maxlen=maxlen)


def find_all(data, needle, limit=32):
    """返回 needle 在 data 中所有出现位置。"""
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
        if len(out) >= limit:
            break
    return out


class Report(object):
    """收集发现，按优先级排序后输出。"""

    def __init__(self, path):
        self.path = Path(path)
        self.items = []

    def add(self, pri, title, detail, blob=None):
        self.items.append({"pri": pri, "title": title,
                           "detail": detail, "blob": blob})

    def add_bytes(self, pri, title, blob, note=""):
        """带数据块的发现：自动判断该显示文本还是 hex。"""
        self.items.append({"pri": pri, "title": title, "detail": note,
                           "blob": blob})

    def has_high(self):
        return any(it["pri"] == P_HIGH for it in self.items)

    def render(self, verbose=False, max_blob=256):
        self.items.sort(key=lambda it: it["pri"])
        if not self.items:
            print("  没有发现明显异常（结构干净）。")
            return
        for it in self.items:
            print("  %s %s" % (P_LABEL[it["pri"]], it["title"]))
            if it["detail"]:
                for line in it["detail"].splitlines():
                    print("       %s" % line)
            if it["blob"] is not None:
                n = max_blob if not verbose else max(max_blob, 4096)
                print("       ---- 数据预览 ----")
                for line in preview(it["blob"][:n]).splitlines():
                    print("       %s" % line)


# ==================================================================== PNG

def _png_chunks(data):
    """返回 [(type, body, offset_of_type_field)]，遇到截断就停下并标注。"""
    pos = 8
    n = len(data)
    out = []
    truncated = None
    while pos + 8 <= n:
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if ln > 0x7FFFFFFF:
            truncated = "块长度字段异常（%d）" % ln
            break
        body_end = pos + 8 + ln
        if body_end + 4 > n:
            truncated = ("块 %s 声明 %d 字节，文件只剩 %d 字节"
                         % (typ.decode("latin-1", "replace"), ln, n - pos - 8))
            break
        body = data[pos + 8:body_end]
        out.append((typ, body, pos + 4))
        pos = body_end + 4
        if typ == b"IEND":
            break
    return out, pos, truncated


def check_png(data, rep, deep):
    chunks, end_pos, trunc = _png_chunks(data)
    if trunc:
        rep.add(P_HIGH, "PNG 结构被截断/损坏", trunc)
    if not chunks:
        rep.add(P_HIGH, "PNG 没有任何可解析的块", "文件只有签名，没有 IHDR")
        return end_pos

    types = [c[0] for c in chunks]
    if types[0] != b"IHDR":
        rep.add(P_HIGH, "PNG 第一个块不是 IHDR",
                "实际是 %s —— 头部被替换或拼接了别的文件"
                % types[0].decode("latin-1", "replace"))
    if b"IEND" not in types:
        rep.add(P_HIGH, "PNG 缺少 IEND", "像素数据可能被截断，或者文件没写完")

    # 未知块 / 关键块顺序
    known = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM",
             b"sRGB", b"iCCP", b"sBIT", b"bKGD", b"hIST", b"pHYs", b"tIME",
             b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"oFFs", b"sPLT", b"hIST"}
    unknown = [t for t in types if t not in known]
    if unknown:
        names = ", ".join(sorted(set(t.decode("latin-1", "replace")
                                      for t in unknown)))
        rep.add(P_MID, "PNG 含非标准块：%s" % names,
                "有些隐写工具会把数据塞进私有块（如 stEG、raNd）")

    # 文本块内容直接看
    for typ, body, _off in chunks:
        if typ in (b"tEXt", b"iTXt", b"zTXt"):
            txt = body
            if typ == b"zTXt":
                k = body.find(b"\x00")
                if k > 0 and k + 2 <= len(body):
                    try:
                        txt = body[:k] + b" = " + zlib.decompress(body[k + 2:])
                    except zlib.error:
                        txt = body
            try:
                s = txt.decode("utf-8")
            except UnicodeDecodeError:
                s = txt.decode("latin-1")
            rep.add(P_MID, "PNG 文本块 %s 有内容"
                    % typ.decode("latin-1"), s[:400])
        if typ == b"eXIf":
            rep.add(P_MID, "PNG 带 eXIf 块（EXIF）",
                    "里面有 %d 字节元数据，可能藏注释/缩略图" % len(body))

    # IEND 之后
    tail = data[end_pos:] if end_pos < len(data) else b""
    if tail:
        kind = detect_magic(tail)
        note = "共 %d 字节，紧跟在 IEND 之后" % len(tail)
        if kind:
            note += "；开头魔数是 %s" % kind
        rep.add_bytes(P_HIGH, "PNG 的 IEND 之后有附加数据", tail, note)
        embedded = scan_embedded(tail, 0)
        for off, name in embedded[:6]:
            rep.add(P_MID, "附加数据里有内嵌 %s（偏移 +%d）" % (name, off), "")
    return end_pos


def _png_pixel_expect(data, chunks):
    """按 IHDR 声明算「应有的文件大小」，和实际对比。"""
    ihdr = None
    for typ, body, _o in chunks:
        if typ == b"IHDR":
            ihdr = body
            break
    if ihdr is None or len(ihdr) < 13:
        return None
    w, h, depth, ctype, _c, _f, inter = struct.unpack(">IIBBBBB", ihdr[:13])
    nch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ctype)
    if nch is None:
        return None
    raw = w * h * nch * depth
    return {"w": w, "h": h, "depth": depth, "ctype": ctype,
            "inter": inter, "raw_bytes": raw}


def check_png_size(data, chunks, rep):
    info = _png_pixel_expect(data, chunks)
    if not info:
        return
    w, h = info["w"], info["h"]
    if w == 0 or h == 0:
        rep.add(P_HIGH, "PNG 尺寸为 0", "%dx%d" % (w, h))
        return
    idat = b"".join(body for typ, body, _o in chunks if typ == b"IDAT")
    try:
        raw = zlib.decompress(idat)
    except zlib.error as exc:
        rep.add(P_HIGH, "PNG 的 IDAT 解压失败",
                "%s —— 像素数据被改过，或尺寸声明与实际不符" % exc)
        return
    nch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[info["ctype"]]
    stride = (w * nch * info["depth"] + 7) // 8
    expect = (stride + 1) * h
    if len(raw) < expect:
        rep.add(P_HIGH, "PNG 像素数据比声明的尺寸少",
                "需要 %d 字节（%dx%d），实际解出 %d 字节，差 %d\n"
                "典型手法：改小 IHDR 的高度，让数据被「切掉」"
                % (expect, w, h, len(raw), expect - len(raw)))
    elif len(raw) > expect + stride:
        extra = len(raw) - expect
        rep.add(P_HIGH, "PNG 像素数据比声明的尺寸多",
                "声明 %dx%d 只需 %d 字节，实际解出 %d 字节，多出 %d\n"
                "典型手法：改小 IHDR 的宽/高把图「截短」，多出的行是隐藏内容"
                % (w, h, expect, len(raw), extra))
    elif len(raw) != expect:
        rep.add(P_LOW, "PNG 像素数据长度轻微不符",
                "需要 %d，实际 %d（差 %d，可能只是行对齐）"
                % (expect, len(raw), len(raw) - expect))


# ==================================================================== JPEG

def check_jpeg(data, rep, deep):
    """JPEG 按段解析，找 EOI 之后的尾巴和异常段。"""
    n = len(data)
    pos = 2
    segs = []
    eoi_at = None
    while pos + 1 < n:
        if data[pos] != 0xFF:
            # 进入熵编码数据区后就没有段结构了，找 EOI
            i = data.find(b"\xff\xd9", pos)
            if i >= 0:
                eoi_at = i
            break
        marker = data[pos + 1]
        if marker == 0xD8:            # SOI
            pos += 2
            continue
        if marker == 0xD9:            # EOI
            eoi_at = pos
            break
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:   # RSTn / TEM
            pos += 2
            continue
        if pos + 4 > n:
            break
        ln = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if ln < 2:
            rep.add(P_HIGH, "JPEG 段长度非法", "段 0xFF%02X 声明长度 %d" % (marker, ln))
            break
        body = data[pos + 4:pos + 2 + ln]
        segs.append((marker, body, pos))
        if marker == 0xDA:            # SOS 之后是熵编码数据
            i = data.find(b"\xff\xd9", pos + ln)
            if i >= 0:
                eoi_at = i
            break
        pos += 2 + ln
    if eoi_at is None:
        # 没有 EOI：可能被截断，也可能尾巴盖掉了
        i = data.rfind(b"\xff\xd9")
        eoi_at = i if i >= 0 else None
        if eoi_at is None:
            rep.add(P_HIGH, "JPEG 找不到 EOI 结束标记",
                    "文件可能在 EOI 前被截断，或者尾部数据盖掉了 EOI")
    if eoi_at is not None:
        tail = data[eoi_at + 2:]
        if tail:
            kind = detect_magic(tail)
            note = "共 %d 字节，在 EOI 之后" % len(tail)
            if kind:
                note += "；开头魔数是 %s" % kind
            rep.add_bytes(P_HIGH, "JPEG 的 EOI 之后有附加数据", tail, note)
            for off, name in scan_embedded(tail, 0)[:6]:
                rep.add(P_MID, "附加数据里有内嵌 %s（偏移 +%d）" % (name, off), "")

    # 段统计
    counts = {}
    for marker, body, _p in segs:
        counts[marker] = counts.get(marker, 0) + 1
    if counts.get(0xE1, 0) > 1:
        rep.add(P_MID, "JPEG 有 %d 个 APP1(EXIF) 段" % counts[0xE1],
                "正常只有 1 个；多出来的常被用来塞数据")
    if counts.get(0xFE):
        for marker, body, _p in segs:
            if marker == 0xFE:
                try:
                    s = body.decode("utf-8")
                except UnicodeDecodeError:
                    s = body.decode("latin-1")
                rep.add(P_MID, "JPEG COM 注释段有内容", s[:400])
    if 0xEE in counts:                # APP14 Adobe
        rep.add(P_LOW, "JPEG 含 APP14(Adobe) 段", "一般无害，但有时被当作载体")
    return eoi_at


# ==================================================================== BMP

def check_bmp(data, rep, deep):
    if len(data) < 54:
        rep.add(P_HIGH, "BMP 文件太小", "只有 %d 字节" % len(data))
        return len(data)
    off = struct.unpack("<I", data[10:14])[0]
    dib = struct.unpack("<I", data[14:18])[0]
    w = struct.unpack("<i", data[18:22])[0]
    h = struct.unpack("<i", data[22:26])[0]
    bpp = struct.unpack("<H", data[28:30])[0]
    declared = struct.unpack("<I", data[2:6])[0]      # bfSize
    if declared == 0:
        rep.add(P_LOW, "BMP 头部 bfSize 为 0", "有些工具不写这个字段，无法据此判断")
    elif declared != len(data):
        diff = len(data) - declared
        if diff > 0:
            rep.add(P_HIGH, "BMP 声明大小小于实际文件大小",
                    "头里写 %d 字节，实际 %d 字节，尾部多出 %d\n"
                    "这是最经典的 BMP 隐写：数据直接接在像素数据后面"
                    % (declared, len(data), diff))
            rep.add_bytes(P_HIGH, "BMP 尾部附加数据", data[declared:],
                          "从偏移 %d 开始" % declared)
        else:
            rep.add(P_HIGH, "BMP 声明大小大于实际文件大小",
                    "头里写 %d 字节，实际只有 %d 字节（缺 %d）"
                    % (declared, len(data), -diff))
    if bpp not in (1, 4, 8, 16, 24, 32):
        rep.add(P_MID, "BMP 位深异常", "%d bpp" % bpp)
    # 按尺寸算应有像素数据
    nch = bpp // 8 if bpp >= 8 else 1
    stride = ((w * bpp + 31) // 32) * 4
    expect = abs(h) * stride
    actual_pix = len(data) - off
    if actual_pix > expect + stride:
        rep.add(P_HIGH, "BMP 像素数据比声明的尺寸多",
                "声明 %dx%d 只需 %d 字节，从偏移 %d 起有 %d 字节，多出 %d"
                % (w, abs(h), expect, off, actual_pix, actual_pix - expect))
        rep.add_bytes(P_HIGH, "BMP 像素区之后的数据",
                      data[off + expect:], "从偏移 %d 开始" % (off + expect))
    elif actual_pix < expect:
        rep.add(P_HIGH, "BMP 像素数据比声明的尺寸少",
                "需要 %d 字节，只有 %d 字节" % (expect, actual_pix))
    # 调色板后面 / 像素前面是否有空隙
    if bpp <= 8:
        pal_n = struct.unpack("<I", data[46:50])[0] or (1 << bpp)
        pal_end = 14 + dib + pal_n * 4
        if off > pal_end + 4:
            rep.add(P_MID, "BMP 调色板与像素数据之间有 %d 字节空隙"
                    % (off - pal_end),
                    "空隙常被用来藏数据（偏移 %d - %d）" % (pal_end, off))
            rep.add_bytes(P_MID, "空隙内容", data[pal_end:off], "")
    return len(data)


# ==================================================================== 通用

def scan_embedded(data, skip=0, limit=8):
    """扫内嵌容器的魔数。跳过文件自身的头部（skip 字节以内）。"""
    hits = []
    for magic, name in EMBED_MAGICS:
        for off in find_all(data, magic, limit=limit * 4):
            if off < skip:
                continue
            hits.append((off, name))
    hits.sort()
    # 去掉挨得太近的重复（比如 ZIP 内多个本地头）
    out = []
    for off, name in hits:
        if out and off - out[-1][0] < 16 and name == out[-1][1]:
            continue
        out.append((off, name))
    return out[:limit]


def check_embedded(data, rep, fmt, own_end=None):
    """在整份文件里找内嵌的压缩包/文件（排除文件自身头部）。"""
    skip = 16
    hits = scan_embedded(data, skip)
    # 自身格式的魔数出现在偏移 0 是正常的，已由 skip 排除
    shown = 0
    for off, name in hits:
        if fmt == name:
            continue
        if own_end is not None and off >= own_end and fmt in ("PNG", "JPEG"):
            # 尾部数据已经在「附加数据」里报过了，别重复
            continue
        rep.add(P_HIGH, "文件内嵌 %s（偏移 0x%x / %d）" % (name, off, off),
                "整份文件里出现了另一个容器的魔数，多半是拼接隐藏")
        shown += 1
        if shown >= 4:
            break


def check_flag_strings(data, rep):
    """直接在字节流里搜 flag/ctf 字样 —— 最省事的命中。"""
    pats = (b"flag{", b"ctf{", b"FLAG{", b"CTF{", b"flag[", b"key{")
    for pat in pats:
        for off in find_all(data, pat, limit=3):
            end = data.find(b"}", off)
            if 0 < end - off < 200:
                snip = data[off:end + 1]
            else:
                snip = data[off:off + 80]
            rep.add(P_HIGH, "明文命中 %s（偏移 0x%x）"
                    % (pat.decode("latin-1"), off), preview(snip, 200))


def check_trailing_text(data, rep):
    """文件末尾的可打印串（有些题直接把 flag 贴在最后）。"""
    if len(data) < 32:
        return
    tail = data[-2048:]
    pr = printable_ratio(tail)
    if pr >= 0.90 and len(tail) >= 16:
        rep.add(P_MID, "文件末尾是可读文本（最后 %d 字节）" % len(tail),
                preview(tail, 400))


def check_entropy(data, rep, fmt):
    """整体熵：接近 8 说明文件本身被加密/压缩，不是原始载体。"""
    sample = data[:65536]
    h = entropy(sample)
    if h > 7.9 and fmt in ("PNG", "BMP", "JPEG", "WAV"):
        rep.add(P_LOW, "文件熵极高（%.2f）" % h,
                "像素/采样数据通常不会这么高；可能是整段被加密了，"
                "也可能是正常的高压缩率图像（仅供参考）")


def scan_file(path, verbose=False, deep=False):
    p = Path(path)
    if not p.exists():
        raise ScanError("文件不存在：%s" % p)
    if not p.is_file():
        raise ScanError("不是普通文件：%s" % p)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ScanError("读取失败：%s" % exc)
    if not data:
        raise ScanError("文件是空的：%s" % p)

    fmt = detect_magic(data)
    rep = Report(p)
    print("=" * 66)
    print("文件: %s" % p)
    print("大小: %d 字节   类型: %s" % (len(data), fmt or "未知"))
    print("-" * 66)

    if fmt == "PNG":
        end_pos = check_png(data, rep, deep)
        chunks, _ep, _tr = _png_chunks(data)
        check_png_size(data, chunks, rep)
        check_embedded(data, rep, "PNG", own_end=end_pos)
    elif fmt == "JPEG":
        end_pos = check_jpeg(data, rep, deep)
        check_embedded(data, rep, "JPEG", own_end=end_pos)
    elif fmt == "BMP":
        check_bmp(data, rep, deep)
        check_embedded(data, rep, "BMP")
    else:
        if fmt is None:
            rep.add(P_MID, "无法识别文件类型",
                    "前 16 字节：%s\n既不是常见图片也不是压缩包，"
                    "如果这是隐写题的载体，可能是被改了扩展名的裸数据"
                    % hexdump(data[:16]))
        check_embedded(data, rep, fmt)
        check_trailing_text(data, rep)

    if fmt != "PNG" or True:
        check_flag_strings(data, rep)
    check_entropy(data, rep, fmt)

    rep.render(verbose=verbose)
    print("")
    return rep


# ==================================================================== diff

def _load_png_rgba(data):
    """只为 --diff 服务的精简 PNG 解码（8-bit，非隔行）。"""
    pos = 8
    ihdr = None
    idat = []
    plte = None
    n = len(data)
    while pos + 8 <= n:
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if pos + 8 + ln + 4 > n:
            raise ScanError("PNG 块被截断")
        body = data[pos + 8:pos + 8 + ln]
        if typ == b"IHDR":
            ihdr = body
        elif typ == b"IDAT":
            idat.append(body)
        elif typ == b"PLTE":
            plte = body
        elif typ == b"IEND":
            break
        pos += 12 + ln
    if ihdr is None or not idat:
        raise ScanError("PNG 缺少 IHDR 或 IDAT")
    w, h, depth, ctype, _c, _f, inter = struct.unpack(">IIBBBBB", ihdr[:13])
    if depth != 8 or inter != 0:
        raise ScanError("--diff 只支持 8-bit 非隔行 PNG（当前 %d-bit，隔行=%d）"
                        % (depth, inter))
    if ctype not in (0, 2, 4, 6):
        raise ScanError("--diff 暂不支持调色板 PNG（请先转成 RGB/RGBA）")
    nch = {0: 1, 2: 3, 4: 2, 6: 4}[ctype]
    try:
        raw = zlib.decompress(b"".join(idat))
    except zlib.error as exc:
        raise ScanError("IDAT 解压失败：%s" % exc)
    stride = w * nch
    if len(raw) < (stride + 1) * h:
        raise ScanError("像素数据不足")
    # 反过滤
    out = bytearray(stride * h)
    prev = bytearray(stride)
    pos = 0
    for y in range(h):
        ft = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if ft == 1:
            for i in range(nch, stride):
                line[i] = (line[i] + line[i - nch]) & 0xFF
        elif ft == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(stride):
                a = line[i - nch] if i >= nch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(stride):
                a = line[i - nch] if i >= nch else 0
                b = prev[i]
                c = prev[i - nch] if i >= nch else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                if pa <= pb and pa <= pc:
                    pr = a
                elif pb <= pc:
                    pr = b
                else:
                    pr = c
                line[i] = (line[i] + pr) & 0xFF
        elif ft != 0:
            raise ScanError("未知行过滤类型 %d" % ft)
        out[y * stride:(y + 1) * stride] = line
        prev = line

    rgba = bytearray(w * h * 4)
    if ctype == 0:
        for i in range(w * h):
            v = out[i]
            rgba[i * 4:i * 4 + 4] = bytes((v, v, v, 255))
    elif ctype == 2:
        for i in range(w * h):
            s = i * 3
            d = i * 4
            rgba[d:d + 3] = out[s:s + 3]
            rgba[d + 3] = 255
    elif ctype == 4:
        for i in range(w * h):
            v = out[i * 2]
            d = i * 4
            rgba[d] = v
            rgba[d + 1] = v
            rgba[d + 2] = v
            rgba[d + 3] = out[i * 2 + 1]
    else:
        rgba[:] = out[:w * h * 4]
    return w, h, bytes(rgba)


def _load_bmp_rgba(data):
    off = struct.unpack("<I", data[10:14])[0]
    w = struct.unpack("<i", data[18:22])[0]
    h = struct.unpack("<i", data[22:26])[0]
    bpp = struct.unpack("<H", data[28:30])[0]
    if w <= 0 or h == 0 or bpp not in (24, 32):
        raise ScanError("--diff 只支持 24/32-bit BMP")
    topdown = h < 0
    h = abs(h)
    stride = ((w * bpp + 31) // 32) * 4
    rgba = bytearray(w * h * 4)
    for y in range(h):
        row = off + y * stride
        dy = y if topdown else h - 1 - y
        for x in range(w):
            s = row + x * (bpp // 8)
            d = (dy * w + x) * 4
            rgba[d] = data[s + 2]
            rgba[d + 1] = data[s + 1]
            rgba[d + 2] = data[s]
            rgba[d + 3] = data[s + 3] if bpp == 32 else 255
    return w, h, bytes(rgba)


def load_rgba(path):
    p = Path(path)
    if not p.exists():
        raise ScanError("文件不存在：%s" % p)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ScanError("读取失败：%s" % exc)
    if data.startswith(PNG_SIG):
        return _load_png_rgba(data)
    if data[:2] == b"BM":
        return _load_bmp_rgba(data)
    raise ScanError("--diff 只支持 PNG / BMP：%s" % p)


def _write_png(path, w, h, pixels, mode):
    def chunk(typ, body):
        return (struct.pack(">I", len(body)) + typ + body
                + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))
    nch = 1 if mode == "gray" else 4
    ctype = 0 if mode == "gray" else 6
    stride = w * nch
    raw = bytearray((stride + 1) * h)
    for y in range(h):
        raw[y * (stride + 1)] = 0
        raw[y * (stride + 1) + 1:y * (stride + 1) + 1 + stride] = \
            pixels[y * stride:(y + 1) * stride]
    blob = (PNG_SIG
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, ctype, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))
    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(blob)
    return len(blob)


def do_diff(path_a, path_b, out_path, force=False, amplify=True):
    wa, ha, pa = load_rgba(path_a)
    wb, hb, pb = load_rgba(path_b)
    print("A: %s  %dx%d" % (path_a, wa, ha))
    print("B: %s  %dx%d" % (path_b, wb, hb))
    if (wa, ha) != (wb, hb):
        print("")
        print("尺寸不一致，无法逐像素对比。")
        print("  提示：尺寸差异本身就是重要线索 —— 常见手法是改 IHDR 让图"
              "「变小」，把内容藏到多出来的像素里。")
        return 1
    w, h = wa, ha
    diff_pixels = 0
    max_delta = 0
    sum_delta = 0
    channel_hits = [0, 0, 0, 0]
    out = bytearray(w * h)             # 灰度差异图
    for i in range(w * h):
        d = i * 4
        biggest = 0
        for c in range(4):
            va = pa[d + c]
            vb = pb[d + c]
            if va != vb:
                delta = abs(va - vb)
                channel_hits[c] += 1
                if delta > biggest:
                    biggest = delta
                sum_delta += delta
        if biggest:
            diff_pixels += 1
        if biggest > max_delta:
            max_delta = biggest
        # 放大差异：LSB 级的差别只有 1，直接画出来几乎全黑
        v = biggest
        if amplify and v:
            v = min(255, v * 32)
        out[i] = v

    print("")
    print("== 差异统计 ==")
    print("  不同像素: %d / %d (%.4f%%)"
          % (diff_pixels, w * h, 100.0 * diff_pixels / (w * h)))
    print("  最大通道差: %d" % max_delta)
    if diff_pixels:
        print("  平均每像素差值: %.4f" % (sum_delta / float(diff_pixels)))
    names = ("R", "G", "B", "A")
    print("  各通道有差异的像素数: " +
          "  ".join("%s=%d" % (names[c], channel_hits[c]) for c in range(4)))
    if max_delta <= 1 and diff_pixels:
        print("")
        print("  => 差异全部不超过 1，这是典型的 LSB 级改动。")
        print("     用 lsb.py 分别提取两张图的最低位来对比更直接。")
    elif diff_pixels == 0:
        print("")
        print("  => 两图像素完全一致。差异只可能在元数据 / 文件尾。")
    if out_path:
        p = Path(out_path)
        if p.exists() and not force:
            raise ScanError("目标文件已存在：%s（要覆盖请加 --force）" % p)
        size = _write_png(p, w, h, bytes(out), "gray")
        print("")
        print("  差异图已写出: %s (%dx%d, %d 字节)" % (p, w, h, size))
        print("  （差异已放大 32 倍，白色=改动最大）")
    return 0


# ==================================================================== 入口

USAGE = """stegodetect.py -- 隐写总检：一次性找出文件里「不该有的东西」

做什么
  按优先级列出结构异常：文件尾附加数据 > 内嵌压缩包 > 块/段异常 > 尺寸不符
  > 熵偏高等仅供参考的线索。避免「换个工具再看一眼」的反复折腾。

用法
  python -X utf8 stegodetect.py 图.png
        单个文件体检

  python -X utf8 stegodetect.py 题目目录 -r
        递归检查目录下所有文件

  python -X utf8 stegodetect.py a.png b.jpg c.bmp
        一次给多个文件

  python -X utf8 stegodetect.py --diff 原图.png 可疑.png -o 差异.png
        两图逐像素对比，输出放大后的差异图

  python -X utf8 stegodetect.py 图.png --tail-dump -o tail.bin
        把文件尾附加数据单独存出来

参数
  -r, --recursive   目录递归
  --diff A B        两图对比模式
  -o, --output      输出文件（差异图 / 尾部数据）
  --tail-dump       导出文件尾附加数据
  --force           允许覆盖已存在文件
  -v, --verbose     预览多打印一些
  --no-amplify      差异图不做 32 倍放大（看原始差值）

已知限制
  只做结构层判断，不做 RS / 卡方等统计型隐写分析。
  尾部数据按启发式切分，长度头加密时切不准。
  --diff 要求两图尺寸一致且为 8-bit 非隔行 PNG 或 24/32-bit BMP。
"""


def iter_files(targets, recursive):
    out = []
    for t in targets:
        p = Path(t)
        if p.is_dir():
            it = p.rglob("*") if recursive else p.glob("*")
            for f in sorted(it):
                if f.is_file():
                    out.append(f)
        elif p.exists():
            out.append(p)
        else:
            out.append(p)          # 交给 scan_file 报「不存在」
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(USAGE)
        return 0
    ap = argparse.ArgumentParser(prog="stegodetect.py", add_help=True,
                                 description="隐写总检")
    ap.add_argument("targets", nargs="*", help="文件或目录")
    ap.add_argument("-r", "--recursive", action="store_true", help="目录递归")
    ap.add_argument("--diff", nargs=2, metavar=("A", "B"), help="两图对比")
    ap.add_argument("-o", "--output", help="输出文件")
    ap.add_argument("--tail-dump", action="store_true", dest="tail_dump",
                    help="导出文件尾附加数据")
    ap.add_argument("--force", action="store_true", help="允许覆盖")
    ap.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    ap.add_argument("--no-amplify", action="store_true", dest="no_amplify",
                    help="差异图不放大")
    args = ap.parse_args(argv)

    try:
        if args.diff:
            return do_diff(args.diff[0], args.diff[1], args.output,
                           args.force, not args.no_amplify)

        if not args.targets:
            print(USAGE)
            return 0

        files = iter_files(args.targets, args.recursive)
        if not files:
            print("错误: 目录里没有文件", file=sys.stderr)
            return 1

        reports = []
        failed = 0
        for f in files:
            try:
                rep = scan_file(f, verbose=args.verbose)
                reports.append(rep)
            except ScanError as exc:
                print("=" * 66)
                print("文件: %s" % f)
                print("  跳过: %s" % exc)
                failed += 1

        # 汇总：把「高置信度」的文件挑出来，方便扫完目录直接看
        if len(reports) > 1:
            print("=" * 66)
            print("== 汇总（只列有高置信度发现的文件）==")
            hits = [r for r in reports if r.has_high()]
            if not hits:
                print("  所有 %d 个文件都没有高置信度发现。" % len(reports))
            else:
                for r in hits:
                    highs = [it["title"] for it in r.items if it["pri"] == P_HIGH]
                    print("  %s" % r.path.name)
                    for t in highs[:4]:
                        print("     - %s" % t)
            print("")
            print("共检查 %d 个文件，跳过 %d 个。" % (len(reports), failed))

        # 一个文件都没成功：这是错误，不能用 0 退出码蒙混过去，
        # 否则调用方（和 GUI）会以为检查通过了。
        if not reports:
            print("错误: 没有任何文件被成功检查（全部跳过）", file=sys.stderr)
            return 1

        if args.tail_dump:
            if len(reports) != 1:
                print("错误: --tail-dump 需要恰好一个输入文件", file=sys.stderr)
                return 1
            blobs = [it["blob"] for it in reports[0].items
                     if it["blob"] and "附加数据" in it["title"]]
            if not blobs:
                print("没有找到文件尾附加数据，不生成输出文件。", file=sys.stderr)
                return 1
            out = Path(args.output) if args.output else \
                reports[0].path.with_name(reports[0].path.stem + "_tail.bin")
            if out.exists() and not args.force:
                print("错误: 目标文件已存在：%s（要覆盖请加 --force）" % out,
                      file=sys.stderr)
                return 1
            out.write_bytes(blobs[0])
            print("尾部数据已写出: %s (%d 字节)" % (out, len(blobs[0])))
        return 0
    except ScanError as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 1
    except OSError as exc:
        print("错误: 文件操作失败：%s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        # 兜底：宁可给一句人话，也不要甩 traceback。排查时用 DSH_STEGO_DEBUG=1
        import os
        import traceback
        if os.environ.get("DSH_STEGO_DEBUG"):
            traceback.print_exc()
        print("错误: 处理失败（%s: %s）" % (type(exc).__name__, exc), file=sys.stderr)
        print("      如果这看起来不该发生，请设 DSH_STEGO_DEBUG=1 重跑看堆栈",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
