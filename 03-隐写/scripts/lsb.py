# -*- coding: utf-8 -*-
"""
lsb.py -- PNG/BMP 最低有效位（LSB）隐写：提取、写入、位平面可视化。

为什么需要
==========
CTF 杂项里最常见的一类隐写就是把数据藏进像素最低位：肉眼看不出差别，
但按「每像素取 1 bit」读出来就是一串文本。手工用 Stegsolve 点来点去很慢，
而且位平面顺序、通道顺序、位序（MSB/LSB）只要错一个就读不出东西。

本脚本提供三件事：
  1. 按指定参数精确提取（通道 / 位平面 / 位序 / 通道布局 / 长度）；
  2. 不给参数时自动穷举常见组合并打分排序，直接告诉你「最可能是这个」；
  3. --plane N 把第 N 位平面画成 PNG（黑白图），用来肉眼找藏字；
  4. --embed 反向把数据写进最低位（默认另存新文件）。

PNG 解码是自己实现的（zlib + 5 种行过滤 + 调色板），不依赖 Pillow。

用法
====
    # 自动尝试（不知道参数时先跑这个）
    python -X utf8 lsb.py 图.png

    # 精确提取：R 通道第 0 位，LSB 位序，前 200 字节
    python -X utf8 lsb.py 图.png --channel R --bit 0 --bit-order lsb --count 200

    # 结果写文件（默认只打印预览）
    python -X utf8 lsb.py 图.png --channel all --bit 0 -o out.bin

    # 位平面可视化：输出第 3 位平面的黑白图
    python -X utf8 lsb.py 图.png --plane 3 -o plane3.png

    # 反向写入
    python -X utf8 lsb.py 图.png --embed -f payload.bin -o 藏了东西.png
    python -X utf8 lsb.py 图.png --embed -f payload.bin --length-header

已知限制
========
    * PNG 只支持 8-bit 色深、非隔行；16-bit / Adam7 隔行会直接报错（并说明原因）。
      调色板 PNG 会被展开成 RGBA，因此读到的是展开后的颜色，不是调色板索引。
    * 位平面可视化对调色板/灰度图只取 R 通道（灰度图 R=G=B，等价）。
    * 纯 Python 逐位循环，几十万像素以上会慢；自动模式只抽样前 1KB 做判断。
    * 不做「自适应/随机间隔」这类非线性 LSB（OpenStego 风格），只做顺序取位。
"""

import argparse
import math
import struct
import sys
import zlib
from pathlib import Path

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# 通道名 -> RGBA 内部偏移
CH_OFF = {"R": 0, "G": 1, "B": 2, "A": 3}


class ImgError(Exception):
    """给用户看的错误（不打印 traceback）。"""


# ==================================================================== 图像容器

class Img(object):
    """统一内部表示：总是 RGBA 8-bit，行优先。"""

    __slots__ = ("width", "height", "rgba", "color_type", "fmt")

    def __init__(self, width, height, rgba, color_type, fmt):
        self.width = width
        self.height = height
        self.rgba = rgba            # bytes, 长度 = w*h*4
        self.color_type = color_type  # PNG 颜色类型；BMP 用 2/6 近似
        self.fmt = fmt

    @property
    def has_alpha(self):
        # PNG 4=灰度+alpha 6=RGBA；BMP 32bit 也当有 alpha
        return self.color_type in (4, 6)

    def describe(self):
        names = {0: "灰度", 2: "RGB", 3: "调色板", 4: "灰度+Alpha", 6: "RGBA"}
        return "%s %dx%d %s" % (self.fmt.upper(), self.width, self.height,
                                names.get(self.color_type, "type%d" % self.color_type))


# ==================================================================== PNG 解码

def _paeth(a, b, c):
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _unfilter(raw, width, height, bpp, stride):
    """把 PNG 的过滤后行数据还原成原始像素。

    PNG 每行开头 1 字节是过滤类型（0-4），必须逐行逆运算；Sub/Paeth 依赖
    同行左侧字节，Up/Average/Paeth 依赖上一行，所以只能顺序处理。
    """
    out = bytearray(stride * height)
    pos = 0
    prev = bytearray(stride)
    for y in range(height):
        if pos + 1 + stride > len(raw):
            raise ImgError("PNG 像素数据在第 %d 行被截断" % y)
        ft = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if ft == 0:
            pass
        elif ft == 1:                       # Sub：左
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ft == 2:                       # Up：上
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:                       # Average：左、上的平均
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ft == 4:                       # Paeth
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + _paeth(a, b, c)) & 0xFF
        else:
            raise ImgError("PNG 行过滤类型非法：%d（第 %d 行）" % (ft, y))
        out[y * stride:(y + 1) * stride] = line
        prev = line
    return out


def _png_chunks(data):
    pos = 8
    n = len(data)
    chunks = []
    bad_crc = 0
    while pos + 8 <= n:
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + ln]
        if len(body) != ln:
            raise ImgError("PNG 块 %s 数据被截断（声明 %d 字节，只剩 %d）"
                           % (typ.decode("latin-1"), ln, len(body)))
        crc_at = pos + 8 + ln
        if crc_at + 4 <= n:
            want = struct.unpack(">I", data[crc_at:crc_at + 4])[0]
            if (zlib.crc32(typ + body) & 0xFFFFFFFF) != want:
                bad_crc += 1
        chunks.append((typ, body))
        pos = crc_at + 4
        if typ == b"IEND":
            break
    if bad_crc:
        # 故意改坏 CRC 也是隐写手法之一，只提示不致命
        print("提示: 有 %d 个 PNG 块 CRC 不匹配（已忽略，继续解析）" % bad_crc,
              file=sys.stderr)
    return chunks


def decode_png(data):
    if not data.startswith(PNG_SIG):
        raise ImgError("不是 PNG 文件（签名不匹配）")
    chunks = _png_chunks(data)
    ihdr = None
    idat = []
    plte = None
    trns = None
    for typ, body in chunks:
        if typ == b"IHDR":
            ihdr = body
        elif typ == b"IDAT":
            idat.append(body)
        elif typ == b"PLTE":
            plte = body
        elif typ == b"tRNS":
            trns = body
    if ihdr is None or len(ihdr) < 13:
        raise ImgError("PNG 缺少 IHDR 头")
    w, h, depth, ctype, comp, filt, inter = struct.unpack(">IIBBBBB", ihdr[:13])
    if w == 0 or h == 0:
        raise ImgError("PNG 尺寸非法：%dx%d" % (w, h))
    if inter != 0:
        raise ImgError("不支持隔行（Adam7）PNG。请先转成非隔行，例如：\n"
                       "  7z / 图像工具另存为普通 PNG，或用 python -c 重写")
    if ctype not in (0, 2, 3, 4, 6):
        raise ImgError("不支持的 PNG 颜色类型 %d" % ctype)
    if depth not in (1, 2, 4, 8):
        raise ImgError("不支持 %d-bit 色深的 PNG（16-bit 的 LSB 语义不同，本工具不猜）。"
                       "请先转成 8-bit 再分析" % depth)
    if ctype not in (0, 3) and depth != 8:
        raise ImgError("颜色类型 %d 只允许 8-bit，当前 %d-bit（文件结构非法）"
                       % (ctype, depth))
    if not idat:
        raise ImgError("PNG 没有 IDAT 像素数据块")
    try:
        raw = zlib.decompress(b"".join(idat))
    except zlib.error as exc:
        raise ImgError("PNG 像素数据解压失败：%s（IDAT 可能被破坏）" % exc)

    nch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ctype]
    # 1/2/4-bit 只出现在灰度与调色板里：每像素不足 1 字节，按位打包，
    # 所以行字节数要向上取整。用 ceil 而不是 (w*depth)//8，否则会少算一行。
    bits_per_px = nch * depth
    stride = (w * bits_per_px + 7) // 8
    need = (stride + 1) * h
    if len(raw) < need:
        raise ImgError("PNG 像素数据不足：需要 %d 字节，实际解出 %d" % (need, len(raw)))
    buf = _unfilter(raw, w, h, max(1, bits_per_px // 8), stride)

    # 先统一成「每像素一个 0-255 样本」，再展开成 RGBA
    if depth == 8:
        samples = buf[:w * h * nch]
    else:
        samples = bytearray(w * h * nch)
        per_byte = 8 // depth
        maxval = (1 << depth) - 1
        step = 255.0 / maxval
        for i in range(w * h * nch):
            byte = buf[i // per_byte]
            shift = 8 - depth * ((i % per_byte) + 1)
            v = (byte >> shift) & maxval
            # 低位深灰度要拉伸到 0-255，否则显示会全黑
            samples[i] = int(round(v * step))
        if ctype == 3:
            # 调色板索引不能拉伸，必须保持原值
            for i in range(w * h):
                byte = buf[i // per_byte]
                shift = 8 - depth * ((i % per_byte) + 1)
                samples[i] = (byte >> shift) & maxval

    rgba = bytearray(w * h * 4)
    if ctype == 0:                                  # 灰度
        for i in range(w * h):
            v = samples[i]
            d = i * 4
            rgba[d] = v
            rgba[d + 1] = v
            rgba[d + 2] = v
            rgba[d + 3] = 255
    elif ctype == 2:                                # RGB
        for i in range(w * h):
            s = i * 3
            d = i * 4
            rgba[d] = samples[s]
            rgba[d + 1] = samples[s + 1]
            rgba[d + 2] = samples[s + 2]
            rgba[d + 3] = 255
    elif ctype == 4:                                # 灰度 + Alpha
        for i in range(w * h):
            s = i * 2
            d = i * 4
            v = samples[s]
            rgba[d] = v
            rgba[d + 1] = v
            rgba[d + 2] = v
            rgba[d + 3] = samples[s + 1]
    elif ctype == 6:                                # RGBA
        rgba[:] = samples[:w * h * 4]
    else:                                           # 调色板
        if plte is None or len(plte) < 3:
            raise ImgError("调色板 PNG 缺少 PLTE")
        ncol = len(plte) // 3
        pal = []
        for i in range(ncol):
            pal.append(bytes((plte[i * 3], plte[i * 3 + 1], plte[i * 3 + 2])))
        alpha = bytes(trns) if trns else b""
        for i in range(w * h):
            idx = samples[i]
            if idx >= ncol:
                raise ImgError("调色板索引 %d 超出 PLTE 色数 %d" % (idx, ncol))
            d = i * 4
            rgba[d:d + 3] = pal[idx]
            rgba[d + 3] = alpha[idx] if idx < len(alpha) else 255
    return Img(w, h, bytes(rgba), ctype, "png")


# ==================================================================== BMP 解码

def decode_bmp(data):
    if len(data) < 54:
        raise ImgError("BMP 文件太小（%d 字节），不是完整位图" % len(data))
    if data[:2] != b"BM":
        raise ImgError("不是 BMP 文件（缺少 BM 签名）")
    off = struct.unpack("<I", data[10:14])[0]
    dib = struct.unpack("<I", data[14:18])[0]
    if dib < 40:
        raise ImgError("不支持老式 BITMAPCOREHEADER（DIB 头 %d 字节）" % dib)
    w = struct.unpack("<i", data[18:22])[0]
    h = struct.unpack("<i", data[22:26])[0]
    bpp = struct.unpack("<H", data[28:30])[0]
    comp = struct.unpack("<I", data[30:34])[0]
    if w <= 0 or h == 0:
        raise ImgError("BMP 尺寸非法：%dx%d" % (w, h))
    topdown = h < 0
    h = abs(h)
    if bpp not in (8, 24, 32):
        raise ImgError("只支持 8/24/32 bit BMP，当前 %d bit" % bpp)
    if comp not in (0, 3):
        raise ImgError("不支持的 BMP 压缩方式 %d（只支持 BI_RGB/BI_BITFIELDS）" % comp)
    if bpp == 8 and comp != 0:
        raise ImgError("8-bit BMP 只支持 BI_RGB")

    palette = []
    if bpp == 8:
        ncol = struct.unpack("<I", data[46:50])[0]
        if ncol == 0:
            ncol = 256
        pstart = 14 + dib
        for i in range(ncol):
            p = pstart + i * 4
            if p + 4 > len(data):
                break
            palette.append(bytes((data[p + 2], data[p + 1], data[p])))
        if not palette:
            raise ImgError("8-bit BMP 调色板缺失")

    stride = ((w * bpp + 31) // 32) * 4            # BMP 每行 4 字节对齐
    if off + stride * h > len(data):
        raise ImgError("BMP 像素数据被截断：需要 %d 字节，文件只有 %d"
                       % (off + stride * h, len(data)))

    rgba = bytearray(w * h * 4)
    for y in range(h):
        row = off + y * stride
        dst_y = y if topdown else (h - 1 - y)      # 默认是自下而上存
        base = dst_y * w * 4
        if bpp == 24:
            for x in range(w):
                s = row + x * 3
                d = base + x * 4
                rgba[d] = data[s + 2]              # BMP 是 BGR
                rgba[d + 1] = data[s + 1]
                rgba[d + 2] = data[s]
                rgba[d + 3] = 255
        elif bpp == 32:
            for x in range(w):
                s = row + x * 4
                d = base + x * 4
                rgba[d] = data[s + 2]
                rgba[d + 1] = data[s + 1]
                rgba[d + 2] = data[s]
                rgba[d + 3] = data[s + 3]
        else:
            for x in range(w):
                idx = data[row + x]
                d = base + x * 4
                if idx < len(palette):
                    rgba[d:d + 3] = palette[idx]
                rgba[d + 3] = 255

    if bpp == 32:
        # 绝大多数 32bit BMP 的 A 字节全是 0（未使用），直接当透明会读不到东西
        alphas = rgba[3::4]
        if not any(alphas):
            for i in range(3, len(rgba), 4):
                rgba[i] = 255
            print("提示: 32bit BMP 的 Alpha 全为 0，已按不透明处理", file=sys.stderr)
    return Img(w, h, bytes(rgba), 6 if bpp == 32 else 2, "bmp")


# ==================================================================== 读图 / 写图

def load_image(path):
    p = Path(path)
    if not p.exists():
        raise ImgError("文件不存在：%s" % p)
    if not p.is_file():
        raise ImgError("不是普通文件：%s" % p)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ImgError("读取失败：%s" % exc)
    if not data:
        raise ImgError("文件是空的：%s" % p)
    if data.startswith(PNG_SIG):
        return decode_png(data)
    if data[:2] == b"BM":
        return decode_bmp(data)
    raise ImgError("只支持 PNG / BMP。当前文件头为 %s（可能扩展名写错了）"
                   % data[:8].hex())


def _png_chunk(typ, body):
    return (struct.pack(">I", len(body)) + typ + body
            + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))


def write_png(path, width, height, pixels, mode):
    """纯 zlib 手写 PNG。mode: 'gray' 1 字节/像素，'rgba' 4 字节/像素。

    所有行都用过滤类型 0（None）：压缩率略差，但解码最不容易出错，
    而且浏览器/任何解码器都必然支持。
    """
    if mode == "gray":
        ctype, nch = 0, 1
    elif mode == "rgba":
        ctype, nch = 6, 4
    else:
        raise ImgError("内部错误：未知 PNG 输出模式 %r" % mode)
    stride = width * nch
    need = stride * height
    if len(pixels) != need:
        raise ImgError("内部错误：像素缓冲区长度 %d 与 %dx%d 不符"
                       % (len(pixels), width, height))
    raw = bytearray((stride + 1) * height)
    for y in range(height):
        src = y * stride
        dst = y * (stride + 1)
        raw[dst] = 0
        raw[dst + 1:dst + 1 + stride] = pixels[src:src + stride]
    ihdr = struct.pack(">IIBBBBB", width, height, 8, ctype, 0, 0, 0)
    blob = (PNG_SIG
            + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + _png_chunk(b"IEND", b""))
    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(blob)
    return len(blob)


def _write_out(path, data, force):
    p = Path(path)
    if p.exists() and not force:
        raise ImgError("目标文件已存在：%s（要覆盖请加 --force）" % p)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_bytes(data)
    except OSError as exc:
        raise ImgError("写入失败：%s" % exc)
    return p


# ==================================================================== 打分工具

MAGICS = (
    (b"\x89PNG", "PNG"), (b"PK\x03\x04", "ZIP"), (b"PK\x05\x06", "ZIP(空)"),
    (b"GIF8", "GIF"), (b"\xff\xd8\xff", "JPEG"), (b"BM", "BMP"),
    (b"Rar!", "RAR"), (b"\x1f\x8b", "gzip"), (b"%PDF", "PDF"),
    (b"7z\xbc\xaf", "7z"), (b"\xfd7zXZ", "xz"), (b"SQLite format 3", "SQLite"),
)


def entropy(data):
    """香农熵。>6.8 基本就是压缩/加密数据，不像明文。"""
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


def score_bytes(data):
    """给一段「疑似明文」的字节打分，0~1。用于自动模式排序。

    为什么不能只看 printable_ratio：把随机位平面（例如自然图像的 bit1）
    读出来，大约 50% 字节落在可打印区间，printable_ratio 也有 0.4 左右，
    和真明文区分不开。所以这里的关键是「窗口质量」——真正的藏数据几乎
    每一段连续字节都是可打印的，噪声则是稀疏的。
    """
    if not data:
        return 0.0
    s = 0.0
    for magic, _name in MAGICS:
        if data.startswith(magic):
            s += 0.55
            break
    s += printable_ratio(data) * 0.30
    # 窗口质量：取最好的 16 字节窗口可打印率。噪声几乎不可能有连续 16 个
    # 可打印字节（概率约 0.4^16 ≈ 4e-7），明文则到处都有。
    win = 16
    best = 0.0
    if len(data) >= win:
        for i in range(0, min(len(data) - win + 1, 256)):
            r = printable_ratio(data[i:i + win])
            if r > best:
                best = r
                if best >= 1.0:
                    break
    else:
        best = printable_ratio(data)
    s += best * 0.40
    low = data.lower()
    for kw in (b"flag{", b"ctf{", b"flag", b"http://", b"<?xml", b"<html"):
        if kw in low:
            s += 0.15
            break
    if entropy(data) > 6.8:
        s -= 0.30
    if len(set(data)) <= 2:
        s -= 0.35                       # 全 0 / 全 1，肯定没取到东西
    return max(0.0, min(1.0, s))


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


def show_bytes(data):
    """能当文本显示就显示文本，否则 hexdump。"""
    pr = printable_ratio(data)
    if pr >= 0.85:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("gb18030", "replace")
        if len(text) > 600:
            text = text[:600] + "\n... (截断)"
        return text
    return hexdump(data)


# ==================================================================== 位提取

def channel_offsets(img, channel):
    """通道名 -> RGBA 内部偏移列表。

    注意 "all" 只含 R/G/B（这是 Stegsolve 等工具的习惯，CTF 出题也是按 RGB
    顺序藏），Alpha 单独用 "A" 或 "rgba" 才取。把 A 混进 "all" 会让绝大多数
    正常题目直接读不出来。
    """
    if channel == "all":
        return [0, 1, 2]
    if channel == "rgba":
        if not img.has_alpha:
            raise ImgError("这张图没有 Alpha 通道（颜色类型 %d），不能取 A"
                           % img.color_type)
        return [0, 1, 2, 3]
    if channel == "A":
        if not img.has_alpha:
            raise ImgError("这张图没有 Alpha 通道（颜色类型 %d），不能从 A 取位"
                           % img.color_type)
        return [3]
    if channel not in CH_OFF:
        raise ImgError("通道只能是 R/G/B/A/all/rgba，收到 %r" % channel)
    return [CH_OFF[channel]]


def capacity_bits(img, channel):
    offs = channel_offsets(img, channel)
    return img.width * img.height * len(offs)


def extract_bits(img, offs, bit, bit_order, max_bytes, layout):
    """按 (通道顺序, 位平面, 位序) 取位并打包成字节。

    layout:
      row    —— 逐像素、逐通道（RGB 顺序）
      bgr    —— 逐像素，但通道顺序 B,G,R(,A)
      planar —— 先把 R 通道整张读完，再读 G，再读 B
    """
    w, h = img.width, img.height
    data = img.rgba
    mask = 1 << bit
    need = max_bytes * 8
    bits = []
    ap = bits.append

    if layout == "planar":
        for off in offs:
            for i in range(w * h):
                ap(1 if (data[i * 4 + off] & mask) else 0)
                if len(bits) >= need:
                    break
            if len(bits) >= need:
                break
    else:
        order = offs
        if layout == "bgr":
            order = [o for o in (2, 1, 0, 3) if o in offs]
        done = False
        for y in range(h):
            base = y * w * 4
            for x in range(w):
                idx = base + x * 4
                for off in order:
                    ap(1 if (data[idx + off] & mask) else 0)
                if len(bits) >= need:
                    done = True
                    break
            if done:
                break
    return _pack_bits(bits, bit_order)


def _pack_bits(bits, bit_order):
    n = len(bits) // 8
    out = bytearray(n)
    if bit_order == "msb":
        # 先读到的位放在输出字节的高位
        for i in range(n):
            v = 0
            b0 = i * 8
            for j in range(8):
                v = (v << 1) | bits[b0 + j]
            out[i] = v
    else:
        # 先读到的位放在输出字节的低位
        for i in range(n):
            v = 0
            b0 = i * 8
            for j in range(8):
                v |= bits[b0 + j] << j
            out[i] = v
    return bytes(out)


# ==================================================================== 自动模式

AUTO_LAYOUTS = ("row", "bgr", "planar")
AUTO_CHANNELS = ("all", "R", "G", "B")
AUTO_BITS = (0, 1)


def _length_header(raw, endian):
    """把前 4 字节当长度头解析；长度合理才算数。"""
    if len(raw) < 8:
        return None
    n = struct.unpack("<I" if endian == "little" else ">I", raw[:4])[0]
    if 0 < n <= len(raw) - 4:
        return n, raw[4:4 + n]
    return None


def auto_scan(img, sample_bytes=1024):
    """穷举常见组合，按打分排序。返回 [(score, layout, bit, order, ch, raw)]。"""
    results = []
    for layout in AUTO_LAYOUTS:
        for bit in AUTO_BITS:
            for order in ("lsb", "msb"):
                for ch in AUTO_CHANNELS:
                    try:
                        offs = channel_offsets(img, ch)
                    except ImgError:
                        continue
                    raw = extract_bits(img, offs, bit, order, sample_bytes, layout)
                    if not raw:
                        continue
                    results.append([score_bytes(raw), layout, bit, order, ch, raw])
    results.sort(key=lambda r: r[0], reverse=True)
    return results


def run_auto(img, args):
    cap = capacity_bits(img, "all") // 8
    print("图像: %s" % img.describe())
    print("最大可提取（RGB 全部通道）: %d 字节" % cap)
    print("")
    if cap <= 0:
        raise ImgError("图像为空，没有可提取的位")
    sample = min(1024, cap)
    res = auto_scan(img, sample)
    if not res:
        print("没有取到任何数据。")
        return 0
    print("== 自动尝试（按可能性从高到低，每项抽样 %d 字节）==" % sample)
    for i, item in enumerate(res[:6], 1):
        score, layout, bit, order, ch, raw = item
        print("%d. 评分 %.2f | 通道=%-3s 位平面=%d 位序=%-3s 布局=%s"
              % (i, score, ch, bit, order, layout))
        # 同时试试「前 4 字节是长度头」这种写法
        for endian in ("little", "big"):
            lh = _length_header(raw, endian)
            if lh:
                n, payload = lh
                if score_bytes(payload) > score:
                    print("   [长度头/%s] 声明 %d 字节，内容评分 %.2f"
                          % ("小端" if endian == "little" else "大端", n,
                             score_bytes(payload)))
                    print("   " + show_bytes(payload[:300]).replace("\n", "\n   "))
        # 噪声的预览只给 64 字节（再长也只是刷屏），像明文的给 256
        preview = raw[:256] if score >= 0.4 else raw[:64]
        print("   预览: " + show_bytes(preview).replace("\n", "\n   "))
        print("   复现: python -X utf8 lsb.py 图 --channel %s --bit %d "
              "--bit-order %s --layout %s" % (ch, bit, order, layout))
        print("")
    if res[0][0] < 0.40:
        print("提示: 最高分只有 %.2f，基本可以认为不是「顺序 LSB」。"
              % res[0][0])
        print("      可以试试：--plane N 看位平面图有没有可见图案；")
        print("      或者这张图本身可能不是隐写载体（先查文件尾附加数据）。")
    return 0


# ==================================================================== 各模式

def do_extract(img, args):
    ch = args.channel or "all"
    offs = channel_offsets(img, ch)
    cap = img.width * img.height * len(offs) // 8
    if args.count and args.count > 0:
        want = args.count
    else:
        want = cap
    if want <= 0:
        raise ImgError("这张图没有可提取的位")
    if want > cap:
        print("警告: 要求 %d 字节，但图像最多只能给出 %d 字节，按上限处理"
              % (want, cap), file=sys.stderr)
        want = cap
    if want > 4 * 1024 * 1024:
        print("提示: 要提取 %d 字节，纯 Python 逐位循环会慢，请耐心等" % want,
              file=sys.stderr)

    print("图像: %s" % img.describe())
    print("参数: 通道=%s 位平面=%d 位序=%s 布局=%s 长度=%d 字节"
          % (ch, args.bit, args.bit_order, args.layout, want))
    raw = extract_bits(img, offs, args.bit, args.bit_order, want, args.layout)
    print("提取: %d 字节（评分 %.2f）" % (len(raw), score_bytes(raw)))
    print("")
    if args.output:
        p = _write_out(args.output, raw, args.force)
        print("已写入: %s (%d 字节)" % (p, len(raw)))
    else:
        print("== 内容 ==")
        print(show_bytes(raw))
        if args.hex:
            print("")
            print(hexdump(raw))
    return 0


def do_plane(img, args):
    bit = args.plane
    if bit < 0 or bit > 7:
        raise ImgError("位平面只能是 0-7，收到 %d" % bit)
    ch = args.channel
    if ch is None:
        ch = "R"                       # 可视化默认看 R（灰度图 R=G=B）
    offs = channel_offsets(img, ch)
    w, h = img.width, img.height
    data = img.rgba
    names = {0: "R", 1: "G", 2: "B", 3: "A"}
    base = Path(args.image)
    print("图像: %s" % img.describe())
    print("位平面 %d 可视化（白=该位为 1，黑=0），通道 %s" % (bit, ch))
    written = []
    for off in offs:
        mask = 1 << bit
        gray = bytearray(w * h)
        for i in range(w * h):
            gray[i] = 255 if (data[i * 4 + off] & mask) else 0
        if args.output and len(offs) == 1:
            out = Path(args.output)
        else:
            out = base.with_name("%s_plane%d_%s.png"
                                 % (base.stem, bit, names.get(off, str(off))))
        if out.exists() and not args.force:
            raise ImgError("目标文件已存在：%s（要覆盖请加 --force）" % out)
        size = write_png(out, w, h, bytes(gray), "gray")
        written.append((out, size))
        print("  已生成: %s (%dx%d, %d 字节)" % (out, w, h, size))
    if not written:
        print("没有生成任何图像。")
    return 0


def do_embed(img, args):
    payload = b""
    if args.payload:
        p = Path(args.payload)
        if not p.exists():
            raise ImgError("payload 文件不存在：%s" % p)
        try:
            payload = p.read_bytes()
        except OSError as exc:
            raise ImgError("payload 读取失败：%s" % exc)
    elif args.payload_text is not None:
        payload = args.payload_text.encode("utf-8")
    if not payload:
        raise ImgError("没有要写入的数据：用 -f 指定文件，或 --payload-text 给文本")

    ch = args.channel or "all"
    offs = channel_offsets(img, ch)
    cap_bits = img.width * img.height * len(offs)
    body = payload
    if args.length_header:
        # 长度头本身也要占 4 字节，且解码时按同一字节序读回
        body = struct.pack("<I" if args.endian == "little" else ">I",
                           len(payload)) + payload
    need_bits = len(body) * 8
    if need_bits > cap_bits:
        raise ImgError("容量不足：需要 %d bit（%d 字节），图像只有 %d bit（%d 字节）"
                       % (need_bits, len(body), cap_bits, cap_bits // 8))

    bits = []
    for byte in body:
        if args.bit_order == "msb":
            for j in range(7, -1, -1):
                bits.append((byte >> j) & 1)
        else:
            for j in range(8):
                bits.append((byte >> j) & 1)

    rgba = bytearray(img.rgba)
    mask = 1 << args.bit
    clear = 0xFF ^ mask
    total = len(bits)
    k = 0
    w, h = img.width, img.height
    if args.layout == "planar":
        for off in offs:
            for i in range(w * h):
                if k >= total:
                    break
                idx = i * 4 + off
                rgba[idx] = (rgba[idx] & clear) | (bits[k] << args.bit)
                k += 1
            if k >= total:
                break
    else:
        order = offs
        if args.layout == "bgr":
            order = [o for o in (2, 1, 0, 3) if o in offs]
        done = False
        for y in range(h):
            base = y * w * 4
            for x in range(w):
                idx = base + x * 4
                for off in order:
                    if k >= total:
                        done = True
                        break
                    rgba[idx + off] = (rgba[idx + off] & clear) | (bits[k] << args.bit)
                    k += 1
                if done:
                    break
            if done:
                break

    if args.output:
        out = Path(args.output)
    else:
        src = Path(args.image)
        out = src.with_name(src.stem + "_lsb.png")
    # 覆盖原图必须显式 --force
    try:
        same = out.resolve() == Path(args.image).resolve()
    except OSError:
        same = False
    if same and not args.force:
        raise ImgError("默认不覆盖原图。要写回原文件请加 --force，"
                       "或用 -o 指定新文件名")
    if out.exists() and not args.force:
        raise ImgError("目标文件已存在：%s（要覆盖请加 --force）" % out)
    size = write_png(out, w, h, bytes(rgba), "rgba")
    print("图像: %s" % img.describe())
    print("已写入 %d 字节（%d bit）到通道 %s 第 %d 位，位序 %s，布局 %s"
          % (len(payload), total, ch, args.bit, args.bit_order, args.layout))
    if args.length_header:
        print("已附带 4 字节长度头（%s端）" % ("小" if args.endian == "little" else "大"))
    print("输出: %s (%dx%d RGBA, %d 字节)" % (out, w, h, size))
    print("提取回来: python -X utf8 lsb.py \"%s\" --channel %s --bit %d "
          "--bit-order %s --layout %s%s"
          % (out, ch, args.bit, args.bit_order, args.layout,
             " --count %d" % (len(payload) + 4) if args.length_header else ""))
    return 0


# ==================================================================== 入口

USAGE = """lsb.py -- PNG/BMP 最低有效位（LSB）隐写提取 / 写入 / 位平面可视化

做什么
  把像素最低位当比特流读出来，或者反过来把数据写进最低位。
  不给参数时自动穷举常见组合并打分排序，省掉手试。

用法
  python -X utf8 lsb.py 图.png
        自动尝试：通道(all/R/G/B) × 位平面(0,1) × 位序(lsb/msb) × 布局(row/bgr/planar)

  python -X utf8 lsb.py 图.png --channel R --bit 0 --count 200
        精确提取：R 通道第 0 位，前 200 字节

  python -X utf8 lsb.py 图.png --channel all --bit 0 -o out.bin
        结果写到文件（不加 -o 只打印预览）

  python -X utf8 lsb.py 图.png --plane 3 -o plane3.png
        把第 3 位平面画成黑白 PNG（白=1），用来肉眼找藏字

  python -X utf8 lsb.py 图.png --embed -f payload.bin
        把 payload 写进最低位，默认另存为 图_lsb.png（要覆盖原图必须加 --force）

  python -X utf8 lsb.py 图.png --embed --payload-text "flag{hello}" --length-header
        文本写入，并在开头加 4 字节长度头（方便自动模式识别）

参数
  --channel R|G|B|A|all   取哪些通道（提取默认 all，可视化默认 R）
  --bit 0-7               取每个通道字节的第 N 位（0 = 最低位）
  --bit-order lsb|msb     先读到的位放到输出字节的低位 / 高位
  --layout row|bgr|planar 逐像素 RGB / 逐像素 BGR / 先整张 R 再 G 再 B
  --count N               提取多少字节（0 = 全部容量）
  --plane N               输出第 N 位平面的可视化 PNG
  --embed                 写入模式
  -f, --payload 文件      要写入的数据
  --length-header         写入时在开头加 4 字节长度
  --endian little|big     长度头的字节序
  -o, --output 文件       输出路径（已存在需 --force）
  --force                 允许覆盖

已知限制
  PNG 仅 8-bit、非隔行；16-bit / Adam7 隔行会明确报错。
  调色板 PNG 会先展开成 RGBA，读到的是展开后的颜色而不是索引。
  只处理「顺序取位」，不支持随机间隔 / 自适应 LSB。
"""


def build_parser():
    ap = argparse.ArgumentParser(
        prog="lsb.py", add_help=True,
        description="PNG/BMP 最低有效位隐写提取 / 写入 / 位平面可视化")
    ap.add_argument("image", nargs="?", help="输入 PNG 或 BMP")
    ap.add_argument("--channel", choices=["R", "G", "B", "A", "all", "rgba"],
                    help="通道（提取默认 all，--plane 默认 R）")
    ap.add_argument("--bit", type=int, default=0, help="位平面 0-7（0=最低位）")
    ap.add_argument("--bit-order", choices=["lsb", "msb"], default="lsb",
                    dest="bit_order", help="位序（默认 lsb）")
    ap.add_argument("--layout", choices=["row", "bgr", "planar"], default="row",
                    help="通道布局（默认 row）")
    ap.add_argument("--count", type=int, default=0, help="提取字节数，0=全部")
    ap.add_argument("--plane", type=int, help="输出第 N 位平面的可视化 PNG")
    ap.add_argument("--embed", action="store_true", help="写入模式")
    ap.add_argument("-f", "--payload", help="写入模式的数据文件")
    ap.add_argument("--payload-text", dest="payload_text", help="写入模式的文本")
    ap.add_argument("--length-header", action="store_true", dest="length_header",
                    help="写入时加 4 字节长度头")
    ap.add_argument("--endian", choices=["little", "big"], default="little",
                    help="长度头字节序（默认 little）")
    ap.add_argument("-o", "--output", help="输出路径")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在文件")
    ap.add_argument("--hex", action="store_true", help="额外打印 hexdump")
    return ap


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(USAGE)
        return 0
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.image:
        print(USAGE)
        return 0
    if args.bit < 0 or args.bit > 7:
        print("错误: --bit 只能是 0-7，收到 %d" % args.bit, file=sys.stderr)
        return 2
    if args.bit_order not in ("lsb", "msb"):
        print("错误: --bit-order 只能是 lsb/msb", file=sys.stderr)
        return 2
    try:
        img = load_image(args.image)
        if args.plane is not None:
            return do_plane(img, args)
        if args.embed:
            return do_embed(img, args)
        if args.channel is None and args.count == 0 and args.bit == 0 \
                and args.bit_order == "lsb" and args.layout == "row" \
                and not args.output and not args.hex:
            return run_auto(img, args)
        return do_extract(img, args)
    except ImgError as exc:
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
