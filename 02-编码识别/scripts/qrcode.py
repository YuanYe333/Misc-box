# -*- coding: utf-8 -*-
"""
qrcode.py -- 纯标准库二维码解码器（不依赖 zbar / opencv / pyzbar）。

为什么需要
==========
CTF 杂项题里的二维码经常是「残缺的、拉伸的、只有一半的、拍屏的」，
用手机扫不出来，但结构信息还在。而 zbar/pyzbar/opencv 要么装不上，
要么在比赛环境里根本不许装。本脚本用纯 Python + 标准库把 QR 码从
PNG/BMP 像素一路解到文本，装个 Python 就能跑。

实现链路（全部自己写）
======================
  1. PNG 解码：zlib 解压 + 五种行滤波反算，支持 8-bit 灰度/RGB/RGBA
     以及调色板、1/2/4 位深度，**不支持隔行扫描**；
     BMP 解码：24/32 位 BI_RGB 与 8 位调色板，支持自底向上/自顶向下。
  2. 二值化：Otsu 全局阈值（可 --threshold 手动覆盖，可 --invert 反色）。
  3. 定位图案检测：逐行扫描 1:1:3:1:1 的黑白游程，再竖向复核，
     聚类去重，最后从候选里挑出「模块尺寸一致 + 近似直角」的三个。
  4. 网格重采样：由三个定位中心做仿射映射，逐模块多点采样，
     自动反推版本号（模块数 = 版本*4+17）。
  5. 格式信息：读取两份格式信息位，对 32 种 (纠错级别, 掩码) 候选做
     BCH(15,5) 最近距离匹配（可纠 3 位错）。
  6. 数据区提取：按标准之字形顺序取码字，跳过全部功能图案模块。
  7. Reed-Solomon 纠错：GF(256) 综合式计算 -> Berlekamp-Massey 求错误
     定位多项式 -> Chien 搜索定位 -> 解 Vandermonde 线性方程求错误幅值
     -> 回代并复核综合式。真的能纠错，不是只看一眼。
  8. 模式解码：数字 / 字母数字 / 字节 / Kanji / ECI / FNC1 / 结构化追加。

用法
====
    python -X utf8 qrcode.py 码.png
    python -X utf8 qrcode.py 码.png --dump            # 打印二值化模块矩阵
    python -X utf8 qrcode.py 码.bmp --invert          # 反色（黑底白码）
    python -X utf8 qrcode.py 码.png --threshold 128   # 手动阈值
    python -X utf8 qrcode.py 码.png --hex             # 解码失败时看数据码字

已知限制（诚实说明）
====================
    * 只支持 **未隔行** 的 PNG，隔行扫描的会明确报错；
    * 只支持 8 位深度的常规色彩类型 + 调色板（16 位取高字节）；
    * 定位图案依赖「横竖都有清晰的 1:1:3:1:1 结构」。透视畸变很大、
      严重模糊、只有部分定位图案的图会检测失败——那时脚本会退化成
      「结构分析」（打印版本/纠错级别/掩码/定位点坐标）并明确告诉你
      没解出内容，**不会假装成功**；
    * 不做多码/拼接码（Structured Append 只打印序号不合并）；
    * 微 QR 码（Micro QR）不支持。

遇到解不出的图，正确做法是用手机扫，或用 zxing（zxing-cpp / 在线
zxing.org）——本脚本的价值在于「没有第三方库时也能出结果」。
"""

import argparse
import math
import struct
import sys
import zlib

# ====================================================================
# 一、PNG / BMP 解码（纯标准库）
# ====================================================================

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _unfilter(raw, width, height, bits_per_pixel):
    """按 PNG 规范反算 5 种行滤波，返回每行的原始字节。"""
    bpp = max(1, bits_per_pixel // 8)          # 滤波用的「像素字节数」
    stride = (width * bits_per_pixel + 7) // 8
    prev = bytearray(stride)
    rows = []
    pos = 0
    for _ in range(height):
        if pos >= len(raw):
            raise ValueError("PNG 数据被截断（IDAT 不足）")
        ftype = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        if len(line) < stride:
            raise ValueError("PNG 数据被截断（行不完整）")
        pos += stride
        if ftype == 1:                          # Sub
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:                        # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:                        # Average
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:                        # Paeth
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                pa = abs(b - c)
                pb = abs(a - c)
                pc = abs(a + b - 2 * c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        elif ftype != 0:
            raise ValueError("PNG 行滤波类型非法：%d" % ftype)
        rows.append(line)
        prev = line
    return rows


def _extract_samples(line, width, bitdepth):
    """把一行字节拆成 width 个采样值（支持 1/2/4/8/16 位深度）。"""
    if bitdepth == 8:
        return list(line[:width])
    if bitdepth == 16:
        # 灰度判定只需要高位，直接取高字节，省一半内存
        return [line[2 * i] for i in range(width) if 2 * i < len(line)]
    mask = (1 << bitdepth) - 1
    per = 8 // bitdepth
    out = []
    for i in range(width):
        byte = line[i // per] if i // per < len(line) else 0
        shift = 8 - bitdepth * (i % per + 1)
        out.append((byte >> shift) & mask)
    return out


def decode_png(data):
    """返回 (width, height, gray) ，gray 是每行一个 bytearray 的灰度图。"""
    if data[:8] != PNG_SIG:
        raise ValueError("不是 PNG 文件（文件头不匹配）")
    pos = 8
    width = height = bitdepth = colortype = None
    interlace = 0
    idat = []
    palette = None
    trns = None
    while pos + 8 <= len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + ln]
        pos += 12 + ln
        if typ == b"IHDR":
            width, height, bitdepth, colortype, _comp, _filt, interlace = \
                struct.unpack(">IIBBBBB", chunk)
        elif typ == b"PLTE":
            palette = chunk
        elif typ == b"tRNS":
            trns = chunk
        elif typ == b"IDAT":
            idat.append(chunk)
        elif typ == b"IEND":
            break
    if width is None:
        raise ValueError("PNG 缺少 IHDR 块")
    if interlace != 0:
        raise ValueError("不支持隔行扫描(Adam7)的 PNG，请先转成非隔行再试")
    if colortype not in (0, 2, 3, 4, 6):
        raise ValueError("不支持的 PNG 颜色类型：%d" % colortype)
    if not idat:
        raise ValueError("PNG 没有 IDAT 数据块")

    try:
        raw = zlib.decompress(b"".join(idat))
    except zlib.error as exc:
        raise ValueError("PNG 像素数据解压失败：%s" % exc)

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[colortype]
    rows = _unfilter(raw, width, height, channels * bitdepth)

    gray = []
    scale_max = float((1 << bitdepth) - 1)
    for y in range(height):
        line = rows[y]
        # 注意：必须按「每行总采样数」= width * channels 来拆，
        # 只传 width 会让 RGB/RGBA/灰度+alpha 的彩色图索引越界。
        vals = _extract_samples(line, width * channels, bitdepth)
        out = bytearray(width)
        if colortype == 3:
            if palette is None:
                raise ValueError("调色板 PNG 缺少 PLTE 块")
            npal = len(palette) // 3
            for x in range(width):
                idx = vals[x]
                if idx >= npal:
                    out[x] = 255
                    continue
                r = palette[3 * idx]
                g = palette[3 * idx + 1]
                b = palette[3 * idx + 2]
                v = (r * 299 + g * 587 + b * 114) // 1000
                a = 255
                if trns is not None and idx < len(trns):
                    a = trns[idx]
                if a < 255:
                    v = (v * a + 255 * (255 - a)) // 255
                out[x] = v
        elif colortype == 0:
            for x in range(width):
                v = vals[x]
                if bitdepth != 8:
                    v = int(round(v * 255.0 / scale_max))
                out[x] = v
        elif colortype == 2:
            for x in range(width):
                r, g, b = vals[3 * x], vals[3 * x + 1], vals[3 * x + 2]
                out[x] = (r * 299 + g * 587 + b * 114) // 1000
        elif colortype == 4:
            for x in range(width):
                v, a = vals[2 * x], vals[2 * x + 1]
                if bitdepth != 8:
                    v = int(round(v * 255.0 / scale_max))
                    a = int(round(a * 255.0 / scale_max))
                out[x] = (v * a + 255 * (255 - a)) // 255
        else:  # colortype == 6
            for x in range(width):
                r, g, b, a = vals[4 * x], vals[4 * x + 1], vals[4 * x + 2], vals[4 * x + 3]
                v = (r * 299 + g * 587 + b * 114) // 1000
                out[x] = (v * a + 255 * (255 - a)) // 255
        gray.append(out)
    return width, height, gray


def decode_bmp(data):
    """返回 (width, height, gray)。支持 24/32 位 BI_RGB 与 8 位调色板。"""
    if len(data) < 54 or data[:2] != b"BM":
        raise ValueError("不是 BMP 文件（文件头不匹配）")
    pixoff = struct.unpack("<I", data[10:14])[0]
    hdrsize = struct.unpack("<I", data[14:18])[0]
    width = struct.unpack("<i", data[18:22])[0]
    raw_h = struct.unpack("<i", data[22:26])[0]
    bpp = struct.unpack("<H", data[28:30])[0]
    comp = struct.unpack("<I", data[30:34])[0]
    if comp != 0:
        raise ValueError("只支持未压缩的 BMP（BI_RGB），当前压缩方式=%d" % comp)
    if bpp not in (8, 24, 32):
        raise ValueError("只支持 8/24/32 位 BMP，当前 %d 位" % bpp)
    topdown = raw_h < 0
    height = abs(raw_h)
    if width <= 0 or height <= 0:
        raise ValueError("BMP 尺寸非法：%dx%d" % (width, height))

    palette = None
    if bpp == 8:
        npal = (pixoff - 14 - hdrsize) // 4
        palette = []
        base = 14 + hdrsize
        for i in range(npal):
            b, g, r, _a = data[base + 4 * i:base + 4 * i + 4]
            palette.append((r, g, b))

    rowsize = ((bpp * width + 31) // 32) * 4
    gray = []
    for y in range(height):
        sy = y if topdown else (height - 1 - y)
        base = pixoff + sy * rowsize
        line = data[base:base + rowsize]
        if len(line) < rowsize:
            line = line + b"\x00" * (rowsize - len(line))
        out = bytearray(width)
        if bpp == 8:
            for x in range(width):
                idx = line[x]
                if palette and idx < len(palette):
                    r, g, b = palette[idx]
                else:
                    r = g = b = idx
                out[x] = (r * 299 + g * 587 + b * 114) // 1000
        elif bpp == 24:
            for x in range(width):
                b, g, r = line[3 * x], line[3 * x + 1], line[3 * x + 2]
                out[x] = (r * 299 + g * 587 + b * 114) // 1000
        else:
            for x in range(width):
                b, g, r = line[4 * x], line[4 * x + 1], line[4 * x + 2]
                out[x] = (r * 299 + g * 587 + b * 114) // 1000
        gray.append(out)
    return width, height, gray


def load_image(path):
    """读图，返回 (width, height, gray)。"""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:8] == PNG_SIG:
        return decode_png(data)
    if data[:2] == b"BM":
        return decode_bmp(data)
    raise ValueError("不认识的图片格式（只支持 PNG 与 BMP，实际文件头=%r）"
                     % data[:8])


# ====================================================================
# 二、二值化
# ====================================================================

def otsu_threshold(gray, width, height):
    """Otsu 最大类间方差阈值。二维码黑白两极分化，这个阈值非常稳。"""
    hist = [0] * 256
    for row in gray:
        for v in row:
            hist[v] += 1
    total = float(width * height)
    if total == 0:
        return 128
    sum_all = 0.0
    for i in range(256):
        sum_all += i * hist[i]
    sum_b = 0.0
    w_b = 0.0
    best = 0.0
    thr = 128
    for i in range(256):
        w_b += hist[i]
        if w_b == 0:
            continue
        w_f = total - w_b
        if w_f == 0:
            break
        sum_b += i * hist[i]
        m_b = sum_b / w_b
        m_f = (sum_all - sum_b) / w_f
        var = w_b * w_f * (m_b - m_f) * (m_b - m_f)
        if var > best:
            best = var
            thr = i
    return thr


def binarize(gray, width, height, threshold=None, invert=False):
    """返回 black[y][x] ∈ {0,1}，1 表示黑（深色模块）。"""
    thr = otsu_threshold(gray, width, height) if threshold is None else threshold
    black = []
    for y in range(height):
        row = gray[y]
        out = bytearray(width)
        for x in range(width):
            out[x] = 1 if row[x] <= thr else 0
        black.append(out)
    if invert:
        for row in black:
            for x in range(width):
                row[x] ^= 1
    return black, thr


# ====================================================================
# 三、定位图案（Finder Pattern）检测
# ====================================================================

def _ratio_ok(v, target, lo=0.42, hi=1.85):
    """游程长度是否落在 target 的可接受范围内（容忍像素量化误差）。"""
    return lo * target <= v <= hi * target


def _run_lengths(row, width):
    """返回 [(颜色, 起点, 长度)]，颜色 1=黑。"""
    runs = []
    x = 0
    while x < width:
        c = row[x]
        start = x
        while x < width and row[x] == c:
            x += 1
        runs.append((c, start, x - start))
    return runs


def _verify_vertical(black, width, height, xc, yc, module):
    """在竖直方向复核 1:1:3:1:1，返回 (精化后的 yc, 模块尺寸) 或 None。

    注意计数口径：up/dn 都**不含**当前行 y，所以中心黑条总长是
    up + 1 + dn，上下相邻白条分别从 y-up-1、y+dn+1 开始数。
    早期版本把 y 算进 up，导致下边界整体偏一格、竖向复核永远失败。
    """
    x = int(round(xc))
    y = int(round(yc))
    if not (0 <= x < width and 0 <= y < height):
        return None
    if not black[y][x]:
        return None

    up = 0
    yy = y - 1
    while yy >= 0 and black[yy][x]:
        up += 1
        yy -= 1
    dn = 0
    yy = y + 1
    while yy < height and black[yy][x]:
        dn += 1
        yy += 1
    center = up + 1 + dn
    if center < 3:
        return None

    # 上方的白条 + 再上方的黑条
    w1 = 0
    yy = y - up - 1
    while yy >= 0 and not black[yy][x]:
        w1 += 1
        yy -= 1
    b1 = 0
    while yy >= 0 and black[yy][x]:
        b1 += 1
        yy -= 1

    # 下方的白条 + 再下方的黑条
    w3 = 0
    yy = y + dn + 1
    while yy < height and not black[yy][x]:
        w3 += 1
        yy += 1
    b3 = 0
    while yy < height and black[yy][x]:
        b3 += 1
        yy += 1

    m = module
    if not (_ratio_ok(center, 3 * m) and _ratio_ok(w1, m) and _ratio_ok(b1, m)
            and _ratio_ok(w3, m) and _ratio_ok(b3, m)):
        return None
    span = b1 + w1 + center + w3 + b3
    return (y - up + center / 2.0, span / 7.0)


def find_finders(black, width, height):
    """扫描全图找候选定位图案中心，返回 [(x, y, module)]。"""
    cands = []
    for y in range(height):
        runs = _run_lengths(black[y], width)
        for i in range(len(runs) - 4):
            r0, r1, r2, r3, r4 = runs[i], runs[i + 1], runs[i + 2], runs[i + 3], runs[i + 4]
            # 必须是 黑-白-黑-白-黑
            if not (r0[0] == 1 and r1[0] == 0 and r2[0] == 1 and r3[0] == 0 and r4[0] == 1):
                continue
            total = r0[2] + r1[2] + r2[2] + r3[2] + r4[2]
            if total < 7:
                continue
            m = total / 7.0
            if not (_ratio_ok(r0[2], m) and _ratio_ok(r1[2], m) and _ratio_ok(r2[2], 3 * m)
                    and _ratio_ok(r3[2], m) and _ratio_ok(r4[2], m)):
                continue
            # 中心黑条的连续坐标中心：起点 + 长度/2（像素 i 覆盖 [i,i+1)）
            xc = r2[1] + r2[2] / 2.0
            ver = _verify_vertical(black, width, height, xc, y, m)
            if ver is None:
                continue
            yc, m2 = ver
            if not _ratio_ok(m2, m, 0.6, 1.7):
                continue
            cands.append((xc, yc, (m + m2) / 2.0))

    # 聚类去重：同一图案会被很多行重复命中
    clusters = []
    for (x, y, m) in cands:
        placed = False
        for c in clusters:
            if abs(c[0] - x) < 3.0 * c[2] and abs(c[1] - y) < 3.0 * c[2]:
                n = c[3] + 1
                c[0] = (c[0] * c[3] + x) / n
                c[1] = (c[1] * c[3] + y) / n
                c[2] = (c[2] * c[3] + m) / n
                c[3] = n
                placed = True
                break
        if not placed:
            clusters.append([x, y, m, 1])
    # 命中次数太少的丢掉（噪声）
    clusters = [c for c in clusters if c[3] >= 1]
    # 用「按自身尺度采样 7x7」复核每个候选：这一步能把数据区里偶然凑出
    # 1:1:3:1:1 的假定位图案筛掉（它们往往还能被扫到十几次，光看命中数
    # 反而会排在真图案前面）。
    scored = []
    for c in clusters:
        rx, ry, rm, fit = refine_finder(black, width, height, c[0], c[1], c[2])
        if fit < 40:                    # 49 个模块至少要对 40 个
            continue
        scored.append((rx, ry, rm, c[3], fit))
    if not scored:
        # 一张真二维码不该连一个定位图案都过不了，退回去只按命中数
        scored = [(c[0], c[1], c[2], c[3], 0) for c in clusters]
    scored.sort(key=lambda c: (-c[4], -c[3]))
    return scored


def score_finder(black, width, height, cx, cy, module):
    """按候选自己的模块尺寸采样 7x7，返回与标准定位图案吻合的模块数(0-49)。

    这是区分「真定位图案」与「数据区里偶然凑出的 1:1:3:1:1 游程」最硬的
    判据：真图案 49/49 全中，假图案通常只有一半多点。而且只花 49 次采样，
    比整矩阵重采样便宜得多，可以拿来当粗筛。
    """
    if module <= 0.4:
        return 0
    hit = 0
    for r in range(7):
        for c in range(7):
            want = 1 if (r in (0, 6) or c in (0, 6)
                         or (2 <= r <= 4 and 2 <= c <= 4)) else 0
            px = int(math.floor(cx + (c - 3) * module))
            py = int(math.floor(cy + (r - 3) * module))
            if 0 <= px < width and 0 <= py < height:
                if black[py][px] == want:
                    hit += 1
    return hit


def refine_finder(black, width, height, cx, cy, module):
    """局部细化候选中心与模块尺寸，返回 (cx, cy, module, fit)。

    聚类出来的质心只是「所有命中行的平均」，一旦图案被噪声/翻转污染，
    质心会偏零点几个像素；模块尺寸只有 1~2 px 时这点偏差就足以让采样
    错格。这里在 ±1.5 px / ±0.25 模块的范围内做小步长搜索，取 7x7 吻合
    度最高的那组参数。
    """
    best = (cx, cy, module, score_finder(black, width, height, cx, cy, module))
    if best[3] >= 49:
        return best
    for dstep in (0.5, 0.25):
        span = 1.5 if dstep == 0.5 else 0.75
        n = int(span / dstep)
        for i in range(-n, n + 1):
            for j in range(-n, n + 1):
                for k in (-2, -1, 0, 1, 2):
                    tx = best[0] + i * dstep
                    ty = best[1] + j * dstep
                    tm = module * (1.0 + k * 0.04)
                    if tm <= 0.3:
                        continue
                    fit = score_finder(black, width, height, tx, ty, tm)
                    if fit > best[3]:
                        best = (tx, ty, tm, fit)
        if best[3] >= 49:
            break
    return best


def pick_finder_triple(cands, black=None, width=None, height=None):
    """从候选里挑三个定位图案，返回 (tl, tr, bl) 或 None。

    QR 的三个定位图案分别在左上、右上、左下，直角顶点就是左上角。

    关键：大版本二维码的数据区里也常出现「长得像定位图案」的 1:1:3:1:1
    游程（纯随机数据必然偶尔凑出来），光靠几何打分不够——必须真的按
    这个三组合去重采样，再校验三个定位图案的 7x7 是否与标准一致。
    所以这里先按几何分排序，再逐个候选组做采样验证，第一个通过的就是对的。
    """
    if len(cands) < 3:
        return None
    n = len(cands)
    lim = min(n, 12)
    options = []
    for i in range(lim):
        for j in range(i + 1, lim):
            for k in range(j + 1, lim):
                pts = [cands[i], cands[j], cands[k]]
                ms = [p[2] for p in pts]
                if min(ms) <= 0:
                    continue
                # 模块尺寸一致性
                spread = max(ms) / min(ms)
                if spread > 1.5:
                    continue
                # 找直角顶点
                best_corner = None
                best_score = None
                for a in range(3):
                    o = pts[a]
                    p1 = pts[(a + 1) % 3]
                    p2 = pts[(a + 2) % 3]
                    v1 = (p1[0] - o[0], p1[1] - o[1])
                    v2 = (p2[0] - o[0], p2[1] - o[1])
                    l1 = (v1[0] ** 2 + v1[1] ** 2) ** 0.5
                    l2 = (v2[0] ** 2 + v2[1] ** 2) ** 0.5
                    if l1 < 1e-6 or l2 < 1e-6:
                        continue
                    dot = (v1[0] * v2[0] + v1[1] * v2[1]) / (l1 * l2)
                    # 两条边长度也要接近（正方形码）
                    len_ratio = max(l1, l2) / min(l1, l2)
                    score = abs(dot) + abs(len_ratio - 1.0) * 2.0
                    if best_score is None or score < best_score:
                        best_score = score
                        best_corner = (a, dot, len_ratio)
                if best_corner is None:
                    continue
                a, dot, len_ratio = best_corner
                if abs(dot) > 0.30 or len_ratio > 1.30:
                    continue
                total_score = best_score + (spread - 1.0) * 3.0
                # 命中次数越多越可信（真定位图案会被很多行扫到）
                hit_bonus = sum(p[3] for p in pts)
                total_score -= min(hit_bonus, 40) * 0.02
                options.append((total_score, a, pts))
    if not options:
        return None
    options.sort(key=lambda o: o[0])

    def orient(corner_idx, pts):
        tl = pts[corner_idx]
        others = [pts[(corner_idx + 1) % 3], pts[(corner_idx + 2) % 3]]
        a, b = others[0], others[1]
        # 用叉积判手性：图像坐标 y 向下时，v(TR)x v(BL) 为正
        cross = (a[0] - tl[0]) * (b[1] - tl[1]) - (a[1] - tl[1]) * (b[0] - tl[0])
        if cross > 0:
            return tl, a, b
        return tl, b, a

    # 先不做采样验证（调用方没给图），退化成纯几何选优
    if black is None:
        _s, corner_idx, pts = options[0]
        return orient(corner_idx, pts)

    # 逐个验证：采样 -> 校验三个定位图案的 7x7 是否与标准一致
    for (_s, corner_idx, pts) in options:
        tl, tr, bl = orient(corner_idx, pts)
        module_est = (tl[2] + tr[2] + bl[2]) / 3.0
        ver = estimate_version(tl, tr, bl, module_est)
        if ver is None:
            continue
        try:
            mods = sample_matrix(black, width, height, tl, tr, bl, ver)
        except (IndexError, ValueError):
            continue
        if validate_finders(mods, ver):
            return tl, tr, bl
    # 全都校验不过，返回几何最优的那个（让调用方给出诊断信息）
    _s, corner_idx, pts = options[0]
    return orient(corner_idx, pts)


# ====================================================================
# 四、功能图案模板（用来判定哪些模块是数据区）
# ====================================================================

# 各版本对齐图案中心坐标（下标 = 版本-1，版本 1 没有）
ALIGN_POS = [
    [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54],
    [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74],
    [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90],
    [6, 28, 50, 72, 94], [6, 26, 50, 74, 98], [6, 30, 54, 78, 102],
    [6, 28, 54, 80, 106], [6, 32, 58, 84, 110], [6, 30, 58, 86, 114],
    [6, 34, 62, 90, 118], [6, 26, 50, 74, 98, 122], [6, 30, 54, 78, 102, 126],
    [6, 26, 52, 78, 104, 130], [6, 30, 56, 82, 108, 134],
    [6, 34, 60, 86, 112, 138], [6, 30, 58, 86, 114, 142],
    [6, 34, 62, 90, 118, 146], [6, 30, 54, 78, 102, 126, 150],
    [6, 24, 50, 76, 102, 128, 154], [6, 28, 54, 80, 106, 132, 158],
    [6, 32, 58, 84, 110, 136, 162], [6, 26, 54, 82, 110, 138, 166],
    [6, 30, 58, 86, 114, 142, 170],
]


def build_function_mask(version):
    """返回 func[row][col]=True 表示该模块属于功能图案（非数据区）。"""
    n = version * 4 + 17
    func = [[False] * n for _ in range(n)]

    # 三个定位图案 + 分隔符（含 -1 圈，即 8x8）
    for (r, c) in ((0, 0), (0, n - 7), (n - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = r + dr, c + dc
                if 0 <= rr < n and 0 <= cc < n:
                    func[rr][cc] = True

    # 定位线（第 6 行、第 6 列）
    for i in range(n):
        func[6][i] = True
        func[i][6] = True

    # 校正图案（5x5），跳过与定位图案重叠的三个角
    if version > 1:
        pos = ALIGN_POS[version - 1]
        corners = {(6, 6), (6, pos[-1]), (pos[-1], 6)}
        for r in pos:
            for c in pos:
                if (r, c) in corners:
                    continue
                for dr in range(-2, 3):
                    for dc in range(-2, 3):
                        func[r + dr][c + dc] = True

    # 格式信息区（第一份绕左上，第二份在右上/左下）
    for i in range(9):
        func[8][i] = True
        func[i][8] = True
    for i in range(8):
        func[8][n - 1 - i] = True
        func[n - 1 - i][8] = True

    # 版本信息区（版本 >= 7）
    if version >= 7:
        for i in range(6):
            for j in range(3):
                func[i][n - 11 + j] = True
                func[n - 11 + j][i] = True
    return func


# ====================================================================
# 五、网格重采样
# ====================================================================

def estimate_version(tl, tr, bl, module_est):
    """由两个定位中心的距离反推版本：中心距 = (n-7) 个模块。"""
    d1 = ((tr[0] - tl[0]) ** 2 + (tr[1] - tl[1]) ** 2) ** 0.5
    d2 = ((bl[0] - tl[0]) ** 2 + (bl[1] - tl[1]) ** 2) ** 0.5
    d = (d1 + d2) / 2.0
    if module_est <= 0:
        return None
    n_est = d / module_est + 7.0
    # 模块数必须是 21,25,...,177（版本 1..40）
    cands = []
    for v in range(1, 41):
        n = v * 4 + 17
        cands.append((abs(n - n_est), v, n))
    cands.sort()
    if cands[0][0] > 3.5:                # 差太远，说明定位/模块尺寸估错了
        return None
    return cands[0][1]


def sample_matrix(black, width, height, tl, tr, bl, version):
    """仿射映射 + 逐模块多点采样，返回 modules[row][col] ∈ {0,1}。"""
    n = version * 4 + 17
    d = float(n - 7)
    ux = ((tr[0] - tl[0]) / d, (tr[1] - tl[1]) / d)
    uy = ((bl[0] - tl[0]) / d, (bl[1] - tl[1]) / d)
    ox = tl[0] - 3.5 * ux[0] - 3.5 * uy[0]
    oy = tl[1] - 3.5 * ux[1] - 3.5 * uy[1]

    def sample(px, py):
        # 坐标是「连续」的：像素 i 覆盖 [i, i+1)，所以取整必须用 floor。
        # 用 round 会在模块尺寸 = 1px 时整体偏移半格，直接把定位图案采样坏。
        ix = int(math.floor(px))
        iy = int(math.floor(py))
        if 0 <= ix < width and 0 <= iy < height:
            return black[iy][ix]
        return 0

    mods = []
    for r in range(n):
        row = bytearray(n)
        for c in range(n):
            # 在模块中心附近取 5 个点投票，抗锯齿/轻微模糊
            votes = 0
            cx = ox + ux[0] * (c + 0.5) + uy[0] * (r + 0.5)
            cy = ox + ux[1] * (c + 0.5) + uy[1] * (r + 0.5)
            votes += sample(cx, cy)
            votes += sample(cx + ux[0] * 0.22, cy + ux[1] * 0.22)
            votes += sample(cx - ux[0] * 0.22, cy - ux[1] * 0.22)
            votes += sample(cx + uy[0] * 0.22, cy + uy[1] * 0.22)
            votes += sample(cx - uy[0] * 0.22, cy - uy[1] * 0.22)
            row[c] = 1 if votes >= 3 else 0
        mods.append(row)
    return mods


def validate_finders(mods, version):
    """校验三个定位图案与分隔符是否与标准一致，用于排除误检。"""
    n = version * 4 + 17
    if len(mods) != n:
        return False
    expected = []
    for r in range(7):
        for c in range(7):
            dark = (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))
            expected.append((r, c, 1 if dark else 0))
    for (orr, occ) in ((0, 0), (0, n - 7), (n - 7, 0)):
        bad = 0
        for (r, c, v) in expected:
            if mods[orr + r][occ + c] != v:
                bad += 1
        if bad > 6:
            return False
    return True


# ====================================================================
# 六、格式信息 / 版本信息
# ====================================================================

G15 = 0x537
G15_MASK = 0x5412
G18 = 0x1F25

EC_NAME = {0: "M", 1: "L", 2: "H", 3: "Q"}


def _bch_type_info(data):
    d = data << 10
    while d.bit_length() - G15.bit_length() >= 0:
        d ^= G15 << (d.bit_length() - G15.bit_length())
    return ((data << 10) | d) ^ G15_MASK


def _bch_version(ver):
    d = ver << 12
    while d.bit_length() - G18.bit_length() >= 0:
        d ^= G18 << (d.bit_length() - G18.bit_length())
    return (ver << 12) | d


FORMAT_TABLE = {}
for _ec in range(4):
    for _mask in range(8):
        FORMAT_TABLE[_bch_type_info((_ec << 3) | _mask)] = (_ec, _mask)


def format_coords(n):
    """返回两份格式信息各自的 (row, col) 坐标列表（bit0 在前）。"""
    vert = []
    for i in range(15):
        if i < 6:
            vert.append((i, 8))
        elif i < 8:
            vert.append((i + 1, 8))
        else:
            vert.append((n - 15 + i, 8))
    horz = []
    for i in range(15):
        if i < 8:
            horz.append((8, n - i - 1))
        elif i < 9:
            horz.append((8, 7))
        else:
            horz.append((8, 15 - i - 1))
    return vert, horz


def _read_bits(mods, coords):
    v = 0
    for i, (r, c) in enumerate(coords):
        if mods[r][c]:
            v |= (1 << i)
    return v


def read_format(mods, version):
    """返回 (ec_level, mask, 两副本各自的最小汉明距离)。"""
    n = version * 4 + 17
    vert, horz = format_coords(n)
    copies = [_read_bits(mods, vert), _read_bits(mods, horz)]
    best = None
    for raw in copies:
        for cand, (ec, mask) in FORMAT_TABLE.items():
            dist = bin(cand ^ raw).count("1")
            if best is None or dist < best[0]:
                best = (dist, ec, mask)
    if best is None:
        return None, None, 99
    dist, ec, mask = best
    # BCH(15,5) 最多纠 3 位错；超过就认为格式信息不可信
    return ec, mask, dist


def read_version_info(mods, version):
    """版本 >=7 时读取版本信息并校验，返回读到的版本号或 None。"""
    if version < 7:
        return version
    n = version * 4 + 17
    bits1 = 0
    bits2 = 0
    for i in range(18):
        r = i // 3
        c = i % 3 + n - 11
        if mods[r][c]:
            bits1 |= (1 << i)
        r2 = i % 3 + n - 11
        c2 = i // 3
        if mods[r2][c2]:
            bits2 |= (1 << i)
    best = None
    for v in range(7, 41):
        cand = _bch_version(v)
        for raw in (bits1, bits2):
            d = bin(cand ^ raw).count("1")
            if best is None or d < best[0]:
                best = (d, v)
    if best is None or best[0] > 3:
        return None
    return best[1]


# ====================================================================
# 七、码字提取 + Reed-Solomon 纠错
# ====================================================================

# 各版本各纠错级别的 RS 分块表：(块数, 总码字, 数据码字) 可多组
RS_BLOCK_TABLE = [
    # L
    [(1, 26, 19)], [(1, 44, 34)], [(1, 70, 55)], [(1, 100, 80)],
    [(1, 134, 108)], [(2, 86, 68)], [(2, 98, 78)], [(2, 121, 97)],
    [(2, 146, 116)], [(2, 86, 68, 2, 87, 69)], [(4, 101, 81)],
    [(2, 116, 92, 2, 117, 93)], [(4, 133, 107)], [(3, 145, 115, 1, 146, 116)],
    [(5, 109, 87, 1, 110, 88)], [(5, 122, 98, 1, 123, 99)],
    [(1, 135, 107, 5, 136, 108)], [(5, 150, 120, 1, 151, 121)],
    [(3, 141, 113, 4, 142, 114)], [(3, 135, 107, 5, 136, 108)],
    [(4, 144, 116, 4, 145, 117)], [(2, 139, 111, 7, 140, 112)],
    [(4, 151, 121, 5, 152, 122)], [(6, 147, 117, 4, 148, 118)],
    [(8, 132, 106, 4, 133, 107)], [(10, 142, 114, 2, 143, 115)],
    [(8, 152, 122, 4, 153, 123)], [(3, 147, 117, 10, 148, 118)],
    [(7, 146, 116, 7, 147, 117)], [(5, 145, 115, 10, 146, 116)],
    [(13, 145, 115, 3, 146, 116)], [(17, 145, 115)],
    [(17, 145, 115, 1, 146, 116)], [(13, 145, 115, 6, 146, 116)],
    [(12, 151, 121, 7, 152, 122)], [(6, 151, 121, 14, 152, 122)],
    [(17, 152, 122, 4, 153, 123)], [(4, 152, 122, 18, 153, 123)],
    [(20, 147, 117, 4, 148, 118)], [(19, 148, 118, 6, 149, 119)],
    # M
    [(1, 26, 16)], [(1, 44, 28)], [(1, 70, 44)], [(2, 50, 32)],
    [(2, 67, 43)], [(4, 43, 27)], [(4, 49, 31)], [(2, 60, 38, 2, 61, 39)],
    [(3, 58, 36, 2, 59, 37)], [(4, 69, 43, 1, 70, 44)],
    [(1, 80, 50, 4, 81, 51)], [(6, 58, 36, 2, 59, 37)],
    [(8, 59, 37, 1, 60, 38)], [(4, 64, 40, 5, 65, 41)],
    [(5, 65, 41, 5, 66, 42)], [(7, 73, 45, 3, 74, 46)],
    [(10, 74, 46, 1, 75, 47)], [(9, 69, 43, 4, 70, 44)],
    [(3, 70, 44, 11, 71, 45)], [(3, 67, 41, 13, 68, 42)],
    [(17, 68, 42)], [(17, 74, 46)], [(4, 75, 47, 14, 76, 48)],
    [(6, 73, 45, 14, 74, 46)], [(8, 75, 47, 13, 76, 48)],
    [(19, 74, 46, 4, 75, 47)], [(22, 73, 45, 3, 74, 46)],
    [(3, 73, 45, 23, 74, 46)], [(21, 73, 45, 7, 74, 46)],
    [(19, 75, 47, 10, 76, 48)], [(2, 74, 46, 29, 75, 47)],
    [(10, 74, 46, 23, 75, 47)], [(14, 74, 46, 21, 75, 47)],
    [(14, 74, 46, 23, 75, 47)], [(12, 75, 47, 26, 76, 48)],
    [(6, 75, 47, 34, 76, 48)], [(29, 74, 46, 14, 75, 47)],
    [(13, 74, 46, 32, 75, 47)], [(40, 75, 47, 7, 76, 48)],
    [(18, 75, 47, 31, 76, 48)],
    # Q
    [(1, 26, 13)], [(1, 44, 22)], [(2, 35, 17)], [(2, 50, 24)],
    [(2, 33, 15, 2, 34, 16)], [(4, 43, 19)], [(2, 32, 14, 4, 33, 15)],
    [(4, 40, 18, 2, 41, 19)], [(4, 36, 16, 4, 37, 17)],
    [(6, 43, 19, 2, 44, 20)], [(4, 50, 22, 4, 51, 23)],
    [(4, 46, 20, 6, 47, 21)], [(8, 44, 20, 4, 45, 21)],
    [(11, 36, 16, 5, 37, 17)], [(5, 54, 24, 7, 55, 25)],
    [(15, 43, 19, 2, 44, 20)], [(1, 50, 22, 15, 51, 23)],
    [(17, 50, 22, 1, 51, 23)], [(17, 47, 21, 4, 48, 22)],
    [(15, 54, 24, 5, 55, 25)], [(17, 50, 22, 6, 51, 23)],
    [(7, 54, 24, 16, 55, 25)], [(11, 54, 24, 14, 55, 25)],
    [(11, 54, 24, 16, 55, 25)], [(7, 54, 24, 22, 55, 25)],
    [(28, 50, 22, 6, 51, 23)], [(8, 53, 23, 26, 54, 24)],
    [(4, 54, 24, 31, 55, 25)], [(1, 53, 23, 37, 54, 24)],
    [(15, 54, 24, 25, 55, 25)], [(42, 54, 24, 1, 55, 25)],
    [(10, 54, 24, 35, 55, 25)], [(29, 54, 24, 19, 55, 25)],
    [(44, 54, 24, 7, 55, 25)], [(39, 54, 24, 14, 55, 25)],
    [(46, 54, 24, 10, 55, 25)], [(49, 54, 24, 10, 55, 25)],
    [(48, 54, 24, 14, 55, 25)], [(43, 54, 24, 22, 55, 25)],
    [(34, 54, 24, 34, 55, 25)],
    # H
    [(1, 26, 9)], [(1, 44, 16)], [(2, 35, 13)], [(4, 25, 9)],
    [(2, 33, 11, 2, 34, 12)], [(4, 43, 15)], [(4, 39, 13, 1, 40, 14)],
    [(4, 40, 14, 2, 41, 15)], [(4, 36, 12, 4, 37, 13)],
    [(6, 43, 15, 2, 44, 16)], [(3, 36, 12, 8, 37, 13)],
    [(7, 42, 14, 4, 43, 15)], [(12, 33, 11, 4, 34, 12)],
    [(11, 36, 12, 5, 37, 13)], [(11, 36, 12, 7, 37, 13)],
    [(3, 45, 15, 13, 46, 16)], [(2, 42, 14, 17, 43, 15)],
    [(2, 42, 14, 19, 43, 15)], [(9, 39, 13, 16, 40, 14)],
    [(15, 43, 15, 10, 44, 16)], [(19, 46, 16, 6, 47, 17)],
    [(34, 37, 13)], [(16, 45, 15, 14, 46, 16)],
    [(30, 46, 16, 2, 47, 17)], [(22, 45, 15, 13, 46, 16)],
    [(33, 46, 16, 4, 47, 17)], [(12, 45, 15, 28, 46, 16)],
    [(11, 45, 15, 31, 46, 16)], [(19, 45, 15, 26, 46, 16)],
    [(23, 45, 15, 25, 46, 16)], [(23, 45, 15, 28, 46, 16)],
    [(19, 45, 15, 35, 46, 16)], [(11, 45, 15, 46, 46, 16)],
    [(59, 46, 16, 1, 47, 17)], [(22, 45, 15, 41, 46, 16)],
    [(2, 45, 15, 64, 46, 16)], [(24, 45, 15, 46, 46, 16)],
    [(42, 45, 15, 32, 46, 16)], [(10, 45, 15, 67, 46, 16)],
    [(20, 45, 15, 61, 46, 16)],
]

# 上面的表每条写成 [(n1,total1,data1), (n2,total2,data2), ...] 便于核对，
# 这里统一压平成 (n1,total1,data1,n2,total2,data2,...) 的扁平格式。
RS_BLOCK_TABLE = [tuple(v for grp in row for v in grp) for row in RS_BLOCK_TABLE]

# RS_BLOCK_TABLE 的行序是 L,M,Q,H 各 40 条连续排列，
# 而 EC 级别编号 0=M,1=L,2=H,3=Q（QR 规范里的 2 位值），这里做映射
EC_TO_TABLE_OFFSET = {1: 0, 0: 40, 3: 80, 2: 120}


def rs_blocks(version, ec):
    """返回 [(total_count, data_count)] 列表。"""
    off = EC_TO_TABLE_OFFSET[ec] + (version - 1)
    spec = RS_BLOCK_TABLE[off]
    blocks = []
    for i in range(0, len(spec), 3):
        count, total, data = spec[i], spec[i + 1], spec[i + 2]
        for _ in range(count):
            blocks.append((total, data))
    return blocks


# ---- GF(256)，QR 用的本原多项式 0x11D ----
GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


def gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError("GF 除法除数为 0")
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] - GF_LOG[b]) % 255]


def gf_inv(a):
    if a == 0:
        raise ZeroDivisionError("GF 求逆的输入为 0")
    return GF_EXP[(255 - GF_LOG[a]) % 255]


def gf_pow(a, n):
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] * n) % 255]


def gf_poly_eval(poly, x):
    """霍纳法求值。poly[0] 是最高次项系数。"""
    v = 0
    for c in poly:
        v = gf_mul(v, x) ^ c
    return v


def _poly_shift(poly, m):
    return [0] * m + list(poly)


def _poly_add(a, b):
    n = max(len(a), len(b))
    out = [0] * n
    for i, v in enumerate(a):
        out[i + n - len(a)] = v
    for i, v in enumerate(b):
        out[i + n - len(b)] ^= v
    return out


def _poly_scale(poly, s):
    return [gf_mul(c, s) for c in poly]


def _poly_trim(poly):
    i = 0
    while i < len(poly) - 1 and poly[i] == 0:
        i += 1
    return poly[i:]


# ---- 多项式约定（务必看仔细，这里最容易错） ----
#   * gf_poly_eval 的输入是「高次项在前」，即 [c_{n-1}, ..., c_1, c_0]；
#   * Berlekamp-Massey 用的是「低次项在前」的系数表，即 C[0]=1；
#   * 两者之间靠 list(reversed(...)) 转换，不要直接混用。


def berlekamp_massey(synd, ec):
    """Berlekamp-Massey：求错误定位多项式 Λ(x)。

    返回 (lam, L)。lam 是**低次项在前**的系数表，lam[0] 恒为 1；
    L 是推测的错误个数。这里用最朴素的「低次项在前 + 显式移位」写法，
    避免大小端混用——早期版本就是因为混用导致 L 恒等于 1、纠错全错。
    """
    C = [1]                     # 当前定位多项式（低次在前）
    B = [1]                     # 上一次更新前的 C
    L = 0
    m = 1
    b = 1
    for i in range(ec):
        # 偏差 d = S_i + Σ_{j=1..L} C[j] * S_{i-j}
        d = synd[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= gf_mul(C[j], synd[i - j])
        if d == 0:
            m += 1
            continue
        coef = gf_div(d, b)
        # T = C - coef * x^m * B （GF 里加减都是异或）
        shifted = [0] * m + list(B)
        if len(shifted) > len(C):
            C = C + [0] * (len(shifted) - len(C))
        newC = list(C)
        for j, v in enumerate(shifted):
            newC[j] ^= gf_mul(coef, v)
        if 2 * L <= i:
            T = list(C)
            L = i + 1 - L
            B = T
            b = d
            m = 1
            C = newC
        else:
            C = newC
            m += 1
    return C, L


def gf_solve(matrix, rhs):
    """GF(256) 上的高斯消元，解 A x = b。奇异返回 None。"""
    t = len(matrix)
    M = [list(matrix[i]) + [rhs[i]] for i in range(t)]
    for col in range(t):
        piv = None
        for r in range(col, t):
            if M[r][col]:
                piv = r
                break
        if piv is None:
            return None
        M[col], M[piv] = M[piv], M[col]
        inv = gf_inv(M[col][col])
        M[col] = [gf_mul(v, inv) for v in M[col]]
        for r in range(t):
            if r != col and M[r][col]:
                f = M[r][col]
                M[r] = [M[r][c] ^ gf_mul(f, M[col][c]) for c in range(t + 1)]
    return [M[i][t] for i in range(t)]


def rs_correct(codeword, ec_count):
    """对一个 RS 块做纠错。返回 (纠错后的码字列表, 纠正的错误数)；不可纠返回 None。"""
    n = len(codeword)
    synd = [gf_poly_eval(codeword, GF_EXP[j % 255]) for j in range(ec_count)]
    if not any(synd):
        return codeword, 0

    lam, L = berlekamp_massey(synd, ec_count)
    if L <= 0 or L * 2 > ec_count:
        return None

    # Chien 搜索：Λ(α^{-e}) == 0 说明第 e 次幂位置出错
    positions = []
    for p in range(n):
        e = (n - 1 - p) % 255
        if gf_poly_eval(list(reversed(lam)), GF_EXP[(255 - e) % 255]) == 0:
            positions.append((p, e))
    if len(positions) != L:
        return None

    # S_j = Σ err_k · Y_k^j ，Y_k = α^{e_k}，解 Vandermonde 求幅值
    Y = [GF_EXP[e % 255] for (_p, e) in positions]
    A = [[gf_pow(Y[k], j) for k in range(L)] for j in range(L)]
    rhs = synd[:L]
    errs = gf_solve(A, rhs)
    if errs is None:
        return None

    fixed = list(codeword)
    for (p, _e), val in zip(positions, errs):
        fixed[p] ^= val

    # 回代复核：综合式必须全部归零，否则说明「纠错了」
    check = [gf_poly_eval(fixed, GF_EXP[j % 255]) for j in range(ec_count)]
    if any(check):
        return None
    return fixed, L


def deinterleave(codewords, blocks):
    """按 RS 分块表把交织的码字拆回各块。返回 [块码字列表]。"""
    nblk = len(blocks)
    out = [[] for _ in range(nblk)]
    pos = 0
    dmax = max(d for (_t, d) in blocks)
    for i in range(dmax):
        for b in range(nblk):
            if i < blocks[b][1]:
                out[b].append(codewords[pos])
                pos += 1
    ec_count = blocks[0][0] - blocks[0][1]
    for i in range(ec_count):
        for b in range(nblk):
            out[b].append(codewords[pos])
            pos += 1
    return out


def concat_data_blocks(blocks_data):
    """把纠错后的各块数据码字拼回连续数据流。

    注意：这里是**按块顺序直接首尾相接**，不是再交织一次。
    QR 编码时先把数据流顺序切给各块，再交织发送；解码时拆块纠错后
    要还原成「块1 全部数据 + 块2 全部数据 + ...」才是原始数据流。
    （早期版本错误地又交织了一遍，导致所有多分块码全部解错。）
    """
    out = []
    for b in blocks_data:
        out.extend(b)
    return out


# ====================================================================
# 八、数据区提取与掩码
# ====================================================================

def mask_bit(mask, r, c):
    if mask == 0:
        return (r + c) % 2 == 0
    if mask == 1:
        return r % 2 == 0
    if mask == 2:
        return c % 3 == 0
    if mask == 3:
        return (r + c) % 3 == 0
    if mask == 4:
        return (r // 2 + c // 3) % 2 == 0
    if mask == 5:
        return ((r * c) % 2) + ((r * c) % 3) == 0
    if mask == 6:
        return (((r * c) % 2) + ((r * c) % 3)) % 2 == 0
    if mask == 7:
        return (((r + c) % 2) + ((r * c) % 3)) % 2 == 0
    raise ValueError("掩码编号非法：%d" % mask)


def extract_codewords(mods, version, mask, total_codewords):
    """按之字形顺序读数据模块，去掩码后组装成码字。"""
    n = version * 4 + 17
    func = build_function_mask(version)
    bits = []
    col = n - 1
    upward = True
    while col > 0:
        if col == 6:                    # 第 6 列是定位线，整列跳过
            col -= 1
        for i in range(n):
            r = (n - 1 - i) if upward else i
            for c in (col, col - 1):
                if c < 0 or func[r][c]:
                    continue
                v = mods[r][c]
                if mask_bit(mask, r, c):
                    v ^= 1
                bits.append(v)
        upward = not upward
        col -= 2
    need = total_codewords * 8
    bits = bits[:need]
    out = []
    for i in range(0, need, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        out.append(b)
    return out


# ====================================================================
# 九、模式解码
# ====================================================================

ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

MODE_SIZES = {
    # (模式, 版本组) -> 字符计数位数
    (1, 0): 10, (1, 1): 12, (1, 2): 14,
    (2, 0): 9, (2, 1): 11, (2, 2): 13,
    (4, 0): 8, (4, 1): 16, (4, 2): 16,
    (8, 0): 8, (8, 1): 10, (8, 2): 12,
}


class BitReader(object):
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def remaining(self):
        return len(self.data) * 8 - self.pos

    def read(self, n):
        if self.pos + n > len(self.data) * 8:
            raise ValueError("比特流不足（需要 %d 位，剩余 %d 位）"
                             % (n, self.remaining()))
        v = 0
        for _ in range(n):
            byte = self.data[self.pos >> 3]
            bit = (byte >> (7 - (self.pos & 7))) & 1
            v = (v << 1) | bit
            self.pos += 1
        return v


def _version_group(version):
    if version <= 9:
        return 0
    if version <= 26:
        return 1
    return 2


def _decode_kanji(v):
    """13 位 Kanji 值 -> Shift-JIS 两字节。"""
    v = ((v // 0xC0) << 8) | (v % 0xC0)
    if v < 0x1F00:
        v += 0x8140
    else:
        v += 0xC140
    return bytes([(v >> 8) & 0xFF, v & 0xFF])


def decode_payload(data, version):
    """把数据码字按 QR 模式逐段解出来。返回 (文本, 段信息列表, 字节串)。"""
    br = BitReader(data)
    out_bytes = bytearray()
    segments = []
    while br.remaining() >= 4:
        mode = br.read(4)
        if mode == 0:                    # 终止符
            break
        if mode == 1:                    # 数字
            cnt = br.read(MODE_SIZES[(1, _version_group(version))])
            seg = []
            while cnt >= 3:
                seg.append("%03d" % br.read(10))
                cnt -= 3
            if cnt == 2:
                seg.append("%02d" % br.read(7))
            elif cnt == 1:
                seg.append("%d" % br.read(4))
            text = "".join(seg)
            out_bytes.extend(text.encode("ascii", "replace"))
            segments.append(("numeric", text))
        elif mode == 2:                  # 字母数字
            cnt = br.read(MODE_SIZES[(2, _version_group(version))])
            seg = []
            while cnt >= 2:
                v = br.read(11)
                a, b = divmod(v, 45)
                seg.append(ALNUM[a])
                seg.append(ALNUM[b])
                cnt -= 2
            if cnt == 1:
                seg.append(ALNUM[br.read(6)])
            text = "".join(seg)
            out_bytes.extend(text.encode("ascii", "replace"))
            segments.append(("alnum", text))
        elif mode == 4:                  # 字节
            cnt = br.read(MODE_SIZES[(4, _version_group(version))])
            raw = bytearray()
            for _ in range(cnt):
                raw.append(br.read(8))
            out_bytes.extend(raw)
            segments.append(("byte", len(raw)))
        elif mode == 8:                  # Kanji
            cnt = br.read(MODE_SIZES[(8, _version_group(version))])
            raw = bytearray()
            for _ in range(cnt):
                raw.extend(_decode_kanji(br.read(13)))
            out_bytes.extend(raw)
            segments.append(("kanji", len(raw) // 2))
        elif mode == 7:                  # ECI
            first = br.read(8)
            if first & 0x80 == 0:
                eci = first & 0x7F
            elif first & 0xC0 == 0x80:
                eci = ((first & 0x3F) << 8) | br.read(8)
            else:
                eci = ((first & 0x1F) << 16) | br.read(16)
            segments.append(("eci", eci))
        elif mode == 3:                  # 结构化追加
            idx = br.read(4)
            total = br.read(4)
            br.read(8)                   # 校验位
            segments.append(("structured-append", (idx, total)))
        elif mode in (5, 9):             # FNC1
            segments.append(("fnc1", mode))
        else:
            segments.append(("unknown-mode", mode))
            break
    return out_bytes, segments


def bytes_to_text(raw):
    """按常见编码顺序尝试解码，返回 (文本, 实际使用的编码名)。"""
    for enc in ("utf-8", "gb18030", "shift-jis", "latin-1"):
        try:
            return raw.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "replace"), "latin-1(replace)"


# ====================================================================
# 十、主流程
# ====================================================================

def dump_matrix(mods):
    """把模块矩阵打成字符图：黑=##，白=两个空格。"""
    lines = []
    for row in mods:
        lines.append("".join("##" if v else "  " for v in row))
    return lines


class DecodeAbort(Exception):
    """解码中途放弃。携带已打印的诊断，交给外层决定是否换反色再试。"""

    def __init__(self, code):
        Exception.__init__(self, "decode aborted")
        self.code = code


def analyze(path, args):
    """完整分析流程。返回退出码。

    先按给定极性解一次；如果失败且用户没强制 --invert，自动换反色再解一次
    （黑底白码在 CTF 里很常见，而且「极性反了」不一定表现为「找不到定位
    图案」——也可能找到假图案后采样失败）。
    """
    width, height, gray = load_image(path)
    print("图片尺寸: %d x %d" % (width, height))

    polarities = [args.invert]
    if not args.invert:
        polarities.append(True)         # 失败时自动再试反色

    last_code = 1
    for attempt, invert in enumerate(polarities):
        if attempt > 0:
            print("")
            print("（第一次没解出来，自动换反色再试一次……）", file=sys.stderr)
        try:
            return analyze_once(gray, width, height, args, invert)
        except DecodeAbort as exc:
            last_code = exc.code
    return last_code


def analyze_once(gray, width, height, args, invert):
    """按指定极性解一次。成功返回 0，失败抛 DecodeAbort。"""
    black, thr = binarize(gray, width, height, args.threshold, invert)
    print("二值化阈值: %d%s" % (thr, "（已反色）" if invert else ""))

    cands = find_finders(black, width, height)
    if not cands:
        print("")
        print("没有找到任何定位图案（Finder Pattern）。可能原因：")
        print("  1. 图片不是二维码，或二维码被严重裁剪/模糊；")
        print("  2. 黑底白码但没有加 --invert；")
        print("  3. 阈值不合适，试试 --threshold 128；")
        print("  4. 隔行扫描 PNG 或 CMYK 等特殊格式（本脚本不支持）。")
        if args.dump:
            print("")
            print("== 二值化后的像素图（供人工核对）==")
            for row in black:
                print("".join("##" if v else "  " for v in row))
        raise DecodeAbort(1)

    print("定位图案候选: %d 个" % len(cands))
    for i, (x, y, m, hits, fit) in enumerate(cands[:6], 1):
        print("  #%d 中心 (%.1f, %.1f)  模块尺寸≈%.2f px  命中 %d 次  7x7吻合 %d/49"
              % (i, x, y, m, hits, fit))

    triple = pick_finder_triple(cands, black, width, height)
    if triple is None:
        print("")
        print("找到了定位图案，但无法凑出「模块尺寸一致 + 近似直角」的三个。")
        print("这通常意味着图片有严重透视畸变，或只拍到部分二维码。")
        print("建议：用手机扫，或用 zxing 的透视校正。")
        raise DecodeAbort(1)

    tl, tr, bl = triple
    module_est = (tl[2] + tr[2] + bl[2]) / 3.0
    version = estimate_version(tl, tr, bl, module_est)
    print("")
    print("== 结构分析 ==")
    print("左上定位点: (%.1f, %.1f)" % (tl[0], tl[1]))
    print("右上定位点: (%.1f, %.1f)" % (tr[0], tr[1]))
    print("左下定位点: (%.1f, %.1f)" % (bl[0], bl[1]))
    print("模块尺寸  : ≈%.2f 像素" % module_est)
    if version is None:
        print("版本号    : 推算失败（定位点间距与模块尺寸不匹配）")
        raise DecodeAbort(1)
    n = version * 4 + 17
    print("版本号    : %d  (模块数 %d x %d)" % (version, n, n))

    mods = sample_matrix(black, width, height, tl, tr, bl, version)
    if not validate_finders(mods, version):
        print("采样出的矩阵与标准定位图案不符（误差过大）。")
        print("可能定位点选错了，或图片畸变超出本脚本能力。")
        if args.dump:
            print("")
            for line in dump_matrix(mods):
                print(line)
        raise DecodeAbort(1)

    ec, mask, fdist = read_format(mods, version)
    if ec is None or fdist > 3:
        print("格式信息   : 读取失败（最近候选距离 %d，超过可纠范围 3）" % fdist)
        print("这通常说明采样有错位，解码无法继续。")
        raise DecodeAbort(1)
    print("纠错级别  : %s  (格式信息汉明距离 %d)" % (EC_NAME[ec], fdist))
    print("掩码编号  : %d" % mask)

    if version >= 7:
        vi = read_version_info(mods, version)
        if vi is None:
            print("版本信息  : 校验失败（与推算的版本 %d 不符）" % version)
        else:
            print("版本信息  : 校验通过（%d）" % vi)

    blocks = rs_blocks(version, ec)
    total_cw = sum(t for (t, _d) in blocks)
    print("RS 分块   : %d 块，共 %d 码字，每块纠错码字 %d 个"
          % (len(blocks), total_cw, blocks[0][0] - blocks[0][1]))

    codewords = extract_codewords(mods, version, mask, total_cw)
    if len(codewords) != total_cw:
        print("码字提取不完整（%d/%d），采样有问题。" % (len(codewords), total_cw))
        raise DecodeAbort(1)

    if args.dump:
        print("")
        print("== 二值化模块矩阵（黑=##，白=空格）==")
        for line in dump_matrix(mods):
            print(line)
        print("")

    if args.hex:
        print("")
        print("== 去掩码后的原始码字（hex）==")
        print(" ".join("%02X" % b for b in codewords))

    # ---- 分块 + 纠错 ----
    chunks = deinterleave(codewords, blocks)
    total_fixed = 0
    data_blocks = []
    ok = True
    for i, chunk in enumerate(chunks):
        ec_count = blocks[i][0] - blocks[i][1]
        res = rs_correct(chunk, ec_count)
        if res is None:
            print("第 %d 块 RS 纠错失败（错误数超过该块纠错能力 %d）"
                  % (i + 1, ec_count // 2))
            ok = False
            data_blocks.append(chunk[:blocks[i][1]])
        else:
            fixed, nerr = res
            total_fixed += nerr
            data_blocks.append(fixed[:blocks[i][1]])

    if not ok:
        print("")
        print("纠错没能完全修复，下面的内容可能是错的（或解不出来）。")

    data_stream = concat_data_blocks(data_blocks)
    raw, segments = decode_payload(data_stream, version)

    print("")
    print("== 解码结果 ==")
    if total_fixed:
        print("纠正错误  : %d 个码字" % total_fixed)
    print("数据段    : %s" % ", ".join(
        "%s(%s)" % (name, val) for name, val in segments) or "（空）")

    if not raw:
        print("内容      : （空，只有填充码字）")
        return 0

    text, enc = bytes_to_text(raw)
    print("字节长度  : %d" % len(raw))
    print("内容编码  : %s" % enc)
    print("内容      :")
    print(text)

    if not ok:
        return 2
    return 0


USAGE = """\
qrcode.py -- 纯标准库二维码解码器（不依赖 zbar / opencv / pyzbar）

做什么：把 PNG/BMP 里的 QR 码解成文本。自己实现 PNG 解码、二值化、
        定位图案检测、格式信息 BCH 解析、之字形数据提取、
        Reed-Solomon 纠错（Berlekamp-Massey + Chien + Forney 思路）、
        数字/字母数字/字节/Kanji 模式解码。

用法：
    python -X utf8 qrcode.py 码.png
    python -X utf8 qrcode.py 码.png --dump           打印二值化模块矩阵
    python -X utf8 qrcode.py 码.bmp --invert         黑底白码
    python -X utf8 qrcode.py 码.png --threshold 128  手动阈值
    python -X utf8 qrcode.py 码.png --hex            打印原始码字

参数：
    file               PNG（非隔行）或 BMP 图片
    --dump             把二值化后的模块矩阵打成字符图（黑=##，白=空格）
    --invert           强制反色（黑底白码时用；不加也会自动试一次）
    --threshold N      手动指定二值化阈值 0-255
    --hex              打印去掩码后的原始数据码字

已知限制：
    * 只支持非隔行 PNG 与 BI_RGB 的 BMP；
    * 透视畸变过大 / 严重模糊 / 只拍到部分码时检测会失败；
    * 不支持 Micro QR、不支持多码合并（结构化追加只打印序号）。

解不出来时，脚本会打印「结构分析」（版本/纠错级别/掩码/定位点坐标）
并明确说明没解出内容 —— 不会假装成功。完整内容解码建议用手机或 zxing。
"""


def main():
    ap = argparse.ArgumentParser(add_help=True, description="纯标准库二维码解码器")
    ap.add_argument("file", nargs="?", help="PNG 或 BMP 图片路径")
    ap.add_argument("--dump", action="store_true", help="打印二值化模块矩阵")
    ap.add_argument("--invert", action="store_true", help="强制反色（黑底白码）")
    ap.add_argument("--threshold", type=int, default=None, help="手动二值化阈值 0-255")
    ap.add_argument("--hex", action="store_true", help="打印原始数据码字")
    args = ap.parse_args()

    if not args.file:
        print(USAGE)
        return 0

    if args.threshold is not None and not (0 <= args.threshold <= 255):
        print("错误：--threshold 必须在 0-255 之间。", file=sys.stderr)
        return 1

    try:
        return analyze(args.file, args)
    except FileNotFoundError:
        print("错误：文件不存在 —— %s" % args.file, file=sys.stderr)
        return 1
    except IsADirectoryError:
        print("错误：%s 是一个目录，不是图片文件。" % args.file, file=sys.stderr)
        return 1
    except PermissionError:
        print("错误：没有权限读取 %s" % args.file, file=sys.stderr)
        return 1
    except ValueError as exc:
        print("错误：%s" % exc, file=sys.stderr)
        return 1
    except (OSError, struct.error, zlib.error) as exc:
        print("错误：读取图片失败 —— %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
