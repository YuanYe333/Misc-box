# -*- coding: utf-8 -*-
"""
audiospec.py -- WAV 波形图 / 频谱图：把声音画成能「看见字」的图。

为什么需要
==========
CTF 里「频谱藏字」是固定题型：把一段文字用音频编辑器写进高频区，
听不出任何异常，但一看频谱图就有明显的笔画。手工要装 Audacity / Sonic
Visualizer，本脚本纯标准库就能出图，拷到哪都能跑。

本脚本：
  1. 自己解析 RIFF/WAVE 头，支持 PCM 8/16/24/32bit、单/双声道；
  2. 画波形图（看包络、找断续、看静音段）；
  3. 画频谱图（短时傅里叶变换 + 对数幅度 + 伪彩色），藏的字会浮出来；
  4. 支持截取时间段、指定输出尺寸。

FFT 是自己实现的基 2 迭代 Cooley-Tukey。标准库没有 FFT，直接 DFT 在
4096 点 × 上千帧的量级上会慢到不可用（O(n²)），所以必须上 FFT。

用法
====
    python -X utf8 audiospec.py 题目.wav
    python -X utf8 audiospec.py 题目.wav --spec -o 频谱.png
    python -X utf8 audiospec.py 题目.wav --wave -o 波形.png
    python -X utf8 audiospec.py 题目.wav --spec --start 2.5 --end 4.0
    python -X utf8 audiospec.py 题目.wav --channel L --spec --width 1200 --height 600

已知限制
========
    * 只支持 WAV（PCM / IEEE float32）。MP3/FLAC/OGG 请先转 WAV。
    * 频谱是 STFT 幅度谱，不是「专业声谱仪」；窗函数只有 Hann。
    * 纯 Python 逐样本处理，10 分钟以上的音频会明显慢（会提示）。
    * 伪彩色是手写的三段渐变，不追求色准，只求对比度够看字。
"""

import argparse
import math
import struct
import sys
import zlib
from pathlib import Path

PNG_SIG = b"\x89PNG\r\n\x1a\n"


class AudioError(Exception):
    """给用户看的错误。"""


# ==================================================================== PNG 输出

def _png_chunk(typ, body):
    return (struct.pack(">I", len(body)) + typ + body
            + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))


def write_png(path, width, height, pixels, mode="rgba"):
    """纯 zlib 手写 PNG，所有行用过滤类型 0（兼容性最好）。"""
    if mode == "gray":
        ctype, nch = 0, 1
    elif mode == "rgb":
        ctype, nch = 2, 3
    elif mode == "rgba":
        ctype, nch = 6, 4
    else:
        raise AudioError("内部错误：未知输出模式 %r" % mode)
    stride = width * nch
    if len(pixels) != stride * height:
        raise AudioError("内部错误：像素缓冲区 %d 与 %dx%d 不符"
                         % (len(pixels), width, height))
    raw = bytearray((stride + 1) * height)
    for y in range(height):
        src = y * stride
        dst = y * (stride + 1)
        raw[dst] = 0
        raw[dst + 1:dst + 1 + stride] = pixels[src:src + stride]
    ihdr = struct.pack(">IIBBBBB", width, height, 8, ctype, 0, 0, 0)
    blob = (PNG_SIG + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + _png_chunk(b"IEND", b""))
    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(blob)
    return len(blob)


# ==================================================================== WAV 解析

WAVE_FORMAT_PCM = 1
WAVE_FORMAT_IEEE_FLOAT = 3
WAVE_FORMAT_EXTENSIBLE = 0xFFFE


class Wav(object):
    def __init__(self):
        self.rate = 0
        self.channels = 0
        self.bits = 0
        self.fmt = 0
        self.samples = []      # list[list[float]]，每声道一个列表，值域 -1..1
        self.frames = 0
        self.duration = 0.0

    def describe(self):
        fmt_name = {1: "PCM", 3: "IEEE float", 0xFFFE: "Extensible"}.get(
            self.fmt, "format%d" % self.fmt)
        return "%d Hz / %d ch / %d bit / %s / %.3f 秒" % (
            self.rate, self.channels, self.bits, fmt_name, self.duration)


def _parse_fmt(body, wav):
    if len(body) < 16:
        raise AudioError("fmt 块太小（%d 字节）" % len(body))
    (fmt, ch, rate, _byterate, _blockalign,
     bits) = struct.unpack("<HHIIHH", body[:16])
    wav.fmt = fmt
    wav.channels = ch
    wav.rate = rate
    wav.bits = bits
    if fmt == WAVE_FORMAT_EXTENSIBLE:
        if len(body) < 40:
            raise AudioError("WAVE_FORMAT_EXTENSIBLE 的 fmt 块不足 40 字节")
        # 真正格式在 SubFormat GUID 的头两个字节
        sub = struct.unpack("<H", body[24:26])[0]
        wav.fmt = sub
    if wav.channels <= 0 or wav.channels > 32:
        raise AudioError("声道数非法：%d" % wav.channels)
    if wav.rate <= 0:
        raise AudioError("采样率非法：%d" % wav.rate)
    if wav.fmt not in (WAVE_FORMAT_PCM, WAVE_FORMAT_IEEE_FLOAT):
        raise AudioError("只支持 PCM / IEEE float32，当前格式码 %d" % wav.fmt)
    if wav.bits not in (8, 16, 24, 32):
        raise AudioError("只支持 8/16/24/32 bit，当前 %d bit" % wav.bits)


def _decode_pcm(raw, wav):
    """把交织的 PCM 数据拆成每声道一个 float 列表（-1..1）。"""
    ch = wav.channels
    bits = wav.bits
    n = len(raw) // (bits // 8) // ch
    wav.frames = n
    if n == 0:
        raise AudioError("data 块里没有完整采样帧")
    chans = [[] for _ in range(ch)]

    if bits == 8:
        # 8-bit WAV 是无符号，128 是零点
        for i in range(n):
            base = i * ch
            for c in range(ch):
                chans[c].append((raw[base + c] - 128) / 128.0)
    elif bits == 16:
        for i in range(n):
            base = i * ch * 2
            for c in range(ch):
                v = struct.unpack_from("<h", raw, base + c * 2)[0]
                chans[c].append(v / 32768.0)
    elif bits == 24:
        for i in range(n):
            base = i * ch * 3
            for c in range(ch):
                o = base + c * 3
                v = raw[o] | (raw[o + 1] << 8) | (raw[o + 2] << 16)
                if v & 0x800000:
                    v -= 0x1000000
                chans[c].append(v / 8388608.0)
    else:
        if wav.fmt == WAVE_FORMAT_IEEE_FLOAT:
            for i in range(n):
                base = i * ch * 4
                for c in range(ch):
                    v = struct.unpack_from("<f", raw, base + c * 4)[0]
                    if v != v or v in (float("inf"), float("-inf")):
                        v = 0.0
                    chans[c].append(max(-1.0, min(1.0, v)))
        else:
            for i in range(n):
                base = i * ch * 4
                for c in range(ch):
                    v = struct.unpack_from("<i", raw, base + c * 4)[0]
                    chans[c].append(v / 2147483648.0)
    wav.samples = chans
    wav.duration = n / float(wav.rate)


def load_wav(path):
    p = Path(path)
    if not p.exists():
        raise AudioError("文件不存在：%s" % p)
    if not p.is_file():
        raise AudioError("不是普通文件：%s" % p)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise AudioError("读取失败：%s" % exc)
    if len(data) < 12:
        raise AudioError("文件太小（%d 字节），不是 WAV" % len(data))
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise AudioError("不是 WAV（RIFF/WAVE 签名不匹配，开头是 %s）"
                         % data[:12].hex())
    riff_size = struct.unpack("<I", data[4:8])[0]

    wav = Wav()
    pos = 12
    n = len(data)
    fmt_body = None
    data_body = None
    while pos + 8 <= n:
        cid = data[pos:pos + 4]
        clen = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        body = data[pos + 8:pos + 8 + clen]
        if len(body) != clen:
            # 截断的块：data 块经常被截断，尽力而为
            if cid == b"data":
                body = data[pos + 8:]
                print("提示: data 块声明 %d 字节，实际只有 %d 字节（按实际处理）"
                      % (clen, len(body)), file=sys.stderr)
            else:
                print("提示: 块 %s 被截断，跳过"
                      % cid.decode("latin-1", "replace"), file=sys.stderr)
                break
        if cid == b"fmt " and fmt_body is None:
            fmt_body = body
        elif cid == b"data" and data_body is None:
            data_body = body
        pos += 8 + clen
        if clen % 2:
            pos += 1                     # RIFF 块 2 字节对齐
        if fmt_body is not None and data_body is not None:
            break

    if fmt_body is None:
        raise AudioError("WAV 缺少 fmt 块（可能文件被截断或不是标准 WAV）")
    if data_body is None:
        raise AudioError("WAV 缺少 data 块")
    _parse_fmt(fmt_body, wav)
    _decode_pcm(data_body, wav)
    if riff_size + 8 != len(data):
        print("提示: RIFF 声明大小 %d，实际文件 %d 字节（差 %d，"
              "尾部可能有附加数据）"
              % (riff_size + 8, len(data), len(data) - riff_size - 8),
              file=sys.stderr)
    return wav


# ==================================================================== FFT

def _next_pow2(n):
    p = 1
    while p < n:
        p <<= 1
    return p


def fft(re, im):
    """基 2 迭代 Cooley-Tukey FFT，原地修改。

    为什么用迭代而不是递归：递归版本每层都要新建列表，4096 点 × 上千帧
    会产生大量小对象，纯 Python 下慢得离谱。迭代版只做位反转 + 三层循环，
    常数小得多。

    要求 len 是 2 的幂；不是的话先补零到 2 的幂（调用方负责）。
    """
    n = len(re)
    if n & (n - 1):
        raise AudioError("FFT 长度必须是 2 的幂，收到 %d" % n)
    if n <= 1:
        return
    # 位反转置换
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j |= bit
        if i < j:
            re[i], re[j] = re[j], re[i]
            im[i], im[j] = im[j], im[i]
    # 蝶形
    length = 2
    while length <= n:
        ang = -2.0 * math.pi / length
        wr = math.cos(ang)
        wi = math.sin(ang)
        half = length >> 1
        for i in range(0, n, length):
            cur_r = 1.0
            cur_i = 0.0
            for k in range(half):
                a = i + k
                b = a + half
                tr = re[b] * cur_r - im[b] * cur_i
                ti = re[b] * cur_i + im[b] * cur_r
                re[b] = re[a] - tr
                im[b] = im[a] - ti
                re[a] += tr
                im[a] += ti
                # 递推旋转因子（比每步算 cos/sin 快很多）
                nr = cur_r * wr - cur_i * wi
                cur_i = cur_r * wi + cur_i * wr
                cur_r = nr
        length <<= 1


def hann_window(n):
    """Hann 窗，减少频谱泄漏（否则强信号会把邻近频点糊掉）。"""
    return [0.5 - 0.5 * math.cos(2.0 * math.pi * i / (n - 1)) for i in range(n)]


# ==================================================================== 频谱

def stft(samples, n_fft, hop, window):
    """返回每帧的幅度谱（已取前 n_fft/2 个 bin）。"""
    frames = []
    n = len(samples)
    if n < n_fft:
        # 样本不够一帧：补零，至少出一帧
        samples = samples + [0.0] * (n_fft - n)
        n = n_fft
    pos = 0
    half = n_fft // 2
    while pos + n_fft <= n:
        re = [samples[pos + i] * window[i] for i in range(n_fft)]
        im = [0.0] * n_fft
        fft(re, im)
        mags = []
        for k in range(half + 1):
            mags.append(math.hypot(re[k], im[k]))
        frames.append(mags)
        pos += hop
        if pos + n_fft > n:
            break
    return frames


def color_map(v):
    """0..1 -> (r,g,b)。三段渐变：黑 -> 蓝 -> 绿 -> 黄 -> 白。

    为什么不用简单灰度：频谱里强弱动态范围很大，灰度高段容易一片白，
    分层着色能把「字」的边缘和背景区分开。
    """
    if v < 0.0:
        v = 0.0
    elif v > 1.0:
        v = 1.0
    # 段边界
    stops = ((0.00, (0, 0, 0)),
             (0.22, (16, 24, 128)),
             (0.45, (0, 180, 200)),
             (0.68, (60, 220, 60)),
             (0.85, (240, 230, 40)),
             (1.00, (255, 255, 255)))
    for i in range(1, len(stops)):
        v0, c0 = stops[i - 1]
        v1, c1 = stops[i]
        if v <= v1 or i == len(stops) - 1:
            if v1 - v0 <= 1e-9:
                return c1
            t = (v - v0) / (v1 - v0)
            if t < 0:
                t = 0.0
            return (int(c0[0] + (c1[0] - c0[0]) * t),
                    int(c0[1] + (c1[1] - c0[1]) * t),
                    int(c0[2] + (c1[2] - c0[2]) * t))
    return (255, 255, 255)


def render_spectrogram(wav, args):
    chans = pick_channels(wav, args.channel)
    sig = chans[0]
    if len(chans) > 1:
        # 双声道叠加（取平均），这样左右声道各藏一半时也能同时看到
        n = min(len(c) for c in chans)
        sig = [(chans[0][i] + chans[1][i]) * 0.5 for i in range(n)]

    start, end = clamp_range(wav, args.start, args.end)
    s0 = int(start * wav.rate)
    s1 = int(end * wav.rate)
    sig = sig[s0:s1]
    if len(sig) < 64:
        raise AudioError("截取出来的样本太少（%d 个），选的时间段太短了"
                         % len(sig))

    n_fft = args.n_fft
    if n_fft < 32:
        raise AudioError("--n-fft 至少 32")
    n_fft = _next_pow2(n_fft)
    hop = max(1, n_fft // 4)
    window = hann_window(n_fft)

    nframes_est = max(1, (len(sig) - n_fft) // hop + 1)
    print("  截取: %.3f - %.3f 秒（%d 个样本）" % (start, end, len(sig)))
    print("  STFT: n_fft=%d hop=%d 预计 %d 帧" % (n_fft, hop, nframes_est))
    if nframes_est > 6000:
        print("  提示: 帧数很多，纯 Python 可能要几十秒", file=sys.stderr)

    frames = stft(sig, n_fft, hop, window)
    if not frames:
        raise AudioError("STFT 没有产生任何帧（样本太短？）")
    nbin = len(frames[0])

    # 频率轴裁剪：CTF 藏字常常只占一段高频，全谱显示会把它压成一条细线。
    # bin 的索引就是 f = k * rate / n_fft，所以直接按 Hz 换算出下标。
    nyq = wav.rate / 2.0
    f_lo = 0.0 if args.fmin is None else max(0.0, args.fmin)
    f_hi = nyq if args.fmax is None else min(nyq, args.fmax)
    if f_hi <= f_lo:
        raise AudioError("频率范围非法：--fmin %.0f 不小于 --fmax %.0f"
                         % (f_lo, f_hi))
    k0 = int(f_lo / nyq * (nbin - 1))
    k1 = int(f_hi / nyq * (nbin - 1))
    if k1 <= k0:
        raise AudioError("频率范围太窄（换算后只有 1 个 bin），请放宽 --fmin/--fmax")
    if f_lo > 0 or f_hi < nyq:
        print("  频率裁剪: %.0f - %.0f Hz（bin %d..%d）" % (f_lo, f_hi, k0, k1))

    # 幅度归一化：先转 dB，再按全局最大值拉满。
    # 用 dB 是因为音频动态范围大，线性幅度下弱信号（藏的字）会被背景压没。
    eps = 1e-12
    db_frames = []
    peak = eps
    for mags in frames:
        row = []
        for m in mags[k0:k1 + 1]:
            v = 20.0 * math.log10(m + eps)
            row.append(v)
            if v > peak:
                peak = v
        db_frames.append(row)
    floor = peak - args.range_db
    nbin = k1 - k0 + 1

    # 时间轴重采样到输出宽度，频率轴重采样到输出高度
    out_w = max(16, args.width)
    out_h = max(16, args.height)
    nframes = len(db_frames)
    pixels = bytearray(out_w * out_h * 3)

    # 频率轴：第 0 行是最高频（图像习惯上高音在上）
    for yy in range(out_h):
        # yy=0 -> 最高 bin
        fbin_f = (1.0 - (yy + 0.5) / out_h) * (nbin - 1)
        f0 = int(fbin_f)
        f1 = min(nbin - 1, f0 + 1)
        fw = fbin_f - f0
        for xx in range(out_w):
            tbin_f = (xx + 0.5) / out_w * (nframes - 1)
            t0 = int(tbin_f)
            t1 = min(nframes - 1, t0 + 1)
            tw = tbin_f - t0
            # 双线性插值，避免缩放后出现锯齿状「阶梯」
            v00 = db_frames[t0][f0]
            v01 = db_frames[t0][f1]
            v10 = db_frames[t1][f0]
            v11 = db_frames[t1][f1]
            v = (v00 * (1 - tw) * (1 - fw) + v10 * tw * (1 - fw)
                 + v01 * (1 - tw) * fw + v11 * tw * fw)
            t = (v - floor) / (peak - floor) if peak > floor else 0.0
            # 加个 gamma 让弱信号更明显（藏的字通常比主信号弱很多）
            if t < 0:
                t = 0.0
            t = t ** args.gamma
            r, g, b = color_map(t)
            o = (yy * out_w + xx) * 3
            pixels[o] = r
            pixels[o + 1] = g
            pixels[o + 2] = b

    return pixels, out_w, out_h, nframes, nbin, f_lo, f_hi


# ==================================================================== 波形

def render_waveform(wav, args):
    chans = pick_channels(wav, args.channel)
    start, end = clamp_range(wav, args.start, args.end)
    s0 = int(start * wav.rate)
    s1 = int(end * wav.rate)
    out_w = max(16, args.width)
    out_h = max(16, args.height)

    pixels = bytearray(out_w * out_h * 3)
    # 背景淡蓝灰，中间零线画深色，波形用亮绿
    for i in range(out_w * out_h):
        pixels[i * 3] = 18
        pixels[i * 3 + 1] = 20
        pixels[i * 3 + 2] = 26
    mid = out_h // 2
    for xx in range(out_w):
        o = (mid * out_w + xx) * 3
        pixels[o] = 70
        pixels[o + 1] = 70
        pixels[o + 2] = 80

    total = max(1, s1 - s0)
    # 每列取该列覆盖样本区间的 min/max，画成竖线 —— 这是示波器软件的标准做法，
    # 比只采样一个点更能体现包络（找静音段/断续非常有用）。
    colors = ((80, 220, 120), (255, 200, 80))   # 单声道绿，双声道第二路黄
    for ci, sig in enumerate(chans[:2]):
        for xx in range(out_w):
            a = s0 + int(total * xx / float(out_w))
            b = s0 + int(total * (xx + 1) / float(out_w))
            if b <= a:
                b = a + 1
            lo = 1e9
            hi = -1e9
            # 区间太大时抽样，否则纯 Python 会慢
            step = max(1, (b - a) // 512)
            for i in range(a, min(b, len(sig)), step):
                v = sig[i]
                if v < lo:
                    lo = v
                if v > hi:
                    hi = v
            if lo > hi:
                continue
            y0 = int(mid - hi * mid * 0.95)
            y1 = int(mid - lo * mid * 0.95)
            if y1 < y0:
                y0, y1 = y1, y0
            if y0 < 0:
                y0 = 0
            if y1 >= out_h:
                y1 = out_h - 1
            r, g, bb = colors[ci % 2]
            for yy in range(y0, y1 + 1):
                o = (yy * out_w + xx) * 3
                pixels[o] = r
                pixels[o + 1] = g
                pixels[o + 2] = bb
    return pixels, out_w, out_h


# ==================================================================== 公共

def pick_channels(wav, which):
    if which == "both":
        return wav.samples
    if which == "L":
        if len(wav.samples) < 1:
            raise AudioError("没有可用的声道")
        return [wav.samples[0]]
    if which == "R":
        if len(wav.samples) < 2:
            if len(wav.samples) == 1:
                raise AudioError("这是单声道 WAV，没有右声道；用 --channel L")
            raise AudioError("没有可用的右声道")
        return [wav.samples[1]]
    raise AudioError("--channel 只能是 L/R/both，收到 %r" % which)


def clamp_range(wav, start, end):
    total = wav.duration
    if total <= 0:
        raise AudioError("音频时长为 0")
    s = 0.0 if start is None else float(start)
    e = total if end is None else float(end)
    if s < 0:
        s = 0.0
    if e > total:
        e = total
    if e <= s:
        raise AudioError("时间段非法：start=%.3f 不小于 end=%.3f（总长 %.3f 秒）"
                         % (s, e, total))
    return s, e


USAGE = """audiospec.py -- WAV 波形图 / 频谱图：把声音画成能看见字的图

做什么
  CTF 的「频谱藏字」题，答案就在频谱图上。本脚本纯标准库出图，
  不用装 Audacity，也不用 numpy。自带基 2 迭代 FFT。

用法
  python -X utf8 audiospec.py 题目.wav
        默认同时出波形图和频谱图（文件名自动加 _wave / _spec）

  python -X utf8 audiospec.py 题目.wav --spec -o 频谱.png
        只出频谱图

  python -X utf8 audiospec.py 题目.wav --wave -o 波形.png
        只出波形图（找静音段/断续）

  python -X utf8 audiospec.py 题目.wav --spec --start 2.5 --end 4.0
        只看 2.5-4.0 秒这一段（藏字常在某个片段里）

  python -X utf8 audiospec.py 题目.wav --spec --channel R --width 1400 --height 700
        只看右声道，输出大图（字小的时候要放大）

参数
  --spec / --wave         只出频谱 / 只出波形（都不给 = 两个都出）
  -o, --output            输出文件名（两个都出时自动加后缀）
  --channel L|R|both      声道（默认 both，双声道会叠加）
  --start / --end         截取时间段（秒）
  --width / --height      输出尺寸（默认 1000x400 波形 / 1000x500 频谱）
  --n-fft N               STFT 窗长（默认 2048，会向上取到 2 的幂）
  --range-db N            显示多少 dB 动态范围（默认 90，调小更能突出弱信号）
  --gamma X               亮度 gamma（默认 0.7，小于 1 会把弱信号提亮）
  --fmin / --fmax Hz      只显示这一段频率（藏字常在高频，裁掉低频更清楚）
  --force                 允许覆盖已存在文件

已知限制
  只支持 WAV（PCM 8/16/24/32bit、IEEE float32）。MP3/FLAC 请先转 WAV。
  频谱是 STFT 幅度谱（Hann 窗），不是专业声谱仪。
  纯 Python 逐样本处理，长音频慢；帧数过多会提示。
"""


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(USAGE)
        return 0
    ap = argparse.ArgumentParser(prog="audiospec.py", add_help=True,
                                 description="WAV 波形图 / 频谱图")
    ap.add_argument("wav", nargs="?", help="输入 WAV")
    ap.add_argument("--spec", action="store_true", help="只出频谱图")
    ap.add_argument("--wave", action="store_true", help="只出波形图")
    ap.add_argument("-o", "--output", help="输出文件名")
    ap.add_argument("--channel", choices=["L", "R", "both"], default="both",
                    help="声道（默认 both）")
    ap.add_argument("--start", type=float, help="起始秒")
    ap.add_argument("--end", type=float, help="结束秒")
    ap.add_argument("--width", type=int, default=0, help="输出宽度")
    ap.add_argument("--height", type=int, default=0, help="输出高度")
    ap.add_argument("--n-fft", type=int, default=2048, dest="n_fft",
                    help="STFT 窗长（默认 2048）")
    ap.add_argument("--range-db", type=float, default=90.0, dest="range_db",
                    help="动态范围 dB（默认 90）")
    ap.add_argument("--fmin", type=float, help="只显示高于此频率的部分（Hz）")
    ap.add_argument("--fmax", type=float, help="只显示低于此频率的部分（Hz）")
    ap.add_argument("--gamma", type=float, default=0.7, help="亮度 gamma（默认 0.7）")
    ap.add_argument("--force", action="store_true", help="允许覆盖")
    args = ap.parse_args(argv)

    if not args.wav:
        print(USAGE)
        return 0
    if args.n_fft < 32:
        print("错误: --n-fft 至少 32", file=sys.stderr)
        return 2
    if args.range_db <= 0:
        print("错误: --range-db 必须为正", file=sys.stderr)
        return 2
    if args.gamma <= 0:
        print("错误: --gamma 必须为正", file=sys.stderr)
        return 2

    try:
        wav = load_wav(args.wav)
        print("=" * 60)
        print("音频: %s" % Path(args.wav).name)
        print("格式: %s" % wav.describe())
        if wav.duration > 600:
            print("提示: 音频超过 10 分钟，纯 Python 处理会很慢，"
                  "建议先用 --start/--end 截一段", file=sys.stderr)
        print("")

        do_spec = args.spec or not args.wave
        do_wave = args.wave or not args.spec
        base = Path(args.wav)
        written = []
        # 记住用户给的原始尺寸：两种图默认尺寸不同（波形 400 高、频谱 500 高），
        # 如果不先存下来，先跑的波形会把 args 改掉，频谱就会继承波形的尺寸。
        orig_w, orig_h = args.width, args.height

        if do_wave:
            args.width = orig_w if orig_w else 1000
            args.height = orig_h if orig_h else 400
            print("== 波形图 ==")
            pix, ow, oh = render_waveform(wav, args)
            if args.output and not do_spec:
                out = Path(args.output)
            elif args.output:
                out = Path(args.output)
                out = out.with_name(out.stem + "_wave" + out.suffix)
            else:
                out = base.with_name(base.stem + "_wave.png")
            if out.exists() and not args.force:
                raise AudioError("目标文件已存在：%s（要覆盖请加 --force）" % out)
            size = write_png(out, ow, oh, bytes(pix), "rgb")
            written.append((out, ow, oh, size))
            print("  已生成: %s (%dx%d, %d 字节)" % (out, ow, oh, size))
            print("")

        if do_spec:
            args.width = orig_w if orig_w else 1000
            args.height = orig_h if orig_h else 500
            print("== 频谱图 ==")
            pix, ow, oh, nframes, nbin, f_lo, f_hi = render_spectrogram(wav, args)
            if args.output and not do_wave:
                out = Path(args.output)
            elif args.output:
                out = Path(args.output)
                out = out.with_name(out.stem + "_spec" + out.suffix)
            else:
                out = base.with_name(base.stem + "_spec.png")
            if out.exists() and not args.force:
                raise AudioError("目标文件已存在：%s（要覆盖请加 --force）" % out)
            size = write_png(out, ow, oh, bytes(pix), "rgb")
            written.append((out, ow, oh, size))
            print("  已生成: %s (%dx%d, %d 字节)" % (out, ow, oh, size))
            print("  频率轴: 顶=%.0f Hz  底=%.0f Hz  (%d 个 bin)"
                  % (f_hi, f_lo, nbin))
            print("")

        if written:
            print("== 完成 ==")
            for out, ow, oh, size in written:
                print("  %s  (%dx%d)" % (out, ow, oh))
            print("")
            print("看图提示: 频谱里出现规则笔画 = 藏字；波形出现整齐的断续 = 藏数据。")
        return 0
    except AudioError as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 1
    except OSError as exc:
        print("错误: 文件操作失败：%s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        # 兜底：宁可给一句人话，也不要甩 traceback 吓人。
        # 需要排查时用 DSH_STEGO_DEBUG=1 打开完整堆栈。
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
