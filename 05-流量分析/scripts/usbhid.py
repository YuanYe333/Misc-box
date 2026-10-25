# -*- coding: utf-8 -*-
"""
usbhid.py -- 从 pcap 里还原 USB 键盘输入和鼠标轨迹（CTF 高频题型）。

为什么需要
==========
「USB 流量」题几乎必考：给一个抓了 USB 总线的 pcap，要求还原出键盘敲的
字符（flag）或鼠标画出来的轨迹。手工做法是在 Wireshark 里过滤
`usb.transfer_type==0x01`，把 `usb.capdata` 一列列抄出来查 HID 表——
几十个包还行，几百个包就疯了，而且容易抄错一位。

本脚本自己解 usbmon / USBPcap 的记录结构，取出 HID 中断传输的报告，
用状态机还原按键（含 Shift/Ctrl 组合），并把鼠标轨迹画成 PNG。

能做什么
========
  * 识别三种链路类型：LINKTYPE_USB_LINUX(189)、LINKTYPE_USB_LINUX_MMAPPED(220)、
    LINKTYPE_USBPCAP(249)，外加 191（部分工具标成 USB_LINUX 的变体）。
    实际格式按内容自动判断，不迷信链路类型字段。
  * usbmon：解析 48 / 64 字节的 mon_bin_hdr（id / type / xfer_type / epnum /
    devnum / busnum / flag_setup / status / len_urb / len_cap）。
  * USBPcap：解析 27 字节起的 USBPcapPacketHeader（headerLen 决定数据偏移）。
  * 键盘：8 字节 HID 报告（修饰键 + 保留 + 6 键码），维护按键状态，
    只在「新按下的键」出字符；Shift 出大写与符号，Ctrl 出控制字符。
  * 鼠标：3/4 字节报告（按键 + dx + dy + 滚轮），累加还原轨迹，
    可用纯 zlib 手写 PNG 输出轨迹图。
  * --keyboard / --mouse / --all 选择模式；--raw 打印原始报告便于对照。

用法
====
    python -X utf8 usbhid.py 题目.pcap
    python -X utf8 usbhid.py 题目.pcap --keyboard
    python -X utf8 usbhid.py 题目.pcap --mouse -o 轨迹.png
    python -X utf8 usbhid.py 题目.pcap --all --raw

已知限制
========
  * 只处理「中断传输」（transfer_type=1）的 HID 报告。控制传输里的
    GET_REPORT / SET_REPORT 不解析。
  * 键盘报告按标准 8 字节 boot 协议解。若设备是 6 字节报告（无保留字节）
    或 NKRO 位图报告，本脚本会给出警告而不是硬猜。
  * **不处理丢包**。如果抓包漏掉了「松手」报告，连打同一个字母
    （如 flag 里的 ll）可能只出一个字符——这是数据缺失，不是解码错误。
  * 不还原键盘的「按住重复」（autorepeat），那是操作系统行为，报文里没有。
  * 鼠标只还原相对位移轨迹；绝对坐标设备（触摸板/数位板）解不出来。
  * 不做 USB 存储（U盘）的文件提取，那是另一类脚本的活。
"""

import argparse
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from pcapcarve import PcapError, read_packets, safe_setup
except ImportError:                                     # pragma: no cover
    sys.stderr.write("错误：找不到同目录的 pcapcarve.py（复用它的 pcap 读取）\n")
    raise SystemExit(1)

# ---------------------------------------------------------------- 链路类型

LINKTYPE_USB_LINUX = 189
LINKTYPE_USB_LINUX_MMAPPED = 220
LINKTYPE_USBPCAP = 249
LINKTYPE_USB_LINUX_ALT = 191
USB_LINKTYPES = (LINKTYPE_USB_LINUX, LINKTYPE_USB_LINUX_MMAPPED,
                 LINKTYPE_USBPCAP, LINKTYPE_USB_LINUX_ALT)

XFER_INTERRUPT = 1
USB_DIR_IN = 0x80

# ---------------------------------------------------------------- HID 键码表

# 完整表：0x04-0x38 字母数字与符号，0x28-0x2C 控制键，0x39 以后功能键/小键盘。
# 值是 (不加 Shift, 加 Shift)。
HID_KEYS = {
    0x04: ("a", "A"), 0x05: ("b", "B"), 0x06: ("c", "C"), 0x07: ("d", "D"),
    0x08: ("e", "E"), 0x09: ("f", "F"), 0x0A: ("g", "G"), 0x0B: ("h", "H"),
    0x0C: ("i", "I"), 0x0D: ("j", "J"), 0x0E: ("k", "K"), 0x0F: ("l", "L"),
    0x10: ("m", "M"), 0x11: ("n", "N"), 0x12: ("o", "O"), 0x13: ("p", "P"),
    0x14: ("q", "Q"), 0x15: ("r", "R"), 0x16: ("s", "S"), 0x17: ("t", "T"),
    0x18: ("u", "U"), 0x19: ("v", "V"), 0x1A: ("w", "W"), 0x1B: ("x", "X"),
    0x1C: ("y", "Y"), 0x1D: ("z", "Z"),
    0x1E: ("1", "!"), 0x1F: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"),
    0x26: ("9", "("), 0x27: ("0", ")"),
    0x28: ("\n", "\n"),          # Enter
    0x29: ("\x1b", "\x1b"),      # Esc
    0x2A: ("\b", "\b"),          # Backspace
    0x2B: ("\t", "\t"),          # Tab
    0x2C: (" ", " "),            # Space
    0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"),
    0x30: ("]", "}"), 0x31: ("\\", "|"), 0x32: ("#", "~"),
    0x33: (";", ":"), 0x34: ("'", '"'), 0x35: ("`", "~"),
    0x36: (",", "<"), 0x37: (".", ">"), 0x38: ("/", "?"),
    # 功能键与导航键：统一用 <名称> 形式，避免输出乱码
    0x39: ("<CAPS>", "<CAPS>"),
    0x3A: ("<F1>", "<F1>"), 0x3B: ("<F2>", "<F2>"), 0x3C: ("<F3>", "<F3>"),
    0x3D: ("<F4>", "<F4>"), 0x3E: ("<F5>", "<F5>"), 0x3F: ("<F6>", "<F6>"),
    0x40: ("<F7>", "<F7>"), 0x41: ("<F8>", "<F8>"), 0x42: ("<F9>", "<F9>"),
    0x43: ("<F10>", "<F10>"), 0x44: ("<F11>", "<F11>"), 0x45: ("<F12>", "<F12>"),
    0x46: ("<PRTSC>", "<PRTSC>"), 0x47: ("<SCROLL>", "<SCROLL>"),
    0x48: ("<PAUSE>", "<PAUSE>"), 0x49: ("<INS>", "<INS>"),
    0x4A: ("<HOME>", "<HOME>"), 0x4B: ("<PGUP>", "<PGUP>"),
    0x4C: ("<DEL>", "<DEL>"), 0x4D: ("<END>", "<END>"),
    0x4E: ("<PGDN>", "<PGDN>"), 0x4F: ("<RIGHT>", "<RIGHT>"),
    0x50: ("<LEFT>", "<LEFT>"), 0x51: ("<DOWN>", "<DOWN>"),
    0x52: ("<UP>", "<UP>"), 0x53: ("<NUMLK>", "<NUMLK>"),
    0x54: ("/", "/"), 0x55: ("*", "*"), 0x56: ("-", "-"), 0x57: ("+", "+"),
    0x58: ("\n", "\n"),          # 小键盘 Enter
    0x59: ("1", "1"), 0x5A: ("2", "2"), 0x5B: ("3", "3"),
    0x5C: ("4", "4"), 0x5D: ("5", "5"), 0x5E: ("6", "6"),
    0x5F: ("7", "7"), 0x60: ("8", "8"), 0x61: ("9", "9"),
    0x62: ("0", "0"), 0x63: (".", "."),
    0x64: ("\\", "|"), 0x65: ("<APP>", "<APP>"),
    0x66: ("<POWER>", "<POWER>"), 0x67: ("=", "="),
}

# 修饰键位
MOD_LCTRL = 0x01
MOD_LSHIFT = 0x02
MOD_LALT = 0x04
MOD_LGUI = 0x08
MOD_RCTRL = 0x10
MOD_RSHIFT = 0x20
MOD_RALT = 0x40
MOD_RGUI = 0x80

SHIFT_MASK = MOD_LSHIFT | MOD_RSHIFT
CTRL_MASK = MOD_LCTRL | MOD_RCTRL
ALT_MASK = MOD_LALT | MOD_RALT

MOD_NAMES = (
    (MOD_LCTRL, "LCTRL"), (MOD_LSHIFT, "LSHIFT"), (MOD_LALT, "LALT"),
    (MOD_LGUI, "LGUI"), (MOD_RCTRL, "RCTRL"), (MOD_RSHIFT, "RSHIFT"),
    (MOD_RALT, "RALT"), (MOD_RGUI, "RGUI"),
)


# ---------------------------------------------------------------- 记录解析

class UsbRecord(object):
    """一条 USB 事件。"""

    def __init__(self, bus, device, endpoint, transfer, data, urb_id=0,
                 kind="", status=0):
        self.bus = bus
        self.device = device
        self.endpoint = endpoint
        self.transfer = transfer
        self.data = data
        self.urb_id = urb_id
        self.kind = kind
        self.status = status

    def group_key(self):
        return (self.bus, self.device, self.endpoint)


def parse_usbmon(data, mmapped):
    """解 Linux usbmon 的 mon_bin_hdr。返回 UsbRecord 或 None。"""
    hdr_len = 64 if mmapped else 48
    if len(data) < hdr_len:
        return None
    urb_id = struct.unpack("<Q", data[0:8])[0]
    etype = data[8]                      # 'S' / 'C' / 'E'
    if etype not in (0x53, 0x43, 0x45):  # S / C / E
        return None
    xfer = data[9]
    epnum = data[10]
    devnum = data[11]
    busnum = struct.unpack("<H", data[12:14])[0]
    status = struct.unpack("<i", data[28:32])[0]
    len_cap = struct.unpack("<I", data[36:40])[0]
    payload = data[hdr_len:hdr_len + len_cap]
    return UsbRecord(busnum, devnum, epnum, xfer, payload, urb_id,
                     chr(etype), status)


def parse_usbpcap(data):
    """解 Windows USBPcap 的 USBPcapPacketHeader。返回 UsbRecord 或 None。

    头部布局（v1，headerLen = 27）：
        headerLen(2) irpId(8) status(4) function(2) info(1)
        bus(2) device(2) endpoint(1) transfer(1) dataLength(4)
    headerLen 字段本身给出真实长度，所以数据起点不能写死，要用它。
    """
    if len(data) < 27:
        return None
    hdr_len = struct.unpack("<H", data[0:2])[0]
    # headerLen 必须是合理的（27 是标准值，也见过 28/32 的变体）
    if hdr_len < 27 or hdr_len > 128 or hdr_len > len(data):
        return None
    urb_id = struct.unpack("<Q", data[2:10])[0]
    status = struct.unpack("<I", data[10:14])[0]
    _function = struct.unpack("<H", data[14:16])[0]
    _info = data[16]
    bus = struct.unpack("<H", data[17:19])[0]
    device = struct.unpack("<H", data[19:21])[0]
    endpoint = data[21]
    transfer = data[22]
    data_len = struct.unpack("<I", data[23:27])[0]
    payload = data[hdr_len:]
    if 0 < data_len <= len(payload):
        payload = payload[:data_len]
    return UsbRecord(bus, device, endpoint, transfer, payload, urb_id,
                     "C", status)


def looks_like_usbmon(data, linktype):
    """靠内容判断是不是 usbmon 格式（'S'/'C'/'E' 在偏移 8）。"""
    if linktype == LINKTYPE_USB_LINUX_MMAPPED:
        return len(data) >= 64 and data[8] in (0x53, 0x43, 0x45)
    if linktype in (LINKTYPE_USB_LINUX, LINKTYPE_USB_LINUX_ALT):
        return len(data) >= 48 and data[8] in (0x53, 0x43, 0x45)
    return False


def collect_usb(path):
    """遍历 pcap，返回 (UsbRecord 列表, 统计)。"""
    stats = {"packets": 0, "usb": 0, "interrupt": 0, "skipped": 0,
             "linktypes": set(), "non_usb": 0}
    recs = []
    seen_urb = {}
    for idx, _ts, linktype, data in read_packets(path):
        stats["packets"] += 1
        stats["linktypes"].add(linktype)
        if linktype not in USB_LINKTYPES:
            stats["non_usb"] += 1
            continue
        rec = None
        if looks_like_usbmon(data, linktype):
            mmapped = (linktype == LINKTYPE_USB_LINUX_MMAPPED) or len(data) >= 64
            rec = parse_usbmon(data, mmapped)
            if rec is None:
                rec = parse_usbmon(data, not mmapped)
        else:
            rec = parse_usbpcap(data)
            if rec is None:
                rec = parse_usbmon(data, len(data) >= 64) or \
                    parse_usbmon(data, False)
        if rec is None:
            stats["skipped"] += 1
            continue
        stats["usb"] += 1
        if rec.transfer != XFER_INTERRUPT:
            continue
        stats["interrupt"] += 1
        if not rec.data:
            continue
        # 同一个 URB 的 submit 与 complete 会各产生一条记录：
        # 保留 payload 最长的那条（IN 传输的真数据在 complete 里，
        # OUT 传输的真数据在 submit 里，取最长对两边都对）。
        key = (rec.bus, rec.device, rec.endpoint, rec.urb_id)
        old = seen_urb.get(key)
        if old is not None:
            if len(rec.data) > len(old.data):
                old.data = rec.data
            continue
        seen_urb[key] = rec
        recs.append(rec)
    return recs, stats


# ---------------------------------------------------------------- 键盘还原

class KeyboardDecoder(object):
    """按 HID boot 协议的 8 字节报告还原按键。"""

    def __init__(self):
        self.prev = set()
        self.text = []
        self.log = []
        self.warnings = []

    def feed(self, report, meta=""):
        if len(report) < 3:
            return
        mod = report[0]
        # 标准 boot 报告：byte1 是保留位，byte2..7 是键码。
        # 少数设备是 6 字节（无保留位），此时 byte1 直接就是键码。
        keys = [k for k in report[2:8] if k]
        if len(report) == 6 or (len(report) == 8 and report[1] != 0
                               and report[1] in HID_KEYS):
            keys = [k for k in report[1:] if k]
            if not self.warnings:
                self.warnings.append("检测到 6 字节报告（无保留字节），按 6 键位解析")
        cur = set(keys)
        shift = bool(mod & SHIFT_MASK)
        ctrl = bool(mod & CTRL_MASK)
        alt = bool(mod & ALT_MASK)

        for code in keys:
            if code in self.prev:
                continue            # 按住不放，不算新按键
            pair = HID_KEYS.get(code)
            if pair is None:
                ch = "<0x%02X>" % code
                self.text.append(ch)
                self.log.append("%s未知键码 0x%02X%s" % (meta, code,
                                                        "" if not meta else ""))
                continue
            ch = pair[1] if shift else pair[0]
            if ctrl and len(ch) == 1 and ch.isalpha():
                # Ctrl+字母 -> 控制字符（Ctrl+A = 0x01）
                ch = chr(ord(ch.upper()) - 64)
            elif ctrl and len(ch) == 1 and ch == " ":
                ch = "\x00"
            elif alt:
                ch = "\x1b" + ch     # Alt 在终端里相当于 Esc 前缀
            self.text.append(ch)
            mods = [n for bit, n in MOD_NAMES if mod & bit]
            self.log.append("%s键码 0x%02X -> %r%s" % (
                meta, code, ch, ("  [%s]" % "+".join(mods)) if mods else ""))
        self.prev = cur

    def result(self):
        return "".join(self.text)


def group_records(recs):
    """按 (bus, device, endpoint) 分组，保持首次出现顺序。"""
    groups = {}
    order = []
    for r in recs:
        k = r.group_key()
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(r)
    return [(k, groups[k]) for k in order]


def classify_group(items):
    """猜这一组是键盘还是鼠标：看报告长度分布。"""
    lens = {}
    for r in items:
        ln = len(r.data)
        lens[ln] = lens.get(ln, 0) + 1
    if not lens:
        return "unknown"
    # 最常见长度
    common = max(lens.items(), key=lambda kv: kv[1])[0]
    if common >= 8:
        return "keyboard"
    if common in (3, 4, 5):
        return "mouse"
    if common == 6:
        return "keyboard"
    return "unknown"


def group_desc(key):
    bus, dev, ep = key
    return "总线 %d 设备 %d 端点 0x%02X" % (bus, dev, ep)


# ---------------------------------------------------------------- 鼠标 + PNG

def s8(b):
    return b - 256 if b >= 128 else b


class MouseDecoder(object):
    """累加鼠标的相对位移，得到轨迹点。"""

    def __init__(self):
        self.x = 0
        self.y = 0
        self.points = [(0, 0)]
        self.clicks = []
        self.wheel = 0
        self.warnings = []

    def feed(self, report):
        if len(report) < 3:
            return
        buttons = report[0]
        dx = s8(report[1])
        dy = s8(report[2])
        if len(report) >= 4:
            self.wheel += s8(report[3])
        if buttons:
            self.clicks.append((self.x, self.y, buttons))
        if dx or dy:
            self.x += dx
            self.y += dy
            self.points.append((self.x, self.y))

    def bounds(self):
        xs = [p[0] for p in self.points]
        ys = [p[1] for p in self.points]
        return min(xs), min(ys), max(xs), max(ys)


def write_png(path, width, height, rows):
    """纯 zlib 手写 PNG（8 位 RGB，无滤波）。rows 是每行 width*3 字节。"""
    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data +
                struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))

    raw = b"".join(b"\x00" + r for r in rows)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    blob = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
    with open(path, "wb") as fh:
        fh.write(blob)
    return len(blob)


def render_mouse(mouse, path, size=600, margin=40):
    """把轨迹画成 PNG。坐标按边界缩放，画布固定正方形。"""
    x0, y0, x1, y1 = mouse.bounds()
    w = max(1, x1 - x0)
    h = max(1, y1 - y0)
    span = max(w, h)
    inner = size - 2 * margin
    scale = inner / float(span) if span else 1.0

    def to_px(p):
        px = int(margin + (p[0] - x0) * scale)
        py = int(margin + (p[1] - y0) * scale)
        return px, py

    # 白底
    white = bytearray(b"\xff" * (size * 3))
    rows = [bytearray(white) for _ in range(size)]

    def put(px, py, rgb=(0, 0, 0)):
        if 0 <= px < size and 0 <= py < size:
            o = px * 3
            rows[py][o:o + 3] = bytes(rgb)

    def dot(px, py, rgb=(0, 0, 0), r=1):
        for dy in range(-r, r + 1):
            for dx in range(-r, r + 1):
                put(px + dx, py + dy, rgb)

    # 画折线：在相邻点之间线性插值，避免稀疏点连不成线
    prev = None
    for p in mouse.points:
        px, py = to_px(p)
        if prev is not None:
            x_a, y_a = prev
            steps = max(abs(px - x_a), abs(py - y_a))
            for i in range(1, steps + 1):
                t = i / float(steps) if steps else 1.0
                dot(int(x_a + (px - x_a) * t), int(y_a + (py - y_a) * t),
                    (30, 90, 200))
        prev = (px, py)
    # 起点绿色、终点红色
    if mouse.points:
        dot(*to_px(mouse.points[0]), rgb=(0, 160, 0), r=4)
        dot(*to_px(mouse.points[-1]), rgb=(200, 0, 0), r=4)
    # 点击点用橙色方块
    for cx, cy, _b in mouse.clicks:
        dot(*to_px((cx, cy)), rgb=(230, 140, 0), r=3)

    return write_png(path, size, size, rows)


# ---------------------------------------------------------------- 输出

def visible(text):
    """把控制字符渲染成可见形式，方便肉眼看有没有敲对。

    Enter 变 <CR>、Tab 变 <TAB>、Ctrl+A 变 <0x01>，其余照原样。
    """
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\n":
            out.append("<CR>")
        elif ch == "\t":
            out.append("<TAB>")
        elif o < 0x20 or o == 0x7F:
            out.append("<0x%02X>" % o)
        else:
            out.append(ch)
    return "".join(out)


def usage(prog):
    print("usbhid.py -- 从 pcap 里还原 USB 键盘输入 / 鼠标轨迹（CTF 高频）")
    print("")
    print("用法：")
    print("  python -X utf8 %s 题目.pcap                自动识别并还原" % prog)
    print("  python -X utf8 %s 题目.pcap --keyboard     只还原键盘" % prog)
    print("  python -X utf8 %s 题目.pcap --mouse        只还原鼠标轨迹" % prog)
    print("  python -X utf8 %s 题目.pcap --all --raw    全都要，并打印原始报告" % prog)
    print("  python -X utf8 %s 题目.pcap --mouse -o 轨迹.png" % prog)
    print("")
    print("支持的链路类型：189 (USB_LINUX) / 220 (USB_LINUX_MMAPPED) /")
    print("                249 (USBPCAP) / 191（按内容自动判断真实格式）")
    print("")
    print("选项：")
    print("  --keyboard    只处理键盘")
    print("  --mouse       只处理鼠标")
    print("  --all         键盘和鼠标都处理（默认行为）")
    print("  --raw         额外打印每一条 HID 原始报告（十六进制）")
    print("  --device N    只看第 N 组设备（先用 --list 看编号）")
    print("  --list        只列出识别到的 USB 设备分组")
    print("  -o FILE       鼠标轨迹图输出路径（PNG）")
    print("  --force       允许覆盖已存在的输出文件")
    print("  --size N      轨迹图边长（默认 600 像素）")
    print("")
    print("例子：")
    print("  python -X utf8 %s keyboard.pcap --keyboard" % prog)
    print("  python -X utf8 %s mouse.pcap --mouse -o 轨迹.png" % prog)


def main():
    safe_setup()
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--keyboard", action="store_true")
    ap.add_argument("--mouse", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--device", type=int, default=None)
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--size", type=int, default=600)
    try:
        args = ap.parse_args()
    except SystemExit:
        return 2

    prog = os.path.basename(sys.argv[0]) or "usbhid.py"
    if args.help or not args.pcap:
        usage(prog)
        return 0

    path = os.path.abspath(args.pcap)
    if not os.path.isfile(path):
        sys.stderr.write("错误：文件不存在或不是普通文件：%s\n" % path)
        return 1

    try:
        recs, stats = collect_usb(path)
    except PcapError as exc:
        sys.stderr.write("错误：%s\n" % exc)
        return 1
    except (IOError, OSError) as exc:
        sys.stderr.write("错误：读取失败：%s\n" % exc)
        return 1
    except struct.error as exc:
        sys.stderr.write("错误：文件结构异常（%s），可能已损坏或被截断\n" % exc)
        return 1

    if not stats["usb"]:
        sys.stderr.write("错误：这个文件里没有 USB 流量。\n")
        sys.stderr.write("共 %d 个包，链路类型 %s。\n"
                         % (stats["packets"], sorted(stats["linktypes"])))
        sys.stderr.write("USB 题的链路类型应是 189/220/249；"
                         "如果是 1（Ethernet），说明这不是 USB 抓包。\n")
        return 1

    groups = group_records(recs)
    if not groups:
        sys.stderr.write("错误：识别到 %d 条 USB 记录，但没有中断传输的 HID 数据。\n"
                         % stats["usb"])
        sys.stderr.write("（本脚本只处理 transfer_type=1 的中断传输）\n")
        return 1

    if args.list:
        print("共 %d 个包，USB 记录 %d 条，中断传输 %d 条，设备分组 %d 个"
              % (stats["packets"], stats["usb"], stats["interrupt"], len(groups)))
        print("%-4s %-28s %-10s %s" % ("#", "设备", "猜测类型", "报告长度分布"))
        print("-" * 88)
        for i, (key, items) in enumerate(groups, 1):
            lens = {}
            for r in items:
                lens[len(r.data)] = lens.get(len(r.data), 0) + 1
            dist = ", ".join("%d字节x%d" % (k, v) for k, v in sorted(lens.items()))
            print("%-4d %-28s %-10s %s" % (i, group_desc(key),
                                           classify_group(items), dist))
        return 0

    if args.device is not None:
        if args.device < 1 or args.device > len(groups):
            sys.stderr.write("错误：--device %d 超出范围（共 %d 组，编号 1..%d）\n"
                             % (args.device, len(groups), len(groups)))
            return 2
        groups = [groups[args.device - 1]]

    # 模式语义：
    #   --keyboard  -> 只解键盘组（按 8 字节报告判定）
    #   --mouse     -> 只解鼠标组（按 3-5 字节报告判定）
    #   --all / 默认 -> 两组都解，各自按判定结果走
    # 判定为 mouse 的组绝不按键盘解，反之亦然；只有判为 unknown 时才两边都试。
    if args.keyboard and not args.mouse:
        want_kb, want_mouse = True, False
    elif args.mouse and not args.keyboard:
        want_kb, want_mouse = False, True
    else:
        want_kb, want_mouse = True, True

    if args.output and not want_mouse:
        sys.stderr.write("错误：-o 用于鼠标轨迹图，但当前模式不含鼠标。\n")
        return 2

    if args.output:
        outp = os.path.abspath(args.output)
        if os.path.exists(outp) and not args.force:
            sys.stderr.write("错误：输出文件已存在，加 --force 才覆盖：%s\n" % outp)
            return 1
        parent = os.path.dirname(outp)
        if parent and not os.path.isdir(parent):
            sys.stderr.write("错误：输出目录不存在：%s\n" % parent)
            return 1

    print("共 %d 个包，USB 记录 %d 条，中断传输 %d 条，设备分组 %d 个"
          % (stats["packets"], stats["usb"], stats["interrupt"], len(groups)))
    print("")

    kb_total = []
    mouse_result = None
    for i, (key, items) in enumerate(groups, 1):
        kind = classify_group(items)
        print("== 分组 %d：%s（%d 条报告，判为 %s）=="
              % (i, group_desc(key), len(items), kind))
        if args.raw:
            for r in items[:400]:
                print("    %s 0x%02X %s"
                      % (r.kind or "?", r.endpoint, r.data.hex()))
            if len(items) > 400:
                print("    ...（只显示前 400 条）")

        do_kb = want_kb and kind in ("keyboard", "unknown")
        do_mouse = want_mouse and kind in ("mouse", "unknown")
        # 明确判为 mouse 的组绝不按键盘解（否则 3/4 字节报告会被硬塞进
        # 8 字节键位布局，解出一堆假字符）；反之亦然。
        if kind == "mouse":
            do_kb = False
        if kind == "keyboard":
            do_mouse = False

        if do_kb:
            dec = KeyboardDecoder()
            for r in items:
                dec.feed(r.data, meta="")
            text = dec.result()
            kb_total.append((i, text))
            for w in dec.warnings:
                sys.stderr.write("警告（分组 %d）：%s\n" % (i, w))
            if text:
                print("")
                print("-- 键盘还原 --")
                print(visible(text))
                print("")
            else:
                print("  （这组没有还原出字符，可能不是键盘）")

        if do_mouse:
            md = MouseDecoder()
            for r in items:
                md.feed(r.data)
            if md.points and len(md.points) > 1:
                mouse_result = (i, md)
                x0, y0, x1, y1 = md.bounds()
                print("")
                print("-- 鼠标轨迹 --")
                print("采样点 %d 个，范围 x[%d..%d] y[%d..%d]，滚轮累计 %d，点击 %d 次"
                      % (len(md.points), x0, x1, y0, y1, md.wheel, len(md.clicks)))
            elif md.clicks:
                print("  （只有点击，没有位移）")
        print("")

    if mouse_result is not None and args.output:
        gi, md = mouse_result
        try:
            size = max(120, min(4000, args.size))
            n = render_mouse(md, os.path.abspath(args.output), size=size)
        except (IOError, OSError) as exc:
            sys.stderr.write("错误：写轨迹图失败（%s）\n" % exc)
            return 1
        sys.stderr.write("已写入轨迹图 %s（%d 字节，分组 %d）\n"
                         % (os.path.abspath(args.output), n, gi))

    if len(kb_total) > 1 and want_kb:
        print("== 合并后的键盘输入 ==")
        print(visible("".join(t for _i, t in kb_total)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
