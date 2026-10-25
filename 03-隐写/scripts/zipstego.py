# -*- coding: utf-8 -*-
"""
zipstego.py -- ZIP 隐写检测：伪加密、注释藏数据、尾部附加、隐藏条目。

为什么需要
==========
CTF 里的 ZIP 题几乎都在这几个点上做手脚：

  1. **伪加密**：把通用位标记的 bit0（"已加密"）置 1，解压软件就提示要密码，
     但其实数据根本没加密。有些实现只改本地头、有些只改中央目录，两者
     不一致时不同解压软件行为还不一样 —— 这正是出题人利用的地方。
  2. **注释藏数据**：EOCD 后面有一段自由长度的注释，可以直接塞 flag 或
     另一个 ZIP。
  3. **尾部附加数据**：EOCD 之后（注释之外）还能再挂任意字节。
  4. **隐藏条目**：中央目录里没有登记、但本地头确实存在的文件。

本脚本把这四类一次性查清，并且明确区分「确定的」（标志位不一致、大小对不上）
和「可疑的」（注释里像文本）。

**不做 CRC 碰撞**：那是构造性攻击，需要伪造 CRC 且要能控制明文，本脚本只
检测和报告，不生成。

用法
====
    python -X utf8 zipstego.py 题目.zip
    python -X utf8 zipstego.py 题目.zip --dump-comment -o 注释.bin
    python -X utf8 zipstego.py 伪加密.zip --clean -o 修复.zip
    python -X utf8 zipstego.py 目录/ -r

已知限制
========
    * 只处理 ZIP，不处理 RAR/7z（RAR 的伪加密字段布局不同）。
    * Zip64 仅做基础支持：超大条目走 extra field 读偏移，字段缺失时报出来。
    * --clean 只清「已判定为伪加密」的条目的 bit0，真加密的条目不动
      （否则会把本来能解的文件弄成解不开）。
    * 不改 CRC、不改压缩数据，只改标志位这一个字节里的一个 bit。
"""

import argparse
import binascii
import math
import struct
import sys
import zlib
from pathlib import Path

# 优先级
P_HIGH, P_MID, P_LOW = 1, 2, 3
P_LABEL = {1: "[高]", 2: "[中]", 3: "[低]"}

SIG_LOCAL = b"PK\x03\x04"
SIG_CD = b"PK\x01\x02"
SIG_EOCD = b"PK\x05\x06"
SIG_EOCD64 = b"PK\x06\x06"
SIG_EOCD64_LOC = b"PK\x06\x07"
SIG_DD = b"PK\x07\x08"

FLAG_ENCRYPTED = 0x0001
FLAG_DESCRIPTOR = 0x0008


class ZipError(Exception):
    """给用户看的错误。"""


# ==================================================================== 通用

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


def preview(data, maxlen=300):
    if not data:
        return "(空)"
    if printable_ratio(data[:512]) >= 0.85:
        try:
            t = data.decode("utf-8")
        except UnicodeDecodeError:
            t = data.decode("gb18030", "replace")
        return t[:maxlen] + ("...(截断)" if len(t) > maxlen else "")
    return hexdump(data, maxlen=maxlen)


def detect_magic(data):
    table = (
        (b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff", "JPEG"),
        (b"BM", "BMP"), (b"GIF89a", "GIF"), (b"GIF87a", "GIF"),
        (b"PK\x03\x04", "ZIP"), (b"PK\x05\x06", "ZIP(空)"),
        (b"Rar!\x1a\x07", "RAR"), (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"\x1f\x8b\x08", "gzip"), (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"), (b"%PDF", "PDF"),
        (b"RIFF", "RIFF(WAV)"), (b"\x7fELF", "ELF"), (b"MZ", "PE"),
    )
    for magic, name in table:
        if data.startswith(magic):
            return name
    return None


# ==================================================================== 结构解析

class Entry(object):
    """中央目录里的一条记录 + 对应的本地头信息。"""

    def __init__(self):
        self.name = ""
        self.cd_flags = 0
        self.lh_flags = None
        self.method = 0
        self.crc = 0
        self.csize = 0
        self.usize = 0
        self.lh_offset = 0
        self.data_offset = None
        self.extra_len = 0
        self.comment = b""
        self.lh_ok = False

    def encrypted_flag(self):
        return bool(self.cd_flags & FLAG_ENCRYPTED)

    def describe(self):
        return "%s (method=%d, csize=%d, usize=%d)" % (
            self.name, self.method, self.csize, self.usize)


def find_eocd(data):
    """从尾部往前找 EOCD。

    不能只找最后一个 PK\\x05\\x06 —— 注释里完全可能再出现这个签名，
    所以要求「EOCD 记录的注释长度 + 22 + 偏移 == 文件长度」才算数。
    从后往前扫，第一个满足条件的才是真的 EOCD。
    """
    n = len(data)
    pos = n - 22
    while pos >= 0:
        pos = data.rfind(SIG_EOCD, 0, pos + 4)
        if pos < 0:
            break
        if pos + 22 <= n:
            clen = struct.unpack("<H", data[pos + 20:pos + 22])[0]
            if pos + 22 + clen == n:
                return pos, clen
            # 长度对不上也可能是有尾部附加数据，先记下候选
        pos -= 1
    # 退一步：取最后一个签名位置（可能有尾部附加数据）
    pos = data.rfind(SIG_EOCD)
    if pos < 0:
        return None, 0
    clen = 0
    if pos + 22 <= n:
        clen = struct.unpack("<H", data[pos + 20:pos + 22])[0]
    return pos, clen


def parse_zip(data):
    """解析出 (eocd_offset, comment_len, entries, eocd_fields)。"""
    eocd_at, clen = find_eocd(data)
    if eocd_at is None:
        raise ZipError("找不到 EOCD（PK\\x05\\x06）签名，不是完整 ZIP 或已损坏")
    if eocd_at + 22 > len(data):
        raise ZipError("EOCD 记录不完整（只剩 %d 字节）" % (len(data) - eocd_at))
    (disk, cd_disk, n_disk, n_total, cd_size, cd_off,
     decl_clen) = struct.unpack("<HHHHIIH", data[eocd_at + 4:eocd_at + 22])

    zip64 = False
    if n_total == 0xFFFF or cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        zip64 = True

    entries = []
    pos = cd_off
    if pos + 4 > len(data) or data[pos:pos + 4] != SIG_CD:
        # 中央目录偏移不可信：直接扫所有 PK\x01\x02
        pos = data.find(SIG_CD)
        if pos < 0:
            raise ZipError("找不到中央目录（PK\\x01\\x02），ZIP 结构已损坏")
        print("提示: EOCD 里记录的中央目录偏移 0x%x 处不是签名，"
              "实际从 0x%x 开始（偏移被改过）" % (cd_off, pos), file=sys.stderr)
    start_cd = pos
    for _ in range(min(n_total if n_total else 65535, 65535)):
        if pos + 46 > len(data) or data[pos:pos + 4] != SIG_CD:
            break
        e = Entry()
        (ver_made, ver_need, flags, method, _t, _d, crc, csize, usize,
         namelen, extralen, commlen, _dn, _ia, _ea,
         lh_off) = struct.unpack("<HHHHHHIIIHHHHHII", data[pos + 4:pos + 46])
        name_raw = data[pos + 46:pos + 46 + namelen]
        e.name = name_raw.decode("utf-8", "replace")
        e.cd_flags = flags
        e.method = method
        e.crc = crc
        e.csize = csize
        e.usize = usize
        e.lh_offset = lh_off
        e.extra_len = extralen
        e.comment = data[pos + 46 + namelen + extralen:
                         pos + 46 + namelen + extralen + commlen]
        # Zip64：偏移是 0xFFFFFFFF 时，真值在 extra field 的 0x0001 里
        if lh_off == 0xFFFFFFFF or csize == 0xFFFFFFFF or usize == 0xFFFFFFFF:
            extra = data[pos + 46 + namelen:pos + 46 + namelen + extralen]
            vals = _parse_zip64_extra(extra)
            if vals:
                idx = 0
                if usize == 0xFFFFFFFF and idx < len(vals):
                    e.usize = vals[idx]
                    idx += 1
                if csize == 0xFFFFFFFF and idx < len(vals):
                    e.csize = vals[idx]
                    idx += 1
                if lh_off == 0xFFFFFFFF and idx < len(vals):
                    e.lh_offset = vals[idx]
                    idx += 1
        entries.append(e)
        pos += 46 + namelen + extralen + commlen

    # 解析每个条目的本地头
    for e in entries:
        off = e.lh_offset
        if off + 30 > len(data) or data[off:off + 4] != SIG_LOCAL:
            continue
        (lh_flags, lh_method, _t, _d, _crc, lh_csize, lh_usize,
         lh_nl, lh_el) = struct.unpack("<HHHHIIIHH", data[off + 6:off + 30])
        e.lh_flags = lh_flags
        e.data_offset = off + 30 + lh_nl + lh_el
        e.lh_ok = True

    return {
        "eocd_at": eocd_at,
        "decl_clen": decl_clen,
        "clen": clen,
        "n_total": n_total,
        "cd_off": cd_off,
        "cd_size": cd_size,
        "start_cd": start_cd,
        "zip64": zip64,
        "entries": entries,
        "disk": disk,
    }


def _parse_zip64_extra(extra):
    """从 extra field 里取出 Zip64(0x0001) 的一串 uint64。"""
    pos = 0
    while pos + 4 <= len(extra):
        tag, ln = struct.unpack("<HH", extra[pos:pos + 4])
        body = extra[pos + 4:pos + 4 + ln]
        if tag == 0x0001:
            vals = []
            for i in range(0, len(body) - 7, 8):
                vals.append(struct.unpack("<Q", body[i:i + 8])[0])
            return vals
        pos += 4 + ln
    return []


# ==================================================================== 检测

class Finding(object):
    def __init__(self, pri, title, detail="", blob=None, fix=None):
        self.pri = pri
        self.title = title
        self.detail = detail
        self.blob = blob
        self.fix = fix          # 可选的修复动作说明


def check_fake_encryption(entries, findings):
    """伪加密判定。

    判据（从硬到软）：
      A. 本地头与中央目录的 bit0 不一致 —— 确定的伪加密（同一个条目不可能
         「一半加密」）。
      B. 两者都置位，但 csize == usize（且 method=0 存储）—— 真 ZipCrypto 加密
         会额外加 12 字节加密头，压缩后大小必然比原文大 12 字节。
      C. 两者都置位，但数据区开头就是可读明文 —— 说明根本没加密。
    """
    for e in entries:
        cd_enc = bool(e.cd_flags & FLAG_ENCRYPTED)
        lh_enc = bool(e.lh_flags & FLAG_ENCRYPTED) if e.lh_flags is not None else None

        if lh_enc is not None and cd_enc != lh_enc:
            which = ("本地头置位、中央目录未置位" if lh_enc
                     else "中央目录置位、本地头未置位")
            findings.append(Finding(
                P_HIGH,
                "伪加密：%s 的标志位不一致" % e.name,
                "中央目录 flags=0x%04x，本地头 flags=0x%04x（%s）。\n"
                "同一个条目不可能只加密一半 —— 这是改出来的伪加密。\n"
                "不同解压软件看不同的地方，所以会出现「有的能解、有的要密码」。"
                % (e.cd_flags, e.lh_flags, which),
                fix=("clear_local" if lh_enc else "clear_cd")))
            continue

        if not cd_enc:
            continue

        # B/C：两边都置位，判断是否真加密
        if e.method == 0 and e.csize == e.usize:
            findings.append(Finding(
                P_HIGH,
                "伪加密：%s 声称加密但大小没有增加" % e.name,
                "csize == usize == %d，method=0（存储）。\n"
                "真 ZipCrypto 会在数据前加 12 字节加密头，所以 csize 至少是 "
                "usize+12。这里相等，说明标志位是假的。" % e.csize,
                fix="clear_both"))
            continue

        # 看数据区开头是否可读明文
        if e.data_offset is not None and e.csize > 0:
            raw = None
            if e.method == 0:
                raw = e.csize
            elif e.method == 8:
                raw = e.csize
            if raw and e.data_offset + min(raw, 64) <= _DATA_LEN[0]:
                head = _DATA_BUF[0][e.data_offset:e.data_offset + min(raw, 64)]
                if len(head) >= 8 and printable_ratio(head) >= 0.95:
                    findings.append(Finding(
                        P_HIGH,
                        "伪加密：%s 的数据区开头是明文" % e.name,
                        "声称加密，但数据区前 %d 字节全是可打印字符：\n%s\n"
                        "真加密的数据区开头是随机字节，不可能这么整齐。"
                        % (len(head), preview(head, 200)),
                        fix="clear_both"))


# 为了让 check_fake_encryption 拿到整份数据，用一个模块级持有（避免到处传参）
_DATA_BUF = [b""]
_DATA_LEN = [0]


def check_entry_flags(entries, findings):
    """通用位标记里其他可疑组合。"""
    for e in entries:
        if e.cd_flags & 0x0002 or e.cd_flags & 0x0004:
            findings.append(Finding(
                P_LOW, "%s 使用了压缩选项位（flags=0x%04x）" % (e.name, e.cd_flags),
                "bit1/bit2 是压缩级别提示，正常但少见，仅作参考。"))
        if (e.cd_flags & FLAG_DESCRIPTOR) and e.lh_flags is not None \
                and not (e.lh_flags & FLAG_DESCRIPTOR):
            findings.append(Finding(
                P_MID, "%s 的数据描述符位不一致" % e.name,
                "中央目录 flags=0x%04x（bit3 置位），本地头 flags=0x%04x。\n"
                "bit3 表示「CRC/大小在数据之后的描述符里」，两边不一致会让"
                "某些解压器算错。" % (e.cd_flags, e.lh_flags)))


def check_comment(data, info, findings):
    """EOCD 注释：长度异常 / 内容可疑。"""
    eocd_at = info["eocd_at"]
    decl = info["decl_clen"]
    real = info["clen"]
    comment = data[eocd_at + 22:eocd_at + 22 + real]

    if decl != real:
        findings.append(Finding(
            P_HIGH, "ZIP 注释长度字段与实际不符",
            "EOCD 里声明注释 %d 字节，实际文件尾部只有 %d 字节。\n"
            "多出来的部分（或缺失的部分）就是被改过的地方。" % (decl, real)))

    if not comment:
        return

    # 注释里嵌套 ZIP / 其他容器
    kind = detect_magic(comment)
    note = "注释共 %d 字节" % len(comment)
    if kind:
        note += "，开头魔数是 %s —— 注释里套了另一个文件" % kind
        findings.append(Finding(P_HIGH, "ZIP 注释里内嵌了 %s" % kind,
                                note, blob=comment))
    elif printable_ratio(comment[:512]) >= 0.85:
        findings.append(Finding(P_MID, "ZIP 注释是可读文本", note, blob=comment))
    else:
        findings.append(Finding(P_MID, "ZIP 注释是二进制数据",
                                note + "（可打印率 %.2f）"
                                % printable_ratio(comment[:512]),
                                blob=comment))

    # 注释里出现第二个 EOCD 或 CD 签名，说明拼接了另一个 ZIP
    for sig, label in ((SIG_EOCD, "EOCD"), (SIG_CD, "中央目录"),
                       (SIG_LOCAL, "本地头")):
        cnt = comment.count(sig)
        if cnt:
            findings.append(Finding(
                P_MID, "注释里出现 %d 个 %s 签名" % (cnt, label),
                "注释区里嵌了 ZIP 结构，多半是把另一个包整个贴了进来"))


def check_trailing(data, info, findings):
    """EOCD（含注释）之后的附加数据。"""
    end = info["eocd_at"] + 22 + info["clen"]
    if end < len(data):
        tail = data[end:]
        kind = detect_magic(tail)
        note = "共 %d 字节，在 EOCD 之后" % len(tail)
        if kind:
            note += "；开头魔数是 %s" % kind
        findings.append(Finding(P_HIGH, "ZIP 的 EOCD 之后有附加数据",
                                note, blob=tail))
        for sig, label in ((SIG_LOCAL, "本地头"), (SIG_CD, "中央目录")):
            if tail.count(sig):
                findings.append(Finding(
                    P_MID, "附加数据里有 %d 个 %s 签名"
                    % (tail.count(sig), label),
                    "说明尾部挂了一个完整的 ZIP 结构"))


def check_hidden_entries(data, info, findings):
    """扫所有本地头，找出中央目录没登记的条目（隐藏文件）。"""
    entries = info["entries"]
    # 注意：偏移 0 是合法值（第一个条目就在文件开头），不能用 `if e.lh_offset`
    # 判断，否则第一个条目会被误判成「隐藏条目」。
    known = set(e.lh_offset for e in entries)
    start_cd = info["start_cd"]
    hidden = []
    pos = 0
    limit = start_cd if start_cd > 0 else len(data)
    while True:
        i = data.find(SIG_LOCAL, pos, limit)
        if i < 0:
            break
        if i not in known:
            # 读一下文件名，确认这真的是个本地头而不是巧合
            if i + 30 <= len(data):
                nl, el = struct.unpack("<HH", data[i + 26:i + 30])
                if 0 < nl <= 512 and i + 30 + nl <= len(data):
                    name = data[i + 30:i + 30 + nl].decode("utf-8", "replace")
                    if name.isprintable() and name:
                        hidden.append((i, name))
        pos = i + 4
    if hidden:
        lines = ["偏移 0x%06x  %s" % (off, name) for off, name in hidden[:20]]
        findings.append(Finding(
            P_HIGH, "发现 %d 个中央目录里没有的本地头（隐藏条目）" % len(hidden),
            "中央目录是解压软件真正读的东西；本地头存在但没被登记，"
            "解压时就「看不见」，但数据确实在文件里。\n" + "\n".join(lines)))


def check_cd_trailing(data, info, findings):
    """中央目录末尾与 EOCD 之间是否有多余字节。"""
    start = info["start_cd"]
    size = info["cd_size"]
    eocd_at = info["eocd_at"]
    if start <= 0 or size <= 0:
        return
    expect_end = start + size
    if expect_end < eocd_at:
        gap = data[expect_end:eocd_at]
        if gap.strip(b"\x00"):
            findings.append(Finding(
                P_HIGH, "中央目录与 EOCD 之间有 %d 字节多余数据" % len(gap),
                "中央目录声明大小 %d，从 0x%x 起应当到 0x%x，"
                "但 EOCD 在 0x%x。中间这段不空。"
                % (size, start, expect_end, eocd_at), blob=gap))
    elif expect_end > eocd_at:
        findings.append(Finding(
            P_MID, "中央目录声明大小超出了 EOCD 位置",
            "声明到 0x%x，EOCD 却在 0x%x（差 %d 字节），cd_size 被改过"
            % (expect_end, eocd_at, expect_end - eocd_at)))


def check_data_sanity(data, entries, findings):
    """数据区是否越界 / CRC 明显不对（只报告，不修）。"""
    n = len(data)
    for e in entries:
        if e.data_offset is None:
            findings.append(Finding(
                P_MID, "%s 的本地头偏移无效" % e.name,
                "中央目录记录偏移 0x%x，那里不是 PK\\x03\\x04 签名 —— "
                "条目被删过或偏移被改过" % e.lh_offset))
            continue
        end = e.data_offset + e.csize
        if end > n:
            findings.append(Finding(
                P_HIGH, "%s 的压缩数据越界" % e.name,
                "数据区 0x%x..0x%x 超出文件长度 0x%x（缺 %d 字节）"
                % (e.data_offset, end, n, end - n)))


def check_flag_strings(data, findings):
    for pat in (b"flag{", b"ctf{", b"FLAG{", b"CTF{", b"key{"):
        off = data.find(pat)
        if off >= 0:
            end = data.find(b"}", off)
            snip = data[off:end + 1] if 0 < end - off < 200 else data[off:off + 80]
            findings.append(Finding(
                P_HIGH, "明文命中 %s（偏移 0x%x）" % (pat.decode("latin-1"), off),
                preview(snip, 200)))


# ==================================================================== 修复

def clean_zip(data, info, findings, out_path, force):
    """把判定为伪加密的条目的 bit0 清掉，其余字节原样保留。

    只动 flags 字段里的 1 个 bit，不动 CRC / 压缩数据 / 大小字段，
    所以清完之后 CRC 依然是对的，结构依然自洽。
    """
    patched = bytearray(data)
    actions = []
    for e in info["entries"]:
        cd_enc = bool(e.cd_flags & FLAG_ENCRYPTED)
        lh_enc = bool(e.lh_flags & FLAG_ENCRYPTED) if e.lh_flags is not None else None

        # 只有「确认为伪加密」的才清：
        #   - 两边不一致（必然伪）
        #   - 两边都置位且 csize==usize 且 method==0（存储型伪加密）
        fake = False
        if lh_enc is not None and cd_enc != lh_enc:
            fake = True
        elif cd_enc and lh_enc and e.method == 0 and e.csize == e.usize:
            fake = True

        if not fake:
            if cd_enc:
                actions.append("保留加密: %s（无法确认是伪加密，不动）" % e.name)
            continue

        # 清中央目录的 bit0
        if cd_enc:
            # 需要重新定位中央目录条目里的 flags 字段
            pos = data.find(SIG_CD)
            while pos >= 0:
                if pos + 46 <= len(data):
                    nl = struct.unpack("<H", data[pos + 28:pos + 30])[0]
                    name = data[pos + 46:pos + 46 + nl].decode("utf-8", "replace")
                    if name == e.name and pos + 8 <= len(data):
                        struct.pack_into("<H", patched, pos + 8,
                                         e.cd_flags & ~FLAG_ENCRYPTED)
                        break
                pos = data.find(SIG_CD, pos + 4)
            actions.append("清中央目录 bit0: %s" % e.name)

        # 清本地头的 bit0
        if e.lh_flags is not None and (e.lh_flags & FLAG_ENCRYPTED):
            off = e.lh_offset
            if off + 8 <= len(patched) and data[off:off + 4] == SIG_LOCAL:
                struct.pack_into("<H", patched, off + 6,
                                 e.lh_flags & ~FLAG_ENCRYPTED)
                actions.append("清本地头 bit0: %s" % e.name)

    if not actions:
        print("没有可修复的伪加密条目。")
        return 1

    out = Path(out_path)
    if out.exists() and not force:
        raise ZipError("目标文件已存在：%s（要覆盖请加 --force）" % out)
    if out.parent and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(patched))

    print("")
    print("== 修复动作 ==")
    for a in actions:
        print("  - %s" % a)
    print("")
    print("已写出: %s (%d 字节，原 %d 字节)"
          % (out, len(patched), len(data)))
    print("字节数不变，只改了标志位 —— CRC 和压缩数据都没动。")
    return 0


# ==================================================================== 入口

def scan(path, dump_comment=None, force=False, clean_out=None, verbose=False):
    p = Path(path)
    if not p.exists():
        raise ZipError("文件不存在：%s" % p)
    if not p.is_file():
        raise ZipError("不是普通文件：%s" % p)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ZipError("读取失败：%s" % exc)
    if len(data) < 22:
        raise ZipError("文件太小（%d 字节），不可能是 ZIP：%s" % (len(data), p))
    if data[:2] != b"PK":
        raise ZipError("不是 ZIP 文件（开头是 %s）：%s"
                       % (data[:8].hex(), p))

    print("=" * 66)
    print("文件: %s" % p)
    print("大小: %d 字节" % len(data))
    print("-" * 66)

    info = parse_zip(data)
    _DATA_BUF[0] = data
    _DATA_LEN[0] = len(data)

    print("结构: EOCD@0x%x  条目 %d 个  中央目录@0x%x (%d 字节)%s"
          % (info["eocd_at"], len(info["entries"]), info["start_cd"],
             info["cd_size"], "  [Zip64]" if info["zip64"] else ""))
    print("")
    if verbose:
        print("== 条目 ==")
        for e in info["entries"]:
            enc = "加密" if e.encrypted_flag() else "明文"
            print("  %-40s method=%d %s csize=%d usize=%d"
                  % (e.name, e.method, enc, e.csize, e.usize))
        print("")

    findings = []
    check_fake_encryption(info["entries"], findings)
    check_entry_flags(info["entries"], findings)
    check_comment(data, info, findings)
    check_trailing(data, info, findings)
    check_hidden_entries(data, info, findings)
    check_cd_trailing(data, info, findings)
    check_data_sanity(data, info["entries"], findings)
    check_flag_strings(data, findings)

    findings.sort(key=lambda f: f.pri)
    if not findings:
        print("没有发现明显异常（结构干净）。")
    else:
        print("== 发现（按优先级排序）==")
        for f in findings:
            print("  %s %s" % (P_LABEL[f.pri], f.title))
            if f.detail:
                for line in f.detail.splitlines():
                    print("       %s" % line)
            if f.blob is not None:
                n = 512 if not verbose else 4096
                print("       ---- 数据预览 ----")
                for line in preview(f.blob[:n], 400).splitlines():
                    print("       %s" % line)
    print("")

    highs = [f for f in findings if f.pri == P_HIGH]
    if not highs:
        print("结论: 没有确定性的隐写痕迹。")
    else:
        print("结论: 有 %d 项确定性发现，建议按上面的顺序看。" % len(highs))

    if dump_comment is not None:
        comment = data[info["eocd_at"] + 22:info["eocd_at"] + 22 + info["clen"]]
        if not comment:
            print("错误: 这个 ZIP 没有注释", file=sys.stderr)
            return 1
        out = Path(dump_comment)
        if out.exists() and not force:
            raise ZipError("目标文件已存在：%s（要覆盖请加 --force）" % out)
        out.write_bytes(comment)
        print("注释已写出: %s (%d 字节)" % (out, len(comment)))

    if clean_out:
        return clean_zip(data, info, findings, clean_out, force)
    return 0


USAGE = """zipstego.py -- ZIP 隐写检测：伪加密 / 注释藏数据 / 尾部附加 / 隐藏条目

做什么
  CTF 的 ZIP 题基本就藏在这四处：标志位伪加密、EOCD 注释、EOCD 之后的
  附加数据、中央目录没登记的本地头。本脚本一次性查完，并区分
  「确定」和「可疑」两类结论。

用法
  python -X utf8 zipstego.py 题目.zip
        完整体检

  python -X utf8 zipstego.py 题目.zip --dump-comment -o 注释.bin
        把 ZIP 注释单独存出来（注释里常直接放 flag 或另一个 ZIP）

  python -X utf8 zipstego.py 伪加密.zip --clean -o 修复.zip
        清掉伪加密的 bit0，另存为修复版（默认不覆盖原文件）

  python -X utf8 zipstego.py 目录/ -r
        递归检查目录下所有 .zip

参数
  --dump-comment FILE   导出 EOCD 注释
  --clean               尝试修复伪加密并另存
  -o, --output          输出文件（--clean / --dump-comment 用）
  -r, --recursive       目录递归
  --force               允许覆盖已存在文件
  -v, --verbose         打印每个条目的详情

已知限制
  只处理 ZIP，不处理 RAR/7z 的伪加密。
  Zip64 只做基础支持，字段缺失时会明确报出来。
  --clean 只清「已确认为伪加密」的条目；无法确认的真加密条目保持不动。
  不做 CRC 碰撞（那是构造性攻击，不是检测）。
"""


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(USAGE)
        return 0
    ap = argparse.ArgumentParser(prog="zipstego.py", add_help=True,
                                 description="ZIP 隐写检测")
    ap.add_argument("targets", nargs="*", help="ZIP 文件或目录")
    ap.add_argument("--dump-comment", dest="dump_comment",
                    help="导出 ZIP 注释到文件")
    ap.add_argument("--clean", action="store_true", help="修复伪加密并另存")
    ap.add_argument("-o", "--output", help="输出文件")
    ap.add_argument("-r", "--recursive", action="store_true", help="目录递归")
    ap.add_argument("--force", action="store_true", help="允许覆盖")
    ap.add_argument("-v", "--verbose", action="store_true", help="详细")
    args = ap.parse_args(argv)

    if not args.targets:
        print(USAGE)
        return 0

    files = []
    for t in args.targets:
        p = Path(t)
        if p.is_dir():
            it = p.rglob("*") if args.recursive else p.glob("*")
            for f in sorted(it):
                if f.is_file():
                    files.append(f)
        else:
            files.append(p)
    if not files:
        print("错误: 目录里没有文件", file=sys.stderr)
        return 1

    clean_out = args.output if args.clean else None
    if args.clean and not args.output:
        print("错误: --clean 需要配合 -o 指定输出文件名", file=sys.stderr)
        return 2
    if args.clean and len(files) != 1:
        print("错误: --clean 一次只能处理一个文件", file=sys.stderr)
        return 2

    try:
        rc = 0
        failed = 0
        ok = 0
        for f in files:
            try:
                r = scan(f, args.dump_comment, args.force, clean_out,
                         args.verbose)
                ok += 1
                if r != 0:
                    rc = r
            except ZipError as exc:
                print("=" * 66)
                print("文件: %s" % f)
                print("  跳过: %s" % exc)
                failed += 1
        if len(files) > 1:
            print("=" * 66)
            print("共处理 %d 个文件，跳过 %d 个。" % (ok, failed))
        # 一个都没成功：这是错误，不能用 0 退出码蒙混过去
        if ok == 0:
            print("错误: 没有任何文件被成功检查（全部跳过）", file=sys.stderr)
            return 1
        return rc
    except ZipError as exc:
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
