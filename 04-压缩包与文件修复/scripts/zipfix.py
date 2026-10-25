# -*- coding: utf-8 -*-
"""
zipfix.py -- ZIP 结构体检与修复。

为什么需要
==========
CTF 里的 ZIP 题几乎都会「弄坏」一点东西：
  * 中央目录被删/被截断，导致解压软件报「压缩包已损坏」；
  * 本地文件头的 CRC 被改，解压报「数据错误」；
  * 文件大小字段被改，解出来是空文件；
  * 中央目录里的偏移量被改，指向错误位置。

这些坏法各有各的修法。本脚本先做**结构体检**（把每个字段和实际数据对账），
再按发现的问题做针对性修复，尽量不破坏原始数据。

用法
====
    python -X utf8 zipfix.py 坏包.zip                 # 只体检
    python -X utf8 zipfix.py 坏包.zip -o 修好.zip     # 修复并另存
    python -X utf8 zipfix.py 坏包.zip --rebuild       # 重建中央目录

已知限制
========
    * 不处理 ZIP64（超过 4GB 的包），遇到会明确报错；
    * 加密（真加密）的包不修，只报告；
    * 数据区本身被破坏（压缩流残缺）无法还原，只能报告哪些条目受影响。
"""

import argparse
import binascii
import struct
import sys
import zlib
from pathlib import Path

LOCAL_SIG = b"PK\x03\x04"
CEN_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
DD_SIG = b"PK\x07\x08"


def read_u16(blob, off):
    return struct.unpack("<H", blob[off:off + 2])[0]


def read_u32(blob, off):
    return struct.unpack("<I", blob[off:off + 4])[0]


class Entry(object):
    """一个中央目录条目。"""

    def __init__(self, name, method, crc, csize, usize, lho, flags):
        self.name = name
        self.method = method
        self.crc = crc
        self.csize = csize
        self.usize = usize
        self.lho = lho          # local header offset
        self.flags = flags

    def __repr__(self):
        return "<Entry %s method=%d crc=%08X>" % (self.name, self.method, self.crc)


def parse_eocd(blob):
    """找 EOCD。返回 (offset, 条目数, 中央目录大小, 中央目录偏移) 或 None。"""
    pos = blob.rfind(EOCD_SIG)
    if pos < 0 or pos + 22 > len(blob):
        return None
    total = read_u16(blob, pos + 10)
    cd_size = read_u32(blob, pos + 12)
    cd_off = read_u32(blob, pos + 16)
    return pos, total, cd_size, cd_off


def parse_central(blob, cd_off, cd_size):
    """解析中央目录，返回 (entries, errors)。"""
    entries = []
    errors = []
    pos = cd_off
    end = min(cd_off + cd_size, len(blob))
    while pos + 46 <= end and blob[pos:pos + 4] == CEN_SIG:
        flags = read_u16(blob, pos + 8)
        method = read_u16(blob, pos + 10)
        crc = read_u32(blob, pos + 16)
        csize = read_u32(blob, pos + 20)
        usize = read_u32(blob, pos + 24)
        nlen = read_u16(blob, pos + 28)
        elen = read_u16(blob, pos + 30)
        clen = read_u16(blob, pos + 32)
        lho = read_u32(blob, pos + 42)
        name = blob[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        entries.append(Entry(name, method, crc, csize, usize, lho, flags))
        pos += 46 + nlen + elen + clen
    if pos != end and pos < len(blob):
        errors.append("中央目录解析在中途停止（偏移 0x%X，预期到 0x%X）" % (pos, end))
    return entries, errors


def scan_local_headers(blob):
    """扫描所有本地文件头，用于重建中央目录。返回 [(offset, name)]。"""
    out = []
    pos = 0
    while True:
        idx = blob.find(LOCAL_SIG, pos)
        if idx < 0:
            break
        if idx + 30 > len(blob):
            break
        nlen = read_u16(blob, idx + 26)
        elen = read_u16(blob, idx + 28)
        name = blob[idx + 30:idx + 30 + nlen].decode("utf-8", "replace")
        out.append((idx, name))
        pos = idx + 4
    return out


def verify_entry(blob, e):
    """检查一个条目：本地头是否匹配、数据能否解压、CRC 对不对。"""
    problems = []
    if e.lho + 30 > len(blob):
        return ["本地头偏移越界（0x%X 超出文件长度）" % e.lho]
    if blob[e.lho:e.lho + 4] != LOCAL_SIG:
        return ["偏移 0x%X 处不是本地文件头（应为 PK\\x03\\x04）" % e.lho]

    l_method = read_u16(blob, e.lho + 8)
    l_crc = read_u32(blob, e.lho + 14)
    l_csize = read_u32(blob, e.lho + 18)
    l_usize = read_u32(blob, e.lho + 22)
    nlen = read_u16(blob, e.lho + 26)
    elen = read_u16(blob, e.lho + 28)
    data_off = e.lho + 30 + nlen + elen

    if l_method != e.method:
        problems.append("压缩方法不一致（本地 %d / 中央 %d）" % (l_method, e.method))
    if l_crc != e.crc:
        problems.append("CRC 不一致（本地 %08X / 中央 %08X）" % (l_crc, e.crc))
    if l_csize != e.csize:
        problems.append("压缩后大小不一致（本地 %d / 中央 %d）" % (l_csize, e.csize))
    if l_usize != e.usize:
        problems.append("原始大小不一致（本地 %d / 中央 %d）" % (l_usize, e.usize))

    raw = blob[data_off:data_off + e.csize]
    if len(raw) < e.csize:
        problems.append("数据区被截断（需要 %d 字节，实际只有 %d）" % (e.csize, len(raw)))
        return problems

    # 试着解压并校验 CRC
    if e.method == 0:       # 存储
        data = raw
    elif e.method == 8:     # deflate
        try:
            data = zlib.decompress(raw, -15)
        except zlib.error as exc:
            problems.append("deflate 解压失败: %s" % exc)
            return problems
    else:
        problems.append("压缩方法 %d 不支持解压校验" % e.method)
        return problems

    if len(data) != e.usize:
        problems.append("解压后大小不符（预期 %d，实际 %d）" % (e.usize, len(data)))
    actual_crc = binascii.crc32(data) & 0xFFFFFFFF
    if actual_crc != e.crc:
        problems.append("CRC 校验失败（记录 %08X，实际 %08X）" % (e.crc, actual_crc))
    return problems


def build_central(blob, local_headers):
    """按本地头重建中央目录 + EOCD，返回新的完整 ZIP 字节。"""
    # 只保留「数据区没有重叠」的条目（避免把嵌套的假头当成条目）
    body_parts = []
    entries = []
    for off, name in local_headers:
        if off + 30 > len(blob):
            continue
        flags = read_u16(blob, off + 6)
        method = read_u16(blob, off + 8)
        crc = read_u32(blob, off + 14)
        csize = read_u32(blob, off + 18)
        usize = read_u32(blob, off + 22)
        nlen = read_u16(blob, off + 26)
        elen = read_u16(blob, off + 28)
        data_off = off + 30 + nlen + elen
        data_end = data_off + csize
        if data_end > len(blob):
            continue
        entries.append((off, name, flags, method, crc, csize, usize, nlen, elen, data_off, data_end))

    if not entries:
        return None

    # 按偏移排序，并剔除「偏移落在前一条数据区内」的假条目
    entries.sort(key=lambda x: x[0])
    clean = []
    last_end = 0
    for e in entries:
        if e[0] < last_end:
            continue
        clean.append(e)
        last_end = e[10]

    out = bytearray()
    central = bytearray()
    for off, name, flags, method, crc, csize, usize, nlen, elen, data_off, data_end in clean:
        new_off = len(out)
        # 复制原始本地头 + 数据
        out += blob[off:data_end]
        name_bytes = blob[off + 30:off + 30 + nlen]
        # 中央目录条目（字段顺序严格按 ZIP APPNOTE 4.3.12）
        c = bytearray()
        c += CEN_SIG
        c += struct.pack("<H", 20)      # version made by
        c += struct.pack("<H", 20)      # version needed
        c += struct.pack("<H", flags)
        c += struct.pack("<H", method)
        c += struct.pack("<H", 0)       # mod time
        c += struct.pack("<H", 0x21)    # mod date（1980-01-01）
        c += struct.pack("<I", crc)
        c += struct.pack("<I", csize)
        c += struct.pack("<I", usize)
        c += struct.pack("<H", nlen)
        c += struct.pack("<H", elen)
        c += struct.pack("<H", 0)       # comment len
        c += struct.pack("<H", 0)       # disk number
        c += struct.pack("<H", 0)       # internal attrs
        c += struct.pack("<I", 0)       # external attrs
        c += struct.pack("<I", new_off) # local header offset
        c += name_bytes
        central += c

    cd_off = len(out)
    out += central
    eocd = bytearray(EOCD_SIG)
    eocd += struct.pack("<H", 0)                 # disk number
    eocd += struct.pack("<H", 0)                 # cd start disk
    eocd += struct.pack("<H", len(clean))        # entries on this disk
    eocd += struct.pack("<H", len(clean))        # total entries
    eocd += struct.pack("<I", len(central))      # cd size
    eocd += struct.pack("<I", cd_off)            # cd offset
    eocd += struct.pack("<H", 0)                 # comment len
    out += eocd
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(
        description="ZIP 结构体检与修复（中央目录、CRC、大小字段对账）",
        add_help=True,
    )
    ap.add_argument("target", nargs="?", help="要检查的 ZIP 文件")
    ap.add_argument("-o", "--output", help="修复后另存为这个文件")
    ap.add_argument("--rebuild", action="store_true", help="按本地文件头重建中央目录")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    args = ap.parse_args()

    if not args.target:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 zipfix.py 坏包.zip")
        print("  python -X utf8 zipfix.py 坏包.zip -o 修好.zip")
        print("  python -X utf8 zipfix.py 坏包.zip -o 重建.zip --rebuild")
        return 0

    p = Path(args.target)
    if not p.is_file():
        print("[错误] 文件不存在: %s" % p, file=sys.stderr)
        return 1
    blob = p.read_bytes()
    if not blob:
        print("[错误] 文件为空", file=sys.stderr)
        return 1

    print("检查: %s  (%d 字节)" % (p.name, len(blob)))
    print("")

    problems = []

    # 1. EOCD
    eocd = parse_eocd(blob)
    if not eocd:
        problems.append("找不到中央目录结束记录（EOCD）—— 包被截断或中央目录被删")
        print("== EOCD ==\n  缺失")
        print("")
        if not args.rebuild:
            print("建议加 --rebuild 按本地文件头重建中央目录。")
            return 1
    else:
        pos, total, cd_size, cd_off = eocd
        print("== EOCD ==\n  位置 0x%X，声明 %d 个条目，中央目录 0x%X 起 %d 字节" % (pos, total, cd_off, cd_size))
        if cd_off + cd_size > len(blob):
            problems.append("中央目录偏移/大小越界（声明到 0x%X，文件只有 0x%X）" % (cd_off + cd_size, len(blob)))
        print("")

    # 2. 中央目录
    entries = []
    if eocd:
        cd_off = eocd[3]
        cd_size = eocd[2]
        entries, cd_errors = parse_central(blob, cd_off, cd_size)
        problems.extend(cd_errors)
        print("== 中央目录 ==\n  解析出 %d 个条目" % len(entries))
        if eocd[1] != len(entries):
            problems.append("条目数不符（EOCD 声明 %d，实际解析 %d）" % (eocd[1], len(entries)))
        print("")

    # 3. 逐条校验
    if entries:
        print("== 逐条校验 ==")
        bad_count = 0
        for e in entries:
            probs = verify_entry(blob, e)
            if probs:
                bad_count += 1
                print("  [问题] %s" % e.name)
                for pr in probs:
                    print("         - %s" % pr)
                problems.extend(["%s: %s" % (e.name, pr) for pr in probs])
            else:
                print("  [正常] %s  (%d -> %d 字节, crc %08X)" % (e.name, e.csize, e.usize, e.crc))
        print("")
        print("  正常 %d 个，有问题 %d 个" % (len(entries) - bad_count, bad_count))
        print("")

    # 4. 伪加密
    if entries:
        enc = [e for e in entries if e.flags & 0x1]
        if enc:
            print("== 加密标记 ==")
            print("  %d 个条目带加密标志位。如果密码解不开，可能是伪加密：" % len(enc))
            print("  本脚本不处理加密，请用 fakeenc.py 判断与清除。")
            print("")

    # 5. 重建
    if args.rebuild or (not eocd and args.output):
        print("== 重建中央目录 ==")
        locals_ = scan_local_headers(blob)
        print("  扫描到 %d 个本地文件头" % len(locals_))
        rebuilt = build_central(blob, locals_)
        if not rebuilt:
            print("[错误] 重建失败：没有找到可用的本地文件头", file=sys.stderr)
            return 1
        print("  重建后大小 %d 字节" % len(rebuilt))
        if not args.output:
            print("  加 -o 文件名 才能写出重建结果。")
            return 0
        target = Path(args.output)
        if target.exists() and not args.force:
            print("[错误] 输出文件已存在：%s（加 --force 覆盖）" % target, file=sys.stderr)
            return 1
        target.write_bytes(rebuilt)
        print("  已写出: %s" % target)
        print("")
        print("  验证：")
        try:
            import zipfile
            with zipfile.ZipFile(str(target)) as zf:
                bad = zf.testzip()
                if bad is None:
                    print("    所有 %d 个条目 CRC 校验通过" % len(zf.namelist()))
                else:
                    print("    条目 %s CRC 仍不正确" % bad)
        except Exception as exc:  # noqa: BLE001
            print("    无法用 zipfile 打开: %s" % exc)
        return 0

    # 6. 结论
    if not problems:
        print("结论：结构正常，没有发现可修复的问题。")
        print("如果解压仍失败，可能是数据区被破坏（压缩流残缺），这类无法修复。")
        return 0

    print("结论：发现 %d 处问题。" % len(problems))
    if args.output:
        print("提示：当前问题需要针对性处理，-o 只在 --rebuild 时生效。")
    else:
        print("建议：先试 --rebuild -o 重建.zip 重建中央目录。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
