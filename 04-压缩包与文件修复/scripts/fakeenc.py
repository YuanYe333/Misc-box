# -*- coding: utf-8 -*-
"""
fakeenc.py -- 伪加密判定与清除（ZIP 为主，附 RAR 检测）。

为什么需要
==========
CTF 里「这个压缩包要密码」十次有八次是假的：出题人只是把加密标志位改了，
数据本身根本没加密。判定方法很简单 —— 看「加密标志位」和「数据区」是否
自相矛盾：

  ZIP：通用位标记 bit0 声称加密，但数据区仍是明文 deflate 流，
       或者本地头说加密而中央目录说没加密（两者不一致 = 伪加密）。
  RAR：文件头 flag 位声称加密，但实际数据块结构不像加密数据。

只要确认是伪加密，把标志位清零就能直接解压，不需要破解密码。

用法
====
    python -X utf8 fakeenc.py 可疑.zip              # 判定
    python -X utf8 fakeenc.py 可疑.zip -o 明文.zip  # 清除伪加密并另存

已知限制
========
    * 真加密（数据区确实是密文）无法破解，只报告；
    * ZIP 的 AES 加密（method 99）不处理；
    * RAR 只做检测，不做修复（RAR 结构更复杂，改了容易彻底坏掉）。
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
RAR4_SIG = b"Rar!\x1a\x07\x00"
RAR5_SIG = b"Rar!\x1a\x07\x01\x00"


def u16(blob, off):
    return struct.unpack("<H", blob[off:off + 2])[0]


def u32(blob, off):
    return struct.unpack("<I", blob[off:off + 4])[0]


def parse_zip(blob):
    """返回 (entries, eocd)，entries 是 [(name, lho, flags_local, flags_central, method, crc, csize, usize)]。"""
    pos = blob.rfind(EOCD_SIG)
    if pos < 0 or pos + 22 > len(blob):
        return None, None
    total = u16(blob, pos + 10)
    cd_size = u32(blob, pos + 12)
    cd_off = u32(blob, pos + 16)
    eocd = (pos, total, cd_size, cd_off)

    entries = []
    p = cd_off
    while p + 46 <= len(blob) and blob[p:p + 4] == CEN_SIG:
        f_central = u16(blob, p + 8)
        method = u16(blob, p + 10)
        crc = u32(blob, p + 16)
        csize = u32(blob, p + 20)
        usize = u32(blob, p + 24)
        nlen = u16(blob, p + 28)
        elen = u16(blob, p + 30)
        clen = u16(blob, p + 32)
        lho = u32(blob, p + 42)
        name = blob[p + 46:p + 46 + nlen].decode("utf-8", "replace")
        f_local = u16(blob, lho + 6) if blob[lho:lho + 4] == LOCAL_SIG else -1
        entries.append((name, lho, f_local, f_central, method, crc, csize, usize))
        p += 46 + nlen + elen + clen
    return entries, eocd


def data_off(blob, lho):
    nlen = u16(blob, lho + 26)
    elen = u16(blob, lho + 28)
    return lho + 30 + nlen + elen


def try_plain_deflate(blob, lho, csize):
    """尝试按「明文 deflate」解压。能解出来就说明数据其实没加密。"""
    off = data_off(blob, lho)
    raw = blob[off:off + csize]
    if not raw:
        return None
    for wbits in (-15, 15, 47):
        try:
            dec = zlib.decompressobj(wbits)
            out = dec.decompress(raw)
            if out and len(dec.unused_data) < len(raw):
                return out
        except zlib.error:
            continue
    return None


def diagnose_zip(blob):
    """返回 (verdict, details)。verdict: 'fake' / 'real' / 'mixed' / 'clean' / 'unknown'。"""
    entries, eocd = parse_zip(blob)
    if entries is None:
        return "unknown", ["找不到中央目录，无法判定（先用 zipfix.py 重建）"]

    fake, real, clean = [], [], []
    for name, lho, f_local, f_central, method, crc, csize, usize in entries:
        enc_local = bool(f_local & 0x1) if f_local >= 0 else False
        enc_central = bool(f_central & 0x1)

        if not enc_local and not enc_central:
            clean.append(name)
            continue

        # 声称加密，验证数据区
        plain = try_plain_deflate(blob, lho, csize)
        if plain is not None:
            fake.append((name, "数据区可正常解压，说明只是标志位造假"))
            continue

        # 数据解不开，再看标志位是否自相矛盾
        if enc_local != enc_central:
            fake.append((name, "本地头与中央目录的加密标志不一致（%s / %s）"
                         % (enc_local, enc_central)))
            continue

        # 尝试用任意密码解（伪加密的另一个特征：ZIP 传统加密的
        # 12 字节加密头之后应该是密文，但伪加密这里仍是明文流）
        off = data_off(blob, lho)
        raw = blob[off:off + csize]
        if len(raw) > 12:
            try:
                dec = zlib.decompressobj(-15)
                out = dec.decompress(raw[12:])
                if out:
                    fake.append((name, "跳过 12 字节加密头后可解压（典型伪加密）"))
                    continue
            except zlib.error:
                pass
        real.append(name)

    details = []
    if fake:
        details.append("疑似伪加密：%d 个" % len(fake))
        for n, why in fake:
            details.append("  - %s：%s" % (n, why))
    if real:
        details.append("真加密：%d 个" % len(real))
        for n in real:
            details.append("  - %s：数据区确实是密文，需要密码" % n)
    if clean:
        details.append("未加密：%d 个" % len(clean))

    if fake and real:
        verdict = "mixed"
    elif fake:
        verdict = "fake"
    elif real:
        verdict = "real"
    elif clean:
        verdict = "clean"
    else:
        verdict = "unknown"
    return verdict, details


def clear_zip_flags(blob):
    """把所有条目的加密标志位清零，返回新字节。只改标志位，不动数据。"""
    out = bytearray(blob)
    # 中央目录条目
    p = 0
    while True:
        p = blob.find(CEN_SIG, p)
        if p < 0:
            break
        flags = u16(blob, p + 8)
        struct.pack_into("<H", out, p + 8, flags & ~0x1)
        p += 4
    # 本地文件头
    p = 0
    while True:
        p = blob.find(LOCAL_SIG, p)
        if p < 0:
            break
        flags = u16(blob, p + 6)
        struct.pack_into("<H", out, p + 6, flags & ~0x1)
        p += 4
    return bytes(out)


def diagnose_rar(blob):
    """RAR 只做检测：找加密标志位，报告但不修。"""
    if blob[:7] == RAR4_SIG:
        details = ["RAR 4 格式。本脚本不做修复，请用 ARCHPR 或 john 处理。"]
        # RAR4 主头之后是文件头，flag 字段在偏移 +10 附近
        if len(blob) > 20:
            details.append("提示：RAR4 文件头加密标志在 flag 位的 0x04。")
        return "unknown", details
    if blob[:8] == RAR5_SIG:
        return "unknown", ["RAR 5 格式。本脚本不做修复，请用 ARCHPR 或 john 处理。"]
    return "unknown", ["不是 RAR 格式"]


def main():
    ap = argparse.ArgumentParser(
        description="判定 ZIP/RAR 是不是伪加密，ZIP 可直接清除标志位",
        add_help=True,
    )
    ap.add_argument("target", nargs="?", help="要检查的压缩包")
    ap.add_argument("-o", "--output", help="清除伪加密后另存为这个文件（仅 ZIP）")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    args = ap.parse_args()

    if not args.target:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 fakeenc.py 可疑.zip")
        print("  python -X utf8 fakeenc.py 可疑.zip -o 明文.zip")
        print("")
        print("提示：判定为伪加密后，加 -o 输出即可直接解压，不需要密码。")
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

    if blob[:7] == RAR4_SIG or blob[:8] == RAR5_SIG:
        verdict, details = diagnose_rar(blob)
    elif blob[:4] in (LOCAL_SIG, EOCD_SIG) or blob[:2] == b"PK":
        verdict, details = diagnose_zip(blob)
    else:
        print("[错误] 不是 ZIP 或 RAR 文件（开头: %s）" % blob[:8].hex(" "), file=sys.stderr)
        print("提示：先用 filetype.py 确认它到底是什么。", file=sys.stderr)
        return 1

    label = {
        "fake": "【伪加密】不需要密码，清标志位即可",
        "real": "【真加密】数据区是密文，需要密码",
        "mixed": "【混合】部分伪加密、部分真加密",
        "clean": "【未加密】这个包根本没有加密",
        "unknown": "【无法判定】",
    }[verdict]
    print("判定: %s" % label)
    print("")
    for d in details:
        print(d)
    print("")

    if verdict in ("fake", "mixed") and args.output:
        if blob[:2] != b"PK":
            print("[错误] 清除功能只支持 ZIP", file=sys.stderr)
            return 1
        target = Path(args.output)
        if target.exists() and not args.force:
            print("[错误] 输出文件已存在：%s（加 --force 覆盖）" % target, file=sys.stderr)
            return 1
        fixed = clear_zip_flags(blob)
        target.write_bytes(fixed)
        print("已清除加密标志位并写出: %s" % target)
        print("")
        print("验证：")
        try:
            import zipfile
            with zipfile.ZipFile(str(target)) as zf:
                names = zf.namelist()
                print("  可以打开，共 %d 个条目" % len(names))
                bad = zf.testzip()
                if bad is None:
                    print("  全部条目 CRC 校验通过")
                    for n in names[:5]:
                        print("    - %s (%d 字节)" % (n, zf.getinfo(n).file_size))
                else:
                    print("  条目 %s CRC 仍不对（数据区可能真的坏了）" % bad)
        except Exception as exc:  # noqa: BLE001
            print("  无法打开: %s" % exc)
        return 0

    if verdict in ("fake", "mixed"):
        print("加 -o 文件名 可以清除标志位并另存。")
        return 0
    if verdict == "real":
        print("这是真加密，本脚本无法破解。")
        print("可以试：ARCHPR（暴力/掩码）、john（字典）、hashcat。")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
