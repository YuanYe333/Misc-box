# -*- coding: utf-8 -*-
"""
deleted.py -- NTFS 已删除文件枚举（直接解析 $MFT，只读）。

为什么需要
==========
取证里最常问的一句话是「这个盘上原来有什么、被删了什么」。
Windows 删文件只是把 MFT 记录标记为「未使用」，文件名、大小、
时间戳往往还留在原处，直到被新文件覆盖。

本脚本直接读 NTFS 的 $MFT（主文件表），把标记为删除的记录列出来：
文件名、原始大小、创建/修改时间、是否还能恢复数据。

用法
====
    # 需要管理员权限（直接读卷）
    python -X utf8 deleted.py --drive D
    python -X utf8 deleted.py --drive D --csv 已删除.csv
    # 也可以给一个 MFT 的镜像文件
    python -X utf8 deleted.py --mft MFT.dd

已知限制
========
    * 只解析 $MFT 的记录头与 $FILE_NAME / $DATA 属性，不做完整属性解析；
    * **不恢复数据**，只报告「数据簇是否仍可能有效」；
    * 需要原始设备读取权限（管理员），否则会明确报错；
    * 只支持 NTFS，FAT/exFAT 不适用。
"""

import argparse
import csv
import struct
import sys
from datetime import datetime, timedelta
from pathlib import Path

MFT_RECORD_SIZE = 1024
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF

# NTFS 时间戳是 1601-01-01 起的 100 纳秒数
EPOCH_DIFF = 116444736000000000


def filetime_to_dt(ft):
    """NTFS FILETIME 转 datetime。"""
    if ft == 0:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10.0)
    except (OverflowError, ValueError):
        return None


def fmt_dt(dt):
    if dt is None:
        return "(无)"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


class Record(object):
    def __init__(self):
        self.number = 0
        self.in_use = False
        self.is_dir = False
        self.name = ""
        self.parent = 0
        self.size = 0
        self.alloc_size = 0
        self.mtime = None
        self.ctime = None
        self.atime = None
        self.entry_time = None
        self.has_data = False


def apply_fixup(buf, sector_size=512):
    """应用 update sequence array 修复，返回修好的字节。

    NTFS 每条记录末尾的 USA 会把每个扇区最后两字节替换成序列号，
    读的时候必须换回来，否则数据是错的。
    """
    if len(buf) < 48:
        return buf
    usa_off = struct.unpack_from("<H", buf, 4)[0]
    usa_count = struct.unpack_from("<H", buf, 6)[0]
    if usa_count == 0 or usa_off + usa_count * 2 > len(buf):
        return buf
    usa = buf[usa_off:usa_off + usa_count * 2]
    usn = usa[0:2]
    out = bytearray(buf)
    for i in range(1, usa_count):
        pos = i * sector_size - 2
        if pos + 2 > len(out):
            break
        # 校验：该位置应当等于 USN
        if bytes(out[pos:pos + 2]) != usn:
            # 不匹配说明记录损坏，仍尽力修复
            pass
        out[pos:pos + 2] = usa[i * 2:i * 2 + 2]
    return bytes(out)


def parse_record(buf, number):
    """解析一条 MFT 记录，返回 Record 或 None。"""
    if len(buf) < 48 or buf[:4] != b"FILE":
        return None
    rec = Record()
    rec.number = number

    flags = struct.unpack_from("<H", buf, 22)[0]
    rec.in_use = bool(flags & 0x1)
    rec.is_dir = bool(flags & 0x2)

    attr_off = struct.unpack_from("<H", buf, 20)[0]
    pos = attr_off
    while pos + 8 <= len(buf):
        try:
            atype, alen = struct.unpack_from("<II", buf, pos)
        except struct.error:
            break
        if atype == ATTR_END or alen == 0:
            break
        if alen < 8 or pos + alen > len(buf):
            break
        non_resident = buf[pos + 8]
        name_len = buf[pos + 9]
        name_off = struct.unpack_from("<H", buf, pos + 10)[0]

        if atype == ATTR_FILE_NAME and not non_resident:
            # 常驻属性：内容就在记录里
            content_len = struct.unpack_from("<I", buf, pos + 16)[0]
            content_off = struct.unpack_from("<H", buf, pos + 20)[0]
            cstart = pos + content_off
            if cstart + content_len <= len(buf) and content_len >= 66:
                try:
                    parent = struct.unpack_from("<Q", buf, cstart)[0] & 0xFFFFFFFFFFFF
                    rec.parent = parent
                    rec.ctime = filetime_to_dt(struct.unpack_from("<Q", buf, cstart + 8)[0])
                    rec.atime = filetime_to_dt(struct.unpack_from("<Q", buf, cstart + 16)[0])
                    rec.mtime = filetime_to_dt(struct.unpack_from("<Q", buf, cstart + 24)[0])
                    rec.entry_time = filetime_to_dt(struct.unpack_from("<Q", buf, cstart + 32)[0])
                    rec.alloc_size = struct.unpack_from("<Q", buf, cstart + 40)[0]
                    rec.size = struct.unpack_from("<Q", buf, cstart + 48)[0]
                    fn_len = buf[cstart + 64]
                    if cstart + 66 + fn_len * 2 <= len(buf):
                        raw = buf[cstart + 66:cstart + 66 + fn_len * 2]
                        rec.name = raw.decode("utf-16-le", "replace")
                except struct.error:
                    pass
        elif atype == ATTR_DATA:
            rec.has_data = True
            if non_resident and pos + 64 <= len(buf):
                try:
                    # 非驻留 $DATA 的真实大小在 +48
                    rec.size = struct.unpack_from("<Q", buf, pos + 48)[0]
                except struct.error:
                    pass
        pos += alen
    return rec


def iter_records(data):
    """从原始 MFT 字节流里逐条产出 Record。"""
    n = len(data) // MFT_RECORD_SIZE
    for i in range(n):
        raw = data[i * MFT_RECORD_SIZE:(i + 1) * MFT_RECORD_SIZE]
        if raw[:4] != b"FILE":
            continue
        fixed = apply_fixup(raw)
        rec = parse_record(fixed, i)
        if rec is None:
            continue
        yield rec


def read_drive(drive_letter):
    """直接读卷。Windows 上需要管理员权限。"""
    path = "\\\\.\\%s:" % drive_letter.upper().rstrip(":")
    try:
        fh = open(path, "rb")
    except OSError as exc:
        raise RuntimeError(
            "无法打开卷 %s（%s）。\n"
            "这通常是因为没有管理员权限。请用管理员身份运行本脚本。\n"
            "或者：先用取证工具把磁盘镜像出来，再用 --mft 指定 MFT 文件。" % (path, exc)
        )
    try:
        # 读 NTFS 引导扇区，拿到 MFT 起始簇与簇大小
        fh.seek(0)
        boot = fh.read(512)
        if len(boot) < 512 or boot[3:11] != b"NTFS    ":
            raise RuntimeError("这不是 NTFS 卷（引导扇区签名不对）。本脚本只支持 NTFS。")
        bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
        sectors_per_cluster = boot[13]
        if sectors_per_cluster == 0:
            raise RuntimeError("簇大小字段异常（0），无法继续。")
        cluster_size = bytes_per_sector * sectors_per_cluster
        mft_lcn = struct.unpack_from("<Q", boot, 48)[0]
        mft_offset = mft_lcn * cluster_size
        # 读 MFT 大小：从 $MFT 自己的记录里取，简化起见读一个上限
        total_size = struct.unpack_from("<Q", boot, 40)[0]
        if total_size == 0:
            total_size = 256 * 1024 * 1024
        # 读整个 MFT（最多 512MB，防止爆内存）
        read_size = min(total_size, 512 * 1024 * 1024)
        fh.seek(mft_offset)
        data = fh.read(read_size)
        return data, cluster_size, mft_offset
    finally:
        fh.close()


def main():
    ap = argparse.ArgumentParser(
        description="枚举 NTFS 已删除文件（解析 $MFT，只读，不恢复数据）",
        add_help=True,
    )
    ap.add_argument("--drive", help="盘符，如 D 或 D:")
    ap.add_argument("--mft", help="MFT 镜像文件（如果已用取证工具导出）")
    ap.add_argument("--csv", help="输出 CSV")
    ap.add_argument("--limit", type=int, default=0, help="最多显示多少条（0 = 全部）")
    ap.add_argument("--deleted-only", action="store_true", default=True,
                    help="只显示已删除的（默认）")
    ap.add_argument("--all", action="store_true", help="显示所有记录（含未删除的）")
    args = ap.parse_args()

    if not args.drive and not args.mft:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 deleted.py --drive D")
        print("  python -X utf8 deleted.py --mft MFT.dd --csv 已删除.csv")
        print("")
        print("注意：--drive 需要管理员权限；只读，不会修改磁盘任何内容。")
        print("      本脚本只列出记录，不恢复文件数据。")
        return 0

    if args.mft:
        p = Path(args.mft)
        if not p.is_file():
            print("[错误] 文件不存在: %s" % p, file=sys.stderr)
            return 1
        data = p.read_bytes()
        print("读取 MFT 镜像: %s (%d 字节)" % (p.name, len(data)))
        mft_offset = 0
    else:
        letter = args.drive.strip().rstrip(":\\")
        if len(letter) != 1 or not letter.isalpha():
            print("[错误] --drive 只接受单个盘符，如 D", file=sys.stderr)
            return 1
        try:
            data, cluster_size, mft_offset = read_drive(letter)
        except RuntimeError as exc:
            print("[错误] %s" % exc, file=sys.stderr)
            return 1
        print("读取卷 %s: MFT 位于 0x%X，簇大小 %d 字节，读到 %d 字节"
              % (letter.upper(), mft_offset, cluster_size, len(data)))

    print("")

    total = 0
    deleted = []
    live = []
    for rec in iter_records(data):
        total += 1
        if not rec.name:
            continue
        if rec.in_use:
            live.append(rec)
            continue
        deleted.append(rec)

    print("解析了 %d 条 MFT 记录（在用 %d 条，已删除且有文件名 %d 条）。"
          % (total, len(live), len(deleted)))
    print("")

    if not deleted and not args.all:
        print("没有找到已删除的记录。")
        print("可能原因：")
        print("  - 这个卷的 MFT 被大量覆盖（删除太久）")
        print("  - 不是 NTFS 卷")
        print("  - 权限不足只读到很少的数据")
        return 0

    # --all 时把在用的记录也一起列出（排在后面）
    if args.all:
        deleted = deleted + live

    # 按删除时间（这里用 mtime 近似）排序，最近的在前
    deleted.sort(key=lambda r: (r.mtime or datetime(1900, 1, 1)), reverse=True)

    print("%-6s %-19s %10s  %s" % ("记录", "修改时间", "大小", "文件名"))
    print("-" * 90)

    show = deleted if args.limit <= 0 else deleted[:args.limit]
    for r in show:
        mark = "[目录]" if r.is_dir else "      "
        print("%-6d %-19s %10d  %s %s" % (r.number, fmt_dt(r.mtime), r.size, mark, r.name))

    if args.limit > 0 and len(deleted) > args.limit:
        print("...")
        print("（只显示前 %d 条，共 %d 条）" % (args.limit, len(deleted)))

    print("")
    print("提示：这些是「MFT 记录还在」的已删除文件。数据簇是否还能恢复")
    print("      取决于是否已被覆盖，需要专门的恢复工具（如 TestDisk/Recuva）。")

    if args.csv:
        try:
            with open(args.csv, "w", encoding="utf-8-sig", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["record", "name", "size", "is_dir", "mtime", "ctime", "atime", "parent"])
                for r in deleted:
                    w.writerow([r.number, r.name, r.size, r.is_dir,
                                fmt_dt(r.mtime), fmt_dt(r.ctime), fmt_dt(r.atime), r.parent])
            print("")
            print("CSV 已写出: %s" % args.csv)
        except OSError as exc:
            print("[错误] 写 CSV 失败: %s" % exc, file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
