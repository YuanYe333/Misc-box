# -*- coding: utf-8 -*-
"""
timeline.py -- 文件系统时间线（按修改/访问/创建时间排序）。

为什么需要
==========
取证题经常问「哪个文件最先被创建」「这个文件在什么时候被改过」
「按时间顺序还原操作过程」。资源管理器只能一个文件夹一个文件夹地看，
没法跨目录排序，也看不到访问时间（atime）。

本脚本把指定目录下所有文件的时间戳汇总成一条时间线，支持：
  * 按 mtime（修改）/ atime（访问）/ ctime（Windows 创建时间）排序；
  * 过滤时间区间（只关心某个时间段的操作）；
  * 输出 CSV 便于后续分析。

用法
====
    python -X utf8 timeline.py 目录
    python -X utf8 timeline.py 目录 --sort atime
    python -X utf8 timeline.py 目录 --since 2026-01-01 --until 2026-12-31
    python -X utf8 timeline.py 目录 --csv 时间线.csv

已知限制
========
    * 只读文件系统元数据，不解析 NTFS 的 $STANDARD_INFORMATION / $FILE_NAME
      双时间戳（那需要直接读 MFT，见 deleted.py）；
    * Windows 的 ctime 是「创建时间」，Linux 的 ctime 是「inode 变更时间」，
      含义不同，本脚本按平台标注；
    * 时间戳可被程序伪造，不能作为唯一证据。
"""

import argparse
import csv
import os
import sys
import time
from datetime import datetime
from pathlib import Path


def fmt_ts(ts):
    """时间戳转可读字符串；无效值给占位符。"""
    if ts is None or ts <= 0:
        return "(无)"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "(无效)"


def parse_date(text):
    """解析 --since/--until 参数，返回时间戳。"""
    text = text.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d", "%Y%m%d"):
        try:
            return time.mktime(datetime.strptime(text, fmt).timetuple())
        except ValueError:
            continue
    raise ValueError("无法解析日期: %s（请用 2026-01-01 或 2026-01-01 12:00:00）" % text)


def collect(root, recursive=True, follow_links=False):
    """收集文件条目。返回 [(路径, size, mtime, atime, ctime)]。"""
    out = []
    root = Path(root)
    if root.is_file():
        st = root.stat()
        return [(root, st.st_size, st.st_mtime, st.st_atime, st.st_ctime)]

    walker = os.walk(root, followlinks=follow_links) if recursive else [(str(root), [], [p.name for p in root.iterdir()])]
    for dirpath, dirnames, filenames in walker:
        if not recursive:
            dirnames[:] = []
        for name in filenames:
            p = Path(dirpath) / name
            try:
                st = p.stat()
            except OSError:
                continue
            out.append((p, st.st_size, st.st_mtime, st.st_atime, st.st_ctime))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="生成文件系统时间线（按 mtime/atime/ctime 排序）",
        add_help=True,
    )
    ap.add_argument("target", nargs="?", help="目录或文件")
    ap.add_argument("--sort", default="mtime", choices=["mtime", "atime", "ctime"],
                    help="按哪个时间排序（默认 mtime 修改时间）")
    ap.add_argument("--since", help="只显示这个时间之后的（如 2026-01-01）")
    ap.add_argument("--until", help="只显示这个时间之前的")
    ap.add_argument("--no-recursive", action="store_true", help="不递归子目录")
    ap.add_argument("--csv", help="同时写出 CSV 文件")
    ap.add_argument("--limit", type=int, default=0, help="最多显示多少条（0 = 全部）")
    args = ap.parse_args()

    if not args.target:
        ap.print_help()
        print("")
        print("例子：")
        print("  python -X utf8 timeline.py 目录")
        print("  python -X utf8 timeline.py 目录 --sort atime")
        print("  python -X utf8 timeline.py 目录 --since 2026-01-01 --csv 时间线.csv")
        print("")
        print("说明：Windows 上 ctime 是「创建时间」，Linux 上是「inode 变更时间」。")
        return 0

    p = Path(args.target)
    if not p.exists():
        print("[错误] 路径不存在: %s" % p, file=sys.stderr)
        return 1

    try:
        since = parse_date(args.since) if args.since else None
        until = parse_date(args.until) if args.until else None
    except ValueError as exc:
        print("[错误] %s" % exc, file=sys.stderr)
        return 1

    entries = collect(p, recursive=not args.no_recursive)
    if not entries:
        print("[错误] 没有找到任何文件", file=sys.stderr)
        return 1

    # 按选定的时间字段排序
    idx = {"mtime": 2, "atime": 3, "ctime": 4}[args.sort]
    entries.sort(key=lambda e: e[idx])

    # 时间过滤
    if since is not None:
        entries = [e for e in entries if e[idx] >= since]
    if until is not None:
        entries = [e for e in entries if e[idx] <= until]

    if not entries:
        print("过滤后没有符合条件的文件。")
        print("提示：检查 --since/--until 的格式与范围。")
        return 0

    print("目录: %s" % p)
    print("共 %d 个文件，按 %s 排序" % (len(entries), args.sort))
    if since or until:
        print("时间范围: %s ~ %s" % (fmt_ts(since) if since else "不限",
                                     fmt_ts(until) if until else "不限"))
    print("")

    # 时间跨度提示
    first = entries[0][idx]
    last = entries[-1][idx]
    print("跨度: %s  ~  %s" % (fmt_ts(first), fmt_ts(last)))
    print("")
    print("%-19s  %-19s  %-19s  %10s  %s" % ("修改时间", "访问时间", "创建时间", "大小", "文件"))
    print("-" * 100)

    show = entries if args.limit <= 0 else entries[:args.limit]
    for path, size, mtime, atime, ctime in show:
        try:
            rel = path.relative_to(p) if p.is_dir() else path.name
        except ValueError:
            rel = path
        print("%-19s  %-19s  %-19s  %10d  %s" % (fmt_ts(mtime), fmt_ts(atime),
                                                 fmt_ts(ctime), size, rel))

    if args.limit > 0 and len(entries) > args.limit:
        print("...")
        print("（只显示前 %d 条，共 %d 条）" % (args.limit, len(entries)))

    # CSV 输出
    if args.csv:
        try:
            with open(args.csv, "w", encoding="utf-8-sig", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["mtime", "atime", "ctime", "size", "path"])
                for path, size, mtime, atime, ctime in entries:
                    w.writerow([fmt_ts(mtime), fmt_ts(atime), fmt_ts(ctime), size, str(path)])
            print("")
            print("CSV 已写出: %s（用 Excel 打开可做进一步排序筛选）" % args.csv)
        except OSError as exc:
            print("[错误] 写 CSV 失败: %s" % exc, file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
