# -*- coding: utf-8 -*-
"""envcheck.py —— 工具箱环境体检。

下载仓库后第一件事：跑一遍，看看这台机器缺什么、哪些工具能用。
纯标准库、只读探测、不联网、不修改任何东西。
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

VERSION = "1.0"

# 各分类依赖的外部程序：id -> (可执行名, 用途, 是否必需)
EXTERNAL = [
    ("python",      None,                "Python 运行时（工具箱自己的脚本靠它）", True),
    ("java",        "java",              "Java 运行时（CyberChef / 部分 jar 工具）", False),
    ("7z",          "7z",                "7-Zip（解包、看压缩包结构）", True),
    ("tshark",      "tshark",            "Wireshark 命令行（流量分析）", False),
    ("nmap",        "nmap",              "nmap（端口扫描）", False),
    ("hashcat",     "hashcat",           "hashcat（GPU 爆破）", False),
    ("john",        "john",              "John the Ripper（CPU 爆破）", False),
    ("exiftool",    "exiftool",          "exiftool（元数据读写）", False),
    ("perl",        "perl",              "Strawberry Perl（部分 CTF 脚本依赖）", False),
    ("binwalk",     "binwalk",           "binwalk（固件/嵌套文件分析）", False),
    ("foremost",    "foremost",          "foremost（文件雕刻）", False),
    ("volatility3", "vol",               "Volatility 3（内存取证）", False),
]

# 本仓库自带的 Python 脚本，按分类列出，检查能否 import/运行
# 参与体检的分类目录（按展示顺序）
CATEGORIES = [
    "01-环境配置", "02-编码识别", "03-隐写", "04-压缩包与文件修复",
    "05-流量分析", "06-取证", "07-OSINT",
]

MIN_PY = (3, 9)


def find_root():
    """从本脚本位置往上找工具箱根目录（含 _box/tools.json 的那一层）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    cur = here
    for _ in range(6):
        if os.path.isfile(os.path.join(cur, "_box", "tools.json")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return None


def _candidate_dirs(root):
    """可能的工具安装目录：工具箱自带 + 常见安装位置。"""
    dirs = []
    if root:
        # 工具箱把下载的工具放在各分类目录下
        for cat in ("01-环境配置", "04-压缩包与文件修复", "05-流量分析",
                    "06-取证", "07-OSINT", "03-隐写", "02-编码识别"):
            base = os.path.join(root, cat)
            if os.path.isdir(base):
                dirs.append(base)
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local = os.environ.get("LOCALAPPDATA", "")
    for d in ("7-Zip", "Wireshark", "Nmap", "Hashcat", "John", "ExifTool",
              "Strawberry", "Volatility"):
        dirs.append(os.path.join(pf, d))
        dirs.append(os.path.join(pf86, d))
        if local:
            dirs.append(os.path.join(local, "Programs", d))
    return dirs


def locate(exe, root=None):
    """先查 PATH，再在工具箱和常见安装目录里按文件名找。"""
    if not exe:
        return None
    hit = shutil.which(exe)
    if hit:
        return hit
    names = [exe]
    if not exe.lower().endswith(".exe"):
        names.append(exe + ".exe")
    for base in _candidate_dirs(root):
        for name in names:
            # 直接看该目录，以及一层子目录（如 7-Zip/7z.exe、bin/xxx.exe）
            for cand in (os.path.join(base, name),
                         os.path.join(base, "bin", name)):
                if os.path.isfile(cand):
                    return cand
    return None


# 各工具的版本参数，按顺序尝试；None 表示不带参数
VERSION_ARGS = {
    "7z": [[], ["i"]],
    "tshark": [["-v"], ["--version"]],
    "java": [["-version"], ["--version"]],
    "nmap": [["--version"]],
    "hashcat": [["--version"]],
    "john": [["--list=build-info"], ["--version"]],
    "exiftool": [["-ver"]],
    "perl": [["-v"], ["--version"]],
    "binwalk": [["--help"]],
    "foremost": [["-V"]],
    "vol": [["--version"]],
}

_BAD_WORDS = ("error", "unknown", "usage:", "cannot", "invalid",
              "command line", "no such")


def try_version(exe, tid=None):
    """按工具尝试合适参数，返回可读的版本行；全失败返回 None。"""
    combos = VERSION_ARGS.get(tid or "", [["--version"], ["-v"], ["-V"]])
    for args in combos:
        try:
            r = subprocess.run([exe] + args, capture_output=True, timeout=15)
        except Exception:
            continue
        out = (r.stdout or b"") + (r.stderr or b"")
        txt = out.decode("utf-8", "replace")
        for line in txt.splitlines():
            line = line.strip().strip("|").strip()
            if len(line) < 4:
                continue
            low = line.lower()
            if any(w in low for w in _BAD_WORDS):
                continue
            return line[:70]
    return None


def check_python():
    ok = sys.version_info >= MIN_PY
    ver = "%d.%d.%d" % sys.version_info[:3]
    detail = "Python %s (%s)" % (ver, "满足 >=3.9" if ok else "过低，需要 >=3.9")
    return ok, detail


def check_external(root=None):
    rows = []
    for tid, exe, purpose, required in EXTERNAL:
        if tid == "python":
            ok, detail = check_python()
            rows.append((tid, purpose, ok, detail, required))
            continue
        path = locate(exe, root)
        if path:
            ver = try_version(path, tid)
            rows.append((tid, purpose, True, ver or path, required))
        else:
            rows.append((tid, purpose, False, "未找到", required))
    return rows


def discover_scripts(root):
    """扫描各分类 scripts 目录，返回 {分类: [脚本名(不含.py)]}。"""
    found = {}
    for cat in CATEGORIES:
        sdir = os.path.join(root, cat, "scripts")
        if not os.path.isdir(sdir):
            continue
        names = sorted(f[:-3] for f in os.listdir(sdir)
                       if f.endswith(".py"))
        if names:
            found[cat] = names
    return found


def check_scripts(root):
    """检查仓库自带的 .py 是否都在，并逐个编译（不执行，避免副作用）。"""
    import py_compile
    import tempfile

    rows = []
    for cat, names in discover_scripts(root).items():
        sdir = os.path.join(root, cat, "scripts")
        for name in names:
            p = os.path.join(sdir, name + ".py")
            try:
                with tempfile.TemporaryDirectory() as td:
                    py_compile.compile(p, cfile=os.path.join(td, "x.pyc"),
                                       doraise=True)
                rows.append((cat, name, True, "语法正常"))
            except Exception as exc:
                rows.append((cat, name, False,
                             "语法错误: %s" % str(exc).splitlines()[0][:60]))
    return rows


def check_layout(root):
    """检查关键文件是否齐全。

    区分两种形态：
      - 仓库：有 .git 或 scripts/bootstrap.ps1，需要引导脚本
      - 工具箱：装好之后，只要 _box 与分类目录在就行
    """
    core_files = ["_box", "_box/tools.json", "_box/app/core.py",
                  "_box/app/gui.py"]
    repo_only = ["scripts/bootstrap.ps1", "scripts/tools-manifest.json"]

    rows = []
    for w in core_files:
        p = os.path.join(root, w.replace("/", os.sep))
        rows.append((w, os.path.exists(p)))

    # 判断是不是仓库形态
    is_repo = (os.path.isdir(os.path.join(root, ".git"))
               or os.path.isfile(os.path.join(root, "scripts",
                                              "bootstrap.ps1")))
    for w in repo_only:
        p = os.path.join(root, w.replace("/", os.sep))
        exists = os.path.exists(p)
        # 工具箱形态下缺这两个不算问题，标记为「不适用」
        rows.append((w, exists if is_repo else None))
    return rows


def report(root, ext_rows, scr_rows, lay_rows, as_json):
    total_ext = len(ext_rows)
    ok_ext = sum(1 for r in ext_rows if r[2])
    missing_required = [r[0] for r in ext_rows if r[4] and not r[2]]
    scr_ok = sum(1 for r in scr_rows if r[2])
    lay_bad = [r[0] for r in lay_rows if r[1] is False]

    if as_json:
        data = {
            "root": root,
            "python": "%d.%d.%d" % sys.version_info[:3],
            "platform": platform.platform(),
            "external": [
                {"id": r[0], "purpose": r[1], "ok": r[2], "detail": r[3],
                 "required": r[4]} for r in ext_rows
            ],
            "scripts": [
                {"category": r[0], "name": r[1], "ok": r[2], "detail": r[3]}
                for r in scr_rows
            ],
            "layout": [{"path": r[0], "ok": r[1]} for r in lay_rows],
            "summary": {
                "external_ok": ok_ext, "external_total": total_ext,
                "scripts_ok": scr_ok, "scripts_total": len(scr_rows),
                "missing_required": missing_required,
                "layout_bad": lay_bad,
            },
        }
        sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        return 0 if not missing_required and not lay_bad else 1

    out = []
    out.append("== 工具箱环境体检 ==")
    out.append("  根目录  : %s" % (root or "未识别"))
    out.append("  Python  : %d.%d.%d" % sys.version_info[:3])
    out.append("  系统    : %s" % platform.platform())
    out.append("")

    out.append("-- 外部程序 (%d/%d) --" % (ok_ext, total_ext))
    for tid, purpose, ok, detail, required in ext_rows:
        mark = "[OK]  " if ok else ("[缺]  " if required else "[可选]")
        out.append("  %s %-11s %-8s %s" % (mark, tid, "", detail))
        if not ok and not required:
            out.append("          用途: %s" % purpose)
    out.append("")

    out.append("-- 自带脚本 (%d/%d) --" % (scr_ok, len(scr_rows)))
    by_cat = {}
    for cat, name, ok, detail in scr_rows:
        by_cat.setdefault(cat, []).append((name, ok, detail))
    for cat in CATEGORIES:
        items = by_cat.get(cat, [])
        bad = [i for i in items if not i[1]]
        if bad:
            out.append("  %s: %d/%d 正常" % (cat, len(items) - len(bad), len(items)))
            for name, _ok, detail in bad:
                out.append("      [X] %s  %s" % (name, detail))
        else:
            out.append("  %s: %d/%d 正常" % (cat, len(items), len(items)))
    out.append("")

    na = [r[0] for r in lay_rows if r[1] is None]
    if lay_bad:
        out.append("-- 目录结构：缺 %d 项 --" % len(lay_bad))
        for b in lay_bad:
            out.append("  [X] %s" % b)
        out.append("")
    elif na:
        out.append("-- 目录结构：齐全 --")
        out.append("  （%s 属于仓库文件，工具箱形态下不需要）" % ", ".join(na))
        out.append("")

    out.append("== 结论 ==")
    if missing_required:
        out.append("  必需项缺失: %s" % ", ".join(missing_required))
        out.append("  请先运行 _box\\setup.ps1 自动补齐。")
    elif lay_bad:
        out.append("  目录结构不完整，可能是克隆不完整，请重新 clone。")
    else:
        out.append("  环境正常，可以直接使用。")
        opt = [r[0] for r in ext_rows if not r[2] and not r[4]]
        if opt:
            out.append("  可选工具未装（不影响核心功能）: %s" % ", ".join(opt))
            has_boot = os.path.isfile(os.path.join(root, "scripts",
                                                   "bootstrap.ps1"))
            if has_boot:
                out.append("  需要的话运行 scripts\\bootstrap.ps1 自动下载。")
            else:
                out.append("  需要的话运行 _box\\setup.ps1 自动下载。")

    sys.stdout.write("\n".join(out) + "\n")
    return 0 if not missing_required and not lay_bad else 1


def build_usage():
    return (
        "envcheck.py -- 工具箱环境体检\n"
        "\n"
        "用法:\n"
        "  python -X utf8 envcheck.py            体检并给出结论\n"
        "  python -X utf8 envcheck.py --json     输出 JSON（给脚本/CI 用）\n"
        "\n"
        "检查内容:\n"
        "  1. 外部程序（7z / tshark / nmap / hashcat / exiftool 等）是否可用\n"
        "  2. 仓库自带的 28 个 Python 脚本是否齐全、语法是否正常\n"
        "  3. 7 个分类目录与 _box 关键文件是否完整\n"
        "\n"
        "只读探测，不联网，不修改任何文件。\n"
    )


def main(argv=None):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    root = find_root()
    if root is None:
        sys.stderr.write("找不到工具箱根目录（没看到 _box/tools.json）。\n"
                         "请把本脚本放在工具箱的 01-环境配置/scripts/ 下运行。\n")
        return 2

    ext_rows = check_external(root)
    scr_rows = check_scripts(root)
    lay_rows = check_layout(root)
    return report(root, ext_rows, scr_rows, lay_rows, args.json)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
