"""杂项工具箱 - 导航层核心逻辑。

职责：
  * 读取 tools.json（唯一数据源）
  * 解析相对/绝对路径
  * 按声明方式启动工具（exe / bat / cli / html / script / shell / powershell）
  * 提供搜索、按分类过滤、按扩展名推荐工具链
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------- 路径解析

APP_DIR = Path(__file__).resolve().parent           # ...\_box\app
BOX_DIR = APP_DIR.parent                            # ...\_box
DEFAULT_ROOT = BOX_DIR.parent                       # ...\杂项工具
CONFIG_PATH = BOX_DIR / "tools.json"


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def project_root(cfg: dict[str, Any]) -> Path:
    """优先使用 tools.json 里的 root，其次退回本文件上级目录。"""
    raw = (cfg.get("meta") or {}).get("root") or ""
    if raw and Path(raw).is_dir():
        return Path(raw)
    return DEFAULT_ROOT


def resolve(root: Path, rel: str) -> Path:
    """把配置里的路径解析成绝对路径。

    绝对路径（含盘符）原样返回；其余按工具箱根目录拼接。
    统一把 / 转成系统分隔符，并展开 %ENVVAR% 形式的环境变量引用
    （tools.json 是发布版共享的，不能写死某一台机器的绝对路径）。
    """
    if not rel:
        return root
    expanded = os.path.expandvars(rel)
    p = Path(expanded.replace("/", os.sep))
    return p if p.is_absolute() else (root / p)


# ---------------------------------------------------------------- 数据模型

@dataclass
class Tool:
    raw: dict[str, Any]
    root: Path

    @property
    def id(self) -> str:
        return self.raw.get("id", "")

    @property
    def category(self) -> str:
        return self.raw.get("category", "")

    @property
    def name(self) -> str:
        return self.raw.get("name", self.id)

    @property
    def name_en(self) -> str:
        return self.raw.get("name_en", "")

    @property
    def version(self) -> str:
        return self.raw.get("version", "")

    @property
    def type(self) -> str:
        return self.raw.get("type", "")

    @property
    def summary(self) -> str:
        return self.raw.get("summary", "")

    @property
    def when(self) -> str:
        return self.raw.get("when", "")

    @property
    def path(self) -> Path:
        return resolve(self.root, self.raw.get("path", ""))

    @property
    def launch(self) -> dict[str, Any]:
        return self.raw.get("launch") or {}

    @property
    def usage(self) -> list[dict[str, Any]]:
        return self.raw.get("usage") or []

    @property
    def params(self) -> list[dict[str, str]]:
        return self.raw.get("params") or []

    @property
    def pitfalls(self) -> list[str]:
        return self.raw.get("pitfalls") or []

    @property
    def next_ids(self) -> list[str]:
        return self.raw.get("next") or []

    @property
    def exists(self) -> bool:
        kind = self.launch.get("kind", "")
        if kind == "none":
            return True
        target = self.launch.get("target") or self.raw.get("path", "")
        return resolve(self.root, target).exists()


def build_tools(cfg: dict[str, Any]) -> list[Tool]:
    root = project_root(cfg)
    return [Tool(raw=t, root=root) for t in cfg.get("tools", [])]


def categories(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(cfg.get("categories", []), key=lambda c: c.get("index", 999))


# ---------------------------------------------------------------- 启动逻辑

def _open_html(path: Path) -> None:
    webbrowser.open(path.as_uri())


def _run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    kwargs: dict[str, Any] = {}
    if cwd and cwd.is_dir():
        kwargs["cwd"] = str(cwd)
    if env:
        merged = os.environ.copy()
        merged.update(env)
        kwargs["env"] = merged
    subprocess.Popen(cmd, **kwargs)


def launch_tool(tool: Tool) -> tuple[bool, str]:
    """按声明方式启动。返回 (是否成功, 提示信息)。"""
    kind = tool.launch.get("kind", "")
    target_raw = tool.launch.get("target", "") or tool.raw.get("path", "")
    target = resolve(tool.root, target_raw)
    workdir = resolve(tool.root, tool.launch["workdir"]) if tool.launch.get("workdir") else tool.path.parent

    if kind == "none":
        return False, "该条目仅用于说明，无需启动。"

    if not target.exists():
        return False, f"文件不存在：{target}\n请先运行「环境自检」或检查是否被移动。"

    try:
        if kind == "html":
            _open_html(target)
            return True, f"已在浏览器打开：{target.name}"

        if kind == "exe":
            _run([str(target)], cwd=workdir)
            return True, f"已启动：{target.name}"

        if kind == "bat":
            _run(["cmd", "/c", "start", "", str(target)], cwd=workdir)
            return True, f"已启动：{target.name}"

        if kind == "script":
            # .bat 启动器优先；否则用 Python 跑 .py
            if target.suffix.lower() == ".bat":
                _run(["cmd", "/c", "start", "", str(target)], cwd=workdir)
            else:
                _run([sys.executable, "-X", "utf8", str(target)], cwd=workdir)
            return True, f"已启动：{target.name}"

        if kind == "cli":
            if target.suffix.lower() == ".bat":
                _run(["cmd", "/c", "start", "", str(target)], cwd=workdir)
            else:
                _run(["cmd", "/c", "start", "cmd", "/k", str(target)], cwd=workdir)
            return True, f"已打开命令行：{target.name}"

        if kind == "shell":
            _run(["cmd", "/c", "start", "", str(target)], cwd=workdir)
            return True, f"已启动：{target.name}"

        if kind == "powershell":
            args = tool.launch.get("args") or []
            cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(target), *args]
            _run(cmd, cwd=workdir)
            return True, "已启动环境自检"

        if kind == "dir":
            os.startfile(str(target))  # type: ignore[attr-defined]
            return True, f"已打开目录：{target}"

        return False, f"未知启动类型：{kind}"
    except Exception as exc:  # noqa: BLE001
        return False, f"启动失败：{exc}"


def open_in_explorer(path: Path) -> None:
    if path.is_file():
        subprocess.Popen(["explorer", "/select,", str(path)])
    elif path.is_dir():
        subprocess.Popen(["explorer", str(path)])
    else:
        raise FileNotFoundError(str(path))


# ---------------------------------------------------------------- 搜索 / 推荐

def search_tools(tools: list[Tool], keyword: str,
                 categories: list[dict[str, Any]] | None = None) -> list[Tool]:
    """按关键词过滤工具。

    搜索范围覆盖：工具名（中/英）、id、简介、适用场景、版本、参数名、
    教程标题与命令、踩坑提醒、分类名与分类描述。
    传入 categories 时，命中分类名/描述的工具也会被返回，
    这样搜「隐写」能找到该分类下的全部工具（此前只搜名称会导致 0 结果）。
    """
    kw = keyword.strip().lower()
    if not kw:
        return tools

    # 分类 id -> 该分类的检索文本（名称 + 描述）
    cat_hay: dict[str, str] = {}
    for c in (categories or []):
        cid = c.get("id", "")
        cat_hay[cid] = f"{c.get('name', '')} {c.get('desc', '')}".lower()

    out = []
    for t in tools:
        hay = " ".join([
            t.name, t.name_en, t.id, t.summary, t.when, t.version,
            " ".join(p.get("flag", "") for p in t.params),
            " ".join(p.get("desc", "") for p in t.params),
            " ".join(u.get("title", "") for u in t.usage),
            " ".join(u.get("code", "") for u in t.usage),
            " ".join(t.pitfalls),
            cat_hay.get(t.category, ""),
        ]).lower()
        if kw in hay:
            out.append(t)
    return out


# 扩展名 -> 推荐工具 id（按顺序）
EXT_RECOMMEND: dict[str, list[str]] = {
    ".png": ["pngcheck", "imgsize", "stegsolve", "exiftool"],
    ".jpg": ["imgsize", "exiftool", "stegsolve"],
    ".jpeg": ["imgsize", "exiftool", "stegsolve"],
    ".bmp": ["imgsize", "stegsolve", "exiftool"],
    ".gif": ["imgsize", "stegsolve", "exiftool"],
    ".zip": ["7zip", "archpr", "john", "hashcat"],
    ".rar": ["7zip", "archpr", "john", "hashcat"],
    ".7z": ["7zip", "perl", "archpr", "hashcat"],
    ".pcap": ["tshark"],
    ".pcapng": ["tshark"],
    ".cap": ["tshark"],
    ".raw": ["volatility3", "binwalk"],
    ".mem": ["volatility3", "binwalk"],
    ".vmem": ["volatility3", "binwalk"],
    ".bin": ["binwalk", "foremost", "pngcheck"],
    ".img": ["binwalk", "foremost"],
    ".txt": ["cyberchef", "imgsize"],
    ".py": ["imgsize"],
}

# 按文件头 magic 兜底识别
MAGIC_RECOMMEND: list[tuple[bytes, list[str]]] = [
    (b"\x89PNG", ["pngcheck", "imgsize", "stegsolve"]),
    (b"\xff\xd8\xff", ["imgsize", "exiftool"]),
    (b"GIF8", ["imgsize", "stegsolve"]),
    (b"PK\x03\x04", ["7zip", "archpr", "john"]),
    (b"Rar!", ["7zip", "archpr", "john"]),
    (b"7z\xbc\xaf", ["7zip", "perl", "archpr"]),
    (b"\xd4\xc3\xb2\xa1", ["tshark"]),
    (b"\x0a\x0d\x0d\x0a", ["tshark"]),
]


def recommend_for_file(tools: list[Tool], file_path: Path) -> list[Tool]:
    """给定一个文件，返回推荐的工具链。"""
    by_id = {t.id: t for t in tools}
    ids: list[str] = []

    # 1) 扩展名
    ids.extend(EXT_RECOMMEND.get(file_path.suffix.lower(), []))

    # 2) 文件头（覆盖/补充）
    try:
        with open(file_path, "rb") as f:
            head = f.read(16)
        for magic, rec in MAGIC_RECOMMEND:
            if head.startswith(magic):
                ids = rec + [i for i in ids if i not in rec]
                break
    except OSError:
        pass

    # 3) 去重并保序
    seen: set[str] = set()
    ordered: list[str] = []
    for i in ids:
        if i in by_id and i not in seen:
            seen.add(i)
            ordered.append(i)
    return [by_id[i] for i in ordered]
