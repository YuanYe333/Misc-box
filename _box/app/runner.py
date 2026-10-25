# -*- coding: utf-8 -*-
"""runner.py -- 工具执行层：把「选工具 → 拖文件 → 点运行 → 看结果」跑通。

设计要点
========
1. **数据驱动**：每个工具的跑法写在 tools.json 的 ``run`` 字段里，不在代码里
   写死 if/else。加新工具只改 JSON。
2. **不碰用户的原始文件**：每次运行开一个全新目录
   ``_box/work/runs/<时间>_<工具id>``，把它当 cwd，工具产生的文件都落在这里，
   跑完直接列出来给用户看。输入文件始终只读。
3. **实时输出**：子进程输出用线程收，解码后进队列，GUI 用 ``after()`` 轮询。
   不阻塞 Tk 主循环，跑大文件也不假死。
4. **编码兜底**：自家 Python 脚本靠 ``PYTHONUTF8=1`` 保证 UTF-8；外部 exe
   （pngcheck / exiftool 等）在中文 Windows 上常输出 GBK，所以逐行解码时
   先试 UTF-8 再退 GBK，实在不行 replace，绝不让界面崩。

占位符（presets 的 argv 里用）
=============================
    {file}     第一个文件（绝对路径）
    {files}    全部文件，逐个展开
    {stem}     第一个文件的主文件名（不含扩展名）
    {name}     第一个文件的文件名（含扩展名）
    {text}     文本框内容
    {outdir}   本次运行的输出目录

命令行里的 ``run.kind``：``python``（走本机 Python）、``exe``（直接执行）、
``bat``（cmd /c 调用）。
"""
from __future__ import annotations

import os
import queue
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

RUNS_DIRNAME = "runs"
MAX_RUNS_KEPT = 40          # 只保留最近这么多次运行，防止 work 目录无限膨胀

CREATE_NO_WINDOW = 0x08000000

# 占位符：{file} {files} {stem} {name} {ext} {text} {outdir} {args}
# 除此之外的任何 {xxx} 都视为「需要用户填的字段」（如 {mask} {crc} {len}），
# 由 GUI 动态生成输入框，值放在 RunTarget.fields 里。
_BUILTIN_PLACEHOLDERS = {"file", "files", "stem", "name", "ext",
                         "text", "outdir", "args", "root"}
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def custom_fields(argv: List[str]) -> List[str]:
    """从 argv 里找出需要用户填的自定义字段名（按出现顺序去重）。"""
    seen: List[str] = []
    for token in argv:
        for name in _PLACEHOLDER_RE.findall(token):
            if name not in _BUILTIN_PLACEHOLDERS and name not in seen:
                seen.append(name)
    return seen


# ---------------------------------------------------------------- 编码

def _decode_line(raw: bytes) -> str:
    """单行解码：先 UTF-8，再 GBK/CP936，最后无损替换。

    不能整块 decode 再 split——中文多字节会被切在行边界上，整块解码一旦
    失败整段就乱码了。逐行解码，坏一行只坏一行。
    """
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


# ---------------------------------------------------------------- 数据模型

@dataclass
class RunSpec:
    """tools.json 里 ``run`` 字段的解析结果。"""
    kind: str = ""                       # python / exe / bat
    argv: List[str] = field(default_factory=list)
    presets: List[Dict[str, Any]] = field(default_factory=list)
    input_mode: str = "files"            # files / text / none
    accept: List[str] = field(default_factory=list)
    multi: bool = False
    cwd_mode: str = "run"                # run / tool
    intro: str = ""

    @classmethod
    def parse(cls, raw: Optional[Dict[str, Any]]) -> "RunSpec":
        raw = raw or {}
        return cls(
            kind=raw.get("kind", ""),
            argv=list(raw.get("argv") or []),
            presets=list(raw.get("presets") or []),
            input_mode=raw.get("input", "files"),
            accept=[a.lower() for a in (raw.get("accept") or [])],
            multi=bool(raw.get("multi")),
            cwd_mode=raw.get("cwd", "run"),
            intro=raw.get("intro", ""),
        )


@dataclass
class RunTarget:
    """一次运行需要的全部上下文。"""
    tool_id: str
    tool_name: str
    spec: RunSpec
    entry: Path                          # 真正要执行的脚本/exe/bat
    tool_dir: Path
    root: Path
    files: List[Path] = field(default_factory=list)
    text: str = ""
    preset_index: int = 0
    extra_args: List[str] = field(default_factory=list)
    fields: Dict[str, str] = field(default_factory=dict)   # 自定义 {mask}/{crc}/…


# ---------------------------------------------------------------- 运行目录

def make_run_dir(root: Path, tool_id: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tool_id)
    base = root / "_box" / "work" / RUNS_DIRNAME
    path = base / ("%s_%s" % (stamp, safe))
    n = 1
    while path.exists():
        n += 1
        path = base / ("%s_%s_%d" % (stamp, safe, n))
    path.mkdir(parents=True, exist_ok=True)
    _prune_old_runs(base)
    return path


def _prune_old_runs(base: Path) -> None:
    """只留最近 N 次运行目录。失败静默——清理不该影响正事。"""
    try:
        dirs = sorted([d for d in base.iterdir() if d.is_dir()],
                      key=lambda d: d.stat().st_mtime, reverse=True)
        for d in dirs[MAX_RUNS_KEPT:]:
            for f in sorted(d.rglob("*"), key=lambda p: len(str(p)), reverse=True):
                try:
                    f.unlink() if f.is_file() else f.rmdir()
                except OSError:
                    pass
            try:
                d.rmdir()
            except OSError:
                pass
    except OSError:
        pass


def list_artifacts(run_dir: Path, limit: int = 200) -> List[Path]:
    """列出运行目录里产生的文件（按修改时间新→旧）。"""
    out: List[Path] = []
    try:
        for p in run_dir.rglob("*"):
            if p.is_file():
                out.append(p)
                if len(out) >= limit * 4:
                    break
    except OSError:
        return out
    out.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    return out[:limit]


# ---------------------------------------------------------------- 命令拼装

def python_exe() -> str:
    """优先用跑 GUI 的这个 Python，保证版本与依赖一致。"""
    return sys.executable or "python"


def expand(argv: List[str], target: RunTarget, run_dir: Path) -> List[str]:
    """把占位符换成真实值。

    ``{files}`` 特殊处理：它是「多个参数」，展开后按位置插入若干项，
    其余占位符都只产生一个字符串。
    """
    files = [str(f) for f in target.files]
    first = files[0] if files else ""
    stem = Path(first).stem if first else ""
    name = Path(first).name if first else ""
    ext = Path(first).suffix if first else ""

    values = {
        "{file}": first,
        "{stem}": stem,
        "{name}": name,
        "{ext}": ext,
        "{text}": target.text,
        "{outdir}": str(run_dir),
        "{root}": str(target.root),
    }
    # 自定义字段：{mask} -> target.fields["mask"]，没填就留空
    for key, val in target.fields.items():
        values["{%s}" % key] = val

    out: List[str] = []
    for token in argv:
        if token == "{files}":
            out.extend(files)
            continue
        if token == "{args}":
            # 附加参数：用户手填的「原样透传」参数，按空格切分。
            # 有了它，预设之外的冷门组合不必再写进 tools.json。
            out.extend(target.extra_args)
            continue
        replaced = token
        for key, val in values.items():
            if key in replaced:
                replaced = replaced.replace(key, val)
        out.append(replaced)
    return out


def current_preset(target: RunTarget) -> Dict[str, Any]:
    spec = target.spec
    if spec.presets and 0 <= target.preset_index < len(spec.presets):
        return spec.presets[target.preset_index]
    return {}


def effective_entry(target: RunTarget) -> Path:
    """preset 可以覆盖入口脚本。

    有些工具的「一条命令」其实是不同的可执行文件（john 的 zip2john / rar2john），
    把它们塞进同一个工具条目里，靠 preset.entry 切换，比拆成多个卡片更顺手。
    """
    preset = current_preset(target)
    raw = preset.get("entry")
    if not raw:
        return target.entry
    p = Path(raw.replace("/", os.sep))
    return p if p.is_absolute() else (target.root / p)


def perl_exe(root: Path) -> Path:
    """工具箱自带的 perl（john 的 2john 脚本有一半是 .pl）。"""
    return root / "04-压缩包与文件修复" / "perl" / "perl" / "bin" / "perl.exe"


def build_command(target: RunTarget, run_dir: Path) -> List[str]:
    spec = target.spec
    preset = current_preset(target)
    argv = list(preset.get("argv") or spec.argv or [])
    args = expand(argv, target, run_dir) + list(target.extra_args)

    entry = effective_entry(target)
    # preset 也能覆盖 kind：john 的 pdf2john 是 .pl，但整个工具条目按 exe 走
    kind = preset.get("kind") or spec.kind or _guess_kind(entry)

    if kind == "python":
        return [python_exe(), "-X", "utf8", str(entry)] + args
    if kind == "bat":
        return ["cmd", "/c", str(entry)] + args
    if kind == "perl":
        perl = perl_exe(target.root)
        return [str(perl if perl.exists() else "perl"), str(entry)] + args
    return [str(entry)] + args


def _guess_kind(entry: Path) -> str:
    suffix = entry.suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in (".bat", ".cmd"):
        return "bat"
    return "exe"


# ---------------------------------------------------------------- 作业

class Job:
    """一个正在跑的子进程。GUI 侧只通过 poll()/stop() 和它打交道。"""

    def __init__(self, cmd: List[str], cwd: Path, run_dir: Path,
                 tool_name: str = "", tool_id: str = "") -> None:
        self.cmd = cmd
        self.cwd = cwd
        self.run_dir = run_dir
        self.tool_name = tool_name
        self.tool_id = tool_id          # 界面用它判断输出该写到哪个面板
        self.proc: Optional[subprocess.Popen] = None
        self.returncode: Optional[int] = None
        self.started_at = time.time()
        self.finished_at: Optional[float] = None
        self.error: str = ""
        self._q: "queue.Queue[Optional[str]]" = queue.Queue()
        self._thread: Optional[threading.Thread] = None

    # -------------------------------------------------- 生命周期

    def start(self) -> None:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["PYTHONUNBUFFERED"] = "1"        # 否则自家脚本的输出会攒到最后才吐
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                cwd=str(self.cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                creationflags=CREATE_NO_WINDOW,
                bufsize=0,
            )
        except OSError as exc:
            self.error = "启动失败：%s" % exc
            self.returncode = -1
            self.finished_at = time.time()
            self._q.put(None)
            return

        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        buf = b""
        stream = self.proc.stdout
        while True:
            try:
                chunk = stream.read(4096)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            buf += chunk
            # \r\n、\n、以及进度条的裸 \r 都当作换行，逐行吐出
            buf = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                self._q.put(_decode_line(line))
        if buf:
            self._q.put(_decode_line(buf))
        self.returncode = self.proc.wait()
        self.finished_at = time.time()
        self._q.put(None)                    # 结束哨兵

    # -------------------------------------------------- 轮询

    def poll(self) -> "tuple[List[str], bool]":
        """取走当前积累的输出行；第二个返回值表示是否已结束。"""
        lines: List[str] = []
        done = False
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                done = True
                break
            lines.append(item)
        if self.returncode is not None:
            done = True
        return lines, done

    @property
    def running(self) -> bool:
        return self.returncode is None

    def stop(self) -> None:
        """先礼后兵：terminate，等 2 秒不退再 kill。"""
        if self.proc is None or self.returncode is not None:
            return
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        except OSError:
            pass

    @property
    def elapsed(self) -> float:
        end = self.finished_at or time.time()
        return end - self.started_at

    def summary(self) -> str:
        if self.error:
            return self.error
        if self.running:
            return "运行中…（%.1f 秒）" % self.elapsed
        if self.returncode == 0:
            return "完成，用时 %.1f 秒" % self.elapsed
        return "异常结束（退出码 %s），用时 %.1f 秒" % (self.returncode, self.elapsed)


# ---------------------------------------------------------------- 对外入口

def preset_needs_file(target: RunTarget) -> bool:
    """当前预设是否需要文件。

    preset 里写 ``"no_file": true`` 表示这个预设完全不碰文件（例如
    「列出支持的格式」），GUI 据此把拖放区置灰，避免用户白拖。
    """
    preset = current_preset(target)
    if preset.get("no_file"):
        return False
    argv = list(preset.get("argv") or target.spec.argv or [])
    joined = " ".join(argv)
    return "{file}" in joined or "{files}" in joined


def preset_needs_text(target: RunTarget) -> bool:
    preset = current_preset(target)
    argv = list(preset.get("argv") or target.spec.argv or [])
    return "{text}" in " ".join(argv)


def preset_custom_fields(target: RunTarget) -> List[str]:
    preset = current_preset(target)
    argv = list(preset.get("argv") or target.spec.argv or [])
    return custom_fields(argv)


def validate(target: RunTarget) -> str:
    """运行前检查。返回空串表示可以跑，否则是给人看的错误说明。"""
    spec = target.spec
    if not spec.kind:
        return "该工具还没有配置运行方式（tools.json 缺 run 字段）。"
    entry = effective_entry(target)
    if not entry.exists():
        return "找不到可执行文件：\n%s" % entry

    if not spec.multi and len(target.files) > 1:
        return "这个工具一次只处理一个文件，请只留一个（已拖入 %d 个）。" % len(target.files)

    needs_file = preset_needs_file(target)
    needs_text = preset_needs_text(target)

    if needs_file and not target.files:
        return "这个运行方式需要文件，先把文件拖进上面的框里。"
    if needs_text and not target.text.strip():
        return "这个运行方式需要输入内容，请在上面的输入框里填写。"

    missing = [f for f in preset_custom_fields(target)
               if not (target.fields.get(f) or "").strip()]
    if missing:
        return "请先填写：%s" % "、".join("{%s}" % m for m in missing)

    if target.files and spec.accept:
        bad = [f.name for f in target.files if f.suffix.lower() not in spec.accept]
        if bad:
            allow = "、".join(spec.accept)
            return "文件类型不对：%s\n这个工具只接受：%s" % ("、".join(bad), allow)
    return ""


def start_job(target: RunTarget) -> Job:
    """校验 → 建运行目录 → 拼命令 → 起进程。调用方负责处理 validate 的错误。"""
    run_dir = make_run_dir(target.root, target.tool_id)
    cwd = target.tool_dir if target.spec.cwd_mode == "tool" else run_dir
    if not cwd.is_dir():
        cwd = run_dir
    cmd = build_command(target, run_dir)
    job = Job(cmd, cwd, run_dir, target.tool_name, target.tool_id)
    job.start()
    return job


def command_preview(target: RunTarget) -> str:
    """给界面显示的「将要执行的命令」，让用户知道背后在跑什么。"""
    preset = current_preset(target)
    argv = list(preset.get("argv") or target.spec.argv or [])
    parts = [effective_entry(target).name] + argv
    return " ".join(parts)
