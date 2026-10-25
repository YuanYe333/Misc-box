"""杂项工具箱 - tkinter 启动器。

布局：左侧分类导航 + 搜索框，右侧工具卡片详情页。
交互：点分类过滤、点卡片看说明、双击卡片直接启动、拖文件进窗口推荐工具链。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

import core  # noqa: E402

# ---------------------------------------------------------------- 主题

BG = "#1e1f26"
PANEL = "#282a36"
CARD = "#313342"
CARD_HOVER = "#3d4052"
ACCENT = "#7aa2f7"
ACCENT_DIM = "#5b7fc7"
TEXT = "#e6e6e6"
TEXT_DIM = "#9aa0b0"
OK = "#9ece6a"
WARN = "#e0af68"
ERR = "#f7768e"
FONT = "Microsoft YaHei UI"


class MiscBoxApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.cfg = core.load_config()
        self.root_dir = core.project_root(self.cfg)
        self.tools = core.build_tools(self.cfg)
        self.cats = core.categories(self.cfg)
        self.by_id = {t.id: t for t in self.tools}

        self.current_cat: str | None = None
        self.current_tool: core.Tool | None = None
        self._cards: dict[str, tk.Frame] = {}

        self.title("杂项工具箱 · MiscBox")
        self.geometry("1180x760")
        self.minsize(900, 600)
        self.configure(bg=BG)
        self._center()

        self._build_style()
        self._build_layout()
        self._select_category(self.cats[0]["id"] if self.cats else None)
        self._bind_dnd()

    # ------------------------------------------------------------ 基础

    def _center(self) -> None:
        self.update_idletasks()
        w, h = 1180, 760
        x = (self.winfo_screenwidth() - w) // 2
        y = max(0, (self.winfo_screenheight() - h) // 2 - 20)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_style(self) -> None:
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("TScrollbar", background=PANEL, troughcolor=BG,
                     bordercolor=BG, arrowcolor=TEXT_DIM)

    def _build_layout(self) -> None:
        # 左侧
        self.left = tk.Frame(self, bg=PANEL, width=230)
        self.left.pack(side="left", fill="y")
        self.left.pack_propagate(False)

        title = tk.Label(self.left, text="杂项工具箱", bg=PANEL, fg=TEXT,
                         font=(FONT, 15, "bold"), anchor="w")
        title.pack(fill="x", padx=16, pady=(18, 2))
        sub = tk.Label(self.left, text=f"MiscBox v{self.cfg['meta'].get('version','')}",
                       bg=PANEL, fg=TEXT_DIM, font=(FONT, 9), anchor="w")
        sub.pack(fill="x", padx=16, pady=(0, 12))

        # 搜索
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_cards())
        ent = tk.Entry(self.left, textvariable=self.search_var, bg=CARD, fg=TEXT,
                       insertbackground=TEXT, relief="flat", font=(FONT, 10))
        ent.pack(fill="x", padx=14, pady=(0, 4), ipady=5)
        ent.insert(0, "")
        self.search_entry = ent
        ph = tk.Label(self.left, text="搜索工具名 / 功能 / 参数", bg=PANEL, fg=TEXT_DIM,
                      font=(FONT, 8), anchor="w")
        ph.pack(fill="x", padx=16, pady=(0, 8))

        # 分类按钮容器：先 pack 底部，再 pack 分类区，否则分类区会先吃掉
        # 全部纵向空间，把底部按钮挤成 1px（pack 按调用顺序分配剩余空间）。
        bottom = tk.Frame(self.left, bg=PANEL)
        bottom.pack(side="bottom", fill="x", padx=14, pady=12)
        tk.Frame(bottom, bg=CARD, height=1).pack(fill="x", pady=(0, 10))

        # 「补齐缺失」放在自检上面：新手看到红点后最想知道的是「怎么装」，
        # 而不是「哪里错了」。只统计 auto=True 的条目——手动工具下载不了。
        self.btn_fill = tk.Label(bottom, text="⬇  补齐缺失工具", bg=ACCENT, fg=BG,
                                 font=(FONT, 10, "bold"), pady=7, cursor="hand2")
        self.btn_fill.pack(fill="x")
        self.btn_fill.bind("<Button-1>", lambda e: self._install_missing())
        self.btn_fill.bind("<Enter>", lambda e: self.btn_fill.config(bg=ACCENT_DIM))
        self.btn_fill.bind("<Leave>", lambda e: self.btn_fill.config(bg=ACCENT))

        btn_env = tk.Label(bottom, text="⚙  环境自检", bg=CARD, fg=TEXT,
                           font=(FONT, 10), pady=7, cursor="hand2")
        btn_env.pack(fill="x", pady=(6, 0))
        btn_env.bind("<Button-1>", lambda e: self._run_setup())
        btn_env.bind("<Enter>", lambda e: btn_env.config(bg=CARD_HOVER))
        btn_env.bind("<Leave>", lambda e: btn_env.config(bg=CARD))

        tk.Label(bottom, text=f"根目录 {self.root_dir}", bg=PANEL, fg=TEXT_DIM,
                 font=(FONT, 8), anchor="w", wraplength=200).pack(fill="x", pady=(10, 0))

        # 分类按钮容器（在底部之后 pack，剩余空间归它）
        self.cat_frame = tk.Frame(self.left, bg=PANEL)
        self.cat_frame.pack(fill="both", expand=True, padx=8)
        self._cat_buttons: dict[str, tk.Label] = {}
        for c in self.cats:
            row = tk.Frame(self.cat_frame, bg=PANEL, cursor="hand2")
            row.pack(fill="x", pady=1)
            lbl = tk.Label(row, text=f"  {c.get('icon','')}  {c['name']}",
                           bg=PANEL, fg=TEXT, font=(FONT, 10), anchor="w",
                           padx=8, pady=7)
            lbl.pack(fill="x")
            cnt = sum(1 for t in self.tools if t.category == c["id"])
            num = tk.Label(row, text=str(cnt), bg=PANEL, fg=TEXT_DIM,
                           font=(FONT, 8), padx=10)
            num.pack(side="right")
            for w in (row, lbl, num):
                w.bind("<Button-1>", lambda e, cid=c["id"]: self._select_category(cid))
                w.bind("<Enter>", lambda e, r=row, l=lbl, n=num, cid=c["id"]: self._cat_hover(r, l, n, cid, True))
                w.bind("<Leave>", lambda e, r=row, l=lbl, n=num, cid=c["id"]: self._cat_hover(r, l, n, cid, False))
            self._cat_buttons[c["id"]] = lbl

        # 右侧
        self.right = tk.Frame(self, bg=BG)
        self.right.pack(side="left", fill="both", expand=True)

        self.head = tk.Frame(self.right, bg=BG, height=76)
        self.head.pack(fill="x")
        self.head.pack_propagate(False)
        self.cat_title = tk.Label(self.head, text="", bg=BG, fg=TEXT,
                                  font=(FONT, 16, "bold"), anchor="w")
        self.cat_title.pack(fill="x", padx=24, pady=(16, 0))
        self.cat_desc = tk.Label(self.head, text="", bg=BG, fg=TEXT_DIM,
                                 font=(FONT, 9), anchor="w", justify="left")
        self.cat_desc.pack(fill="x", padx=24, pady=(2, 0))

        body = tk.Frame(self.right, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        # 卡片区（可滚动）
        self.canvas = tk.Canvas(body, bg=BG, highlightthickness=0, width=300)
        self.vsb = ttk.Scrollbar(body, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="left", fill="y")
        self.canvas.pack(side="left", fill="y", padx=(0, 10))

        self.cards_holder = tk.Frame(self.canvas, bg=BG)
        self._win = self.canvas.create_window((0, 0), window=self.cards_holder, anchor="nw")
        self.cards_holder.bind("<Configure>",
                               lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",
                         lambda e: self.canvas.itemconfig(self._win, width=e.width))
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)

        # 详情区
        self.detail = tk.Frame(body, bg=PANEL)
        self.detail.pack(side="left", fill="both", expand=True)

    def _on_wheel(self, e) -> None:
        try:
            self.canvas.yview_scroll(int(-e.delta / 120), "units")
        except tk.TclError:
            pass

    def _cat_hover(self, row, lbl, num, cid, on) -> None:
        if cid == self.current_cat:
            return
        bg = CARD if on else PANEL
        for w in (row, lbl, num):
            w.config(bg=bg)

    # ------------------------------------------------------------ 分类

    def _select_category(self, cid: str | None) -> None:
        self.current_cat = cid
        for c in self.cats:
            lbl = self._cat_buttons[c["id"]]
            row = lbl.master
            active = c["id"] == cid
            bg = CARD if active else PANEL
            for w in (row, lbl, *row.winfo_children()):
                w.config(bg=bg)
            lbl.config(fg=ACCENT if active else TEXT)

        cat = next((c for c in self.cats if c["id"] == cid), None)
        if cat:
            self.cat_title.config(text=f"{cat.get('icon','')}  {cat['name']}")
            self.cat_desc.config(text=cat.get("desc", ""))
        self._refresh_cards()
        # 默认选中第一个
        items = self._visible_tools()
        if items:
            self._show_detail(items[0])

    def _visible_tools(self) -> list[core.Tool]:
        kw = self.search_var.get().strip()
        pool = self.tools if kw else [t for t in self.tools if t.category == self.current_cat]
        # 把分类元数据一并传进去，搜分类名/描述时才能命中该分类下的工具
        return core.search_tools(pool, kw, self.cats)

    # ------------------------------------------------------------ 卡片

    def _refresh_cards(self) -> None:
        for w in self.cards_holder.winfo_children():
            w.destroy()
        self._cards.clear()

        items = self._visible_tools()
        if not items:
            tk.Label(self.cards_holder, text="没有匹配的工具", bg=BG, fg=TEXT_DIM,
                     font=(FONT, 10), pady=20).pack()
            return

        for t in items:
            self._make_card(t)

    def _make_card(self, t: core.Tool) -> None:
        card = tk.Frame(self.cards_holder, bg=CARD, cursor="hand2")
        card.pack(fill="x", pady=3, padx=2)
        inner = tk.Frame(card, bg=CARD)
        inner.pack(fill="x", padx=12, pady=9)

        top = tk.Frame(inner, bg=CARD)
        top.pack(fill="x")
        name = tk.Label(top, text=t.name, bg=CARD, fg=TEXT, font=(FONT, 11, "bold"), anchor="w")
        name.pack(side="left")
        ver = tk.Label(top, text=t.version, bg=CARD, fg=TEXT_DIM, font=(FONT, 8))
        ver.pack(side="right")

        # 状态点
        dot = tk.Label(top, text="●", bg=CARD, fg=(OK if t.exists else ERR), font=(FONT, 9))
        dot.pack(side="right", padx=(0, 6))

        desc = tk.Label(inner, text=t.summary, bg=CARD, fg=TEXT_DIM, font=(FONT, 9),
                        anchor="w", justify="left", wraplength=250)
        desc.pack(fill="x", pady=(3, 0))

        widgets = [card, inner, top, name, ver, dot, desc]
        for w in widgets:
            w.bind("<Button-1>", lambda e, tool=t: self._show_detail(tool))
            w.bind("<Double-Button-1>", lambda e, tool=t: self._launch(tool))
            w.bind("<Enter>", lambda e, ws=widgets: [x.config(bg=CARD_HOVER) for x in ws])
            w.bind("<Leave>", lambda e, ws=widgets: [x.config(bg=CARD) for x in ws])
        self._cards[t.id] = card

    # ------------------------------------------------------------ 详情

    def _clear_detail(self) -> None:
        for w in self.detail.winfo_children():
            w.destroy()

    def _show_detail(self, t: core.Tool) -> None:
        self.current_tool = t
        for tid, card in self._cards.items():
            for w in (card, *card.winfo_children(), *[c for f in card.winfo_children() for c in f.winfo_children()]):
                try:
                    w.config(bg=CARD_HOVER if tid == t.id else CARD)
                except tk.TclError:
                    pass

        self._clear_detail()

        # 顶部标题区
        head = tk.Frame(self.detail, bg=PANEL)
        head.pack(fill="x", padx=20, pady=(16, 8))

        line1 = tk.Frame(head, bg=PANEL)
        line1.pack(fill="x")
        tk.Label(line1, text=t.name, bg=PANEL, fg=TEXT, font=(FONT, 15, "bold"),
                 anchor="w").pack(side="left")
        if t.name_en:
            tk.Label(line1, text=f"  {t.name_en}", bg=PANEL, fg=TEXT_DIM,
                     font=(FONT, 9)).pack(side="left", padx=(6, 0))
        tk.Label(line1, text=t.version, bg=PANEL, fg=ACCENT_DIM,
                 font=(FONT, 9)).pack(side="right")

        tk.Label(head, text=t.summary, bg=PANEL, fg=TEXT_DIM, font=(FONT, 9),
                 anchor="w", justify="left", wraplength=620).pack(fill="x", pady=(6, 0))

        # 操作按钮
        bar = tk.Frame(head, bg=PANEL)
        bar.pack(fill="x", pady=(10, 0))
        if t.launch.get("kind") not in (None, "none"):
            self._mkbtn(bar, "▶  打开工具", ACCENT, lambda: self._launch(t)).pack(side="left")
        self._mkbtn(bar, "📂 打开目录", CARD, lambda: self._open_dir(t)).pack(side="left", padx=(8, 0))
        self._mkbtn(bar, "📄 完整教程", CARD, lambda: self._open_guide(t)).pack(side="left", padx=(8, 0))

        # 滚动内容
        wrap = tk.Frame(self.detail, bg=PANEL)
        wrap.pack(fill="both", expand=True, padx=0, pady=(6, 0))
        cv = tk.Canvas(wrap, bg=PANEL, highlightthickness=0)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        holder = tk.Frame(cv, bg=PANEL)
        cv.create_window((0, 0), window=holder, anchor="nw", width=640)
        holder.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(cv.find_all()[0], width=e.width - 4))

        def section(title: str) -> None:
            tk.Frame(holder, bg=CARD, height=1).pack(fill="x", padx=20, pady=(12, 6))
            tk.Label(holder, text=title, bg=PANEL, fg=ACCENT, font=(FONT, 10, "bold"),
                     anchor="w").pack(fill="x", padx=20)

        # 什么时候用
        if t.when:
            section("什么时候用")
            tk.Label(holder, text=t.when, bg=PANEL, fg=TEXT, font=(FONT, 9),
                     anchor="w", justify="left", wraplength=600).pack(fill="x", padx=20, pady=(4, 0))

        # 用法
        if t.usage:
            section("怎么用")
            for u in t.usage:
                box = tk.Frame(holder, bg=CARD)
                box.pack(fill="x", padx=20, pady=(6, 0))
                tk.Label(box, text=u.get("title", "用法"), bg=CARD, fg=TEXT,
                         font=(FONT, 9, "bold"), anchor="w").pack(fill="x", padx=10, pady=(6, 2))
                if u.get("steps"):
                    for i, s in enumerate(u["steps"], 1):
                        tk.Label(box, text=f"  {i}. {s}", bg=CARD, fg=TEXT_DIM, font=(FONT, 9),
                                 anchor="w", justify="left", wraplength=560).pack(fill="x", padx=10)
                    tk.Frame(box, bg=CARD, height=6).pack()
                if u.get("code"):
                    code_text = u["code"]
                    # 估算换行后的行数。中文/全角字符占 2 个字符宽度，
                    # 只按 len() 折行会把含中文注释的命令算少，导致最后几行被截断。
                    def _vis_len(s: str) -> int:
                        return sum(2 if ord(ch) > 0x2E7F else 1 for ch in s)
                    est_lines = 0
                    for seg in code_text.split("\n"):
                        est_lines += max(1, (_vis_len(seg) + 77) // 78)
                    code = tk.Text(box, bg=BG, fg="#c0caf5", font=("Consolas", 9),
                                   relief="flat", wrap="word", height=min(max(est_lines, 1), 24),
                                   width=1, padx=8, pady=6)
                    code.insert("1.0", code_text)
                    code.config(state="disabled")
                    code.pack(fill="x", padx=10, pady=(2, 8))

        # 参数
        if t.params:
            section("参数速查")
            for p in t.params:
                row = tk.Frame(holder, bg=PANEL)
                row.pack(fill="x", padx=20, pady=1)
                tk.Label(row, text=p.get("flag", ""), bg=PANEL, fg=OK,
                         font=("Consolas", 9), anchor="w", width=22).pack(side="left")
                tk.Label(row, text=p.get("desc", ""), bg=PANEL, fg=TEXT, font=(FONT, 9),
                         anchor="w", justify="left", wraplength=400).pack(side="left")

        # 踩坑
        if t.pitfalls:
            section("踩坑提醒")
            for x in t.pitfalls:
                tk.Label(holder, text=f"• {x}", bg=PANEL, fg=WARN, font=(FONT, 9),
                         anchor="w", justify="left", wraplength=600).pack(fill="x", padx=20, pady=1)

        # 上下游
        if t.next_ids:
            section("上下游工具")
            nrow = tk.Frame(holder, bg=PANEL)
            nrow.pack(fill="x", padx=20, pady=(4, 0))
            for nid in t.next_ids:
                nt = self.by_id.get(nid)
                if not nt:
                    continue
                self._mkbtn(nrow, nt.name, CARD,
                            lambda x=nt: self._select_category_and_show(x)).pack(side="left", padx=(0, 6))

        tk.Frame(holder, bg=PANEL, height=16).pack()

    def _mkbtn(self, parent, text, color, cmd):
        b = tk.Label(parent, text=text, bg=color,
                     fg=(BG if color == ACCENT else TEXT),
                     font=(FONT, 9, "bold"), padx=12, pady=6, cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        hover = ACCENT_DIM if color == ACCENT else CARD_HOVER
        b.bind("<Enter>", lambda e: b.config(bg=hover))
        b.bind("<Leave>", lambda e: b.config(bg=color))
        return b

    # ------------------------------------------------------------ 动作

    def _launch(self, t: core.Tool) -> None:
        ok, msg = core.launch_tool(t)
        if not ok:
            messagebox.showwarning("无法启动", msg, parent=self)
        else:
            self.status(f"{t.name}：{msg}")

    def _open_dir(self, t: core.Tool) -> None:
        try:
            target = t.path
            if not target.exists():
                target = target.parent
            core.open_in_explorer(target)
        except Exception as exc:  # noqa: BLE001
            messagebox.showwarning("打开失败", str(exc), parent=self)

    def _open_guide(self, t: core.Tool) -> None:
        cat = next((c for c in self.cats if c["id"] == t.category), None)
        if not cat:
            return
        g = self.root_dir / cat.get("guide", "").replace("/", os.sep)
        if g.exists():
            core.open_in_explorer(g)
        else:
            messagebox.showinfo("教程尚未生成",
                                f"预期位置：{g}\n\n请运行「环境自检」或查看 README。", parent=self)

    def _select_category_and_show(self, t: core.Tool) -> None:
        self.search_var.set("")
        self._select_category(t.category)
        self._show_detail(t)

    def _run_setup(self) -> None:
        t = self.by_id.get("setup")
        if t:
            self._launch(t)
        else:
            messagebox.showinfo("提示", "未找到环境自检脚本。", parent=self)

    # ------------------------------------------------------------ 补齐缺失

    def _manifest(self) -> dict | None:
        """读取 scripts/tools-manifest.json（bootstrap 的唯一数据源）。"""
        p = self.root_dir / "scripts" / "tools-manifest.json"
        if not p.exists():
            return None
        try:
            with open(p, "r", encoding="utf-8-sig") as fh:
                return json.load(fh)
        except Exception:  # noqa: BLE001
            return None

    def _missing_auto(self) -> list[dict]:
        """返回「可自动下载但当前缺失」的条目。

        判定用 manifest 自己的 target/entry，而不是 tools.json 的 launch.target，
        因为后者可能指向一个 .bat 启动器（如 volatility3），而真正判断
        「装没装」要看 venv 里的 exe。
        """
        man = self._manifest()
        if not man:
            return []
        out: list[dict] = []
        for t in man.get("tools", []):
            if not t.get("auto"):
                continue
            target = (t.get("target") or "").replace("/", os.sep)
            entry = (t.get("entry") or "").replace("/", os.sep)
            if not target or not entry:
                continue
            p = Path(entry) if os.path.isabs(entry) else (self.root_dir / target / entry)
            if not p.exists():
                out.append(t)
        return out

    def _install_missing(self) -> None:
        missing = self._missing_auto()
        manual_note = ""
        man = self._manifest()
        if man:
            n_manual = sum(
                1 for t in man.get("tools", [])
                if not t.get("auto") and not self._entry_exists(t)
            )
            if n_manual:
                manual_note = f"\n\n另有 {n_manual} 个工具需手动获取（授权或需编译），不会自动下载。"

        if not missing:
            messagebox.showinfo("无需补齐",
                                "所有可自动下载的工具都已就位。" + manual_note,
                                parent=self)
            return

        names = "\n".join(f"  · {t.get('name')}  {t.get('version', '')}" for t in missing)
        if not messagebox.askyesno(
            "补齐缺失工具",
            f"以下 {len(missing)} 个工具缺失，将从官方地址下载：\n\n{names}"
            f"{manual_note}\n\n继续吗？",
            parent=self,
        ):
            return

        boot = self.root_dir / "scripts" / "bootstrap.ps1"
        if not boot.exists():
            messagebox.showwarning("缺少脚本",
                                   f"找不到 {boot}\n请确认仓库完整。", parent=self)
            return

        # -Yes 表示「全部装」，不给逐个确认；GUI 已经把清单给用户看过了。
        # 用新控制台窗口跑，下载进度和报错用户都能看到。
        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(boot), "-Yes"],
                cwd=str(self.root_dir),
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            self.status(f"正在下载 {len(missing)} 个工具，请稍候……")
        except Exception as exc:  # noqa: BLE001
            messagebox.showwarning("启动失败", str(exc), parent=self)

    def _entry_exists(self, t: dict) -> bool:
        target = (t.get("target") or "").replace("/", os.sep)
        entry = (t.get("entry") or "").replace("/", os.sep)
        if not target or not entry:
            return False
        p = Path(entry) if os.path.isabs(entry) else (self.root_dir / target / entry)
        return p.exists()

    def status(self, text: str) -> None:
        self.cat_desc.config(text=text)

    # ------------------------------------------------------------ 拖拽

    def _bind_dnd(self) -> None:
        """Windows 下用 tkdnd 或兜底按钮；这里提供「选择文件」兜底入口。"""
        bar = tk.Frame(self.head, bg=BG)
        bar.pack(fill="x", padx=24, pady=(6, 0))
        self._mkbtn(bar, "📎 选择文件推荐工具", CARD, self._pick_file).pack(side="left")
        self._mkbtn(bar, "🔄 刷新状态", CARD, self._reload).pack(side="left", padx=(8, 0))

    def _pick_file(self) -> None:
        p = filedialog.askopenfilename(title="选择题目文件", parent=self)
        if p:
            self._recommend(Path(p))

    def _recommend(self, path: Path) -> None:
        recs = core.recommend_for_file(self.tools, path)
        if not recs:
            messagebox.showinfo("没有匹配",
                                f"未识别 {path.name} 的类型，可先用 CyberChef 或 binwalk 看一眼。",
                                parent=self)
            return
        # 在搜索框里展示推荐
        self.search_var.set("")
        self._select_category(recs[0].category)
        for w in self.cards_holder.winfo_children():
            w.destroy()
        tk.Label(self.cards_holder, text=f"📎 {path.name} 推荐工具链",
                 bg=BG, fg=ACCENT, font=(FONT, 10, "bold"), anchor="w").pack(fill="x", pady=(4, 6))
        for t in recs:
            self._make_card(t)
        self._show_detail(recs[0])
        self.status(f"已为 {path.name} 推荐 {len(recs)} 个工具")

    def _reload(self) -> None:
        self.cfg = core.load_config()
        self.tools = core.build_tools(self.cfg)
        self.by_id = {t.id: t for t in self.tools}
        self._select_category(self.current_cat)
        self.status("已刷新工具状态")


def main() -> None:
    app = MiscBoxApp()
    app.mainloop()


if __name__ == "__main__":
    main()
