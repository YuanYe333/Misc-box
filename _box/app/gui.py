"""杂项工具箱 - tkinter 启动器。

布局：左侧分类导航 + 搜索框，右侧工具卡片 + 详情页。
交互：点分类过滤、点卡片看说明、双击卡片启动；选中工具后把文件拖进窗口
（或点拖放区选文件），选好预设，点「运行」，输出实时显示在下方面板。

设计原则：不做「自动猜工具」。拖进来的文件只会填进**当前选中工具**的运行区，
用户始终清楚自己在跑什么。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

import core    # noqa: E402
import dnd     # noqa: E402
import runner  # noqa: E402

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

# 自定义占位符的输入提示（占位符名 -> 一句话说明）
FIELD_HINTS = {
    "mask": "如 ?d?d?d?d（?d 数字 ?l 小写 ?u 大写 ?s 符号 ?a 全部）",
    "crc": "目标 CRC32，十六进制如 1a2b3c4d",
    "len": "长度，如 4",
    "fmt": "哈希格式，如 raw-md5",
}


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

        # ---- 运行面板状态 ----
        self.job: runner.Job | None = None
        self.run_files: list[Path] = []
        self._drop_widgets: list[tuple[tk.Widget, str]] = []   # (控件, 常态底色)
        self._preset_var = tk.StringVar()
        self._text_var = tk.StringVar()
        self._field_vars: dict[str, tk.StringVar] = {}
        self._run_ui: dict[str, object] = {}
        self._poll_after: str | None = None
        self._current_tab: str | None = None
        self._dnd_ok = False
        # 当前 job 的输出该写进哪块面板（用户中途切工具时用来防止串台）
        self._job_panel_tool: str | None = None
        self._bg_lines: list[str] = []

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

        # 关窗口时把定时器和子进程收干净：after 回调在窗口销毁后还会被触发，
        # 那时对应的 Tcl 命令已不存在，Tk 会打 invalid command name。
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self) -> None:
        try:
            if self._poll_after:
                self.after_cancel(self._poll_after)
                self._poll_after = None
        except Exception:  # noqa: BLE001
            pass
        try:
            dnd.cancel(self)
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.job is not None and self.job.running:
                self.job.stop()
        except Exception:  # noqa: BLE001
            pass
        self.destroy()

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
        # 切换工具时，正在跑的任务保留（用户可能想看它跑完），但拖放列表清空
        self.run_files = []
        self._field_vars = {}
        self._run_ui = {}
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

        # ---- 页签：运行 / 说明 ----
        tabbar = tk.Frame(self.detail, bg=PANEL)
        tabbar.pack(fill="x", padx=20, pady=(4, 0))
        body = tk.Frame(self.detail, bg=PANEL)
        body.pack(fill="both", expand=True)

        tabs: dict[str, tk.Label] = {}

        def switch(name: str) -> None:
            self._current_tab = name
            for key, lbl in tabs.items():
                lbl.config(bg=(ACCENT if key == name else CARD),
                           fg=(BG if key == name else TEXT))
            for w in body.winfo_children():
                w.destroy()
            self._run_ui = {}
            self._drop_widgets = []
            if name == "run":
                self._build_run_panel(body, t)
            else:
                self._build_doc_panel(body, t)

        for key, label in (("run", "▶  运行"), ("doc", "📖  说明")):
            lbl = tk.Label(tabbar, text=label, bg=CARD, fg=TEXT, font=(FONT, 9, "bold"),
                           padx=16, pady=6, cursor="hand2")
            lbl.pack(side="left", padx=(0, 4))
            lbl.bind("<Button-1>", lambda e, k=key: switch(k))
            tabs[key] = lbl

        self._switch_tab = switch
        switch("run" if t.runnable else "doc")

    # ------------------------------------------------------------ 运行面板

    def _build_run_panel(self, parent: tk.Frame, t: core.Tool) -> None:
        """拖放区 + 预设 + 输入 + 运行按钮 + 实时输出 + 产物。

        布局用纵向堆叠：详情区本身只有约 600px 宽，若左右分栏，输出区会被
        挤到 250px 左右，命令行和十六进制dump 都会折断。纵向排列让输出
        拿到整行宽度，这才是主要看点。
        """
        spec = runner.RunSpec.parse(t.run_raw)

        if not t.runnable:
            tk.Label(parent, text="这个工具是图形界面程序，请点上面的「▶ 打开工具」。",
                     bg=PANEL, fg=TEXT_DIM, font=(FONT, 10),
                     anchor="w").pack(fill="x", padx=24, pady=20)
            return

        outer = tk.Frame(parent, bg=PANEL)
        outer.pack(fill="both", expand=True, padx=20, pady=(10, 12))

        # ---------------- 拖放区 ----------------
        drop = tk.Frame(outer, bg=CARD, height=82)
        drop.pack(fill="x")
        drop.pack_propagate(False)
        self._drop_widgets = []

        dz_title = tk.Label(drop, text="⬇  把文件拖到这里", bg=CARD, fg=ACCENT,
                            font=(FONT, 11, "bold"))
        dz_title.pack(pady=(10, 0))
        dz_list = tk.Label(drop, text="（还没选文件）", bg=CARD, fg=TEXT,
                           font=(FONT, 9))
        dz_list.pack(pady=(2, 0))
        dz_hint = tk.Label(drop, text=self._accept_hint(spec), bg=CARD, fg=TEXT_DIM,
                           font=(FONT, 8))
        dz_hint.pack()

        for w in (drop, dz_title, dz_hint, dz_list):
            self._drop_widgets.append((w, CARD))
            w.bind("<Button-1>", lambda e: self._pick_for_run(t))

        # ---------------- 预设 + 输入 ----------------
        # 预设下拉单独一行（要够宽，标题长的时候别被裁）；
        # 下面一行左边是文本输入、右边是自定义字段。
        prow = tk.Frame(outer, bg=PANEL)
        prow.pack(fill="x", pady=(8, 0))
        tk.Label(prow, text="运行方式", bg=PANEL, fg=TEXT_DIM, font=(FONT, 9),
                 width=8, anchor="w").pack(side="left")
        titles = [p.get("title", "默认") for p in spec.presets] or ["默认"]
        combo = ttk.Combobox(prow, textvariable=self._preset_var, values=titles,
                             state="readonly", font=(FONT, 9))
        combo.pack(side="left", fill="x", expand=True)
        combo.current(0)
        combo.bind("<<ComboboxSelected>>", lambda e: self._on_preset_change(t))

        mid = tk.Frame(outer, bg=PANEL)
        mid.pack(fill="x", pady=(6, 0))

        left_col = tk.Frame(mid, bg=PANEL)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 12))

        self._text_label = tk.Label(left_col, text="输入内容", bg=PANEL, fg=TEXT_DIM,
                                    font=(FONT, 9), anchor="w")
        self._text_label.pack(fill="x")
        tb = tk.Text(left_col, bg=CARD, fg=TEXT, insertbackground=TEXT, relief="flat",
                     font=("Consolas", 9), height=3, padx=6, pady=4)
        tb.pack(fill="x", pady=(2, 0))
        self._text_box = tb
        self._text_holder = left_col

        # 自定义字段栏（占满剩余宽度，否则条目会被压成 0 高看不见）
        right_col = tk.Frame(mid, bg=PANEL)
        right_col.pack(side="left", fill="both", expand=True)
        self._field_frame = right_col

        # ---------------- 按钮 + 命令预览 ----------------
        brow = tk.Frame(outer, bg=PANEL)
        brow.pack(fill="x", pady=(10, 0))
        self._btn_run = self._mkbtn(brow, "▶  运行", ACCENT, lambda: self._start_run(t))
        self._btn_run.pack(side="left")
        self._btn_stop = self._mkbtn(brow, "■  停止", CARD, self._stop_run)
        self._btn_stop.pack(side="left", padx=(8, 0))
        self._btn_clear = self._mkbtn(brow, "🧹 清空文件", CARD, lambda: self._clear_run_files(t))
        self._btn_clear.pack(side="left", padx=(8, 0))
        self._btn_outdir = self._mkbtn(brow, "📂 输出目录", CARD, self._open_run_dir)
        self._btn_outdir.pack(side="right")

        self._status_label = tk.Label(brow, text="就绪", bg=PANEL, fg=TEXT_DIM,
                                      font=(FONT, 9), anchor="w")
        self._status_label.pack(side="left", padx=(12, 0))

        self._cmd_label = tk.Label(outer, text="", bg=PANEL, fg=TEXT_DIM,
                                   font=("Consolas", 8), anchor="w",
                                   justify="left", wraplength=560)
        self._cmd_label.pack(fill="x", pady=(6, 0))

        # ---------------- 输出 ----------------
        twrap = tk.Frame(outer, bg=BG)
        twrap.pack(fill="both", expand=True, pady=(8, 0))
        self._out = tk.Text(twrap, bg=BG, fg="#c0caf5", font=("Consolas", 9),
                            relief="flat", wrap="none", padx=8, pady=6,
                            insertbackground=TEXT)
        vs = ttk.Scrollbar(twrap, orient="vertical", command=self._out.yview)
        hs = ttk.Scrollbar(twrap, orient="horizontal", command=self._out.xview)
        self._out.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side="right", fill="y")
        hs.pack(side="bottom", fill="x")
        self._out.pack(side="left", fill="both", expand=True)
        self._out.tag_config("err", foreground=ERR)
        self._out.tag_config("ok", foreground=OK)
        self._out.tag_config("warn", foreground=WARN)
        self._out.tag_config("dim", foreground=TEXT_DIM)

        self._art_label = tk.Label(outer, text="", bg=PANEL, fg=OK, font=(FONT, 9),
                                   anchor="w", justify="left", wraplength=560)
        self._art_label.pack(fill="x", pady=(6, 0))

        self._run_ui = {"drop_list": dz_list, "status": self._status_label,
                        "out": self._out, "art": self._art_label, "cmd": self._cmd_label}
        self._on_preset_change(t)
        self._refresh_cmd(t)
        self._write_out("准备就绪。拖入文件后点「▶ 运行」。\n", "dim")

    def _accept_hint(self, spec: runner.RunSpec) -> str:
        if spec.input_mode == "none":
            return "这个工具不需要文件，直接点运行"
        if spec.input_mode == "text":
            return "这个工具主要用输入框，也可以拖文件"
        if spec.accept:
            return "接受：" + "  ".join(spec.accept) + ("（可多选）" if spec.multi else "")
        return "任意文件" + ("（可多选）" if spec.multi else "")

    def _on_preset_change(self, t: core.Tool) -> None:
        """切换预设：重建自定义字段输入框，并更新命令预览。"""
        if not self._run_ui:
            return
        spec = runner.RunSpec.parse(t.run_raw)
        idx = self._preset_index(t)
        target = self._make_target(t, preset_index=idx)

        # 重建自定义字段
        for w in self._field_frame.winfo_children():
            w.destroy()
        self._field_vars = {}
        fields = runner.preset_custom_fields(target)
        if fields:
            tk.Label(self._field_frame, text="需要填写的参数", bg=PANEL, fg=TEXT_DIM,
                     font=(FONT, 9), anchor="w").pack(fill="x")
        for name in fields:
            row = tk.Frame(self._field_frame, bg=PANEL)
            row.pack(fill="x", pady=(4, 0))
            tk.Label(row, text="{%s}" % name, bg=PANEL, fg=OK,
                     font=("Consolas", 9), width=8, anchor="w").pack(side="left")
            var = tk.StringVar()
            ent = tk.Entry(row, textvariable=var, bg=CARD, fg=TEXT, relief="flat",
                           insertbackground=TEXT, font=("Consolas", 9))
            ent.pack(side="left", fill="x", expand=True, ipady=3)
            hint = FIELD_HINTS.get(name)
            if hint:
                tk.Label(row, text=hint, bg=PANEL, fg=TEXT_DIM,
                         font=(FONT, 8)).pack(side="left", padx=(6, 0))
            self._field_vars[name] = var

        needs_text = runner.preset_needs_text(target)
        needs_file = runner.preset_needs_file(target)
        if self._text_box is not None:
            # 不需要文本时整块收起来，别白占三行高度——输出区才是主看点
            if needs_text:
                self._text_label.pack(fill="x")
                self._text_box.pack(fill="x", pady=(2, 0))
                self._text_box.configure(state="normal")
                self._text_label.config(fg=TEXT_DIM)
            else:
                self._text_box.configure(state="disabled")
                self._text_box.pack_forget()
                self._text_label.pack_forget()
        for w, base in self._drop_widgets:
            try:
                w.config(bg=(base if needs_file else "#242630"))
            except tk.TclError:
                pass
        dl = self._run_ui.get("drop_list")
        if dl is not None:
            dl.config(text=self._files_summary() if needs_file else "（当前方式不需要文件）")
        self._refresh_cmd(t)

    def _preset_index(self, t: core.Tool) -> int:
        spec = runner.RunSpec.parse(t.run_raw)
        title = self._preset_var.get()
        for i, p in enumerate(spec.presets):
            if p.get("title", "默认") == title:
                return i
        return 0

    def _make_target(self, t: core.Tool, preset_index: int | None = None) -> runner.RunTarget:
        spec = runner.RunSpec.parse(t.run_raw)
        entry = core.resolve(self.root_dir, t.raw.get("path", ""))
        text = ""
        if self._text_box is not None:
            text = self._text_box.get("1.0", "end").strip()
        fields = {k: v.get() for k, v in self._field_vars.items()}
        return runner.RunTarget(
            tool_id=t.id, tool_name=t.name, spec=spec, entry=entry,
            tool_dir=entry.parent, root=self.root_dir,
            files=list(self.run_files), text=text,
            preset_index=(preset_index if preset_index is not None else self._preset_index(t)),
            fields=fields,
        )

    def _refresh_cmd(self, t: core.Tool) -> None:
        if not self._run_ui:
            return
        try:
            preview = runner.command_preview(self._make_target(t))
        except Exception:  # noqa: BLE001
            preview = ""
        self._run_ui["cmd"].config(text=preview)

    def _files_summary(self) -> str:
        if not self.run_files:
            return "（还没选文件）"
        if len(self.run_files) == 1:
            return self.run_files[0].name
        return "%d 个文件：%s" % (len(self.run_files),
                                 "、".join(f.name for f in self.run_files[:3])
                                 + ("…" if len(self.run_files) > 3 else ""))

    def _pick_for_run(self, t: core.Tool) -> None:
        spec = runner.RunSpec.parse(t.run_raw)
        paths = filedialog.askopenfilenames(title="选择要处理的文件", parent=self)
        if not paths:
            return
        self._add_files([Path(p) for p in paths], t)

    def _add_files(self, paths: list[Path], t: core.Tool | None = None) -> None:
        """把文件加入运行区（不自动切工具、不自动推荐）。"""
        t = t or self.current_tool
        if t is None:
            return
        spec = runner.RunSpec.parse(t.run_raw)
        files = [p for p in paths if p.is_file()]
        if not files:
            messagebox.showinfo("没有文件", "拖进来的不是文件（文件夹暂不支持）。", parent=self)
            return
        if not spec.multi:
            files = files[:1]
            if len(paths) > 1:
                self.status("这个工具一次只处理一个文件，已取第一个。")
        self.run_files = files if spec.multi else files[:1]

        if self._run_ui:
            self._run_ui["drop_list"].config(text=self._files_summary())
            self._refresh_cmd(t)
            self.status("已放入 %d 个文件：%s" % (len(self.run_files),
                                                self.run_files[0].name))

    def _clear_run_files(self, t: core.Tool) -> None:
        self.run_files = []
        if self._run_ui:
            self._run_ui["drop_list"].config(text="（还没选文件）")
            self._refresh_cmd(t)

    # ------------------------------------------------------------ 运行

    def _start_run(self, t: core.Tool) -> None:
        if self.job is not None and self.job.running:
            messagebox.showinfo("正在运行", "上一个任务还没结束，先停止或等它跑完。", parent=self)
            return

        target = self._make_target(t)
        err = runner.validate(target)
        if err:
            messagebox.showwarning("还不能运行", err, parent=self)
            return

        self._out.delete("1.0", "end")
        self._art_label.config(text="")
        try:
            job = runner.start_job(target)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("启动失败", str(exc), parent=self)
            return

        self.job = job
        self._job_panel_tool = t.id      # 这块面板属于哪个工具
        self._status_label.config(text="运行中…", fg=WARN)
        self._write_out("$ " + " ".join(job.cmd) + "\n", "dim")
        self._write_out("输出目录：" + str(job.run_dir) + "\n\n", "dim")
        self._poll_job()

    def _poll_job(self) -> None:
        job = self.job
        if job is None:
            return
        lines, done = job.poll()

        # 用户中途切到了别的工具：这块面板已经不属于这个 job，
        # 继续往这里写就会把 A 工具的输出糊到 B 工具的脸上。
        # 输出先攒着，等 job 结束给一句汇总（内容仍在输出目录里）。
        visible = (self._job_panel_tool == getattr(self.current_tool, "id", None))
        if visible:
            for line in lines:
                tag = ""
                low = line.lower()
                if "错误" in line or "error" in low or "fail" in low or "[!]" in line:
                    tag = "err"
                elif "通过" in line or "ok" in low or "成功" in low or "找到" in line:
                    tag = "ok"
                elif "警告" in line or "warn" in low:
                    tag = "warn"
                self._write_out(line + "\n", tag)
        else:
            self._bg_lines.extend(lines)

        if done:
            self._finish_run(job, visible)
            return
        if visible:
            self._status_label.config(text="运行中…（%.1f 秒）" % job.elapsed, fg=WARN)
        self._poll_after = self.after(80, self._poll_job)

    def _finish_run(self, job: runner.Job, visible: bool = True) -> None:
        self._poll_after = None
        ok = (job.returncode == 0)

        if not visible:
            # 面板已经换成别的工具了，只在状态栏提一句，别污染别人的输出区
            self.status("%s %s（输出在 %s）"
                        % (job.tool_name or job.tool_id, job.summary(),
                           job.run_dir.name))
            self._bg_lines.clear()
            self._btn_run.config(bg=ACCENT)
            return

        self._status_label.config(text=job.summary(), fg=(OK if ok else ERR))
        self._write_out("\n" + job.summary() + "\n", "ok" if ok else "err")

        arts = runner.list_artifacts(job.run_dir)
        if arts:
            shown = arts[:8]
            names = "\n".join("  · " + str(p.relative_to(job.run_dir)) for p in shown)
            more = "" if len(arts) <= 8 else "\n  …… 还有 %d 个" % (len(arts) - 8)
            self._art_label.config(text="产出文件：\n" + names + more)
            self._write_out("\n产出文件（%d 个）：\n%s%s\n" % (len(arts), names, more), "ok")
        self._btn_run.config(bg=ACCENT)

    def _stop_run(self) -> None:
        if self.job is None or not self.job.running:
            self.status("当前没有正在运行的任务。")
            return
        self.job.stop()
        self._write_out("\n[已请求停止]\n", "warn")
        self._status_label.config(text="正在停止…", fg=WARN)

    def _open_run_dir(self) -> None:
        if self.job is None:
            messagebox.showinfo("还没有运行", "先跑一次再打开输出目录。", parent=self)
            return
        core.open_in_explorer(self.job.run_dir)

    def _write_out(self, text: str, tag: str = "") -> None:
        out = self._run_ui.get("out") if self._run_ui else None
        if out is None:
            return
        out.insert("end", text, (tag,) if tag else ())
        out.see("end")

    # ------------------------------------------------------------ 说明面板

    def _build_doc_panel(self, parent: tk.Frame, t: core.Tool) -> None:
        # 滚动内容
        wrap = tk.Frame(parent, bg=PANEL)
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
        """挂上原生拖放，并在顶部放两个辅助按钮。

        拖放的目标是**当前选中工具**的运行区，不做任何自动推荐：
        用户先选工具，再拖文件，点运行。
        """
        bar = tk.Frame(self.head, bg=BG)
        bar.pack(fill="x", padx=24, pady=(6, 0))
        self._mkbtn(bar, "📎 选择文件", CARD, self._pick_for_current).pack(side="left")
        self._mkbtn(bar, "🔄 刷新状态", CARD, self._reload).pack(side="left", padx=(8, 0))

        self._dnd_ok = dnd.enable(self, self._on_drop)
        if not self._dnd_ok:
            self.status("拖放不可用（非 Windows 环境），请用「📎 选择文件」。")

    def _on_drop(self, paths: list[str]) -> None:
        """系统拖放回调：只把文件放进当前工具，不切工具。"""
        t = self.current_tool
        if t is None:
            messagebox.showinfo(
                "先选一个工具",
                "请先在左侧选好要用哪个工具，再把文件拖进来。\n\n"
                "（工具箱不会自动猜工具，避免跑错。）", parent=self)
            return
        if not t.runnable:
            messagebox.showinfo(
                "这个工具不在这里运行",
                f"「{t.name}」是图形界面程序，请点「▶ 打开工具」后在里面打开文件。",
                parent=self)
            return
        # 若当前在「说明」页，切回「运行」页，让用户看到文件已放进去
        if "run" not in (self._current_tab or ""):
            if callable(getattr(self, "_switch_tab", None)):
                self._switch_tab("run")
        self._add_files([Path(p) for p in paths], t)

    def _pick_for_current(self) -> None:
        t = self.current_tool
        if t is None:
            messagebox.showinfo("先选一个工具", "请先在左侧选好要用哪个工具。", parent=self)
            return
        if not t.runnable:
            messagebox.showinfo("这个工具不在这里运行",
                                f"「{t.name}」是图形界面程序，请点「▶ 打开工具」。", parent=self)
            return
        self._pick_for_run(t)

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
