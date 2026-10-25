# -*- coding: utf-8 -*-
"""dnd.py -- Windows 原生文件拖放（WM_DROPFILES），不依赖任何第三方库。

为什么自己写
============
tkinter 本身不支持文件拖放；常用方案 tkinterdnd2 / windnd 都是第三方包，
本工具箱约定「只用标准库」，所以直接用 ctypes 调 Win32。

原理
====
1. ``DragAcceptFiles(hwnd, True)`` 告诉系统「这个窗口接受拖放」；
2. 用 ``SetWindowLongPtrW`` 把窗口过程换成我们自己的 ``WNDPROC``；
3. 文件拖进来时系统发 ``WM_DROPFILES``，wParam 是一个 HDROP 句柄；
4. 用 ``DragQueryFileW`` 逐个取出路径，``DragFinish`` 释放；
5. 其余消息原样交给 ``CallWindowProcW``，不影响 Tk 正常工作。

hwnd 的取法：``GetParent(root.winfo_id())``。``winfo_id()`` 给的是 Tk 内部的
子窗口，真正接收拖放的是它的父窗口（顶层窗口）。这一点不实测很容易搞错。

⚠️ 绝不能在窗口过程里调用任何 Tk/Tcl 函数（包括 ``root.after``）。
窗口过程是在 Tk 自己的消息处理里被回调的，此时再进 Tcl 属于重入，
实测会直接崩进程（``PyEval_RestoreThread: GIL is released``）。
所以这里只把路径塞进普通 Python 列表，由 Tk 侧的定时器来取。

⚠️ 回调函数必须保持引用（存在模块级列表里），否则会被 Python 回收，
之后系统再调用就是野指针 —— 表现为拖一次就崩。
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Callable, List

WM_DROPFILES = 0x0233
GWLP_WNDPROC = -4

LONG_PTR = ctypes.c_longlong
WNDPROC = ctypes.WINFUNCTYPE(LONG_PTR, wintypes.HWND, wintypes.UINT,
                             wintypes.WPARAM, wintypes.LPARAM)

user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

user32.GetParent.argtypes = [wintypes.HWND]
user32.GetParent.restype = wintypes.HWND
user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, LONG_PTR]
user32.SetWindowLongPtrW.restype = LONG_PTR
user32.CallWindowProcW.argtypes = [LONG_PTR, wintypes.HWND, wintypes.UINT,
                                   wintypes.WPARAM, wintypes.LPARAM]
user32.CallWindowProcW.restype = LONG_PTR
shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT,
                                   wintypes.LPWSTR, wintypes.UINT]
shell32.DragQueryFileW.restype = wintypes.UINT
shell32.DragFinish.argtypes = [wintypes.HANDLE]

# 保活：ctypes 回调被 Python 回收后系统再调用会直接崩进程
_ALIVE: List[object] = []
_old: List[int] = [0]

# 拖放投递过来的路径先攒在这里，由 Tk 定时器取走（窗口过程里不能碰 Tcl）
_PENDING: List[str] = []


def _query_paths(hdrop: int) -> List[str]:
    count = shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
    out: List[str] = []
    for i in range(count):
        need = shell32.DragQueryFileW(hdrop, i, None, 0)
        buf = ctypes.create_unicode_buffer(need + 1)
        if shell32.DragQueryFileW(hdrop, i, buf, need + 1):
            out.append(buf.value)
    return out


def enable(widget, on_drop: Callable[[List[str]], None], interval_ms: int = 120) -> bool:
    """让顶层窗口接受文件拖放。

    ``on_drop`` 在 Tk 主线程被调用（由定时器派发），参数是路径列表。
    返回 True 表示挂上了，False 表示环境不支持（非 Windows / 调用失败）。
    """
    try:
        root = widget.winfo_toplevel()
        root.update_idletasks()
        hwnd = user32.GetParent(root.winfo_id())
        if not hwnd:
            hwnd = root.winfo_id()
    except Exception:  # noqa: BLE001
        return False

    shell32.DragAcceptFiles(hwnd, True)

    def _proc(h, msg, wparam, lparam):
        # 只做「取路径 + 入队」，不调用任何 Tcl 函数
        if msg == WM_DROPFILES:
            try:
                _PENDING.extend(_query_paths(int(wparam)))
            except Exception:  # noqa: BLE001
                pass
            finally:
                try:
                    shell32.DragFinish(int(wparam))
                except Exception:  # noqa: BLE001
                    pass
            return 0
        return user32.CallWindowProcW(_old[0], h, msg, wparam, lparam)

    cb = WNDPROC(_proc)
    _ALIVE.append(cb)
    try:
        old = user32.SetWindowLongPtrW(hwnd, GWLP_WNDPROC,
                                       LONG_PTR(ctypes.cast(cb, ctypes.c_void_p).value))
    except Exception:  # noqa: BLE001
        return False

    _old[0] = old
    root._dnd_hwnd = hwnd          # 便于测试与排障
    root._dnd_old = old

    def _drain() -> None:
        if _PENDING:
            batch = list(_PENDING)
            _PENDING.clear()
            try:
                on_drop(batch)
            except Exception:  # noqa: BLE001
                pass
        # 窗口已经销毁就别再排下一轮，否则 Tk 会一直报
        # `invalid command name "..._drain"`（after 回调在销毁后仍被触发）
        try:
            if not root.winfo_exists():
                return
            root._dnd_after = root.after(interval_ms, _drain)
        except Exception:  # noqa: BLE001
            pass

    root._dnd_after = root.after(interval_ms, _drain)

    # 窗口销毁前必须把 after 取消掉：那个回调一旦排队，窗口一销毁
    # Tcl 命令就没了，Tk 会直接打 invalid command name，Python 侧来不及拦。
    # ⚠️ <Destroy> 会为「所有子控件」触发，必须判 e.widget is root，
    # 否则切换工具时重建面板（销毁子控件）就会把轮询停掉。
    def _on_destroy(event) -> None:
        if event.widget is root:
            cancel(root)

    try:
        root.bind("<Destroy>", _on_destroy, add="+")
    except Exception:  # noqa: BLE001
        pass
    return True


def cancel(root) -> None:
    """取消拖放轮询定时器（窗口销毁前调用，避免 Tk 报 invalid command name）。"""
    try:
        aid = getattr(root, "_dnd_after", None)
        if aid:
            root.after_cancel(aid)
            root._dnd_after = None
    except Exception:  # noqa: BLE001
        pass


def disable(widget) -> None:
    """撤销拖放注册并还原窗口过程。"""
    try:
        root = widget.winfo_toplevel()
        hwnd = getattr(root, "_dnd_hwnd", None)
        if hwnd:
            shell32.DragAcceptFiles(hwnd, False)
            old = getattr(root, "_dnd_old", 0)
            if old:
                user32.SetWindowLongPtrW(hwnd, GWLP_WNDPROC, LONG_PTR(old))
    except Exception:  # noqa: BLE001
        pass
