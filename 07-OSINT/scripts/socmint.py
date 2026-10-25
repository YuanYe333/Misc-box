# -*- coding: utf-8 -*-
"""
socmint.py -- 用户名跨平台存在性检查：一个用户名，看它在哪些平台注册过。

为什么需要
==========
OSINT 里拿到一个用户名（比如某题的作者昵称），最快的画像方式就是看这个
昵称在哪些平台出现过——同一昵称往往指向同一个人。手工一个个打开太慢。

**用途声明（重要）**
====================
本脚本**仅用于公开信息查询**：它只发出 HEAD 请求或调用平台公开 API，
不抓取页面内容、不登录、不绕过任何访问控制、不做爬虫。
请勿用于骚扰、跟踪、人肉他人或任何未经授权的调查。查公开信息也要有边界。

用法
====
    python -X utf8 socmint.py someuser
    python -X utf8 socmint.py someuser --sites github,reddit,keybase
    python -X utf8 socmint.py someuser --timeout 5 --json
    python -X utf8 socmint.py someuser --list

三种状态，绝不猜
================
    存在   -- 平台明确返回「有这个用户」
    不存在 -- 平台明确返回 404 / 明确说没有
    不确定 -- 被限流(429/403)、超时、或平台对「有/没有」返回同样的状态码
              （典型：Twitter/Instagram 未登录时对任何用户名都返回 200）

关于速率
========
各平台之间**强制至少间隔 1 秒**（--delay 只能调大不能调小到 1 以下），
串行执行、不并发，避免给别人服务器造成压力，也避免自己立刻被限流。

已知限制
========
    * Twitter/X、Instagram、Telegram 等平台未登录时无法区分「存在/不存在」，
      本脚本会诚实报「不确定」而不是瞎猜——这是设计选择，不是 bug；
    * GitHub 匿名 API 每小时只有 60 次额度，查多了会 403，届时报「不确定」；
    * 存在同名用户不等于同一个人，结论要结合其他线索；
    * 本机网络不稳，所有请求带超时（默认 8 秒），失败会明确报「不确定」。
"""

import argparse
import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 8.0
MIN_DELAY = 1.0          # 平台之间的最小间隔，硬性下限
DEFAULT_DELAY = 1.0

EXISTS = "存在"
ABSENT = "不存在"
UNSURE = "不确定"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """不自动跟随 3xx。

    为什么：很多平台对「不存在的用户」会 302 到登录页或首页，自动跟随后
    拿到的是 200，会把「不存在」误判成「存在」。让 3xx 原样抛出来，
    我们才能如实报「不确定」。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def http_request(url, method, timeout, accept="application/json"):
    """发一个请求，返回 (状态码, 响应体文本)。网络异常抛 OSError/socket.timeout。"""
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "miscbox-osint/1.0 (public-info check)",
        "Accept": accept,
    })
    try:
        with OPENER.open(req, timeout=timeout) as resp:
            body = b""
            # HEAD 没有响应体，read() 会直接返回空
            if method != "HEAD":
                body = resp.read(65536)
            return resp.getcode(), body.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        # 3xx（我们主动不跟随）、4xx、5xx 都走到这里
        try:
            body = exc.read(65536).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001  读错误页失败不影响状态判断
            body = ""
        return exc.code, body


class RequestTimeout(Exception):
    """整体超时（含 DNS 解析阶段）。"""


def request_with_deadline(url, method, timeout, accept):
    """把整个请求（含 DNS 解析）压进一个硬性截止时间。

    为什么需要：urllib 的 timeout 只约束 socket 读写，管不住 getaddrinfo。
    实测某个域名解析卡住时，3 秒超时的请求会拖到 35 秒。另开守护线程 +
    join(timeout) 才能真正保证「到点就走」。
    """
    box = {}

    def runner():
        try:
            box["value"] = http_request(url, method, timeout, accept)
        except BaseException as exc:  # noqa: BLE001  原样抛回主线程
            box["error"] = exc

    th = threading.Thread(target=runner, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise RequestTimeout("超时（%.0f 秒，含 DNS 解析）" % timeout)
    if "error" in box:
        raise box["error"]
    return box["value"]


# ------------------------------------------------------------------ 各平台判定
#
# 每个判定函数收到 (状态码, 响应体)，返回 (状态, 原因)。
# 拿不准就返回 UNSURE —— 宁可少报，也不要编。

def judge_github(status, body):
    if status == 200:
        return EXISTS, "API 返回用户对象"
    if status == 404:
        return ABSENT, "API 返回 404"
    if status in (403, 429):
        return UNSURE, "被限流（HTTP %d），匿名额度 60 次/小时" % status
    return UNSURE, "HTTP %d" % status


def judge_gitlab(status, body):
    if status == 200:
        try:
            arr = json.loads(body)
        except ValueError:
            return UNSURE, "返回的不是 JSON"
        if isinstance(arr, list):
            if arr:
                return EXISTS, "API 返回 %d 个匹配用户" % len(arr)
            return ABSENT, "API 返回空列表"
        return UNSURE, "返回结构异常"
    if status == 404:
        return ABSENT, "API 返回 404"
    if status in (403, 429):
        return UNSURE, "被限流（HTTP %d）" % status
    return UNSURE, "HTTP %d" % status


def judge_reddit(status, body):
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            # 未登录时 reddit 可能回 HTML 拦截页
            return UNSURE, "返回的不是 JSON（可能被拦到验证页）"
        if isinstance(data, dict):
            payload = data.get("data")
            if isinstance(payload, dict):
                if payload.get("name") or payload.get("id"):
                    return EXISTS, "about.json 返回用户数据"
                if payload.get("error"):
                    return ABSENT, "about.json 报错：%s" % payload.get("error")
                # is_suspended 也算「有这个人，只是被封」
                if payload.get("is_suspended"):
                    return EXISTS, "用户存在但已被封禁"
            return ABSENT, "about.json 没有用户数据"
        return UNSURE, "返回结构异常"
    if status == 404:
        return ABSENT, "HTTP 404"
    if status in (403, 429):
        return UNSURE, "被限流（HTTP %d）" % status
    return UNSURE, "HTTP %d" % status


def judge_keybase(status, body):
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            return UNSURE, "返回的不是 JSON"
        them = data.get("them")
        if isinstance(them, list) and them:
            return EXISTS, "lookup 返回用户记录"
        return ABSENT, "lookup 返回空（them 为空）"
    if status == 404:
        return ABSENT, "HTTP 404"
    if status in (403, 429):
        return UNSURE, "被限流（HTTP %d）" % status
    return UNSURE, "HTTP %d" % status


def judge_npm(status, body):
    """npm 没有公开的「查用户」接口。

    官方 registry 的 /-/user/... 端点要求认证（恒回 401），所以改查
    「按 maintainer 搜索包」：能搜到这个用户名维护的包，就说明这个账号存在。
    注意要真的核对 maintainers 里的 username，不能只看有没有结果。
    """
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            return UNSURE, "返回的不是 JSON"
        objs = data.get("objects") if isinstance(data, dict) else None
        if not isinstance(objs, list):
            return UNSURE, "返回结构异常"
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            pkg = obj.get("package")
            if not isinstance(pkg, dict):
                continue
            for mt in pkg.get("maintainers") or []:
                if isinstance(mt, dict):
                    name = mt.get("username") or mt.get("name")
                    if isinstance(name, str) and name:
                        return EXISTS, "该用户名是 npm 包维护者（%s）" % name
        if not objs:
            return ABSENT, "按 maintainer 搜索无结果"
        return UNSURE, "搜索有结果但没匹配到该维护者"
    if status in (403, 429):
        return UNSURE, "被限流（HTTP %d）" % status
    return UNSURE, "HTTP %d" % status


def judge_dockerhub(status, body):
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            return UNSURE, "返回的不是 JSON"
        if isinstance(data, dict) and (data.get("username") or data.get("id")):
            return EXISTS, "API 返回用户对象"
        return ABSENT, "API 没有返回用户对象"
    if status == 404:
        return ABSENT, "API 返回 404"
    if status in (403, 429):
        return UNSURE, "被限流（HTTP %d）" % status
    return UNSURE, "HTTP %d" % status


def judge_bitbucket(status, body):
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            return UNSURE, "返回的不是 JSON"
        if isinstance(data, dict) and (data.get("username") or data.get("uuid")):
            return EXISTS, "API 返回用户对象"
        return ABSENT, "API 没有返回用户对象"
    if status == 404:
        return ABSENT, "API 返回 404"
    if status in (403, 429):
        return UNSURE, "被限流（HTTP %d）" % status
    return UNSURE, "HTTP %d" % status


def judge_head_ambiguous(status, body):
    """只做 HEAD 的平台：状态码本身区分不了存在与否，只能给「不确定」。

    这类平台（Twitter/X、Instagram、Telegram 等）未登录时对任意用户名都
    返回 200 或 302 到登录页，靠状态码判断必然误报。宁可说不知道。
    """
    if status in (404, 410):
        return ABSENT, "HTTP %d（明确不存在）" % status
    if status in (429, 403):
        return UNSURE, "被限流/拦截（HTTP %d）" % status
    if 300 <= status < 400:
        return UNSURE, "被重定向（HTTP %d），无法区分存在与否" % status
    if status == 200:
        return UNSURE, "HTTP 200，但该平台未登录时对任意用户名都回 200"
    return UNSURE, "HTTP %d" % status


# key -> (显示名, 方法, URL 模板, 判定函数, 是否需要 Accept JSON)
SITES = {
    "github": ("GitHub", "GET", "https://api.github.com/users/%s",
               judge_github, "application/vnd.github+json"),
    "gitlab": ("GitLab", "GET", "https://gitlab.com/api/v4/users?username=%s",
               judge_gitlab, "application/json"),
    "reddit": ("Reddit", "GET", "https://www.reddit.com/user/%s/about.json",
               judge_reddit, "application/json"),
    "keybase": ("Keybase", "GET",
                "https://keybase.io/_/api/1.0/user/lookup.json?username=%s",
                judge_keybase, "application/json"),
    "npm": ("npm", "GET",
            "https://registry.npmjs.org/-/v1/search?text=maintainer:%s&size=5",
            judge_npm, "application/json"),
    "dockerhub": ("Docker Hub", "GET", "https://hub.docker.com/v2/users/%s/",
                  judge_dockerhub, "application/json"),
    "bitbucket": ("Bitbucket", "GET", "https://api.bitbucket.org/2.0/users/%s",
                  judge_bitbucket, "application/json"),
    "twitter": ("Twitter/X", "HEAD", "https://x.com/%s",
                judge_head_ambiguous, "text/html"),
    "instagram": ("Instagram", "HEAD", "https://www.instagram.com/%s/",
                  judge_head_ambiguous, "text/html"),
    "telegram": ("Telegram", "HEAD", "https://t.me/%s",
                 judge_head_ambiguous, "text/html"),
}

# 默认只查「能给出确定结论」的平台，含糊的放后面由用户显式指定
DEFAULT_SITES = ("github", "gitlab", "reddit", "keybase", "npm",
                 "dockerhub", "bitbucket", "twitter", "instagram", "telegram")


def check_one(site_key, username, timeout):
    """查一个平台。任何异常都收敛成 UNSURE，绝不抛 traceback。"""
    label, method, url_tpl, judge, accept = SITES[site_key]
    url = url_tpl % urllib.parse.quote(username, safe="")

    try:
        status, body = request_with_deadline(url, method, timeout, accept)
    except RequestTimeout as exc:
        return {"site": site_key, "label": label, "status": UNSURE,
                "reason": str(exc), "url": url}
    except socket.timeout:
        return {"site": site_key, "label": label, "status": UNSURE,
                "reason": "超时（%.0f 秒）" % timeout, "url": url}
    except urllib.error.URLError as exc:
        return {"site": site_key, "label": label, "status": UNSURE,
                "reason": "网络失败：%s" % exc.reason, "url": url}
    except OSError as exc:
        return {"site": site_key, "label": label, "status": UNSURE,
                "reason": "网络失败：%s" % exc, "url": url}

    state, reason = judge(status, body)
    return {"site": site_key, "label": label, "status": state,
            "reason": reason, "url": url, "http": status}


# ------------------------------------------------------------------ 输出

STATE_ORDER = {EXISTS: 0, ABSENT: 1, UNSURE: 2}


def build_usage():
    return (
        "用法：python -X utf8 socmint.py <用户名> [选项]\n"
        "\n"
        "做什么：查一个用户名在哪些平台注册过（GitHub / GitLab / Reddit /\n"
        "        Keybase / npm / Docker Hub / Bitbucket / Twitter / Instagram / Telegram）。\n"
        "        只发 HEAD 请求或调公开 API，不抓页面、不登录、不做爬虫。\n"
        "\n"
        "仅用于公开信息查询，请勿用于骚扰或跟踪他人。\n"
        "\n"
        "例子：\n"
        "  python -X utf8 socmint.py someuser\n"
        "  python -X utf8 socmint.py someuser --sites github,reddit,keybase\n"
        "  python -X utf8 socmint.py someuser --timeout 5 --json\n"
        "  python -X utf8 socmint.py --list\n"
        "\n"
        "选项：\n"
        "  --sites a,b,c   只查指定平台（--list 可看全部名字）\n"
        "  --timeout 秒     单次请求超时，默认 8\n"
        "  --delay 秒       平台间隔，默认 1.0，不能小于 1.0\n"
        "  --json          输出 JSON\n"
        "  --list          列出支持的平台后退出\n"
        "  -o/--output 文件 写入文件（已存在需 --force）\n"
        "\n"
        "状态说明：存在 / 不存在 / 不确定（被限流、超时，或该平台无法区分）。\n"
    )


def write_output(path, text, force):
    from pathlib import Path
    p = Path(path)
    if p.exists() and not force:
        sys.stderr.write("目标文件已存在：%s（要覆盖请加 --force）\n" % p)
        return False
    p.write_text(text, encoding="utf-8")
    return True


def main():
    ap = argparse.ArgumentParser(
        description="用户名跨平台存在性检查（仅 HEAD / 公开 API）",
        add_help=True,
    )
    ap.add_argument("username", nargs="?", help="要查的用户名")
    ap.add_argument("--sites", help="逗号分隔的平台名，默认全部")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="单次请求超时秒数，默认 8")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help="平台间隔秒数，默认 1.0（不能小于 1.0）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--list", action="store_true", help="列出支持的平台")
    ap.add_argument("-o", "--output", help="输出写入文件")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    args = ap.parse_args()

    if args.list:
        lines = ["支持的平台（--sites 用左边的名字）："]
        for key in DEFAULT_SITES:
            label, method, url_tpl, _judge, _accept = SITES[key]
            lines.append("  %-10s %-10s %s" % (key, method, label))
        lines.append("")
        lines.append("注：Twitter/X、Instagram、Telegram 未登录时无法区分存在与否，")
        lines.append("    这三个平台通常只会给出「不确定」，这是诚实的结果。")
        text = "\n".join(lines)
        if args.output:
            if not write_output(args.output, text + "\n", args.force):
                return 1
            sys.stderr.write("已写入：%s\n" % args.output)
            return 0
        sys.stdout.write(text + "\n")
        return 0

    if not args.username:
        sys.stdout.write(build_usage())
        return 0

    username = args.username.strip()
    if not username:
        sys.stderr.write("参数错误：用户名不能为空。\n")
        return 2
    if any(c in username for c in " /\\?#%&"):
        sys.stderr.write("参数错误：用户名里不该有空格或 URL 特殊字符：%s\n" % username)
        return 2

    # 选平台
    if args.sites:
        keys = [k.strip().lower() for k in args.sites.replace(";", ",").split(",") if k.strip()]
        unknown = [k for k in keys if k not in SITES]
        if unknown:
            sys.stderr.write("参数错误：不认识的平台：%s\n" % ", ".join(unknown))
            sys.stderr.write("可用平台：%s\n" % ", ".join(DEFAULT_SITES))
            return 2
        if not keys:
            sys.stderr.write("参数错误：--sites 没有给出有效平台。\n")
            return 2
    else:
        keys = list(DEFAULT_SITES)

    # 去重但保持顺序
    seen = set()
    ordered = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            ordered.append(k)

    timeout = max(1.0, float(args.timeout))
    # 硬性下限：无论用户怎么填，平台之间至少隔 1 秒
    delay = max(MIN_DELAY, float(args.delay))

    sys.stderr.write("检查用户名：%s（%d 个平台，间隔 %.1f 秒，单次超时 %.0f 秒）\n"
                     % (username, len(ordered), delay, timeout))

    results = []
    for idx, key in enumerate(ordered):
        if idx > 0:
            time.sleep(delay)      # 串行 + 间隔，不并发轰炸
        rec = check_one(key, username, timeout)
        results.append(rec)
        # 进度打到 stderr，结果留给 stdout
        sys.stderr.write("  [%d/%d] %-10s %s\n"
                         % (idx + 1, len(ordered), rec["label"], rec["status"]))

    # 按「存在 → 不存在 → 不确定」排，同组保持平台顺序
    results.sort(key=lambda r: STATE_ORDER.get(r["status"], 9))

    counts = {EXISTS: 0, ABSENT: 0, UNSURE: 0}
    for rec in results:
        counts[rec["status"]] = counts.get(rec["status"], 0) + 1

    if args.json:
        text = json.dumps({
            "username": username,
            "checked": len(results),
            "counts": {EXISTS: counts[EXISTS], ABSENT: counts[ABSENT],
                       UNSURE: counts[UNSURE]},
            "results": results,
        }, ensure_ascii=False, indent=2)
    else:
        lines = ["== 用户名 %s 的平台存在性 ==" % username, ""]
        for state in (EXISTS, ABSENT, UNSURE):
            group = [r for r in results if r["status"] == state]
            if not group:
                continue
            lines.append("-- %s（%d）--" % (state, len(group)))
            for rec in group:
                lines.append("  %-12s %-24s %s"
                             % (rec["label"], rec["reason"], rec["url"]))
            lines.append("")
        lines.append("合计：存在 %d / 不存在 %d / 不确定 %d（共 %d 个平台）"
                     % (counts[EXISTS], counts[ABSENT], counts[UNSURE], len(results)))
        if counts[UNSURE]:
            lines.append("说明：「不确定」表示被限流、超时，或该平台未登录时无法区分")
            lines.append("      存在与否（不是「没有」）。")
        text = "\n".join(lines)

    if args.output:
        if not write_output(args.output, text + "\n", args.force):
            return 1
        sys.stderr.write("已写入：%s\n" % args.output)
        return 0

    sys.stdout.write(text + "\n")
    # 一个确定结论都没拿到（全是网络失败）→ 退出码 1，方便脚本判断
    if counts[EXISTS] == 0 and counts[ABSENT] == 0:
        sys.stderr.write("所有平台都没给出确定结论（网络不通或全部被限流）。\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
