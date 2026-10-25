# -*- coding: utf-8 -*-
"""
whois.py -- 域名 / IP 归属查询：纯 socket 实现 WHOIS 协议，另支持 RDAP。

为什么需要
==========
OSINT 题第一步通常是「这个域名 / IP 是谁的」。系统里没有 whois 命令，
装第三方库又常常装不上；而 WHOIS 协议本身极其简单：往 TCP 43 端口发一行
查询，然后一直读到对端关连接。

本脚本做三件事：
  1. 域名查询：先问 whois.iana.org 要「权威服务器」，再依次向注册局 /
     注册商追问（最多 3 跳），把每一跳的原文都留下来；
  2. IP 反查：IANA 会把 IP 指到对应的 RIR（APNIC / RIPE / ARIN / LACNIC /
     AFRINIC），再向 RIR 要归属与 ASN（origin: / OriginAS: / aut-num:）；
  3. RDAP（--rdap）：走 HTTP + JSON，结果更规范、更好解析，适合批量。

用法
====
    python -X utf8 whois.py example.com
    python -X utf8 whois.py 8.8.8.8
    python -X utf8 whois.py example.com --rdap
    python -X utf8 whois.py 1.1.1.1 --json
    python -X utf8 whois.py example.com --raw > 原始响应.txt
    python -X utf8 whois.py example.com --server whois.verisign-grs.com

已知限制
========
    * WHOIS 是明文协议、没有标准格式，各注册局字段名五花八门，
      本脚本只做「尽力抽取」，字段抽取不全不代表数据没有；
    * 本机网络不稳，所有请求都有超时（默认 10 秒），超时会明确报错退出，
      不会卡死；
    * RDAP 依赖 rdap.org 这个公共跳转入口，它挂了就查不了；
    * WHOIS 数据本身有缓存延迟，刚注册/刚过户的域名可能查不到。
"""

import argparse
import json
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 10.0
IANA_SERVER = "whois.iana.org"
WHOIS_PORT = 43
RDAP_BASE = "https://rdap.org"

# 各注册局的「下一跳」写法不一样：IANA 用 refer:，ARIN 用 ReferralServer:，
# 注册局用 Registrar WHOIS Server:。一个正则全部覆盖。
REFERRAL_RE = re.compile(
    r"^(?:refer|whois|registrar\s+whois\s+server|referralserver)\s*:\s*([^\s]+)",
    re.I | re.M,
)

# 「查无此域名」的各种说法
NOT_FOUND_PATTERNS = (
    "no match for",
    "not found",
    "no data found",
    "no entries found",
    "domain not found",
    "object does not exist",
    "status: free",
)

ASN_RE = re.compile(r"^(?:origin|originas|aut-num)\s*:\s*(AS\d+)", re.I | re.M)


class NetError(Exception):
    """网络层面的失败（解析不了、连不上、超时）。"""


def call_with_deadline(func, timeout, label=None):
    """在守护线程里跑 func，超过 timeout 秒直接放弃。

    为什么需要：socket 的 settimeout 只约束「连接/读」，管不住 DNS 解析
    （Windows 上 getaddrinfo 可能卡十几秒甚至更久）。只有另开一个守护线程
    才能真正保证「网络不通时也不卡死」——主线程到点就走，守护线程随进程退出。
    """
    box = {}

    def runner():
        try:
            box["value"] = func()
        except BaseException as exc:  # noqa: BLE001  原样抛回主线程
            box["error"] = exc

    th = threading.Thread(target=runner, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise NetError("超时：等待 %.0f 秒仍未完成%s（网络可能不通）"
                       % (timeout, ("，" + label) if label else ""))
    if "error" in box:
        raise box["error"]
    return box.get("value")


# ------------------------------------------------------------------ 协议层

def tcp_query(server, query, timeout=DEFAULT_TIMEOUT, port=WHOIS_PORT):
    """向 whois 服务器发一行查询，读到对端关连接为止。

    返回 (原始文本, 是否被截断)。WHOIS 没有长度字段，只能靠 EOF 判断结束，
    所以必须有整体截止时间；读到一半超时也要把已有内容交出去。
    """
    deadline = time.time() + timeout

    def run():
        try:
            sock = socket.create_connection((server, port), timeout=timeout)
        except socket.gaierror:
            raise NetError("域名解析失败：%s（DNS 不可用？）" % server)
        except socket.timeout:
            raise NetError("连接 %s:%d 超时" % (server, port))
        except OSError as exc:
            raise NetError("连接 %s:%d 失败：%s" % (server, port, exc))

        chunks = []
        truncated = False
        try:
            with sock:
                sock.sendall(query.encode("utf-8") + b"\r\n")
                while True:
                    remain = deadline - time.time()
                    if remain <= 0:
                        truncated = True
                        break
                    sock.settimeout(min(remain, timeout))
                    try:
                        buf = sock.recv(8192)
                    except socket.timeout:
                        truncated = True
                        break
                    except ConnectionResetError:
                        # 部分注册局发完就 RST，按正常结束处理
                        break
                    if not buf:
                        break
                    chunks.append(buf)
        except OSError as exc:
            if not chunks:
                raise NetError("与 %s 通信失败：%s" % (server, exc))
            truncated = True

        raw = b"".join(chunks)
        return decode_bytes(raw), truncated

    return call_with_deadline(run, timeout + 1.0, "向 %s:%d 查询" % (server, port))


def decode_bytes(raw):
    """whois 响应的编码五花八门（UTF-8 / GBK / latin-1 都有），挨个试。"""
    for enc in ("utf-8", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def find_referral(text, current_server):
    """从响应里找下一跳服务器；找不到返回 None。"""
    for m in REFERRAL_RE.finditer(text):
        cand = m.group(1).strip().strip(".,;")
        # 去掉 whois:// 或 rwhois:// 前缀与端口
        cand = re.sub(r"^(?:r?whois|http|https)://", "", cand, flags=re.I)
        cand = cand.split("/")[0].split(":")[0].strip().lower()
        if not cand or cand == current_server.lower():
            continue
        if "." not in cand:
            continue
        return cand
    return None


def looks_not_found(text):
    low = text.lower()
    return any(p in low for p in NOT_FOUND_PATTERNS)


def parse_kv(text):
    """把 'Key: Value' 行抽成有序字典（同名键只留第一次出现的值）。

    为什么只留第一次：whois 里同一个键会重复很多次（多个 name server、
    多个 domain status），全留下会把输出撑爆，第一次出现的通常最关键。
    """
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "%#":
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        if not key or not val or len(key) > 40:
            continue
        out.setdefault(key, val)
    return out


# ------------------------------------------------------------------ 目标识别

def parse_ip(text):
    """自己解析 IPv4/IPv6，返回 (字节串, 版本)；非法返回 None。

    不用 ipaddress 模块是为了让依赖面尽可能小（本项目只允许标准库核心模块）。
    """
    s = text.strip()
    if not s:
        return None
    if ":" not in s:
        parts = s.split(".")
        if len(parts) != 4:
            return None
        out = bytearray()
        for p in parts:
            if not p.isdigit() or len(p) > 3:
                return None
            v = int(p)
            if v > 255:
                return None
            out.append(v)
        return bytes(out), 4

    if s.count("::") > 1:
        return None
    if "::" in s:
        head, _, tail = s.partition("::")
        head_g = [g for g in head.split(":") if g != ""]
        tail_g = [g for g in tail.split(":") if g != ""]
        missing = 8 - len(head_g) - len(tail_g)
        if missing < 0:
            return None
        groups = head_g + ["0"] * missing + tail_g
    else:
        groups = s.split(":")
        if len(groups) != 8:
            return None

    if groups and "." in groups[-1]:
        v4 = parse_ip(groups[-1])
        if not v4 or v4[1] != 4:
            return None
        b = v4[0]
        groups = groups[:-1] + ["%x" % ((b[0] << 8) | b[1]), "%x" % ((b[2] << 8) | b[3])]

    if len(groups) != 8:
        return None
    out = bytearray()
    for g in groups:
        if not re.match(r"^[0-9A-Fa-f]{1,4}$", g):
            return None
        v = int(g, 16)
        out.append((v >> 8) & 0xFF)
        out.append(v & 0xFF)
    return bytes(out), 6


DOMAIN_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?$")


# ------------------------------------------------------------------ WHOIS 查询

def whois_domain(domain, timeout, max_hops):
    """域名：IANA → 注册局 → 注册商，逐跳追问。"""
    hops = []
    server = IANA_SERVER
    seen = set()
    text = ""
    for _ in range(max(1, max_hops)):
        key = server.lower()
        if key in seen:
            break
        seen.add(key)
        raw, truncated = tcp_query(server, domain, timeout=timeout)
        hops.append({
            "server": server,
            "bytes": len(raw),
            "truncated": truncated,
            "not_found": looks_not_found(raw),
        })
        text = raw
        nxt = find_referral(raw, server)
        if not nxt:
            break
        server = nxt
    return hops, text


def whois_ip(ip, timeout, max_hops):
    """IP：先问 IANA 要 RIR，再向 RIR 要归属；IANA 不给就退回 ARIN。"""
    hops = []
    server = IANA_SERVER
    seen = set()
    text = ""
    for idx in range(max(1, max_hops)):
        key = server.lower()
        if key in seen:
            break
        seen.add(key)
        raw, truncated = tcp_query(server, ip, timeout=timeout)
        hops.append({
            "server": server,
            "bytes": len(raw),
            "truncated": truncated,
            "not_found": looks_not_found(raw),
        })
        text = raw
        nxt = find_referral(raw, server)
        if not nxt and idx == 0:
            # IANA 有时不回 refer，ARIN 是 IP 的兜底总入口
            nxt = "whois.arin.net"
        if not nxt:
            break
        server = nxt
    return hops, text


def extract_summary(text, kind):
    """从最后一跳的原文里挑出人最想看的几个字段。"""
    kv = parse_kv(text)
    lower = dict((k.lower(), v) for k, v in kv.items())
    out = []
    if kind == "domain":
        wanted = [
            ("domain name", "域名"),
            ("registrar", "注册商"),
            ("registrar whois server", "注册商服务器"),
            ("creation date", "注册时间"),
            ("registry expiry date", "到期时间"),
            ("updated date", "更新时间"),
            ("name server", "NS"),
            ("domain status", "状态"),
        ]
    else:
        wanted = [
            ("netname", "网络名"),
            ("inetnum", "地址段"),
            ("netrange", "地址段"),
            ("cidr", "CIDR"),
            ("orgname", "机构"),
            ("org-name", "机构"),
            ("descr", "描述"),
            ("country", "国家"),
            ("origin", "ASN"),
            ("originas", "ASN"),
            ("aut-num", "ASN"),
            ("asn", "ASN"),
        ]
    for key, label in wanted:
        if key in lower and lower[key]:
            out.append((label, lower[key]))
    asn = ASN_RE.search(text)
    if asn and not any(lbl == "ASN" for lbl, _ in out):
        out.append(("ASN", asn.group(1)))
    return out, kv


# ------------------------------------------------------------------ RDAP

def rdap_fetch(target, timeout, base=RDAP_BASE):
    """RDAP 走 HTTP+JSON，比 WHOIS 好解析得多。"""
    is_ip = parse_ip(target) is not None
    path = "ip" if is_ip else "domain"
    url = "%s/%s/%s" % (base.rstrip("/"), path, urllib.parse.quote(target, safe=""))

    def run():
        req = urllib.request.Request(url, headers={
            "User-Agent": "miscbox-osint/1.0",
            "Accept": "application/rdap+json, application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                status = resp.getcode()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NetError("RDAP 查无此对象（HTTP 404）：%s" % target)
            raise NetError("RDAP 返回 HTTP %d：%s" % (exc.code, exc.reason))
        except urllib.error.URLError as exc:
            raise NetError("RDAP 请求失败：%s（网络不通？）" % exc.reason)
        except socket.timeout:
            raise NetError("RDAP 请求超时（%d 秒）" % int(timeout))
        except OSError as exc:
            raise NetError("RDAP 请求失败：%s" % exc)
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
        except ValueError:
            raise NetError("RDAP 返回的不是合法 JSON（可能被劫持到登录页）")
        return status, data, url

    return call_with_deadline(run, timeout + 1.0, "请求 RDAP")


def vcard_fn(vcard_array):
    """从 RDAP 的 vcardArray 里取 fn（显示名）。

    结构是 ["vcard", [ ["fn", {}, "text", "示例公司"], ["adr", ...], ... ] ]，
    每一行是 [名字, 参数表, 类型, 值]。这里只认 fn，取不到就返回 None。
    """
    if not isinstance(vcard_array, list):
        return None
    for item in vcard_array:
        if not isinstance(item, list):
            continue
        for card in item:
            if isinstance(card, list) and len(card) >= 4 and card[0] == "fn":
                val = card[3]
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return None


def rdap_summary(data):
    """把 RDAP JSON 压成 [(中文标签, 值)]，只挑通用且稳定的字段。"""
    out = []
    for key, label in (
        ("ldhName", "域名"),
        ("unicodeName", "Unicode 名"),
        ("handle", "句柄"),
        ("name", "网络名"),
        ("type", "类型"),
        ("port43", "WHOIS 服务器"),
    ):
        val = data.get(key)
        if val:
            out.append((label, str(val)))
    for ev in data.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") and ev.get("eventDate"):
            out.append(("事件:%s" % ev["eventAction"], str(ev["eventDate"])))
    for ent in data.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        roles = "/".join(ent.get("roles") or []) or "entity"
        name = vcard_fn(ent.get("vcardArray"))
        if name:
            out.append((roles, name))
    for ns in data.get("nameservers") or []:
        if isinstance(ns, dict) and ns.get("ldhName"):
            out.append(("NS", str(ns["ldhName"])))
    for st in data.get("status") or []:
        out.append(("状态", str(st)))
    # 去掉重复标签（上面 wanted 表里 handle 写重了）
    seen = set()
    uniq = []
    for label, val in out:
        key = (label, val)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((label, val))
    return uniq


# ------------------------------------------------------------------ 输出

def build_usage():
    return (
        "用法：python -X utf8 whois.py <域名|IP> [选项]\n"
        "\n"
        "做什么：查域名 / IP 的归属（注册商、注册时间、机构、ASN 等）。\n"
        "  默认走 WHOIS 协议（TCP 43），先问 whois.iana.org 要权威服务器，\n"
        "  再依次向注册局 / 注册商 / RIR 追问。\n"
        "\n"
        "例子：\n"
        "  python -X utf8 whois.py example.com\n"
        "  python -X utf8 whois.py 8.8.8.8\n"
        "  python -X utf8 whois.py example.com --rdap\n"
        "  python -X utf8 whois.py 1.1.1.1 --json\n"
        "  python -X utf8 whois.py example.com --raw > 响应.txt\n"
        "  python -X utf8 whois.py --file 响应.txt\n"
        "\n"
        "选项：\n"
        "  --file 文件          离线解析已保存的 whois 原始文本（无需联网）\n"
        "  --rdap              改走 RDAP（HTTP+JSON，更规范）\n"
        "  --server 主机        跳过 IANA，直接问指定 whois 服务器\n"
        "  --timeout 秒         单次请求超时，默认 10\n"
        "  --hops N            最多追问几跳，默认 3\n"
        "  --json              输出结构化 JSON\n"
        "  --raw               只输出原始响应文本\n"
        "  -o/--output 文件     写入文件（已存在需 --force）\n"
        "\n"
        "注意：本机网络不稳，所有请求都带超时，连不上会明确报错而不是卡死。\n"
    )


def write_text(path, text, force):
    from pathlib import Path
    p = Path(path)
    if p.exists() and not force:
        sys.stderr.write("目标文件已存在：%s（要覆盖请加 --force）\n" % p)
        return False
    p.write_text(text, encoding="utf-8")
    return True


def emit(text, out_path, force):
    if out_path:
        if not write_text(out_path, text, force):
            return 1
        sys.stderr.write("已写入：%s\n" % out_path)
        return 0
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="域名 / IP 归属查询（WHOIS + RDAP，纯标准库）",
        add_help=True,
    )
    ap.add_argument("target", nargs="?", help="域名或 IP")
    ap.add_argument("--file", help="离线解析：读入已保存的 whois 原始响应文本")
    ap.add_argument("--rdap", action="store_true", help="走 RDAP（HTTP+JSON）")
    ap.add_argument("--server", help="直接指定 whois 服务器，跳过 IANA")
    ap.add_argument("--port", type=int, default=WHOIS_PORT, help="whois 端口，默认 43")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="超时秒数，默认 10")
    ap.add_argument("--hops", type=int, default=3, help="最多追问跳数，默认 3")
    ap.add_argument("--json", action="store_true", help="输出结构化 JSON")
    ap.add_argument("--raw", action="store_true", help="只输出原始响应")
    ap.add_argument("-o", "--output", help="输出写入文件")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    args = ap.parse_args()

    # ---------------- 离线分支：解析已保存的 whois 文本
    if args.file:
        import os
        from pathlib import Path
        fp = Path(args.file)
        if not fp.is_file():
            sys.stderr.write("错误：文件不存在：%s\n" % fp)
            return 1
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            sys.stderr.write("错误：读取失败：%s\n" % exc)
            return 1
        # 自动判断是 IP 还是域名（有 IP 特征字段就是 IP）
        kind = "ip" if re.search(r"(?im)^\s*(inetnum|inet6num|origin|aut-num)\s*:", raw) else "domain"
        if args.raw:
            return emit(raw, args.output, args.force)
        if args.json:
            summ, kv = extract_summary(raw, kind)
            payload = {
                "query": fp.name,
                "kind": kind,
                "protocol": "offline",
                "raw": raw,
                "summary": [{"label": k, "value": v} for k, v in summ],
                "fields": kv,
            }
            return emit(json.dumps(payload, ensure_ascii=False, indent=2), args.output, args.force)
        lines = ["== 离线解析: %s (%s) ==" % (fp.name, kind), ""]
        summ, kv = extract_summary(raw, kind)
        if summ:
            lines.append("== 关键字段 ==")
            for label, val in summ:
                lines.append("%-16s %s" % (label, val))
        else:
            lines.append("（没有抽到通用字段；用 --raw 看完整原文）")
        if kv:
            lines.append("")
            lines.append("== 全部字段（%d 个）==" % len(kv))
            for k in sorted(kv):
                lines.append("  %-28s %s" % (k, kv[k]))
        lines.append("")
        return emit("\n".join(lines), args.output, args.force)

    if not args.target:
        sys.stdout.write(build_usage())
        return 0

    target = args.target.strip()
    ip_parsed = parse_ip(target)
    if ip_parsed:
        kind = "ip"
    else:
        if not DOMAIN_RE.match(target):
            sys.stderr.write("参数错误：既不是合法 IP，也不像域名：%s\n" % target)
            return 2
        kind = "domain"

    timeout = max(1.0, float(args.timeout))

    # ---------------- RDAP 分支
    if args.rdap:
        try:
            status, data, url = rdap_fetch(target, timeout)
        except NetError as exc:
            sys.stderr.write("查询失败：%s\n" % exc)
            sys.stderr.write("提示：网络不通时可去掉 --rdap 改用 WHOIS，或稍后重试。\n")
            return 1
        if args.json:
            payload = {
                "query": target,
                "kind": kind,
                "protocol": "rdap",
                "url": url,
                "http_status": status,
                "raw": data,
                "summary": [{"label": k, "value": v} for k, v in rdap_summary(data)],
            }
            return emit(json.dumps(payload, ensure_ascii=False, indent=2), args.output, args.force)
        if args.raw:
            return emit(json.dumps(data, ensure_ascii=False, indent=2), args.output, args.force)
        lines = ["== RDAP: %s (%s) ==" % (target, kind), "URL: %s  HTTP %d" % (url, status), ""]
        summ = rdap_summary(data)
        if summ:
            lines.append("== 关键字段 ==")
            for label, val in summ:
                lines.append("%-16s %s" % (label, val))
        else:
            lines.append("（没有抽到通用字段，用 --raw 看完整 JSON）")
        lines.append("")
        return emit("\n".join(lines), args.output, args.force)

    # ---------------- WHOIS 分支
    hops = []
    text = ""
    try:
        if args.server:
            raw, truncated = tcp_query(args.server, target, timeout=timeout, port=args.port)
            hops = [{"server": args.server, "bytes": len(raw), "truncated": truncated,
                     "not_found": looks_not_found(raw)}]
            text = raw
        elif kind == "ip":
            hops, text = whois_ip(target, timeout, args.hops)
        else:
            hops, text = whois_domain(target, timeout, args.hops)
    except NetError as exc:
        sys.stderr.write("查询失败：%s\n" % exc)
        sys.stderr.write("提示：WHOIS 走 TCP 43 明文端口，公司网络/防火墙经常直接封掉；\n")
        sys.stderr.write("      可以试试 --rdap（走 443），或换一台能出网的机器。\n")
        return 1
    except OSError as exc:
        sys.stderr.write("查询失败：%s\n" % exc)
        return 1

    if not text:
        # 连上了但一个字节都没收到（常见于防火墙吞包或服务器拒绝明文查询）
        sys.stderr.write("查询失败：没有拿到任何响应内容。\n")
        for hop in hops:
            sys.stderr.write("  [%s] 收到 %d 字节%s\n" % (
                hop["server"], hop["bytes"], "（超时截断）" if hop["truncated"] else ""))
        sys.stderr.write("提示：TCP 43 常被防火墙静默丢弃。可以试试 --rdap（走 443）。\n")
        return 1

    summary, kv = extract_summary(text, kind)

    if args.json:
        payload = {
            "query": target,
            "kind": kind,
            "protocol": "whois",
            "hops": hops,
            "fields": kv,
            "summary": [{"label": k, "value": v} for k, v in summary],
            "raw": text,
        }
        return emit(json.dumps(payload, ensure_ascii=False, indent=2), args.output, args.force)

    if args.raw:
        return emit(text, args.output, args.force)

    lines = []
    lines.append("== 查询：%s（%s）==" % (target, "IP" if kind == "ip" else "域名"))
    for i, hop in enumerate(hops, 1):
        note = []
        if hop["truncated"]:
            note.append("超时截断")
        if hop["not_found"]:
            note.append("疑似未注册")
        suffix = ("（%s）" % "，".join(note)) if note else ""
        lines.append("  [%d] %-28s %6d 字节%s" % (i, hop["server"], hop["bytes"], suffix))
    lines.append("")
    if summary:
        lines.append("== 关键字段（从最后一跳抽取）==")
        for label, val in summary:
            lines.append("%-10s %s" % (label, val))
    else:
        lines.append("== 关键字段 ==")
        lines.append("（没抽到常见字段，直接看下面的原始响应）")
    lines.append("")
    lines.append("== 原始响应（最后一跳：%s）==" % hops[-1]["server"])
    lines.append(text.rstrip())
    return emit("\n".join(lines), args.output, args.force)


if __name__ == "__main__":
    sys.exit(main())
