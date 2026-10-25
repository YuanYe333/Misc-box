# -*- coding: utf-8 -*-
"""
shodanparse.py -- Shodan / FOFA 导出结果解析与聚合（纯离线，不联网）。

为什么需要
==========
打点、复盘、写报告时，Shodan / FOFA / ZoomEye 的导出结果动辄几千条 JSON，
用眼睛翻根本看不完。真正有用的信息其实就几类：开了哪些端口、落在哪些国家、
跑了什么产品、命中哪些 CVE、证书主体是谁。

本脚本把这些维度一次性聚合成表格，并且可以按端口 / CVE 过滤，方便快速
锁定「哪台机器同时开了 22 和 3389」「谁命中了 Log4Shell」。

用法
====
    python -X utf8 shodanparse.py 导出.json
    python -X utf8 shodanparse.py 导出.jsonl --port 22
    python -X utf8 shodanparse.py 导出.json --cve CVE-2021-44228
    python -X utf8 shodanparse.py 导出.json --csv 汇总.csv
    python -X utf8 shodanparse.py 导出.json --hosts

支持的输入格式（自动识别，不用指定）
====================================
    * Shodan JSON 数组导出： [ {...}, {...} ]
    * Shodan JSONL 导出：   每行一个 {...}（Shodan 官方 download 就是这种）
    * Shodan 单条响应：      {"matches": [...]} 或 {"data": [...]}
    * FOFA JSON 导出：      {"results": [["ip","port",...], ...]}（含 rows 数组）
    * 裸数组的 FOFA rows

已知限制
========
    * 只做本地数据处理，不发起任何网络请求（这是刻意设计：可靠、可复现）；
    * FOFA 导出格式版本很多，本脚本认最常见的 results/rows 两种，
      认不出时会明确报错并提示期望的结构，而不是猜；
    * 字段缺失时按「未知」统计，不会编造；
    * CVE 只从 vulns / vulns_cve / cve 字段里取，不联网查证。
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter

UNKNOWN = "(未知)"


# ------------------------------------------------------------------ 读入

def read_records(path):
    """把文件读成 (记录列表, 格式说明)。失败抛 ValueError（带人话原因）。"""
    if not os.path.isfile(path):
        raise ValueError("文件不存在：%s" % path)

    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ValueError("读取失败：%s（%s）" % (path, exc))

    text = raw.strip()
    if not text:
        raise ValueError("文件是空的：%s" % path)

    # 先整体按 JSON 试（数组 / 单个对象）
    try:
        data = json.loads(text)
    except ValueError:
        data = None
        # 整体不是合法 JSON，按 JSONL 逐行试
        records, bad = [], 0
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if isinstance(obj, dict):
                records.append(obj)
            elif isinstance(obj, list):
                records.extend(x for x in obj if isinstance(x, dict))
        if not records:
            raise ValueError(
                "解析失败：既不是合法 JSON，也不是合法 JSONL。\n"
                "  期望：JSON 数组 [ {...} ]，或每行一个 JSON 对象的 JSONL。\n"
                "  首行片段：%s" % text.splitlines()[0][:120])
        note = "JSONL（%d 条记录" % len(records)
        if bad:
            note += "，跳过 %d 行坏行" % bad
        note += "）"
        return records, note

    if isinstance(data, list):
        records = [x for x in data if isinstance(x, dict)]
        if not records:
            raise ValueError("JSON 数组里没有对象记录（可能全是字符串或数字）。")
        return records, "JSON 数组（%d 条）" % len(records)

    if isinstance(data, dict):
        # Shodan 单条响应：matches / data
        for key in ("matches", "data", "banner"):
            val = data.get(key)
            if isinstance(val, list) and val:
                recs = [x for x in val if isinstance(x, dict)]
                if recs:
                    return recs, "Shodan 响应（%s 字段，%d 条）" % (key, len(recs))
        # FOFA：results / rows，元素是「按 fields 排列的数组」
        for key in ("results", "rows"):
            val = data.get(key)
            if isinstance(val, list) and val:
                recs = fofa_rows_to_dicts(val, data.get("fields") or data.get("columns"))
                if recs:
                    return recs, "FOFA 导出（%s 字段，%d 条）" % (key, len(recs))
        raise ValueError(
            "无法识别的 JSON 对象：没有 matches / data / results / rows 字段。\n"
            "  顶层键：%s" % ", ".join(list(data.keys())[:10]))

    raise ValueError("顶层既不是数组也不是对象，不是可解析的导出文件。")


# FOFA 默认字段顺序（导出文件带 fields 时以它为准）
FOFA_DEFAULT_FIELDS = ["host", "ip", "port", "protocol", "country", "country_name",
                       "region", "city", "title", "server", "banner", "header",
                       "cert", "domain", "cve_id"]


def fofa_rows_to_dicts(rows, fields):
    """FOFA 的 rows 是「值数组」，得配 fields 才能变成字典。"""
    if not isinstance(fields, list) or not fields:
        fields = FOFA_DEFAULT_FIELDS
    if not any(isinstance(r, list) for r in rows):
        # 已经是对象数组了
        return [r for r in rows if isinstance(r, dict)]
    out = []
    for row in rows:
        if not isinstance(row, list):
            continue
        rec = {}
        for i, val in enumerate(row):
            if i < len(fields) and isinstance(fields[i], str):
                rec[fields[i]] = val
        out.append(rec)
    return out


# ------------------------------------------------------------------ 字段抽取

def get_host(rec):
    """尽量拿到「这台主机」的标识：ip 优先，其次 hostnames 的第一个。"""
    for key in ("ip_str", "ip", "host", "ipv6"):
        val = rec.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    hosts = rec.get("hostnames")
    if isinstance(hosts, list) and hosts:
        first = hosts[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
    return UNKNOWN


def get_port(rec):
    """端口可能是 int、字符串，也可能藏在 FOFA 的 "port" 里。"""
    val = rec.get("port")
    if val is None:
        val = rec.get("src_port")
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return None


def get_country(rec):
    for key in ("country_name", "country", "location", "country_code"):
        val = rec.get(key)
        if isinstance(val, dict):
            val = val.get("country_name") or val.get("country_code")
        if isinstance(val, str) and val.strip():
            return val.strip()
    return UNKNOWN


def get_product(rec):
    """产品名 + 版本：Shodan 是 product/version，FOFA 是 server/title。"""
    product = rec.get("product")
    if isinstance(product, str) and product.strip():
        version = rec.get("version")
        if isinstance(version, str) and version.strip():
            return "%s %s" % (product.strip(), version.strip())
        return product.strip()

    server = rec.get("server")
    if isinstance(server, str) and server.strip():
        # "nginx/1.18.0" -> "nginx"；只保留产品名，版本噪声太大
        return server.strip().split("/")[0].strip() or UNKNOWN

    title = rec.get("title")
    if isinstance(title, str) and title.strip():
        return "(标题) " + title.strip()[:40]
    return UNKNOWN


def get_cves(rec):
    """CVE 来源：vulns（dict 或 list）、vulns_cve、cve、cve_id。"""
    found = set()
    for key in ("vulns", "vulns_cve", "cve", "cve_id"):
        val = rec.get(key)
        if isinstance(val, dict):
            for k, v in val.items():
                if isinstance(k, str) and k.upper().startswith("CVE-"):
                    found.add(k.upper())
                elif isinstance(v, str) and v.upper().startswith("CVE-"):
                    found.add(v.upper())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.upper().startswith("CVE-"):
                    found.add(item.upper())
                elif isinstance(item, dict):
                    cid = item.get("id") or item.get("cve")
                    if isinstance(cid, str) and cid.upper().startswith("CVE-"):
                        found.add(cid.upper())
        elif isinstance(val, str):
            for part in val.replace(";", ",").split(","):
                part = part.strip().upper()
                if part.startswith("CVE-"):
                    found.add(part)
    return sorted(found)


def get_cert_subject(rec):
    """证书主体：ssl.cert.subject.CN / ssl.cert.subject / cert。"""
    ssl = rec.get("ssl")
    if isinstance(ssl, dict):
        cert = ssl.get("cert")
        if isinstance(cert, dict):
            subject = cert.get("subject")
            if isinstance(subject, dict):
                for key in ("CN", "commonName", "O"):
                    val = subject.get(key)
                    if isinstance(val, str) and val.strip():
                        return val.strip()
            elif isinstance(subject, str) and subject.strip():
                return subject.strip()
            issuer = cert.get("issuer")
            if isinstance(issuer, dict):
                val = issuer.get("CN")
                if isinstance(val, str) and val.strip():
                    return "(issuer) " + val.strip()
    # FOFA 的 cert 是一整段 PEM 文本
    cert = rec.get("cert")
    if isinstance(cert, str) and "BEGIN CERTIFICATE" in cert:
        return "(PEM 证书)"
    return None


def get_banner(rec):
    """banner / data 的前若干字节，用来做服务指纹分类。"""
    for key in ("data", "banner", "header"):
        val = rec.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


# ------------------------------------------------------------------ 服务分类

SERVICE_HINTS = (
    ("HTTP", ("http/", "server:", "get /", "<html", "<?xml")),
    ("SSH", ("ssh-", "openssh")),
    ("FTP", ("220 ", "ftp")),
    ("SMTP", ("smtp", "esmtp", "postfix", "exim")),
    ("MySQL", ("mysql", "mariadb")),
    ("Redis", ("redis",)),
    ("MongoDB", ("mongodb", "mongo")),
    ("RDP", ("rdp", "mstshash")),
    ("SMB", ("smb", "samba", "netbios")),
    ("Telnet", ("telnet",)),
    ("DNS", ("dns", "bind")),
    ("LDAP", ("ldap",)),
    ("MQTT", ("mqtt",)),
)


def classify_service(rec):
    """产品名拿不到时，靠 banner 首行猜个大概。猜不出就归「其他」。"""
    blob = (get_banner(rec) + " " + str(rec.get("product") or "") + " "
            + str(rec.get("server") or "")).lower()
    if not blob.strip():
        return UNKNOWN
    for name, hints in SERVICE_HINTS:
        for hint in hints:
            if hint in blob:
                return name
    return "其他"


# ------------------------------------------------------------------ 过滤

def parse_port_filter(spec):
    """支持 22 / 22,80 / 1-1024 / 混合，返回 (集合, 区间列表)。"""
    ports = set()
    ranges = []
    if not spec:
        return ports, ranges
    for part in str(spec).replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                raise ValueError("端口范围写法不对：%s（要 100-200 这种）" % part)
            if lo > hi:
                lo, hi = hi, lo
            ranges.append((lo, hi))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError("端口写法不对：%s（要数字或 100-200）" % part)
    return ports, ranges


def port_match(port, ports, ranges):
    if port is None:
        return False
    if port in ports:
        return True
    for lo, hi in ranges:
        if lo <= port <= hi:
            return True
    return False


def apply_filters(records, ports, ranges, cve_wanted):
    out = []
    for rec in records:
        if ports or ranges:
            if not port_match(get_port(rec), ports, ranges):
                continue
        if cve_wanted:
            if not (set(get_cves(rec)) & cve_wanted):
                continue
        out.append(rec)
    return out


# ------------------------------------------------------------------ 统计

def aggregate(records):
    """一次性把所有维度数出来。返回 dict，值是 Counter。"""
    port_c = Counter()
    country_c = Counter()
    product_c = Counter()
    service_c = Counter()
    cve_c = Counter()
    cert_c = Counter()
    host_c = Counter()
    hosts_with_cve = set()

    for rec in records:
        port = get_port(rec)
        if port is None:
            port_c[UNKNOWN] += 1
        else:
            port_c[port] += 1
        country_c[get_country(rec)] += 1
        product_c[get_product(rec)] += 1
        service_c[classify_service(rec)] += 1
        cert = get_cert_subject(rec)
        if cert:
            cert_c[cert] += 1
        cves = get_cves(rec)
        for cve in cves:
            cve_c[cve] += 1
        host = get_host(rec)
        host_c[host] += 1
        if cves:
            hosts_with_cve.add(host)

    return {
        "port": port_c,
        "country": country_c,
        "product": product_c,
        "service": service_c,
        "cve": cve_c,
        "cert": cert_c,
        "host": host_c,
        "hosts_with_cve": hosts_with_cve,
    }


def port_sort_key(item):
    """端口统计按端口号升序；未知排最后。"""
    key = item[0]
    if isinstance(key, int):
        return (0, key)
    return (1, 0)


def top(counter, limit):
    """计数降序，同数按名字排，保证两次运行结果一致。"""
    items = counter.most_common()
    items.sort(key=lambda kv: (-kv[1], str(kv[0])))
    return items[:limit] if limit else items


# ------------------------------------------------------------------ 输出

def build_text_report(records, agg, src_note, filters, limit=15):
    lines = []
    lines.append("== 输入 ==")
    lines.append("  记录数：%d" % len(records))
    lines.append("  格式  ：%s" % src_note)
    if filters:
        lines.append("  过滤  ：%s" % filters)
    lines.append("  独立主机：%d" % len(agg["host"]))
    lines.append("")

    # 端口
    lines.append("== 端口分布 ==")
    port_c = agg["port"]
    if port_c:
        total = sum(port_c.values())
        for key, cnt in sorted(port_c.items(), key=port_sort_key):
            label = str(key)
            lines.append("  %-12s %6d  %5.1f%%" % (label, cnt, 100.0 * cnt / total))
    else:
        lines.append("  （无数据）")
    lines.append("")

    lines.append("== 国家分布 ==")
    for key, cnt in top(agg["country"], limit):
        lines.append("  %-24s %6d" % (str(key)[:24], cnt))
    lines.append("")

    lines.append("== 产品 / 服务 ==")
    for key, cnt in top(agg["product"], limit):
        lines.append("  %-34s %6d" % (str(key)[:34], cnt))
    lines.append("")

    lines.append("== 服务类型（按 banner 归类）==")
    for key, cnt in top(agg["service"], limit):
        lines.append("  %-24s %6d" % (str(key)[:24], cnt))
    lines.append("")

    lines.append("== CVE 分布 ==")
    if agg["cve"]:
        for key, cnt in top(agg["cve"], limit):
            lines.append("  %-20s %6d 台主机" % (key, cnt))
        lines.append("  （命中任一 CVE 的主机共 %d 台）" % len(agg["hosts_with_cve"]))
    else:
        lines.append("  （导出数据里没有 CVE 字段）")
    lines.append("")

    lines.append("== 证书主体 ==")
    if agg["cert"]:
        for key, cnt in top(agg["cert"], limit):
            lines.append("  %-40s %6d" % (str(key)[:40], cnt))
    else:
        lines.append("  （导出数据里没有证书字段）")
    lines.append("")

    return "\n".join(lines)


CSV_COLUMNS = ["ip", "port", "country", "product", "service", "cves", "cert"]


def build_csv(records):
    """按主机一行输出，直接能进 Excel。"""
    import io
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for rec in records:
        port = get_port(rec)
        writer.writerow([
            get_host(rec),
            "" if port is None else port,
            get_country(rec),
            get_product(rec),
            classify_service(rec),
            ";".join(get_cves(rec)),
            get_cert_subject(rec) or "",
        ])
    return buf.getvalue()


def build_hosts(records, agg):
    """按主机聚合：一台机器一行，列出它开的所有端口。"""
    ports_by_host = {}
    cves_by_host = {}
    for rec in records:
        host = get_host(rec)
        port = get_port(rec)
        if port is not None:
            ports_by_host.setdefault(host, set()).add(port)
        cves = get_cves(rec)
        if cves:
            cves_by_host.setdefault(host, set()).update(cves)

    lines = ["== 主机清单（%d 台）==" % len(ports_by_host)]
    rows = sorted(ports_by_host.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for host, ports in rows:
        pstr = ",".join(str(p) for p in sorted(ports))
        line = "  %-28s %s" % (host[:28], pstr)
        if host in cves_by_host:
            line += "   [%s]" % ",".join(sorted(cves_by_host[host]))
        lines.append(line)
    return "\n".join(lines)


# ------------------------------------------------------------------ 入口

def build_usage():
    return (
        "用法：python -X utf8 shodanparse.py <导出文件> [选项]\n"
        "\n"
        "做什么：把 Shodan / FOFA 的 JSON / JSONL 导出聚合成表格——\n"
        "        端口分布、国家分布、产品/服务分布、CVE 分布、证书主体。\n"
        "        纯离线处理，不联网。\n"
        "\n"
        "例子：\n"
        "  python -X utf8 shodanparse.py shodan.json\n"
        "  python -X utf8 shodanparse.py shodan.jsonl --port 22\n"
        "  python -X utf8 shodanparse.py 导出.json --cve CVE-2021-44228\n"
        "  python -X utf8 shodanparse.py 导出.json --csv 汇总.csv\n"
        "  python -X utf8 shodanparse.py 导出.json --hosts --top 0\n"
        "\n"
        "选项：\n"
        "  --port 22,80,1000-2000  只保留这些端口（逗号分隔，支持区间）\n"
        "  --cve CVE-2021-44228    只保留命中该 CVE 的记录，可重复给\n"
        "  --csv 文件              输出 CSV（每主机一行，可直接进 Excel）\n"
        "  --hosts                 按主机聚合，列出每台机器开的端口\n"
        "  --top N                 每项显示前 N 条，默认 15，0 表示全部\n"
        "  --json                  输出聚合结果的 JSON\n"
        "  -o/--output 文件         写入文件（已存在需 --force）\n"
        "\n"
        "支持的格式：Shodan JSON 数组 / JSONL / {matches:[...]}、FOFA {results:[...]}。\n"
    )


def write_output(path, text, force):
    from pathlib import Path
    p = Path(path)
    if p.exists() and not force:
        sys.stderr.write("目标文件已存在：%s（要覆盖请加 --force）\n" % p)
        return False
    # newline="" 防止 Windows 把 \n 换成 \r\n 把 CSV 弄脏
    with open(str(p), "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return True


def main():
    ap = argparse.ArgumentParser(
        description="Shodan / FOFA 导出结果解析与聚合（纯离线）",
        add_help=True,
    )
    ap.add_argument("file", nargs="?", help="导出文件（JSON 或 JSONL）")
    ap.add_argument("--port", help="端口过滤，如 22 或 22,80,1000-2000")
    ap.add_argument("--cve", action="append", default=[],
                    help="CVE 过滤，可重复给多个")
    ap.add_argument("--csv", dest="csv_path", help="输出 CSV 到指定文件")
    ap.add_argument("--hosts", action="store_true", help="按主机聚合输出")
    ap.add_argument("--top", type=int, default=15, help="每项显示前 N 条，默认 15，0=全部")
    ap.add_argument("--json", action="store_true", help="输出聚合结果 JSON")
    ap.add_argument("-o", "--output", help="输出写入文件")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    args = ap.parse_args()

    if not args.file:
        sys.stdout.write(build_usage())
        return 0

    try:
        records, src_note = read_records(args.file)
    except ValueError as exc:
        sys.stderr.write("读取失败：%s\n" % exc)
        return 1

    if not records:
        sys.stderr.write("读取失败：文件里没有可用的记录。\n")
        return 1

    try:
        ports, ranges = parse_port_filter(args.port)
    except ValueError as exc:
        sys.stderr.write("参数错误：%s\n" % exc)
        return 2

    cve_wanted = set(c.strip().upper() for c in args.cve if c and c.strip())
    for c in cve_wanted:
        if not c.startswith("CVE-"):
            sys.stderr.write("参数错误：--cve 要写完整编号，如 CVE-2021-44228（收到 %s）\n" % c)
            return 2

    filter_note = []
    if args.port:
        filter_note.append("端口=%s" % args.port)
    if cve_wanted:
        filter_note.append("CVE=%s" % ",".join(sorted(cve_wanted)))
    filters = "；".join(filter_note)

    filtered = apply_filters(records, ports, ranges, cve_wanted)
    if not filtered:
        sys.stderr.write("过滤后没有剩余记录（原始 %d 条，过滤条件：%s）。\n"
                         % (len(records), filters or "无"))
        sys.stderr.write("提示：先用不带过滤的命令看一眼实际有哪些端口/CVE。\n")
        return 1

    agg = aggregate(filtered)

    # ---- CSV 模式（写文件，不进 stdout，避免和报告混在一起）
    if args.csv_path:
        csv_text = build_csv(filtered)
        if not write_output(args.csv_path, csv_text, args.force):
            return 1
        sys.stderr.write("已写入 CSV：%s（%d 行）\n" % (args.csv_path, len(filtered)))
        # 同时打一份简报，方便肉眼确认
        sys.stdout.write(build_text_report(filtered, agg, src_note, filters, args.top))
        return 0

    if args.json:
        payload = {
            "file": args.file,
            "format": src_note,
            "records_total": len(records),
            "records_used": len(filtered),
            "filters": filters,
            "ports": dict((str(k), v) for k, v in agg["port"].items()),
            "countries": dict(agg["country"]),
            "products": dict(agg["product"]),
            "services": dict(agg["service"]),
            "cves": dict(agg["cve"]),
            "certs": dict(agg["cert"]),
            "hosts": dict(agg["host"]),
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.output:
            if not write_output(args.output, text + "\n", args.force):
                return 1
            sys.stderr.write("已写入：%s\n" % args.output)
            return 0
        sys.stdout.write(text + "\n")
        return 0

    parts = [build_text_report(filtered, agg, src_note, filters, args.top)]
    if args.hosts:
        parts.append(build_hosts(filtered, agg))
    text = "\n".join(parts)

    if args.output:
        if not write_output(args.output, text + "\n", args.force):
            return 1
        sys.stderr.write("已写入：%s\n" % args.output)
        return 0

    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
