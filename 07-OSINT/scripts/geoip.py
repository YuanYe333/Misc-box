# -*- coding: utf-8 -*-
"""
geoip.py -- IP 地理定位：优先读本地 MaxMind GeoLite2 (.mmdb)，没库时降级在线 API。

为什么需要
==========
OSINT 题里拿到一个 IP，第一件事就是「这是哪儿的」。离线库（.mmdb）是二进制
格式，标准库读不了，第三方库 geoip2 又不允许装，所以本脚本**自己实现了
mmdb 解析器**——格式是公开的：文件末尾有元数据段，前面是二叉搜索树，
树指向数据段，数据段里是自描述的「类型 + 长度 + 值」编码。

两条路线：
  1. 离线（推荐）：--db 指定 .mmdb，查本地库，不外发任何数据；
  2. 在线（降级）：没有本地库时用 ip-api.com / ipinfo.io，
     **会把你要查的 IP 发给第三方**，脚本会明确提示这一点。

用法
====
    python -X utf8 geoip.py 8.8.8.8
    python -X utf8 geoip.py 8.8.8.8 --db D:\\GeoLite2-Country.mmdb
    python -X utf8 geoip.py --batch ips.txt --db Country.mmdb
    python -X utf8 geoip.py 1.1.1.1 --api ipinfo --json
    python -X utf8 geoip.py --db Country.mmdb --info

已知限制
========
    * 离线只认 MaxMind 的 .mmdb（GeoLite2-Country / GeoLite2-City / 自编译库）。
      IP2Location 的 .bin、纯真库的 .dat 格式完全不同，本脚本不支持；
    * GeoLite2-Country 只有国家级信息，没有城市/经纬度——要城市得用 City 库；
    * 在线 API 有速率限制（ip-api 免费版约 45 次/分钟），批量查询时
      本脚本默认每个 IP 之间停 1.5 秒，别把频率调太小；
    * 本机网络不稳，在线查询带超时（默认 10 秒），失败会明确报错不卡死；
    * 地理定位本身不精确，IP 库只能给到「大概在哪个城市」，别当证据用。
"""

import argparse
import os
import json
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 10.0
DEFAULT_DELAY = 1.5
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
DATA_SECTION_SEPARATOR = 16


class GeoError(Exception):
    """可预期的失败（库损坏、网络不通、API 报错）。"""


def call_with_deadline(func, timeout, label=None):
    """守护线程 + join(timeout)：DNS 卡住时也能到点就返回。

    socket 的 settimeout 管不住 getaddrinfo，只有另开线程才能真正保证不卡死。
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
        raise GeoError("超时：等待 %.0f 秒仍未完成%s（网络可能不通）"
                       % (timeout, ("，" + label) if label else ""))
    if "error" in box:
        raise box["error"]
    return box.get("value")


# ------------------------------------------------------------------ IP 解析

def parse_ip(text):
    """自己解析 IPv4/IPv6，返回 (打包字节, 位数)；非法返回 None。

    IPv4 查 IPv6 库时要补成 ::ffff:a.b.c.d 的 128 位形式，所以返回位数。
    """
    s = (text or "").strip()
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
        return bytes(out), 32

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

    # 末尾嵌 IPv4 的写法：::ffff:1.2.3.4
    if groups and "." in groups[-1]:
        v4 = parse_ip(groups[-1])
        if not v4 or v4[1] != 32:
            return None
        b = v4[0]
        groups = groups[:-1] + ["%x" % ((b[0] << 8) | b[1]), "%x" % ((b[2] << 8) | b[3])]

    if len(groups) != 8:
        return None
    out = bytearray()
    for g in groups:
        if not g or len(g) > 4 or any(c not in "0123456789abcdefABCDEF" for c in g):
            return None
        v = int(g, 16)
        out.append((v >> 8) & 0xFF)
        out.append(v & 0xFF)
    return bytes(out), 128


def is_private(ip_bytes, bits):
    """判断内网/保留地址：这类 IP 任何 GeoIP 库都查不到，提前说清楚。"""
    if bits == 32:
        a, b = ip_bytes[0], ip_bytes[1]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        if a == 169 and b == 254:
            return True
        if a >= 224:
            return True
        return False
    # IPv6：只有 ::1 / fe80::/10 / fc00::/7 算保留
    if ip_bytes == b"\x00" * 15 + b"\x01":
        return True
    if ip_bytes[0] == 0xFE and (ip_bytes[1] & 0xC0) == 0x80:
        return True
    if (ip_bytes[0] & 0xFE) == 0xFC:
        return True
    return False


# ------------------------------------------------------------------ MMDB 解析
#
# 格式速览（详见 MaxMind 的 MaxMind DB File Format Specification）：
#   [ 二叉搜索树 ][ 16 字节分隔符 ][ 数据段 ][ \xab\xcd\xefMaxMind.com 元数据 ]
# 树里每个节点有左右两条记录，记录值 < node_count 表示「继续走这个节点」，
# == node_count 表示「查无此项」，> node_count 表示「数据在数据段里的偏移」。

class MMDB(object):
    """最小可用的 MaxMind DB 读取器（只读，纯标准库）。"""

    def __init__(self, path):
        from pathlib import Path
        p = Path(path)
        if not p.is_file():
            raise GeoError("数据库文件不存在：%s" % p)
        try:
            self.buf = p.read_bytes()
        except OSError as exc:
            raise GeoError("读取数据库失败：%s（%s）" % (p, exc))
        if len(self.buf) < 1024:
            raise GeoError("文件太小，不像 mmdb：%s" % p)

        marker_at = self.buf.rfind(METADATA_MARKER)
        if marker_at < 0:
            raise GeoError("不是 mmdb 文件：找不到元数据标记（\\xab\\xcd\\xefMaxMind.com）。\n"
                           "  如果是 IP2Location 的 .bin 或纯真库的 .dat，本脚本不支持。")
        self.meta_start = marker_at + len(METADATA_MARKER)
        # 元数据段里的指针是「相对元数据段起点」算的（不是数据段），
        # 所以解码元数据时指针基址必须先传 meta_start。
        self.meta = self._decode(self.meta_start, self.meta_start)[0]
        if not isinstance(self.meta, dict):
            raise GeoError("mmdb 元数据损坏（不是 map 结构）")

        try:
            self.node_count = int(self.meta["node_count"])
            self.record_size = int(self.meta["record_size"])
        except (KeyError, TypeError, ValueError):
            raise GeoError("mmdb 元数据缺少 node_count / record_size")

        if self.record_size not in (24, 28, 32):
            raise GeoError("不支持的 record_size：%d（只支持 24/28/32）" % self.record_size)
        self.ip_version = int(self.meta.get("ip_version", 6))
        self.node_byte_size = self.record_size * 2 // 8
        self.search_tree_size = self.node_count * self.node_byte_size
        self.data_start = self.search_tree_size + DATA_SECTION_SEPARATOR
        if self.data_start > len(self.buf):
            raise GeoError("mmdb 结构异常：搜索树长度超出文件大小")

        # IPv4 查 IPv6 库时，前 96 位全是 0，可以一次性跳到对应节点。
        # 注意：必须放在探测偏移基址之前，因为探测要走一遍搜索树。
        self._v4_start = None

        # 数据记录的偏移基址按规范应该是 data_start（树末尾 + 16 字节分隔符），
        # 但实测有些第三方生成的库（如 v2rayN 自带那份 Customized GeoLite2
        # Country）把偏移算成了「相对树末尾」，少了分隔符那 16 字节。
        # 与其猜，不如探测：两种基址各试几个 IP，谁解出合法记录就用谁。
        self.offset_base = self._detect_offset_base()

    # -- 元数据 ----------------------------------------------------
    def info(self):
        out = []
        for key in ("database_type", "binary_format_major_version",
                    "binary_format_minor_version", "build_epoch", "ip_version",
                    "node_count", "record_size", "languages"):
            if key in self.meta:
                val = self.meta[key]
                if isinstance(val, list):
                    val = ",".join(str(x) for x in val)
                if key == "build_epoch":
                    try:
                        val = "%s（%s）" % (val, time.strftime(
                            "%Y-%m-%d", time.gmtime(int(val))))
                    except (TypeError, ValueError):
                        pass
                out.append((key, val))
        desc = self.meta.get("description")
        if isinstance(desc, dict):
            for lang, text in desc.items():
                out.append(("description[%s]" % lang, text))
        return out

    # -- 树遍历 ----------------------------------------------------
    def _read_node(self, node):
        """按 record_size 解出左右两条记录。

        24 位：6 字节，左 3 右 3；
        28 位：7 字节，左 = 前 3 字节 + 第 4 字节高 4 位，右 = 第 4 字节低 4 位 + 后 3 字节；
        32 位：8 字节，左 4 右 4。
        """
        off = node * self.node_byte_size
        if off + self.node_byte_size > self.search_tree_size:
            raise GeoError("节点越界：node=%d" % node)
        b = self.buf[off:off + self.node_byte_size]
        if self.record_size == 24:
            return (b[0] << 16) | (b[1] << 8) | b[2], (b[3] << 16) | (b[4] << 8) | b[5]
        if self.record_size == 28:
            left = ((b[3] & 0xF0) << 20) | (b[0] << 16) | (b[1] << 8) | b[2]
            right = ((b[3] & 0x0F) << 24) | (b[4] << 16) | (b[5] << 8) | b[6]
            return left, right
        left = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
        right = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]
        return left, right

    def _v4_start_node(self):
        """IPv4 在 IPv6 树里的起点：沿 96 个 0 位一路往下走。

        直接复用 lookup 的循环会重复 96 次读节点，没必要，这里单独实现一次
        并缓存结果（同一进程批量查时省掉大量重复遍历）。
        """
        if self._v4_start is None:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                left, _right = self._read_node(node)
                node = left
            self._v4_start = node
        return self._v4_start

    # -- 偏移基址探测 ----------------------------------------------
    def _detect_offset_base(self):
        """确定「节点值 → 数据偏移」用哪个基址。

        规范说偏移相对数据段（树末尾 + 16），但现实中存在少了那 16 字节的库。
        用几个必然有记录的探测点（Google DNS、内网段）各试一遍，谁解出的
        是合法 dict 就用谁；两个都解不出就按规范走，让报错在查询时暴露。
        """
        probes = ("8.8.8.8", "1.1.1.1", "10.0.0.1", "0.0.0.0", "192.168.0.1")
        best = None
        best_hits = 0
        for base in (self.data_start, self.search_tree_size):
            hits = 0
            for ip in probes:
                try:
                    node, _depth = self._node_for(ip)
                except (GeoError, IndexError):
                    continue
                if node is None or node <= self.node_count:
                    continue
                try:
                    val = self._decode(base + (node - self.node_count), self.data_start)[0]
                except (GeoError, IndexError, ValueError, KeyError):
                    continue
                if isinstance(val, dict) and val:
                    hits += 1
            if hits > best_hits:
                best, best_hits = base, hits
        if best is None:
            return self.data_start
        return best

    def _node_for(self, ip_text):
        """走一遍搜索树，返回 (命中节点号, 前缀位数)；查无此项返回 (None, 0)。"""
        parsed = parse_ip(ip_text)
        if not parsed:
            raise GeoError("不是合法 IP：%s" % ip_text)
        packed, bits = parsed

        if bits == 32 and self.ip_version == 6:
            node = self._v4_start_node()
            total_bits = 32
        elif bits == 32:
            node = 0
            total_bits = 32
        elif self.ip_version == 4:
            raise GeoError("这是 IPv4 库，查不了 IPv6 地址：%s" % ip_text)
        else:
            node = 0
            total_bits = 128

        depth = 0
        for i in range(total_bits):
            if node >= self.node_count:
                break
            left, right = self._read_node(node)
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = left if bit == 0 else right
            depth = i + 1
        if node == self.node_count:
            return None, 0
        if node < self.node_count:
            raise GeoError("搜索树走到非法节点（库文件可能被截断）")
        # depth 就是这条记录覆盖的网段长度：树在这个位深上终止
        return node, depth

    def lookup(self, ip_text):
        """查一个 IP，返回 (数据 dict 或 None, 网段前缀长度)。"""
        parsed = parse_ip(ip_text)
        if not parsed:
            raise GeoError("不是合法 IP：%s" % ip_text)
        node, prefix_len = self._node_for(ip_text)
        if node is None:
            return None, 0
        offset = self.offset_base + (node - self.node_count)
        if offset >= len(self.buf):
            raise GeoError("数据偏移越界（库文件可能被截断）")
        # 数据段里的指针相对数据段起点（也就是规范里的 data_start）
        value = self._decode(offset, self.data_start)[0]
        return value, prefix_len

    # -- 数据段解码 -------------------------------------------------
    def _decode(self, offset, ptr_base):
        """解码一条自描述记录，返回 (值, 记录结束后的偏移)。

        ptr_base 是指针的基址：数据段里的记录相对 data_start，元数据段里的
        记录相对 meta_start。这两个段是分开的，用错基址会解出一堆乱码。
        """
        ctrl = self.buf[offset]
        offset += 1
        data_type = ctrl >> 5
        if data_type == 0:
            # 扩展类型：真实类型 = 下一字节 + 7
            data_type = self.buf[offset] + 7
            offset += 1

        size = ctrl & 0x1F
        if data_type == 1:
            # 指针类型：低 3 位是「指针大小 + 值的高位」
            psize = (ctrl >> 3) & 0x03
            value = ctrl & 0x07
            if psize == 0:
                value = (value << 8) | self.buf[offset]
                offset += 1
            elif psize == 1:
                value = ((value << 16) | (self.buf[offset] << 8)
                         | self.buf[offset + 1]) + 2048
                offset += 2
            elif psize == 2:
                value = ((value << 24) | (self.buf[offset] << 16)
                         | (self.buf[offset + 1] << 8) | self.buf[offset + 2]) + 526336
                offset += 3
            else:
                value = ((self.buf[offset] << 24) | (self.buf[offset + 1] << 16)
                         | (self.buf[offset + 2] << 8) | self.buf[offset + 3])
                offset += 4
            return self._decode(ptr_base + value, ptr_base)[0], offset

        # 长度扩展
        if size == 29:
            size = 29 + self.buf[offset]
            offset += 1
        elif size == 30:
            size = 285 + ((self.buf[offset] << 8) | self.buf[offset + 1])
            offset += 2
        elif size == 31:
            size = 65821 + ((self.buf[offset] << 16) | (self.buf[offset + 1] << 8)
                            | self.buf[offset + 2])
            offset += 3

        if data_type == 2:      # utf8 字符串
            raw = self.buf[offset:offset + size]
            offset += size
            try:
                return raw.decode("utf-8"), offset
            except UnicodeDecodeError:
                return raw.decode("utf-8", errors="replace"), offset
        if data_type == 3:      # double
            return struct.unpack(">d", self.buf[offset:offset + 8])[0], offset + 8
        if data_type == 4:      # bytes
            return self.buf[offset:offset + size], offset + size
        if data_type == 5:      # uint16
            return int.from_bytes(self.buf[offset:offset + size], "big"), offset + size
        if data_type == 6:      # uint32
            return int.from_bytes(self.buf[offset:offset + size], "big"), offset + size
        if data_type == 7:      # map：size 是键值对个数
            out = {}
            for _ in range(size):
                key, offset = self._decode(offset, ptr_base)
                val, offset = self._decode(offset, ptr_base)
                if isinstance(key, bytes):
                    key = key.decode("utf-8", errors="replace")
                out[key] = val
            return out, offset
        if data_type == 8:      # int32（负数要符号扩展）
            raw = self.buf[offset:offset + size]
            offset += size
            if raw and (raw[0] & 0x80):
                raw = b"\xff" * (4 - len(raw)) + raw
            return int.from_bytes(raw, "big", signed=True), offset
        if data_type == 9:      # uint64
            return int.from_bytes(self.buf[offset:offset + size], "big"), offset + size
        if data_type == 10:     # uint128
            return int.from_bytes(self.buf[offset:offset + size], "big"), offset + size
        if data_type == 11:     # array
            out = []
            for _ in range(size):
                val, offset = self._decode(offset, ptr_base)
                out.append(val)
            return out, offset
        if data_type == 14:     # boolean：size 为 0/1，不占内容字节
            return (size == 1), offset
        if data_type == 15:     # float
            return struct.unpack(">f", self.buf[offset:offset + 4])[0], offset + 4

        raise GeoError("mmdb 里出现未知数据类型 %d（偏移 %d）" % (data_type, offset))


# ------------------------------------------------------------------ 结果整形

def pick_name(names, prefer=("zh-CN", "zh", "en")):
    """MaxMind 的 names 是 {语言: 名称}，优先中文，其次英文。"""
    if isinstance(names, str):
        return names.strip()
    if not isinstance(names, dict):
        return ""
    for lang in prefer:
        val = names.get(lang)
        if isinstance(val, str) and val.strip():
            return val.strip()
    for val in names.values():
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def as_dict(val):
    """字段可能是 dict，也可能缺失；非 dict 一律当空。"""
    return val if isinstance(val, dict) else {}


def shape_offline(ip, data, prefix_len):
    """把 mmdb 的原始 dict 整理成统一的输出结构。"""
    out = {
        "ip": ip,
        "source": "mmdb",
        "found": data is not None,
    }
    if not isinstance(data, dict) or not data:
        return out

    country = as_dict(data.get("country")) or as_dict(data.get("registered_country"))
    if country:
        out["country"] = pick_name(country.get("names"))
        code = country.get("iso_code") or ""
        # 有些定制库（如 v2rayN 自带的 Country.mmdb）把厂商标记塞进 iso_code：
        # 8.8.8.8 -> "GOOGLE"、1.1.1.1 -> "CLOUDFLARE"。那不是国家代码，
        # 直接当国家显示会误导使用者。
        # 判据：真 ISO 3166-1 alpha-2 是恰好 2 位大写字母。
        is_iso2 = (isinstance(code, str) and len(code) == 2
                   and code.isalpha() and code.isupper())
        if code and not is_iso2:
            out["country_code"] = ""
            out["vendor_tag"] = code
            if not out["country"]:
                out["country"] = "（该库此条只有厂商标记 %s，没有国家名）" % code
        else:
            out["country_code"] = code
            if not out["country"] and isinstance(code, str):
                out["country"] = code
    out["continent"] = pick_name(as_dict(data.get("continent")).get("names"))

    city = as_dict(data.get("city"))
    if city:
        out["city"] = pick_name(city.get("names"))
    subdivisions = data.get("subdivisions")
    if isinstance(subdivisions, list) and subdivisions:
        names = []
        for sub in subdivisions:
            if isinstance(sub, dict):
                nm = pick_name(sub.get("names"))
                if nm:
                    names.append(nm)
        if names:
            out["region"] = "/".join(names)

    loc = as_dict(data.get("location"))
    if loc:
        if loc.get("latitude") is not None:
            out["lat"] = loc.get("latitude")
        if loc.get("longitude") is not None:
            out["lon"] = loc.get("longitude")
        if loc.get("time_zone"):
            out["timezone"] = loc.get("time_zone")

    traits = as_dict(data.get("traits"))
    if traits:
        if traits.get("isp"):
            out["isp"] = traits.get("isp")
        if traits.get("organization"):
            out["org"] = traits.get("organization")
        if traits.get("asn"):
            out["asn"] = "AS%d" % traits.get("asn")
        if traits.get("domain"):
            out["domain"] = traits.get("domain")
    out["prefix_len"] = prefix_len
    return out


def shape_ipapi(ip, data):
    """ip-api.com 的返回结构。status=fail 时 data 里有 message。"""
    if data.get("status") == "fail":
        return {"ip": ip, "source": "ip-api.com", "found": False,
                "error": data.get("message") or "查询失败"}
    return {
        "ip": ip,
        "source": "ip-api.com",
        "found": True,
        "country": data.get("country") or "",
        "country_code": data.get("countryCode") or "",
        "region": data.get("regionName") or "",
        "city": data.get("city") or "",
        "isp": data.get("isp") or "",
        "org": data.get("org") or "",
        "asn": data.get("as") or "",
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "timezone": data.get("timezone") or "",
    }


def shape_ipinfo(ip, data):
    """ipinfo.io 的返回结构：loc 是 "lat,lon" 字符串。"""
    if isinstance(data, dict) and data.get("error"):
        msg = data.get("error")
        if isinstance(msg, dict):
            msg = msg.get("title") or msg.get("message") or "查询失败"
        return {"ip": ip, "source": "ipinfo.io", "found": False, "error": str(msg)}
    out = {
        "ip": ip,
        "source": "ipinfo.io",
        "found": bool(data.get("country") or data.get("city") or data.get("org")),
        "country": data.get("country") or "",
        "country_code": data.get("country") or "",
        "region": data.get("region") or "",
        "city": data.get("city") or "",
        "org": data.get("org") or "",
        "timezone": data.get("timezone") or "",
    }
    loc = data.get("loc")
    if isinstance(loc, str) and "," in loc:
        lat_s, _, lon_s = loc.partition(",")
        try:
            out["lat"] = float(lat_s)
            out["lon"] = float(lon_s)
        except ValueError:
            pass
    if not out["found"] and data.get("bogon"):
        out["found"] = False
        out["error"] = "内网/保留地址（bogon）"
    return out


# ------------------------------------------------------------------ 在线查询

API_URLS = {
    "ip-api": "http://ip-api.com/json/%s?fields=status,message,country,countryCode,"
              "regionName,city,isp,org,as,lat,lon,timezone",
    "ipinfo": "https://ipinfo.io/%s/json",
}


def online_lookup(ip, api, timeout):
    """走 HTTP 免费 API。注意：会把 IP 发给第三方。"""
    url = API_URLS[api] % urllib.parse.quote(ip, safe="")

    def run():
        req = urllib.request.Request(url, headers={
            "User-Agent": "miscbox-osint/1.0",
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise GeoError("被限流（HTTP 429）：%s 免费额度用完了，等一分钟再试" % api)
            raise GeoError("%s 返回 HTTP %d：%s" % (api, exc.code, exc.reason))
        except urllib.error.URLError as exc:
            raise GeoError("请求 %s 失败：%s（网络不通？）" % (api, exc.reason))
        except socket.timeout:
            raise GeoError("请求 %s 超时（%d 秒）" % (api, int(timeout)))
        except OSError as exc:
            raise GeoError("请求 %s 失败：%s" % (api, exc))
        try:
            return json.loads(body.decode("utf-8", errors="replace"))
        except ValueError:
            raise GeoError("%s 返回的不是合法 JSON（可能被劫持或需要 token）" % api)

    data = call_with_deadline(run, timeout + 1.0, "请求 %s" % api)
    if api == "ipinfo":
        return shape_ipinfo(ip, data)
    return shape_ipapi(ip, data)


# ------------------------------------------------------------------ 输出

FIELDS = (
    ("country", "国家"),
    ("country_code", "国家代码"),
    ("continent", "大洲"),
    ("region", "地区"),
    ("city", "城市"),
    ("isp", "ISP"),
    ("org", "机构"),
    ("asn", "ASN"),
    ("domain", "域名"),
    ("lat", "纬度"),
    ("lon", "经度"),
    ("timezone", "时区"),
)


def format_line(rec):
    """一条记录压成一行，批量查询时最省地方。"""
    if not rec.get("found"):
        reason = rec.get("error") or "未收录"
        return "%-40s  未知（%s）" % (rec["ip"], reason)
    bits = []
    if rec.get("country"):
        cc = rec.get("country_code")
        bits.append("%s(%s)" % (rec["country"], cc) if cc else rec["country"])
    for key in ("region", "city"):
        if rec.get(key):
            bits.append(rec[key])
    if rec.get("org") or rec.get("isp"):
        bits.append(rec.get("org") or rec.get("isp"))
    if rec.get("asn"):
        bits.append(rec["asn"])
    if rec.get("lat") is not None and rec.get("lon") is not None:
        try:
            bits.append("%.3f,%.3f" % (float(rec["lat"]), float(rec["lon"])))
        except (TypeError, ValueError):
            pass
    return "%-40s  %s" % (rec["ip"], " | ".join(bits) if bits else "未收录")


def format_block(rec):
    """单条记录展开成多行，方便看细节。"""
    lines = ["== %s ==" % rec["ip"]]
    if not rec.get("found"):
        reason = rec.get("error") or "库里没有这条记录（可能是内网/保留地址）"
        lines.append("  未查到：%s" % reason)
        return "\n".join(lines)
    for key, label in FIELDS:
        val = rec.get(key)
        if val is None or val == "":
            continue
        lines.append("  %-8s %s" % (label, val))
    if rec.get("vendor_tag"):
        lines.append("  %-8s %s" % ("库标记", rec["vendor_tag"]))
        lines.append("            （该库此条没有国家代码，iso_code 位置放的是厂商标记，"
                     "别当国家代码用）")
    if rec.get("prefix_len"):
        lines.append("  %-8s /%d" % ("网段", rec["prefix_len"]))
    return "\n".join(lines)


def build_usage():
    return (
        "用法：python -X utf8 geoip.py <IP> [选项]\n"
        "      python -X utf8 geoip.py --batch IP列表.txt [选项]\n"
        "\n"
        "做什么：查 IP 的地理位置与归属。\n"
        "  * 有本地 .mmdb 时走离线库（不外发数据，推荐）；\n"
        "  * 没有本地库时降级到 ip-api.com / ipinfo.io（在线，会把 IP 发给第三方）。\n"
        "\n"
        "例子：\n"
        "  python -X utf8 geoip.py 8.8.8.8\n"
        "  python -X utf8 geoip.py 8.8.8.8 --db GeoLite2-Country.mmdb\n"
        "  python -X utf8 geoip.py --batch ips.txt --db Country.mmdb --json\n"
        "  python -X utf8 geoip.py 1.1.1.1 --api ipinfo\n"
        "  python -X utf8 geoip.py --db Country.mmdb --info\n"
        "\n"
        "选项：\n"
        "  --db 路径       本地 .mmdb（GeoLite2-Country / GeoLite2-City）\n"
        "  --api 名称      在线接口：ip-api（默认）或 ipinfo\n"
        "  --batch 文件     从文件读一批 IP（每行一个，# 开头为注释）\n"
        "  --timeout 秒     在线请求超时，默认 10\n"
        "  --delay 秒       在线批量查询的间隔，默认 1.5（尊重免费额度）\n"
        "  --json          输出 JSON\n"
        "  --info          只打印 mmdb 元数据后退出\n"
        "  -o/--output 文件 写入文件（已存在需 --force）\n"
        "\n"
        "注意：--db 缺省时会在线查询，等于把你查的 IP 告诉第三方，敏感目标请自备 mmdb。\n"
    )


def write_output(path, text, force):
    from pathlib import Path
    p = Path(path)
    if p.exists() and not force:
        sys.stderr.write("目标文件已存在：%s（要覆盖请加 --force）\n" % p)
        return False
    p.write_text(text, encoding="utf-8")
    return True


def read_batch(path):
    """读 IP 列表：跳过空行和 # 注释，同一行里有多个 IP 也能拆出来。"""
    from pathlib import Path
    p = Path(path)
    if not p.is_file():
        raise GeoError("批量文件不存在：%s" % p)
    try:
        text = p.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise GeoError("读取批量文件失败：%s（%s）" % (p, exc))

    ips = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 允许 "8.8.8.8  # 谷歌DNS" 这种行尾注释
        if "#" in line:
            line = line.split("#")[0].strip()
        for token in line.replace(",", " ").replace("\t", " ").split():
            if token:
                ips.append(token)
    if not ips:
        raise GeoError("批量文件里没有 IP：%s" % p)
    return ips


# ---- 本地 mmdb 自动发现 ----
# 优先级：环境变量 > 脚本附近 > 常见客户端目录 > 工具箱根目录
_MMDB_NAMES = (
    "Country.mmdb", "country.mmdb", "GeoLite2-Country.mmdb",
    "GeoLite2-City.mmdb", "geoip.mmdb", "ipipfree.ipdb",
)


def _iter_mmdb(dirs, max_depth=2):
    """在给定目录里找 .mmdb，限制递归深度，避免全盘扫描。"""
    for base in dirs:
        if not base or not os.path.isdir(base):
            continue
        base_depth = base.rstrip("\\/").count(os.sep)
        for root, subdirs, files in os.walk(base):
            depth = root.rstrip("\\/").count(os.sep) - base_depth
            if depth >= max_depth:
                subdirs[:] = []
            for name in files:
                if name.lower().endswith(".mmdb") or name in _MMDB_NAMES:
                    yield os.path.join(root, name)


def find_local_mmdb(script_path=None):
    """返回一个可用的本地 mmdb 路径，找不到返回 None。"""
    env = os.environ.get("GEOIP_MMDB")
    if env and os.path.isfile(env):
        return env

    here = os.path.dirname(os.path.abspath(script_path or __file__))
    # 脚本同目录 + 往上 3 级
    near = [here]
    p = here
    for _ in range(3):
        p = os.path.dirname(p)
        if not p or p == os.path.dirname(p):
            break
        near.append(p)
    for cand in _iter_mmdb(near, max_depth=1):
        return cand

    # 常见客户端目录（只查固定子路径，不做深扫）
    local = os.environ.get("LOCALAPPDATA") or ""
    appdata = os.environ.get("APPDATA") or ""
    home = os.path.expanduser("~")
    guesses = [
        os.path.join(local, "v2rayN"),
        os.path.join(local, "Programs", "v2rayN"),
        os.path.join(home, "v2rayN"),
        os.path.join(home, ".config", "v2rayA"),
        os.path.join(appdata, "v2rayN"),
        os.path.join(home, ".config", "clash"),
        os.path.join(home, ".config", "mihomo"),
        os.path.join(local, "Programs", "Clash for Windows"),
    ]
    for cand in _iter_mmdb(guesses, max_depth=2):
        return cand
    return None


def main():
    ap = argparse.ArgumentParser(
        description="IP 地理定位（本地 mmdb 优先，缺失时降级在线 API）",
        add_help=True,
    )
    ap.add_argument("ip", nargs="?", help="要查的 IP")
    ap.add_argument("--db", help="本地 .mmdb 路径")
    ap.add_argument("--api", choices=["ip-api", "ipinfo"], default="ip-api",
                    help="在线接口，默认 ip-api")
    ap.add_argument("--batch", help="从文件批量读 IP")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="在线超时秒数，默认 10")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help="在线批量查询间隔秒数，默认 1.5")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--info", action="store_true", help="只打印 mmdb 元数据")
    ap.add_argument("-o", "--output", help="输出写入文件")
    ap.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    args = ap.parse_args()

    # --info 需要 --db
    if args.info:
        if not args.db:
            sys.stderr.write("--info 需要配合 --db 指定一个 .mmdb 文件。\n")
            return 2
        try:
            db = MMDB(args.db)
        except GeoError as exc:
            sys.stderr.write("打开数据库失败：%s\n" % exc)
            return 1
        lines = ["== mmdb 元数据：%s ==" % args.db]
        for key, val in db.info():
            lines.append("  %-28s %s" % (key, val))
        lines.append("  %-28s %s" % ("搜索树字节数", db.search_tree_size))
        lines.append("  %-28s %s" % ("数据段起点", db.data_start))
        text = "\n".join(lines)
        if args.output:
            if not write_output(args.output, text + "\n", args.force):
                return 1
            sys.stderr.write("已写入：%s\n" % args.output)
            return 0
        sys.stdout.write(text + "\n")
        return 0

    # 收集目标 IP
    targets = []
    if args.batch:
        try:
            targets = read_batch(args.batch)
        except GeoError as exc:
            sys.stderr.write("%s\n" % exc)
            return 1
    elif args.ip:
        targets = [args.ip.strip()]
    else:
        sys.stdout.write(build_usage())
        return 0

    # 先校验 IP 合法性，别等发请求才发现写错了
    bad = [t for t in targets if parse_ip(t) is None]
    if bad:
        sys.stderr.write("参数错误：不是合法 IP：%s\n" % ", ".join(bad[:5]))
        return 2

    db = None
    db_path = args.db
    if not db_path:
        # 没指定 --db 时，先找本地库；找到就用，避免联网
        db_path = find_local_mmdb(__file__)
        if db_path:
            sys.stderr.write("[本地库] 自动使用 %s\n" % db_path)
    if db_path:
        try:
            db = MMDB(db_path)
        except GeoError as exc:
            sys.stderr.write("打开数据库失败：%s\n" % exc)
            sys.stderr.write("提示：不想用本地库就去掉 --db，改走在线 API（会外发 IP）。\n")
            return 1
    else:
        # 没给库 = 在线查询，必须把隐私影响说清楚
        sys.stderr.write("提示：未指定 --db，本次走在线查询（%s）。\n" % args.api)
        sys.stderr.write("      这会把你要查的 IP 发送给第三方服务；敏感目标请自备 GeoLite2 库。\n")

    results = []
    net_errors = 0
    online = db is None

    for idx, ip in enumerate(targets):
        if online and idx > 0:
            # 尊重免费 API 的速率限制，逐个来，不并发轰炸
            time.sleep(max(0.0, args.delay))

        if online:
            parsed = parse_ip(ip)
            if parsed and is_private(parsed[0], parsed[1]):
                rec = {"ip": ip, "source": "local", "found": False,
                       "error": "内网/保留地址，任何 GeoIP 都查不到"}
                results.append(rec)
                continue
            try:
                rec = online_lookup(ip, args.api, max(1.0, args.timeout))
            except GeoError as exc:
                net_errors += 1
                rec = {"ip": ip, "source": args.api, "found": False,
                       "error": str(exc)}
                results.append(rec)
                # 连着失败说明不是单个 IP 的问题，别再一个个等超时
                if net_errors >= 3:
                    sys.stderr.write("连续 %d 次失败，判定网络不通，提前结束。\n" % net_errors)
                    break
                continue
        else:
            try:
                data, prefix_len = db.lookup(ip)
            except GeoError as exc:
                rec = {"ip": ip, "source": "mmdb", "found": False, "error": str(exc)}
                results.append(rec)
                continue
            rec = shape_offline(ip, data, prefix_len)
            parsed = parse_ip(ip)
            if not rec["found"] and parsed and is_private(parsed[0], parsed[1]):
                rec["error"] = "内网/保留地址，库里本来就不收录"
        results.append(rec)

    if not results:
        sys.stderr.write("没有查到任何结果。\n")
        return 1

    # ---- 输出
    if args.json:
        text = json.dumps({
            "source": "mmdb" if db else args.api,
            "database": args.db or None,
            "count": len(results),
            "results": results,
        }, ensure_ascii=False, indent=2)
    else:
        if len(results) == 1 and not args.batch:
            text = format_block(results[0])
        else:
            text = "\n".join(format_line(r) for r in results)
            found = sum(1 for r in results if r.get("found"))
            text += "\n\n共 %d 个 IP，查到 %d 个。" % (len(results), found)

    if args.output:
        if not write_output(args.output, text + "\n", args.force):
            return 1
        sys.stderr.write("已写入：%s\n" % args.output)
        return 0

    sys.stdout.write(text + "\n")
    # 全部失败 → 退出码 1，方便脚本判断
    if not any(r.get("found") for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
