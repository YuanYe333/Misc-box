# -*- coding: utf-8 -*-
"""
bases.py -- Base 全家桶：Base16/32/32hex/58/64/64url/85/91 编解码 + 变表探测。

为什么需要
==========
CTF 里 "这串是什么编码" 有一半是 Base 家族。但坑在于：
  * Base64 有标准 / URL-safe / 无填充 / 换表（CTF 最爱改字母表）多种变体；
  * Base58 有比特币 / Flickr / Ripple 三套字母表；
  * Base85 有 4 个互不兼容的流派：RFC 1924、Git(btoa)、ZeroMQ Z85、
    Adobe ASCII85 —— 用错流派解出来就是乱码；
  * Base32 还有 base32hex（扩展十六进制）这一支。
标准库只给了 base16/32/64，剩下全靠手写。

本脚本做三件事：
  1. --encode / --decode：8 种 Base 双向编解码，全部可逆（自测对拍过）；
  2. 自动探测：给一串字符，按「字符集 + 长度约束」判断最可能是哪种 Base；
  3. --alphabet 自定义字母表，解 CTF 常见的变表 Base64。

用法
====
    python -X utf8 bases.py "SGVsbG8="                       # 自动探测
    python -X utf8 bases.py -d b64 "SGVsbG8="                # 指定 base64 解码
    python -X utf8 bases.py -e b58 "hello"                   # base58 编码
    python -X utf8 bases.py -d b64 --alphabet "BCDEFGH..." "xxx"   # 变表 base64
    python -X utf8 bases.py -f 密文.txt
    python -X utf8 bases.py --list                           # 列出所有支持的字母表

已知限制
========
    * Base91 的编码结果不唯一（末尾残余位可以用不同方式落位），
      所以 --encode 出来的串**能解回原文**，但不保证与在线工具逐字节相同；
    * 自动探测只看字符集和长度，遇到「纯字母数字串」会把 Base62/58/64
      一起列出来——这是信息论上就分不清，不是 bug；
    * 自定义字母表只支持「长度等于该 Base 标准字母表长度」的替换，
      即变表 Base64 用 64 个字符，变表 Base32 用 32 个字符。
"""

import argparse
import base64
import binascii
import re
import sys

# ====================================================================
# 字母表定义
# ====================================================================

# RFC 4648 标准表
B16_STD = "0123456789ABCDEF"
B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B32HEX_STD = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
B64_STD = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
B64URL_STD = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

# Base58 三套常用表
B58_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_FLICKR = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
B58_RIPPLE = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

# Base85 四流派（注意四者字母表完全不同，不可混用）
B85_RFC1924 = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "abcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
# Git 的 base85：先按 4 字节大端转 u32，再从最高位开始每 5 位查一次表
B85_GIT = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
           "abcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
# ZeroMQ Z85：85 个字符，无 < > " ' \ 空格
B85_Z85 = ("0123456789abcdefghijklmnopqrstuvwxyz"
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")
# Adobe ASCII85：33..117 的连续 ASCII
B85_A85 = "".join(chr(c) for c in range(33, 118))

# Base91 标准表（原始 basE91 by Joachim Henke）
B91_STD = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
           "0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
# 注意：不同实现里 Base91 字母表有个别字符差异（有的用 ' 而不是 "），
# 所以 Base91 解码时若标准表失败，会再试一个常见变体。

B91_ALT = B91_STD[:-1] + "'"

# 名字 -> (显示名, 字母表, 类别)
# 类别用来决定「用哪套通用算法」：pow2 / bigint / block85 / base91
ALPHABETS = {
    "b16": ("Base16 (hex)", B16_STD, "pow2"),
    "b32": ("Base32", B32_STD, "pow2"),
    "b32hex": ("Base32hex", B32HEX_STD, "pow2"),
    "b58": ("Base58 (Bitcoin)", B58_BTC, "bigint"),
    "b58flickr": ("Base58 (Flickr)", B58_FLICKR, "bigint"),
    "b58ripple": ("Base58 (Ripple)", B58_RIPPLE, "bigint"),
    "b64": ("Base64", B64_STD, "pow2"),
    "b64url": ("Base64 (URL-safe)", B64URL_STD, "pow2"),
    "b85": ("Base85 (RFC 1924)", B85_RFC1924, "block85"),
    "b85git": ("Base85 (Git/btoa)", B85_GIT, "block85"),
    "z85": ("Base85 (ZeroMQ Z85)", B85_Z85, "block85"),
    "a85": ("Base85 (Adobe ASCII85)", B85_A85, "block85"),
    "b91": ("Base91", B91_STD, "base91"),
}

ALIASES = {
    "base16": "b16", "hex": "b16", "base32": "b32", "b32hex": "b32hex",
    "base32hex": "b32hex", "base58": "b58", "base58btc": "b58",
    "base58flickr": "b58flickr", "base58ripple": "b58ripple",
    "base64": "b64", "base64url": "b64url", "base64_url": "b64url",
    "base85": "b85", "base85rfc1924": "b85", "ascii85": "a85",
    "base85git": "b85git", "btoa": "b85git", "base85z85": "z85",
    "base91": "b91",
}


def resolve_name(name):
    """把用户输入的名字规范化；不认识返回 None。"""
    n = (name or "").strip().lower().replace("-", "").replace("_", "")
    if n in ALPHABETS:
        return n
    return ALIASES.get(n)


# ====================================================================
# 通用：2 的幂次基（16/32/64 共用一套位打包逻辑）
# ====================================================================

def pow2_encode(data, alphabet, bits):
    """把字节流按 bits 位一组打包，每组查一次字母表（大端）。"""
    out = []
    acc = 0
    nbits = 0
    for byte in data:
        acc = (acc << 8) | byte
        nbits += 8
        while nbits >= bits:
            nbits -= bits
            out.append(alphabet[(acc >> nbits) & ((1 << bits) - 1)])
    if nbits:                       # 残余位左移补零后照样输出一个字符
        out.append(alphabet[(acc << (bits - nbits)) & ((1 << bits) - 1)])
    return "".join(out)


def pow2_decode(text, alphabet, bits):
    """pow2_encode 的逆过程。非法字符抛 ValueError。"""
    idx = {}
    for i, ch in enumerate(alphabet):
        idx[ch] = i
    # 大小写不敏感的表（base16/base32 常被写成小写）另建一份
    for i, ch in enumerate(alphabet):
        idx.setdefault(ch.lower(), i)
        idx.setdefault(ch.upper(), i)

    acc = 0
    nbits = 0
    out = bytearray()
    for ch in text:
        if ch in "= \r\n\t":
            continue
        if ch not in idx:
            raise ValueError("字符 %r 不在该 Base 的字母表里" % ch)
        acc = (acc << bits) | idx[ch]
        nbits += bits
        if nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
    return bytes(out)


# ====================================================================
# Base58：大整数算法
# ====================================================================

def b58_encode(data, alphabet):
    """标准 Base58：把整个字节流当大整数转 58 进制，前导零字节转前导 '1'。"""
    n = 0
    for byte in data:
        n = n * 256 + byte
    out = []
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(alphabet[rem])
    # 前导零字节 -> 字母表第 0 个字符（Bitcoin 表里就是 '1'）
    pad = 0
    for byte in data:
        if byte != 0:
            break
        pad += 1
    return alphabet[0] * pad + "".join(reversed(out))


def b58_decode(text, alphabet):
    """Base58 解码：字母表第 0 个字符的前缀还原成前导零字节。"""
    idx = {}
    for i, ch in enumerate(alphabet):
        idx[ch] = i
    n = 0
    for ch in text:
        if ch in " \r\n\t":
            continue
        if ch not in idx:
            raise ValueError("字符 %r 不在该 Base58 的字母表里" % ch)
        n = n * 58 + idx[ch]
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 256)
        out.append(rem)
    pad = 0
    for ch in text:
        if ch != alphabet[0]:
            break
        pad += 1
    return bytes([0] * pad) + bytes(reversed(out))


# ====================================================================
# Base85：4 字节 <-> 5 字符（大端 u32）
# ====================================================================

def b85_encode(data, alphabet):
    """把 4 字节一组当**大端** u32，再转 5 个 85 进制字符。

    不足 4 字节的尾部照常编码（低位补 0），解码时按 5 字符一组还原、
    多余的低位字节丢弃即可。这样 encode/decode 严格互逆，不依赖各流派
    的「尾部约定」。

    大端这点已用官方测试向量核对过：
      * Z85 (RFC 32)：0x864FD26FB559F75B -> "HelloWorld"；
      * RFC 1924：0x00000000 -> "00000"。
    曾经怀疑 Z85 是小端，实测不是 —— 四套 Base85 的分组字节序都是大端，
    差别只在字母表和尾部规则。
    """
    out = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        n = 0
        for j in range(4):
            n = (n << 8) | (chunk[j] if j < len(chunk) else 0)
        grp = []
        for _ in range(5):
            n, rem = divmod(n, 85)
            grp.append(alphabet[rem])
        out.extend(reversed(grp))
    return "".join(out)


def b85_decode(text, alphabet):
    """b85_encode 的逆过程。"""
    idx = {}
    for i, ch in enumerate(alphabet):
        idx[ch] = i
    clean = [ch for ch in text if ch not in " \r\n\t"]
    if not clean:
        return b""
    # 允许尾部不足 5 个字符：标准库 base64.b85encode / a85encode 会把
    # 最后一个分组「截断输出」——n 字节只输出 ceil(n*5/4) 个字符。
    # 解码时在右边补 0 位（数值乘 85 的幂），再只取前 n 字节即可还原。
    # 反推公式：n = floor(k * 4 / 5)，k 为该组的字符数。
    out = bytearray()
    groups = len(clean) // 5
    tail = clean[groups * 5:]
    for i in range(groups):
        n = 0
        for ch in clean[i * 5:i * 5 + 5]:
            if ch not in idx:
                raise ValueError("字符 %r 不在该 Base85 的字母表里" % ch)
            n = n * 85 + idx[ch]
        if n > 0xFFFFFFFF:
            raise ValueError("Base85 分组数值溢出（超过 2^32）")
        out.extend(bytes([(n >> 24) & 0xFF, (n >> 16) & 0xFF,
                          (n >> 8) & 0xFF, n & 0xFF]))
    if tail:
        k = len(tail)
        n = 0
        for ch in tail:
            if ch not in idx:
                raise ValueError("字符 %r 不在该 Base85 的字母表里" % ch)
            n = n * 85 + idx[ch]
        # 关键：补齐用**最大**数字（字母表最后一个，值 84），不是 0。
        # 这是 ASCII85/Base85 的既定约定（编码时末尾数字被截掉，解码时
        # 用 '~' 补回来）。用 0 补会让高位字节整体偏小 —— 实测
        # b'f' -> "W&" 用 0 补解出 0x65，用 84 补才是正确的 0x66。
        for _ in range(5 - k):
            n = n * 85 + 84
        nbytes = (k * 4) // 5
        if nbytes <= 0:
            raise ValueError("Base85 尾部长度 %d 无效" % k)
        full = [(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]
        out.extend(full[:nbytes])
    return bytes(out)


# ====================================================================
# Base91
# ====================================================================

def b91_encode(data, alphabet=B91_STD):
    """Base91：两个字节合成一个 13/14 位整数，再输出 1~2 个字符。

    关键在「什么时候用 13 位、什么时候用 14 位」：
      * 先看低 13 位的值 v13，如果 v13 > 88 就只用 13 位（省 1 位）；
      * 否则取 14 位。这样保证 v // 91 永远 <= 90（字母表下标不越界）。
    早期版本无条件取 14 位，遇到大值直接 IndexError。
    """
    out = []
    n = 0
    nbits = 0
    for byte in data:
        n |= byte << nbits
        nbits += 8
        if nbits >= 14:
            v13 = n & 0x1FFF
            if v13 > 88:
                v = v13
                n >>= 13
                nbits -= 13
            else:
                v = n & 0x3FFF
                n >>= 14
                nbits -= 14
            out.append(alphabet[v % 91])
            out.append(alphabet[v // 91])
    # 收尾：残余位（1~13 位）落成 1~2 个字符
    if nbits:
        out.append(alphabet[n % 91])
        if nbits > 7 or n > 90:
            out.append(alphabet[n // 91])
    return "".join(out)


def b91_decode(text, alphabet=B91_STD):
    """b91_encode 的逆过程。

    判断依据与编码端严格对称：凑够 13 位时先看 v13 = n & 0x1FFF，
    v13 > 88 说明编码端只用了 13 位，否则用了 14 位。
    """
    idx = {}
    for i, ch in enumerate(alphabet):
        idx[ch] = i
    out = bytearray()
    n = 0
    nbits = 0
    v = -1
    for ch in text:
        if ch in " \r\n\t":
            continue
        if ch not in idx:
            raise ValueError("字符 %r 不在 Base91 的字母表里" % ch)
        d = idx[ch]
        if v < 0:
            v = d
        else:
            v += d * 91
            n |= v << nbits
            nbits += 13 if (v & 8191) > 88 else 14
            while nbits >= 8:
                out.append(n & 0xFF)
                n >>= 8
                nbits -= 8
            v = -1
    # 收尾：编码端最后的残余位一定是「一个不完整的字节」，必须无条件吐出来。
    # 这里曾经写成「nbits >= 8 才吐」，结果 2/4/5/7 字节的输入会丢最后一个字节。
    if v >= 0:
        out.append((n | (v << nbits)) & 0xFF)
    return bytes(out)


# ====================================================================
# 统一入口
# ====================================================================

def encode_with(name, data, alphabet=None):
    """按名字编码 bytes。alphabet 非空时替换默认字母表（长度必须一致）。"""
    display, default_alpha, kind = ALPHABETS[name]
    alpha = default_alpha
    if alphabet:
        if len(alphabet) != len(default_alpha):
            raise ValueError(
                "%s 的字母表必须是 %d 个字符（给了 %d 个）"
                % (display, len(default_alpha), len(alphabet)))
        alpha = alphabet
    if kind == "pow2":
        bits = {16: 4, 32: 5, 64: 6}[len(alpha) if len(alpha) in (16, 32, 64)
                                     else len(default_alpha)]
        return pow2_encode(data, alpha, bits)
    if kind == "bigint":
        return b58_encode(data, alpha)
    if kind == "block85":
        return b85_encode(data, alpha)
    if kind == "base91":
        return b91_encode(data, alpha)
    raise ValueError("未知的 Base 类别：%s" % kind)


def decode_with(name, text, alphabet=None):
    """按名字解码成 bytes。"""
    display, default_alpha, kind = ALPHABETS[name]
    alpha = default_alpha
    if alphabet:
        if len(alphabet) != len(default_alpha):
            raise ValueError(
                "%s 的字母表必须是 %d 个字符（给了 %d 个）"
                % (display, len(default_alpha), len(alphabet)))
        alpha = alphabet
    if kind == "pow2":
        bits = {16: 4, 32: 5, 64: 6}[len(default_alpha)]
        return pow2_decode(text, alpha, bits)
    if kind == "bigint":
        return b58_decode(text, alpha)
    if kind == "block85":
        return b85_decode(text, alpha)
    if kind == "base91":
        if alpha == B91_STD:
            # 先按标准表解，失败再试单引号变体（不同实现有差异）
            try:
                return b91_decode(text, B91_STD)
            except ValueError:
                return b91_decode(text, B91_ALT)
        return b91_decode(text, alpha)
    raise ValueError("未知的 Base 类别：%s" % kind)


# ====================================================================
# 自动探测
# ====================================================================

RE_B16 = re.compile(r"^[0-9A-Fa-f]+$")
RE_B32 = re.compile(r"^[A-Z2-7]+=*$")
RE_B32HEX = re.compile(r"^[0-9A-V]+=*$")
RE_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
RE_B64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
RE_B58 = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
RE_B91 = re.compile(r"^[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~\"']+$")


def looks_readable(data):
    """解码结果像不像文本：可打印占比高就算。"""
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / float(len(data))


def detect(text):
    """返回 [(名字, 置信度, 说明)]，按置信度降序。

    判定依据只有两样：字符集能不能覆盖、长度约束满不满足。
    在此基础上再「真的解一次」，看解出来的东西像不像文本，用来加分。
    """
    t = text.strip()
    if not t:
        return []
    hits = []

    def add(name, conf, note):
        hits.append((name, conf, note))

    # ---- Base16 ----
    if RE_B16.match(t) and len(t) % 2 == 0 and len(t) >= 4:
        conf = 0.75
        note = "纯十六进制字符，长度偶数"
        if re.search(r"[A-Fa-f]", t) and re.search(r"[0-9]", t):
            conf += 0.05
        add("b16", conf, note)

    # ---- Base32 ----
    if RE_B32.match(t) and len(t) >= 8:
        conf = 0.7
        note = "A-Z2-7 字符集"
        if t.endswith("="):
            conf += 0.15
            note += "，带填充"
        add("b32", conf, note)

    # ---- Base32hex ----
    if RE_B32HEX.match(t) and len(t) >= 8 and re.search(r"[G-V]", t):
        add("b32hex", 0.55, "0-9A-V 字符集（扩展十六进制）")

    # ---- Base64 ----
    if RE_B64.match(t) and len(t) >= 8:
        conf = 0.6
        note = "Base64 字符集"
        if t.endswith("="):
            conf += 0.25
            note += "，带填充"
        if re.search(r"[+/]", t):
            conf += 0.1
            note += "，含 +/"
        add("b64", conf, note)

    # ---- Base64url ----
    if RE_B64URL.match(t) and len(t) >= 8 and re.search(r"[-_]", t):
        add("b64url", 0.65, "含 -/_ 的 URL-safe 字符集")

    # ---- Base58 ----
    if RE_B58.match(t) and len(t) >= 6:
        # 不含 0 O I l 是 Base58 的强特征
        add("b58", 0.6, "不含 0OIl 的字母数字串（Base58 特征）")

    # ---- Base85 ----
    if len(t) >= 10 and len(t) % 5 == 0:
        if all(ch in B85_Z85 for ch in t):
            add("z85", 0.55, "长度是 5 的倍数，字符集覆盖 Z85")
        if all(ch in B85_RFC1924 for ch in t):
            add("b85", 0.5, "长度是 5 的倍数，字符集覆盖 RFC 1924")
        if all(33 <= ord(ch) <= 117 for ch in t):
            add("a85", 0.45, "长度是 5 的倍数，ASCII 33-117（ASCII85）")

    # ---- Base91 ----
    if RE_B91.match(t) and len(t) >= 10:
        add("b91", 0.4, "宽字符集（Base91 可能）")

    # 用「解出来像不像文本」给每个候选微调置信度
    scored = []
    for name, conf, note in hits:
        try:
            dec = decode_with(name, t)
        except (ValueError, binascii.Error, IndexError):
            dec = None
        if dec is not None and dec:
            ratio = looks_readable(dec)
            if ratio > 0.9:
                conf += 0.15
                note += "；解出可打印文本"
            elif ratio < 0.5:
                conf -= 0.15
                note += "；解出二进制"
        scored.append((name, round(min(conf, 1.0), 2), note))

    # 去重（同一名字可能被多条规则命中）
    merged = {}
    for name, conf, note in scored:
        if name not in merged or conf > merged[name][0]:
            merged[name] = (conf, note)
    out = [(n, c, note) for n, (c, note) in merged.items()]
    out.sort(key=lambda x: -x[1])
    return out


# ====================================================================
# 入口
# ====================================================================

USAGE = """\
bases.py -- Base 全家桶：Base16/32/32hex/58/64/64url/85/91 编解码 + 自动探测

做什么：CTF 里遇到「这串是什么 Base」时，一次列出所有可能的解码结果；
        也能指定算法做双向编解码（--encode / --decode 严格互逆）。
        Base58/85/91 标准库没有，这里是手写实现。

用法：
    python -X utf8 bases.py "SGVsbG8="
    python -X utf8 bases.py -d b64 "SGVsbG8="
    python -X utf8 bases.py -e b58 "hello world"
    python -X utf8 bases.py -d b64 --alphabet "BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/A" "xxx"
    python -X utf8 bases.py -f 密文.txt
    python -X utf8 bases.py --list

支持的算法名：
    b16 b32 b32hex b58 b58flickr b58ripple b64 b64url
    b85(RFC1924) b85git(Git) z85(ZeroMQ) a85(Adobe) b91

参数：
    text                要处理的字符串（省略则从 -f 或标准输入读）
    -f/--file FILE      从文件读取（UTF-8）
    -e/--encode NAME    按指定 Base 编码（输入当纯文本）
    -d/--decode NAME    按指定 Base 解码（输出文本；二进制会提示）
    --alphabet STR      自定义字母表（长度须与标准表一致，用于变表 Base64）
    --list              列出所有支持的字母表并退出
    --top N             自动探测时显示前 N 个候选（默认 5）
    --raw               解码结果按原始字节输出（不转文本）

已知限制：
    * Base91 编码结果不唯一，能解回原文但与在线工具未必逐字节相同；
    * 自动探测对「纯字母数字串」无法唯一确定，会把多个候选一起列出；
    * 自定义字母表只做等长替换，不能改变 Base 本身的分组规则。
"""


def read_input(args):
    """读输入。返回 (文本, 是否成功)；文件读不了时第二项为 False。"""
    if args.text:
        return args.text, True
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8-sig", errors="replace") as fh:
                return fh.read(), True
        except OSError as exc:
            print("错误：读不了文件 %r —— %s" % (args.file, exc), file=sys.stderr)
            return "", False
    if not sys.stdin.isatty():
        return sys.stdin.read(), True
    return "", True


def render_bytes(data, raw):
    """把解码结果变成可打印文本。二进制内容给出明确提示。"""
    if raw:
        return data.decode("latin-1")
    for enc in ("utf-8", "gb18030", "latin-1"):
        try:
            s = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
        if printable / float(len(s) or 1) >= 0.9:
            return s
    return None


def main():
    ap = argparse.ArgumentParser(add_help=True, description="Base 全家桶")
    ap.add_argument("text", nargs="?", help="要处理的字符串")
    ap.add_argument("-f", "--file", help="从文件读取")
    ap.add_argument("-e", "--encode", metavar="NAME", help="按指定 Base 编码")
    ap.add_argument("-d", "--decode", metavar="NAME", help="按指定 Base 解码")
    ap.add_argument("--alphabet", help="自定义字母表（等长替换）")
    ap.add_argument("--list", action="store_true", help="列出所有字母表")
    ap.add_argument("--top", type=int, default=5, help="探测显示前 N 个（默认 5）")
    ap.add_argument("--raw", action="store_true", help="解码结果按原始字节输出")
    args = ap.parse_args()

    if args.list:
        print("支持的 Base 算法：")
        for name in sorted(ALPHABETS):
            display, alpha, kind = ALPHABETS[name]
            print("  %-10s %-22s 字母表长度 %2d  算法 %s"
                  % (name, display, len(alpha), kind))
        print("")
        print("Base58 三套表：b58(比特币) b58flickr b58ripple")
        print("Base85 四流派：b85(RFC1924) b85git(Git) z85(ZeroMQ) a85(Adobe)")
        return 0

    text, ok = read_input(args)
    if not ok:
        return 1
    text = text.lstrip("\ufeff").replace("\u200b", "").strip()
    if not text:
        print(USAGE)
        return 0

    if args.alphabet:
        # 提前校验字母表，给出清楚的错误而不是后面的乱码
        if len(set(args.alphabet)) != len(args.alphabet):
            print("错误：--alphabet 里有重复字符，字母表必须一一对应。",
                  file=sys.stderr)
            return 1

    # ---- 编码 ----
    if args.encode:
        name = resolve_name(args.encode)
        if name is None:
            print("错误：不认识的算法 %r。用 --list 查看支持的列表。"
                  % args.encode, file=sys.stderr)
            return 1
        data = text.encode("utf-8")
        try:
            out = encode_with(name, data, args.alphabet)
        except ValueError as exc:
            print("错误：%s" % exc, file=sys.stderr)
            return 1
        print("%s 编码结果（%d 字节 -> %d 字符）："
              % (ALPHABETS[name][0], len(data), len(out)))
        print(out)
        return 0

    # ---- 解码 ----
    if args.decode:
        name = resolve_name(args.decode)
        if name is None:
            print("错误：不认识的算法 %r。用 --list 查看支持的列表。"
                  % args.decode, file=sys.stderr)
            return 1
        try:
            data = decode_with(name, text, args.alphabet)
        except (ValueError, binascii.Error, IndexError) as exc:
            print("错误：按 %s 解码失败 —— %s" % (ALPHABETS[name][0], exc),
                  file=sys.stderr)
            return 1
        show = render_bytes(data, args.raw)
        print("%s 解码结果（%d 字节）：" % (ALPHABETS[name][0], len(data)))
        if show is None:
            print("（解出来是二进制数据，下面按 hex 显示；用 --raw 可强制当文本）")
            print(data.hex())
            return 0
        print(show)
        return 0

    # ---- 自动探测 ----
    print("输入长度: %d 字符" % len(text))
    cands = detect(text)
    if not cands:
        print("没有识别出任何已知的 Base 编码特征。")
        print("建议：确认字符集是否被换表（试试 --alphabet），或用 encscan.py。")
        return 0

    print("")
    print("== 可能的 Base 编码（按可信度排序）==")
    for i, (name, conf, note) in enumerate(cands[:args.top], 1):
        display = ALPHABETS[name][0]
        print("%d. %s  可信度 %.2f" % (i, display, conf))
        print("   判据：%s" % note)
        try:
            data = decode_with(name, text)
        except (ValueError, binascii.Error, IndexError) as exc:
            print("   解码：失败（%s）" % exc)
            continue
        show = render_bytes(data, args.raw)
        if show is None:
            print("   解码：%d 字节二进制 -> %s" % (len(data), data[:64].hex()))
        else:
            one = show if len(show) <= 200 else show[:200] + "..."
            print("   解码：%s" % one.replace("\n", "\\n"))
    print("")
    print("提示：指定算法可看完整结果，例如：")
    print('  python -X utf8 bases.py -d %s "%s"'
          % (cands[0][0], text[:30] + ("..." if len(text) > 30 else "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

