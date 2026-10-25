# -*- coding: utf-8 -*-
"""
encscan.py -- 编码识别器：把一堆「看不懂的字符」扔进来，给出最可能的编码和解码结果。

为什么需要
==========
CTF 杂项题第一眼通常就是「这串是什么」。Base64 / Base32 / Hex / URL 编码 /
HTML 实体 / 摩斯 / 培根 / 凯撒 / ROT / 反转 / 栅栏 …… 手工一个个试很慢，
而且多层嵌套时人工根本试不过来。

本脚本做两件事：
  1. 按特征打分，列出「最可能是哪种编码」的候选排序；
  2. 自动解码一层，如果结果仍然像编码，就继续解（最多 5 层），
     把整条链路打出来，省掉反复复制粘贴。

用法
====
    python -X utf8 encscan.py "SGVsbG8="
    python -X utf8 encscan.py -f 密文.txt
    python -X utf8 encscan.py --deep "5L2g5aW9"      # 只做多层链式解码

已知限制
========
    * 凯撒/栅栏这类「靠自然语言判断」的，只能给候选，不能保证对；
    * 摩斯码依赖分隔符，点划被改写就认不出；
    * 不做 base64 的「隐写位」分析（那是 stego 类脚本的活）。
"""

import argparse
import base64
import binascii
import codecs
import re
import sys
import urllib.parse

# ---------------------------------------------------------------- 判定工具

B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
B32_RE = re.compile(r"^[A-Z2-7]+=*$")
HEX_RE = re.compile(r"^(0x)?[0-9A-Fa-f\s]+$")
BIN_RE = re.compile(r"^[01\s]+$")
MORSE_RE = re.compile(r"^[.\-/ ]+$")
BACON_RE = re.compile(r"^[ABab ]+$")


def printable_ratio(text):
    """可打印字符占比。解码成功的明文通常接近 1.0。"""
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return good / len(text)


def looks_like_text(data):
    """把 bytes 转成可读文本；失败返回 None。"""
    for enc in ("utf-8", "gb18030", "latin-1"):
        try:
            s = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if printable_ratio(s) >= 0.92:
            return s
    return None


COMMON_CJK = set("的一是不了在人有我你个上们来到时大地为子中你说生国年着就那和要"
                 "她出也得里后自以会家可下而过天去能对小多然于心学么之都好看起发"
                 "当没成只如事把还用第样道想作种开美总从无情己面最女但现前些所同"
                 "日手又行意动方期它头经长儿回位分爱老因很给名法间斯知世什两次使"
                 "身果已亲其进此话常与活正感")

FLAG_RE = re.compile(r"(flag|ctf|key|pass|admin)\s*\{", re.I)


def cjk_plausible(text):
    """判断解出来的中文是「真中文」还是「随机字节凑出来的生僻字」。

    随机字节按 utf-8 解出来的 CJK 几乎都是罕用字（氘滊豁绝霝黠…）。
    真中文里常用字占比很高，所以用常用字比例来区分。
    """
    cjk = [ch for ch in text if "\u4e00" <= ch <= "\u9fff"]
    if not cjk:
        return False
    hit = sum(1 for ch in cjk if ch in COMMON_CJK)
    return hit / float(len(cjk)) >= 0.5


def flag_like(text):
    return bool(FLAG_RE.search(text))


def dec_has_fake_cjk(text):
    """解出来的文本里有 CJK 字符，但全是生僻字 —— 说明这次解码是错的。

    典型场景：把纯 hex 串（如 666c61677b...）当 base64 解，得到一串
    「氘滊豁绝霝黠」这种随机凑出来的汉字。这类结果不该被当成有效解码。
    """
    has_cjk = any("\u4e00" <= ch <= "\u9fff" for ch in text)
    if not has_cjk:
        return False
    return not cjk_plausible(text)


def entropy(s):
    """香农熵，用来判断是不是压缩/加密数据（>6.5 基本不是明文）。"""
    if not s:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(s)
    total = float(len(s))
    return -sum((c / total) * math.log(c / total, 2) for c in counts.values())


# ---------------------------------------------------------------- 各编码尝试

def try_base64(text):
    """标准 / URL-safe / 无填充 三种变体都试。"""
    out = []
    for name, fix in (
        ("base64", lambda t: t),
        ("base64-urlsafe", lambda t: t.replace("-", "+").replace("_", "/")),
    ):
        s = fix(text.strip())
        pad = (-len(s)) % 4
        if pad:
            s = s + "=" * pad
        try:
            raw = base64.b64decode(s, validate=False)
        except (binascii.Error, ValueError):
            continue
        dec = looks_like_text(raw)
        if dec:
            out.append((name, dec))
    return out


def try_base32(text):
    s = text.strip().upper()
    pad = (-len(s)) % 8
    if pad:
        s += "=" * pad
    try:
        raw = base64.b32decode(s)
    except (binascii.Error, ValueError):
        return []
    dec = looks_like_text(raw)
    return [("base32", dec)] if dec else []


def try_base58(text):
    """base58 没有标准库实现，手写一个（比特币字母表）。"""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for ch in text.strip():
        idx = alphabet.find(ch)
        if idx < 0:
            return []
        num = num * 58 + idx
    raw = b""
    while num > 0:
        raw = bytes([num & 0xFF]) + raw
        num >>= 8
    # 前导 '1' 代表前导零字节
    for ch in text.strip():
        if ch != "1":
            break
        raw = b"\x00" + raw
    dec = looks_like_text(raw)
    return [("base58", dec)] if dec else []


def try_hex(text):
    s = re.sub(r"0x|[\s:]", "", text.strip(), flags=re.I)
    if len(s) % 2:
        s = "0" + s
    try:
        raw = binascii.unhexlify(s)
    except (binascii.Error, ValueError):
        return []
    dec = looks_like_text(raw)
    return [("hex", dec)] if dec else []


def try_binary(text):
    bits = re.sub(r"\s", "", text.strip())
    if len(bits) % 8:
        return []
    raw = bytearray()
    for i in range(0, len(bits), 8):
        raw.append(int(bits[i:i + 8], 2))
    dec = looks_like_text(bytes(raw))
    return [("binary", dec)] if dec else []


def try_url(text):
    s = text.strip()
    if "%" not in s and "+" not in s:
        return []
    dec = urllib.parse.unquote_plus(s)
    return [("url", dec)] if dec != s and printable_ratio(dec) > 0.9 else []


def try_html_entity(text):
    import html as htmlmod
    s = text.strip()
    if "&" not in s:
        return []
    dec = htmlmod.unescape(s)
    return [("html-entity", dec)] if dec != s else []


def try_rot(text):
    """ROT-n 全扫一遍，返回可读性最高的几个。"""
    out = []
    letters = "abcdefghijklmnopqrstuvwxyz"
    for n in range(1, 26):
        table = str.maketrans(
            letters + letters.upper(),
            letters[n:] + letters[:n] + (letters[n:] + letters[:n]).upper(),
        )
        dec = text.translate(table)
        if printable_ratio(dec) >= 0.95:
            out.append((n, dec))
    # 按「像英文/像中文」粗排：出现 the/and/flag/ctf 之类加分
    def score(item):
        n, dec = item
        low = dec.lower()
        bonus = sum(3 for w in ("the", "and", "flag", "ctf", "is", "you") if w in low)
        return bonus

    out.sort(key=score, reverse=True)
    return [("rot%d" % n, d) for n, d in out[:3]]


def try_morse(text):
    s = text.strip()
    if not MORSE_RE.match(s):
        return []
    table = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6",
        "--...": "7", "---..": "8", "----.": "9",
    }
    words = re.split(r"\s{2,}|/", s.strip())
    parts = []
    for w in words:
        letters = [table.get(c, "?") for c in w.split()]
        parts.append("".join(letters))
    dec = " ".join(p for p in parts if p.strip())
    if dec and "?" not in dec:
        return [("morse", dec)]
    return []


def try_bacon(text):
    s = re.sub(r"\s", "", text.strip()).upper()
    if not BACON_RE.match(s):
        return []
    if len(s) % 5:
        return []
    out = []
    for i in range(0, len(s), 5):
        grp = s[i:i + 5]
        val = int(grp.replace("A", "0").replace("B", "1"), 2)
        out.append(chr(ord("A") + val) if val < 26 else "?")
    dec = "".join(out)
    return [("bacon", dec)] if "?" not in dec else []


def try_reverse(text):
    dec = text.strip()[::-1]
    if dec != text.strip() and printable_ratio(dec) > 0.95:
        return [("reverse", dec)]
    return []


# ---------------------------------------------------------------- 打分

def candidates(text):
    """返回 [(编码名, 解码结果, 置信度)]，按置信度降序。"""
    t = text.strip()
    if not t:
        return []

    found = []
    for fn in (try_base64, try_base32, try_base58, try_hex, try_binary,
               try_url, try_html_entity, try_morse, try_bacon, try_reverse):
        try:
            found.extend(fn(t))
        except Exception:  # noqa: BLE001  单个解码器炸了不影响其他
            continue

    # ROT 单独处理（返回多个候选）
    try:
        found.extend(try_rot(t))
    except Exception:  # noqa: BLE001
        pass

    scored = []
    for name, dec in found:
        if not dec or dec.strip() == t:
            continue
        conf = printable_ratio(dec)
        low = dec.lower()
        human = flag_like(dec) or any(w in low for w in ("the ", "http", "flag", "ctf"))
        cjk = cjk_plausible(dec)
        if human:
            conf = min(1.0, conf + 0.2)
        if cjk:
            conf = min(1.0, conf + 0.2)
        # 熵太高说明解出来还是乱码，扣分
        if entropy(dec) > 6.0:
            conf -= 0.3
        # reverse / rot 对任何输入都能给出「可打印」的结果，信噪比极低：
        # 除非解出来的东西像人话，否则不该排在 base64 这种强特征前面。
        if name.startswith("rot") or name == "reverse":
            if not (human or cjk):
                conf -= 0.45
        # 反过来：解出「生僻 CJK 乱码」说明这次解码基本是错的（典型是
        # 把 hex 串当 base64 解），不能因为「有中文」就加分。
        if dec_has_fake_cjk(dec):
            conf -= 0.5
        scored.append((name, dec, round(conf, 3)))

    scored.sort(key=lambda x: x[2], reverse=True)
    return scored


# ---------------------------------------------------------------- 多层链式

def chain_decode(text, max_depth=5):
    """每层取置信度最高的候选继续解，直到解不动或到达深度上限。

    注意：reverse / rot 这类「可逆但会来回震荡」的变换不能连着用两次——
    reverse(reverse(x)) == x，会陷入 A->B->A->B 的死循环。所以记录已经用过的
    变换名，同一个变换不重复施加。
    """
    path = []
    cur = text.strip()
    used = set()
    for _ in range(max_depth):
        cands = [c for c in candidates(cur) if c[0] not in used]
        if not cands:
            break
        best = cands[0]
        if best[2] < 0.85:          # 置信度太低就别硬解了，避免越解越乱
            break
        if best[1].strip() == cur:
            break
        path.append(best)
        used.add(best[0])
        cur = best[1].strip()
    return path, cur


# ---------------------------------------------------------------- 入口

def read_input(args):
    if args.text:
        return args.text.strip()
    if args.file:
        # utf-8-sig 会吃掉 BOM。Windows 上 Set-Content -Encoding UTF8 / 记事本
        # 存出来的文件都带 BOM，而 BOM 会让 base64/hex 的正则判定直接失败。
        with open(args.file, "r", encoding="utf-8-sig", errors="replace") as fh:
            return fh.read().strip()
    # 从标准输入读（支持管道）
    if not sys.stdin.isatty():
        return sys.stdin.read().strip().lstrip("\ufeff")
    return ""


def main():
    ap = argparse.ArgumentParser(
        description="编码识别器：列出候选编码并尝试解码",
        add_help=True,
    )
    ap.add_argument("text", nargs="?", help="直接给要分析的字符串")
    ap.add_argument("-f", "--file", help="从文件读取")
    ap.add_argument("--deep", action="store_true", help="只做多层链式解码")
    ap.add_argument("--top", type=int, default=5, help="显示前 N 个候选（默认 5）")
    args = ap.parse_args()

    text = read_input(args)
    # 无论来自参数、文件还是管道，统一剥掉 BOM 与零宽字符：
    # 它们肉眼看不见，却会让 base64/hex/morse 的字符集判定全部落空。
    text = text.lstrip("\ufeff").replace("\u200b", "").strip()
    if not text:
        ap.print_help()
        print("")
        print("例子：")
        print('  python -X utf8 encscan.py "SGVsbG8="')
        print("  python -X utf8 encscan.py -f 密文.txt")
        return 0

    # 基本信息
    print("输入长度: %d 字符" % len(text))
    print("香农熵  : %.3f  (>6.5 多半是压缩/加密数据)" % entropy(text))
    print("")

    if not args.deep:
        cands = candidates(text)
        if not cands:
            print("没有识别出已知的单层编码。")
            print("建议：确认是否被裁剪/换行破坏，或用 cyberchef 的 Magic。")
        else:
            print("== 单层解码候选（按可信度排序）==")
            for i, (name, dec, conf) in enumerate(cands[:args.top], 1):
                show = dec if len(dec) <= 200 else dec[:200] + "..."
                print("%d. [%s] 置信度 %.2f" % (i, name, conf))
                print("   %s" % show.replace("\n", "\\n"))
        print("")

    # 链式
    path, final = chain_decode(text)
    if path:
        print("== 多层链式解码 ==")
        print(" -> ".join([p[0] for p in path]))
        print("最终结果：")
        print(final)
    else:
        print("== 多层链式解码 ==")
        print("没有找到可串联的解码路径（可能第一层就不是这些编码）。")

    return 0


if __name__ == "__main__":
    sys.exit(main())
