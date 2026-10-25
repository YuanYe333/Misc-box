#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""hashcrack.py —— 哈希识别与爆破（纯标准库，Python 3.9+）

用途：CTF 里最常见的一步——拿到一串 32/40/64/128 位十六进制，先判断
它是什么算法，再拿字典或掩码把它撞出来。

设计原则：
  * 只做**离线**爆破，不联网、不上传、不查询彩虹表服务；
  * 先「识别」再「爆破」，识别不确定时明确说「不确定」而不是瞎猜；
  * 内置一份小而精的弱口令表，保证离线可用；也可外接字典；
  * 掩码爆破有硬上限，防止手滑跑成几个小时的活。

用法示例：
    python -X utf8 hashcrack.py 5f4dcc3b5aa765d61d8327deb882cf99
    python -X utf8 hashcrack.py <hash> -w rockyou.txt
    python -X utf8 hashcrack.py <hash> --mask 'flag{?l?l?d?d}'
    python -X utf8 hashcrack.py <hash> --wordlist-builtin
    python -X utf8 hashcrack.py --identify <hash>
"""

import argparse
import hashlib
import hmac
import itertools
import os
import re
import struct
import sys
import time

VERSION = "1.0"

# ====================================================================
# 哈希识别
# ====================================================================

# 常见哈希的「长度 -> 候选算法」映射。长度相同就靠其它线索区分，
# 不能只凭长度下结论——这一点在输出里必须讲清楚。
BY_LEN = {
    32: ["MD5", "NTLM", "MD4", "LM(后半)", "MD5(HMAC)"],
    40: ["SHA1", "MySQL5(旧)", "RIPEMD160"],
    56: ["SHA224"],
    64: ["SHA256", "SHA3-256", "BLAKE2s-256", "Keccak-256"],
    80: ["SHA384(部分)", "RIPEMD320"],
    96: ["SHA384"],
    128: ["SHA512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}

# 有明确特征的格式
PATTERNS = [
    (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "Argon2"),
    (re.compile(r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$"), "MD5-crypt"),
    (re.compile(r"^\$5\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$"), "SHA256-crypt"),
    (re.compile(r"^\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$"), "SHA512-crypt"),
    (re.compile(r"^\$pbkdf2-sha256\$"), "PBKDF2-SHA256"),
    (re.compile(r"^\{SSHA\}", re.I), "SSHA (LDAP)"),
    (re.compile(r"^0x[0-9a-f]{32}$", re.I), "NTLM (带 0x 前缀)"),
    (re.compile(r"^[A-Za-z0-9+/]{27}=$"), "LM (Base64 形态，非 hex)"),
]


def identify(text):
    """识别哈希类型。返回 (候选列表, 说明)。"""
    s = text.strip()
    notes = []

    for pat, name in PATTERNS:
        if pat.match(s):
            return [name], "按格式特征匹配（长度/分隔符/前缀都符合 %s）" % name

    body = s[2:] if s.lower().startswith("0x") else s
    if not re.match(r"^[0-9a-fA-F]+$", body):
        return [], "不是十六进制串，也不是已知的带前缀格式"

    n = len(body)
    cands = list(BY_LEN.get(n, []))
    if not cands:
        return [], "十六进制长度 %d 不是常见哈希长度（32/40/56/64/96/128）" % n

    # 长度 32：MD5 与 NTLM 无法靠长度区分，补一条判据
    if n == 32:
        notes.append("32 位 hex 无法只凭长度区分 MD5 / NTLM / MD4，"
                     "通常先按 MD5 试；若来源是 Windows 账户库则可能是 NTLM。")
    if n == 40:
        notes.append("40 位 hex 最常见是 SHA1；MySQL5 旧格式也常是 40 位，"
                     "但 MySQL5 实际是 *+40 位，见到 * 开头即可确认。")
    if n == 64:
        notes.append("64 位 hex 可能是 SHA256 / SHA3-256 / Keccak-256，"
                     "三者对同一输入的输出不同，需用已知明文试算确认。")
    if n == 128:
        notes.append("128 位 hex 通常是 SHA512；Whirlpool 也是 128 位但较少见。")

    # 全数字的 32 位更可能是 MD5 的巧合，也可能是 CRC 类，提示一下
    if n == 32 and body.isdigit():
        notes.append("这串恰好全是数字，别急着当 MD5——也可能是十进制大数或 ID。")

    return cands, "；".join(notes) if notes else "按长度匹配"


# ====================================================================
# 哈希计算（支持多算法）
# ====================================================================

def hash_hex(algo, text_bytes):
    """按算法名算十六进制摘要。text_bytes 是 bytes。"""
    a = algo.upper()
    if a == "MD5":
        return hashlib.md5(text_bytes).hexdigest()
    if a == "MD4":
        return _md4(text_bytes).hex()
    if a == "NTLM":
        # NTLM = MD4(UTF-16LE(密码))
        try:
            u = text_bytes.decode("utf-8").encode("utf-16-le")
        except UnicodeDecodeError:
            u = text_bytes.decode("latin-1").encode("utf-16-le")
        return _md4(u).hex()
    if a in ("SHA1", "SHA-1"):
        return hashlib.sha1(text_bytes).hexdigest()
    if a in ("SHA224", "SHA-224"):
        return hashlib.sha224(text_bytes).hexdigest()
    if a in ("SHA256", "SHA-256"):
        return hashlib.sha256(text_bytes).hexdigest()
    if a in ("SHA384", "SHA-384"):
        return hashlib.sha384(text_bytes).hexdigest()
    if a in ("SHA512", "SHA-512"):
        return hashlib.sha512(text_bytes).hexdigest()
    if a in ("SHA3-256", "SHA3256"):
        return hashlib.sha3_256(text_bytes).hexdigest()
    if a in ("SHA3-512", "SHA3512"):
        return hashlib.sha3_512(text_bytes).hexdigest()
    if a == "RIPEMD160":
        try:
            return hashlib.new("ripemd160", text_bytes).hexdigest()
        except (ValueError, TypeError):
            raise ValueError("当前 Python 的 OpenSSL 不支持 ripemd160")
    raise ValueError("不支持的算法：%s" % algo)


# ---- MD4（NTLM 需要；标准库没有）------------------------------------
def _md4(msg):
    """纯 Python MD4，返回 bytes(16)。仅用于 NTLM 支持。"""
    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", ml & 0xFFFFFFFFFFFFFFFF)

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def rol(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    for off in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d = h
        # round 1
        for i in range(16):
            k = i
            s = [3, 7, 11, 19][i % 4]
            if i % 4 == 0:
                a = rol(a + ((b & c) | (~b & d)) + x[k], s)
            elif i % 4 == 1:
                d = rol(d + ((a & b) | (~a & c)) + x[k], s)
            elif i % 4 == 2:
                c = rol(c + ((d & a) | (~d & b)) + x[k], s)
            else:
                b = rol(b + ((c & d) | (~c & a)) + x[k], s)
        # round 2
        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            s = [3, 5, 9, 13][i % 4]
            if i % 4 == 0:
                a = rol(a + ((b & c) | (b & d) | (c & d)) + x[k] + 0x5A827999, s)
            elif i % 4 == 1:
                d = rol(d + ((a & b) | (a & c) | (b & c)) + x[k] + 0x5A827999, s)
            elif i % 4 == 2:
                c = rol(c + ((d & a) | (d & b) | (a & b)) + x[k] + 0x5A827999, s)
            else:
                b = rol(b + ((c & d) | (c & a) | (d & a)) + x[k] + 0x5A827999, s)
        # round 3
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            s = [3, 9, 11, 15][i % 4]
            if i % 4 == 0:
                a = rol(a + (b ^ c ^ d) + x[k] + 0x6ED9EBA1, s)
            elif i % 4 == 1:
                d = rol(d + (a ^ b ^ c) + x[k] + 0x6ED9EBA1, s)
            elif i % 4 == 2:
                c = rol(c + (d ^ a ^ b) + x[k] + 0x6ED9EBA1, s)
            else:
                b = rol(b + (c ^ d ^ a) + x[k] + 0x6ED9EBA1, s)

        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF

    return struct.pack("<4I", *h)


# ====================================================================
# 内置弱口令表
# ====================================================================

BUILTIN = """
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon
123123 baseball abc123 football monkey letmein 696969 shadow master 666666
qwertyuiop 123321 mustang 1234567890 michael 654321 pussy superman 1qaz2wsx
7777777 fuckyou 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer
zxcvbnm asdfgh hunter buster soccer harley batman andrew tiger sunshine
iloveyou 2000 charlie robert thomas hockey ranger daniel starwars klaster
112233 george computer michelle jessica pepper 1111 zxcvbn 555555 11111111
131313 freedom 777777 pass maggie 159753 aaaaaa ginger princess joshua cheese
amanda summer love ashley 6969 nicole chelsea biteme matthew access yankees
987654321 dallas austin thunder taylor matrix william corvette hello martin
heather secret fucker merlin diamond 1234qwer gfhjkm hammer silver 222222
88888888 anthony justin test bailey q1w2e3r4t5 patrick internet scooter orange
11111 golfer cookie richard samantha bigdog guitar jackson whatever mickey
chicken sparky snoopy maverick phoenix camaro sexy peanut morgan welcome
falcon cowboy ferrari samsung andrea smokey steelers joseph mercedes dakota
arsenal eagles melissa boomer booboo spider nascar monster tigers yellow
xxxxxx 123123123 gateway marina diablo bulldog qwer1234 compaq purple hardcore
banana junebug trucker 123456789a 1234567890q 1234567890a qwerty123
flag ctf key secret hidden password admin root toor test guest user
letmein123 P@ssw0rd Passw0rd admin123 root123 test123 flag123 ctf123
qwertyui password1 password123 abc12345 1q2w3e4r 1qaz2wsx3edc zaq12wsx
sunshine1 iloveyou1 princess1 football1 baseball1 shadow1 master1
""".split()

# 常用掩码字符集
MASK_SETS = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "s": "!@#$%^&*()-_=+[]{};:,.<>/?",
    "a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "b": "abcdefghijklmnopqrstuvwxyz0123456789",
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
    "x": "0123456789abcdefABCDEF",
}

# 掩码爆破上限：超过这个组合数就拒绝，避免手滑跑几小时
MASK_LIMIT = 5000000


def mask_space(mask):
    """算出掩码的总组合数与字符集列表。未知字符抛错。"""
    sets = []
    literal = 0
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?":
            i += 1
            if i >= len(mask):
                raise ValueError("掩码结尾多了一个 '?'，缺少字符集代码")
            code = mask[i]
            if code == "?":
                sets.append("?")
            elif code in MASK_SETS:
                sets.append(MASK_SETS[code])
            else:
                raise ValueError("未知掩码代码 '?%s'（可用：%s）"
                                 % (code, "".join(sorted(MASK_SETS))))
            i += 1
        else:
            sets.append(ch)
            literal += 1
            i += 1
    total = 1
    for s in sets:
        total *= len(s)
    return total, sets


# ====================================================================
# 爆破
# ====================================================================

def try_candidate(target, cand, algos, lower_target):
    """试一个候选，返回命中的 (algo, cand) 或 None。"""
    b = cand.encode("utf-8", "surrogateescape")
    for algo in algos:
        try:
            if hash_hex(algo, b) == lower_target:
                return algo
        except ValueError:
            continue
    return None


def crack_dict(target, algos, words, lower_target, limit=None):
    """按字典顺序试。返回 (命中算法, 明文) 或 None。"""
    n = 0
    for w in words:
        w = w.strip("\r\n")
        if not w:
            continue
        n += 1
        if limit is not None and n > limit:
            break
        hit = try_candidate(target, w, algos, lower_target)
        if hit:
            return hit, w
    return None


def crack_mask(target, algos, mask, lower_target, verbose=False):
    """按掩码穷举。返回 (命中算法, 明文, 尝试次数) 或 (None, None, 次数)。"""
    total, sets = mask_space(mask)
    if total > MASK_LIMIT:
        raise ValueError(
            "掩码组合数 %d 超过上限 %d，请收窄范围（例如少用 ?a，"
            "或用 ?l?d 代替）" % (total, MASK_LIMIT))
    tried = 0
    t0 = time.time()
    for combo in itertools.product(*sets):
        cand = "".join(combo)
        tried += 1
        hit = try_candidate(target, cand, algos, lower_target)
        if hit:
            return hit, cand, tried
        if verbose and tried % 100000 == 0:
            rate = tried / max(time.time() - t0, 1e-9)
            sys.stderr.write("  已试 %d / %d（%.0f/s）\r"
                             % (tried, total, rate))
    return None, None, tried


# ====================================================================
# 输出
# ====================================================================

def build_usage():
    return """用法：python -X utf8 hashcrack.py <哈希> [选项]

做什么：先识别哈希类型，再用字典/掩码把它撞出来。全程离线。

识别：
  python -X utf8 hashcrack.py 5f4dcc3b5aa765d61d8327deb882cf99
  python -X utf8 hashcrack.py --identify '$2b$12$abcdefghijklmnopqrstuv'

爆破：
  python -X utf8 hashcrack.py <hash> --builtin          用内置弱口令表
  python -X utf8 hashcrack.py <hash> -w rockyou.txt     用外部字典
  python -X utf8 hashcrack.py <hash> --mask 'flag{?l?d}'  掩码穷举

选项：
  -w, --wordlist 文件   字典文件（每行一个候选）
  --builtin             使用内置弱口令表（约 300 条常用口令）
  --mask 掩码           掩码穷举，?l=小写 ?u=大写 ?d=数字 ?a=全部
  --algo 名称           只按指定算法试（默认用识别出的全部候选）
  --limit N             字典最多试 N 条
  --identify            只识别不爆破
  --list-algos          列出支持的算法

注意：
  * 掩码组合数上限 500 万，超过会拒绝执行，避免跑成几小时；
  * bcrypt / Argon2 / *-crypt 等慢哈希不支持爆破（只识别）；
  * 32 位 hex 无法只凭长度区分 MD5/NTLM/MD4，默认都试。
"""


def main(argv=None):
    ap = argparse.ArgumentParser(add_help=True, description="哈希识别与爆破")
    ap.add_argument("hash", nargs="?", help="待处理的哈希值")
    ap.add_argument("-w", "--wordlist", help="字典文件路径")
    ap.add_argument("--builtin", action="store_true", help="用内置弱口令表")
    ap.add_argument("--mask", help="掩码穷举，如 'flag{?l?l?d?d}'")
    ap.add_argument("--algo", help="只按指定算法试")
    ap.add_argument("--limit", type=int, help="字典最多试多少条")
    ap.add_argument("--identify", action="store_true", help="只识别不爆破")
    ap.add_argument("--list-algos", action="store_true", help="列出支持的算法")
    ap.add_argument("--quiet", action="store_true", help="只输出结果")
    args = ap.parse_args(argv)

    if args.list_algos:
        print("支持的算法（可爆破）：")
        for a in ("MD5", "MD4", "NTLM", "SHA1", "SHA224", "SHA256",
                  "SHA384", "SHA512", "SHA3-256", "SHA3-512", "RIPEMD160"):
            print("  %s" % a)
        print("")
        print("只识别不爆破：bcrypt / Argon2 / MD5-crypt / SHA256-crypt /")
        print("             SHA512-crypt / PBKDF2 / SSHA / LM")
        return 0

    if not args.hash:
        print(build_usage())
        return 0

    target = args.hash.strip()
    cands, note = identify(target)

    if not args.quiet:
        print("=" * 66)
        print("输入: %s" % target)
        print("长度: %d 字符" % len(target))
        if cands:
            print("识别: %s" % " / ".join(cands))
            print("判据: %s" % note)
        else:
            print("识别: 无法确定（%s）" % note)
        print("=" * 66)

    if args.identify:
        return 0 if cands else 1

    if not cands:
        print("")
        print("既然认不出类型，就不硬猜了。请确认这串是不是哈希，")
        print("或直接用 --algo 指定算法重试。")
        return 1

    # 慢哈希只识别，不爆破
    slow = {"bcrypt", "Argon2", "MD5-crypt", "SHA256-crypt", "SHA512-crypt",
            "PBKDF2-SHA256", "SSHA (LDAP)"}
    if set(cands) & slow:
        print("")
        print("%s 是慢哈希（设计上就是为了拖慢爆破），本工具只做识别。" % cands[0])
        print("这类哈希请用 hashcat / john 配合字典与 GPU。")
        return 0

    algos = [args.algo] if args.algo else cands
    lower_target = target.lower()
    if lower_target.startswith("0x"):
        lower_target = lower_target[2:]

    found = None
    t0 = time.time()

    # 字典
    words = []
    if args.builtin:
        words.extend(BUILTIN)
    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            print("错误：字典文件不存在 —— %s" % args.wordlist, file=sys.stderr)
            return 1
        try:
            import io as _io
            with _io.open(args.wordlist, "r", encoding="utf-8",
                          errors="ignore") as fh:
                words.extend(line.rstrip("\r\n") for line in fh)
        except OSError as exc:
            print("错误：读不了字典 —— %s" % exc, file=sys.stderr)
            return 1

    if words:
        if not args.quiet:
            print("")
            print("== 字典爆破（%d 条候选，算法 %s）=="
                  % (len(words), "/".join(algos)))
        found = crack_dict(target, algos, words, lower_target, args.limit)

    # 掩码
    if found is None and args.mask:
        try:
            total, _sets = mask_space(args.mask)
        except ValueError as exc:
            print("错误：%s" % exc, file=sys.stderr)
            return 1
        if not args.quiet:
            print("")
            print("== 掩码爆破（%s，共 %d 组合）==" % (args.mask, total))
        try:
            algo, cand, tried = crack_mask(target, algos, args.mask,
                                           lower_target, verbose=not args.quiet)
        except ValueError as exc:
            print("错误：%s" % exc, file=sys.stderr)
            return 1
        if cand is not None:
            found = (algo, cand)
        if not args.quiet:
            print("  尝试 %d 次，用时 %.2f 秒" % (tried, time.time() - t0))

    if not words and not args.mask:
        print("")
        print("识别完成，但没有给爆破方式。加 --builtin / -w 字典 / --mask 试试。")
        return 0

    print("")
    if found:
        algo, cand = found
        print("=" * 66)
        print("命中！算法 %s" % algo)
        print("明文：%s" % cand)
        print("=" * 66)
        return 0

    print("=" * 66)
    print("没撞出来。")
    print("  已试算法：%s" % "/".join(algos))
    if args.limit:
        print("  字典上限 %d 条（--limit 限制）" % args.limit)
    print("  建议：换更大的字典（rockyou.txt）、扩大掩码、或用 hashcat。")
    print("=" * 66)
    return 1


if __name__ == "__main__":
    sys.exit(main())
