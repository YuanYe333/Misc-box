# -*- coding: utf-8 -*-
"""
xor.py -- XOR 分析器：单字节爆破、多字节频率分析、已知明文攻击。

为什么需要
==========
CTF 里最常被低估的密码就是 XOR。看起来简单，实际有三个坑：
  1. 单字节 XOR 爆破出来 256 个结果，**哪个是对的**？必须有靠谱的打分器，
     否则「flag」就埋在一堆乱码里没人看见；
  2. 多字节 XOR 的密钥长度怎么定？靠汉明距离（经典方法），但短文本会失效；
  3. 明文的格式往往是已知的（flag{、PNG 头、<?php），这时候**已知明文
     攻击**比盲猜快得多——直接把密钥异或出来。

本脚本把这三件事都做了，并且对中文做了单独的打分（中文 XOR 后常见的
是 GBK/UTF-8 字节，不是纯 ASCII，只按英文打分会把正确答案排到几十名之后）。

用法
====
    python -X utf8 xor.py "1b1b1b1b1b1b"                # 自动：先当 hex，再当文本
    python -X utf8 xor.py -f 密文.bin                   # 二进制文件
    python -X utf8 xor.py -f 密文.bin --keylen 8        # 指定密钥长度
    python -X utf8 xor.py -f 密文.bin --key "abcd"      # 已知密钥解密
    python -X utf8 xor.py -f 密文.bin --known-plaintext "flag{"   # 已知明文
    python -X utf8 xor.py -f 密文.bin --top 20          # 多看几个候选

已知限制
========
    * 打分器是启发式的，短于 8 字节的密文基本无法可靠排序；
    * 多字节密钥长度推测在明文短于 32 字节时很不准，建议手动 --keylen；
    * 已知明文攻击要求给出的明文片段出现在**开头**（脚本按开头对齐）。
"""

import argparse
import binascii
import random
import re
import sys

# ====================================================================
# 打分器
# ====================================================================

# 英文字母频率（A=0..Z=25），来源是通用英语语料统计
EN_FREQ = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
]

# CTF 常见关键词，命中加分（这是「领域知识」而不是作弊）
CTF_WORDS = [
    b"flag", b"ctf", b"key", b"pass", b"admin", b"root", b"secret",
    b"the", b"and", b"you", b"this", b"that", b"with", b"http", b"www",
    b"<?php", b"<html", b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff",
]


# 常用汉字表（GB2312 一级字库，3755 个最常用汉字）。
# 用途：判断 GBK 解出来的汉字「像不像真中文」。
# 随机二进制经 gb18030 双字节区解码几乎必然得到一串合法汉字，但多是
# 生僻字（驺羯稞铙孢玢赃砣絷铒涮…）。真实中文里 99% 以上是 GB2312 一级字。
# 这里不硬编码 3755 个字（太长且易错），而是用「区码范围」判断：
# GB2312 一级汉字位于 16-55 区，二级汉字位于 56-87 区，一级字就是常用字。
def _build_common_hanzi():
    """构造 GB2312 一级汉字（16-55 区）的字符集合。"""
    chars = set()
    for qu in range(16, 56):            # 一级汉字：16~55 区
        for wei in range(1, 95):        # 位 1~94
            try:
                ch = bytes([qu + 0xA0, wei + 0xA0]).decode("gb2312")
            except UnicodeDecodeError:
                continue
            chars.add(ch)
    return frozenset(chars)


COMMON_HANZI = _build_common_hanzi()


# 没有它的话，打分器分不清 "the quick" 和 "xhe quzck" —— 两者可打印率、
# 字母频率几乎一样，只有「是不是真词」能区分开。
EN_WORDS = frozenset("""
a about after again all also am an and any are as at back be because been
before being between both but by can come could did do does doing down each
even every few find first for from get give go going good got great had has
have he her here him his how if in into is it its just know like look made
make many may me might more most much must my need never new no not now of
off on once one only or other our out over own put said same say see should
since so some still such take than that the their them then there these they
thing think this those through time to too two under up use very want was
way we well were what when where which while who why will with would year
you your flag ctf key secret hidden password admin root text message file
open read write data test true false null zero byte bytes string char
multi xor cipher plain ciphertext encrypt decrypt base hex bin encode
decode length column column keylen mode mask shift rotate reverse
""".split())

# 常用英文三元组（比二元组更有区分度）
EN_TRIGRAMS = [
    b"the", b"and", b"ing", b"her", b"hat", b"his", b"tha", b"ere", b"for",
    b"ent", b"ion", b"ter", b"was", b"you", b"ith", b"ver", b"all", b"wit",
    b"thi", b"tio", b"nde", b"has", b"men", b"sta", b"not", b"are", b"but",
]


def word_score(data):
    """统计「切出来的词有多大比例是常见英文词」。

    这是整个打分器里最有区分度的一项：错一个字节往往会把好几个词变成
    非词，而可打印率和字母频率几乎不变。

    实现上必须按**词数比例**给分，且真词加分要明显大于非词扣分：
    早期版本用 good/total*60 - bad/total*40，正确明文里
    flag/multi/byte/xor 这些都不在我的词表里，导致 good 比例很低、
    和乱码一样被压到 -40 的下限，完全失去区分度。现在：
      * 命中的词 +10，未命中 -3（非词扣得轻，避免专有名词/变量名被罚死）；
      * 最后按词数归一化，返回 -3~+10 区间的平均值。
    """
    low = bytes(b | 0x20 if 65 <= b <= 90 else b for b in data)
    # 只按非字母切分（数字/符号/中文都算分隔符）
    words = re.split(rb"[^a-z]+", low)
    words = [w for w in words if len(w) >= 2]
    if not words:
        return 0.0
    total = 0.0
    for w in words:
        # 注意：EN_WORDS 存的是 str，切出来的是 bytes，必须解码后再比。
        # 早期版本直接 `w in EN_WORDS`，bytes 与 str 永不相等，导致
        # 词表形同虚设、所有明文都只拿非词惩罚（实测恒为 -26）。
        word = w.decode("latin-1")
        if word in EN_WORDS:
            total += 10.0
        elif len(word) <= 2:
            total -= 1.0          # 两字母的碎片多半是切分噪声，轻罚
        else:
            total -= 3.0
    return total / float(len(words)) * 10.0


def score_english(data):
    """给一段字节打「像不像英文/代码」的分。越高越像。"""
    if not data:
        return -1e9
    score = 0.0
    n = float(len(data))

    # 1) 可打印字符占比（重要，但权重不能压倒一切：错一两个字节也能
    #    保持 95% 可打印，所以真正的区分靠后面的词表）
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    score += (printable / n) * 60.0

    # 2) 字母频率卡方：只统计字母，避免空格标点干扰
    letters = [b for b in data if 65 <= b <= 90 or 97 <= b <= 122]
    if letters:
        counts = [0] * 26
        for b in letters:
            counts[(b | 0x20) - 97] += 1
        total = float(len(letters))
        chi = 0.0
        for i in range(26):
            expect = EN_FREQ[i] / 100.0 * total
            obs = counts[i]
            if expect > 0:
                chi += (obs - expect) ** 2 / expect
        score += 30.0 / (1.0 + chi / max(total, 1.0) * 2.0)

    low = data.lower()

    # 3) 词表命中率（最强信号，已带非词惩罚）
    score += word_score(data)

    # 4) 常见三元组（二元组太容易偶然命中，权重压低；三元组保留）
    for tg in EN_TRIGRAMS:
        score += low.count(tg) * 2.0

    # 5) 空格频率（英文里约 13%）
    score += 6.0 * (1.0 - abs(data.count(0x20) / n - 0.13) / 0.13)

    # 6) CTF 关键词
    for w in CTF_WORDS:
        if w in data or w in low:
            score += 30.0

    # 7) 惩罚：控制字符（除常见空白）
    ctrl = sum(1 for b in data if b < 32 and b not in (9, 10, 13))
    score -= ctrl * 6.0

    return score


def score_chinese(data):
    """给一段字节打「像不像 UTF-8 / GBK 中文」的分。

    中文 XOR 后常见的是 UTF-8（3 字节一组 E4-E9 开头）或 GBK（两字节
    高位都在 0x81-0xFE）。只看「能不能按中文解出来 + 有没有乱码」。

    注意：这里绝不能对「解出零星 CJK 的随机字节」给高分。早期版本用
    decode(errors="replace") 数替换符，随机二进制里偶尔冒出几个 CJK
    就能拿 60 分，结果在爬山时压过真正的英文明文，把密钥带沟里。
    现在只有「严格解码成功」才算数，且必须满足最低 CJK 数量。

    GBK 还有个更隐蔽的陷阱：gb18030 的双字节区几乎覆盖所有高位字节，
    任意二进制都能「成功解码」成一串汉字——实测 12 字节随机数据解出
    「驺戌羯稞铙孢玢赃砣絷铒涮」，可打印率 100%，白拿 76 分。所以
    GBK 路径必须再要求「这些字是常用字」，生僻字占多数的一律不给分。
    """
    if not data:
        return -1e9
    best = 0.0

    # UTF-8：必须严格解码成功，且 CJK 占一定比例
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        ratio = printable / float(len(text) or 1)
        # 至少要 2 个汉字，且可打印率 ≥ 0.95，才认为「这是中文」
        if ratio >= 0.95 and cjk >= 2:
            best = max(best, 60.0 + min(cjk * 4.0, 60.0))

    # GBK / GB18030：同样要求严格解码 + 汉字数量，外加常用字比例
    try:
        text = data.decode("gb18030")
    except (UnicodeDecodeError, LookupError):
        text = None
    if text is not None:
        cjk_chars = [ch for ch in text if "\u4e00" <= ch <= "\u9fff"]
        cjk = len(cjk_chars)
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        if printable / float(len(text) or 1) >= 0.95 and cjk >= 2:
            # 常用字占比：随机字节解出的多是生僻字（驺羯稞铙…），
            # 真实中文几乎全是常用字。占比低于 0.6 直接判为噪声。
            common = sum(1 for ch in cjk_chars if ch in COMMON_HANZI)
            ratio_common = common / float(cjk)
            if ratio_common >= 0.6:
                best = max(best, 40.0 + min(cjk * 3.0, 50.0) * ratio_common)

    return best


def score(data):
    """综合打分：取英文与中文里的较高者。"""
    return max(score_english(data), score_chinese(data))


def score_frequency(data):
    """纯频率打分：只比字母分布和空格比例，不看「读起来顺不顺」。

    **这是逐列爆破专用的打分器，不要换成 score()。**

    为什么必须分开：多字节 XOR 逐列求解时，每一列拿到的是「被抽取的
    第 i 个字符」——英文原文每 3 个取 1 个，结果像
    "T i o xusv ea gTseeeoasvyeeot"，完全不成词，词表打分器会把它
    判成乱码，而把某些碰巧成词的错误密钥排在前面（实测正确密钥排到
    第 3、8、20 名，逐列解出来全是错的）。

    但**频率分布是保留的**：抽样不改变各字母出现的比例。所以逐列
    求解只该用卡方 + 空格频率，这才是经典频率分析该有的样子。
    """
    if not data:
        return -1e9
    n = float(len(data))

    # 字母频率卡方（越小越好）。抽样后字母分布仍近似英文，这一项最可靠。
    letters = [b for b in data if 65 <= b <= 90 or 97 <= b <= 122]
    if letters:
        counts = [0] * 26
        for b in letters:
            counts[(b | 0x20) - 97] += 1
        total = float(len(letters))
        chi = 0.0
        for i in range(26):
            expect = EN_FREQ[i] / 100.0 * total
            if expect > 0:
                chi += (counts[i] - expect) ** 2 / expect
        chi = chi / total
    else:
        chi = 1e6                    # 一个字母都没有，肯定不对

    # 空格比例：英文约 13%，抽样后仍然成立
    space_pen = abs(data.count(0x20) / n - 0.13)

    # 可打印率只作为「不要解出二进制」的门槛，权重很低
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    nonprint = 1.0 - printable / n

    return -(chi * 40.0) - (space_pen * 100.0) - (nonprint * 60.0)


# CTF 里明文的强结构特征：flag{...} / ctf{...} 等。
# 这是整段才能看到的信号，逐列打分完全看不到，但对 CTF 是最可靠的判据。
FLAG_PATTERNS = (
    b"flag{", b"FLAG{", b"ctf{", b"CTF{", b"flag_", b"key{", b"KEY{",
)
FLAG_TAIL = (b"}", b"}\n", b"}\r\n")


def prefix_seeds(data, klen):
    """用「明文很可能是 flag{...}」反推密钥种子。

    这是短样本破解最有效的一招。原理：若明文以 b"flag{" 开头，
    则密钥前 5 字节 = 密文前 5 字节 XOR b"flag{"。把这段已知前缀
    按周期填进整个密钥，就能得到一个极好的种子。

    为什么必须有：逐字节爬山在短样本上会卡死——实测密钥 b"KEY"、
    24 字节密文，单独换任何一个密钥字节都会**降低**整段得分
    （三个字节必须同时正确才能凑出 flag{...}），逐字节贪心永远
    走不到那个盆地。而前缀反推一步就能拿到全部 3 个字节。
    """
    seeds = []
    for pat in (b"flag{", b"ctf{", b"FLAG{", b"CTF{"):
        if len(data) < len(pat):
            continue
        frag = bytes(data[i] ^ pat[i] for i in range(len(pat)))
        # 按密钥长度循环填满
        seed = bytes(frag[i % len(frag)] for i in range(klen))
        seeds.append(seed)
        # 只用片段里真正对齐 klen 的部分（当 len(pat) >= klen 时最准）
        if len(frag) >= klen:
            seeds.append(frag[:klen])
    return seeds


def flag_bonus(data):
    """整段明文的 CTF 结构加分：以 flag{ 之类开头、以 } 结尾。

    为什么必须有这一项：XOR 密钥逐列破解时，每列只有几个字节，
    正确密钥字节常常连前 5 名都排不进（实测密钥 KEY、24 字节密文，
    每列仅 8 字节，正确字节 0x4B/0x45/0x59 全部落榜）。但整段明文
    的 flag{} 结构是确定的强信号——只要猜到完整密钥就能看到它。

    判据必须严格：加分只给「开头就是 flag{ 且结尾是 }」的**完整结构**。
    早期版本对「任意位置含 key{」也给 120 分，结果长度 12 的假明文
    'etherkey{sandtl]kj~n{oc}' 靠这个白拿高分，压过了真正的
    'flag{xor_single_byte_ok}'。宁可不加分，也不能给错方向。

    另外「flag{」比「ctf{」更常见，给更高分；正文必须是**干净可打印**
    的（flag 内部一般是 [A-Za-z0-9_!?-] 一类），出现控制字符或乱码
    说明这只是碰巧凑出的括号，不给满分。
    """
    if not data:
        return 0.0
    body = data.rstrip(b"\r\n")
    if not body.endswith(b"}"):
        # 没有收尾括号，最多算半个结构
        for pat in FLAG_PATTERNS:
            if body.startswith(pat):
                return 100.0
        return 0.0

    matched = None
    for pat in FLAG_PATTERNS:
        if body.startswith(pat):
            matched = pat
            break
    if matched is None:
        return 0.0

    # 正文干净度：flag{...} 里通常是可打印的 ASCII 词，没有控制字符。
    # 只数「可打印」不够——'xanDsingleQ~bte_ok' 也全是可打印的，
    # 但它有 ~ 这类在 flag 里罕见的符号、还有大小写混排的怪词。
    # 这里用「字母数字下划线连字符」的比例作为干净度，更严格。
    inner = body[len(matched):-1]
    if not inner:
        return 300.0
    good = sum(1 for b in inner
               if 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122
               or b in (0x5F, 0x2D))          # 0-9 A-Z a-z _ -
    clean_ratio = good / float(len(inner))

    base = 600.0 if matched.lower() == b"flag{" else 450.0
    if matched.lower() == b"flag_":
        base = 400.0
    # 干净度不足时按比例扣（乱码凑出来的括号拿不到满分）
    return base * clean_ratio


def score_with_flag(data):
    """带 CTF 结构加分的综合打分（供爬山与排序使用）。"""
    return score(data) + flag_bonus(data)


# ====================================================================
# 单字节爆破
# ====================================================================

def xor_single(data, key):
    return bytes(b ^ key for b in data)


def brute_single(data, top=10):
    """0x00~0xFF 全试一遍，按分数排序返回前 top 个。"""
    results = []
    for k in range(256):
        dec = xor_single(data, k)
        results.append((score(dec), k, dec))
    results.sort(key=lambda x: -x[0])
    return results[:top]


# ====================================================================
# 多字节：密钥长度推测（汉明距离法）
# ====================================================================

def hamming(a, b):
    """两个字节串的汉明距离（不同的位数）。"""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keylen(data, maxlen=40):
    """用「归一化汉明距离」推测密钥长度。

    原理：用同一密钥加密时，相隔 keylen 的两块明文异或后会抵消密钥，
    剩下的就是明文异或明文，汉明距离偏小。距离最小的 keylen 最可疑。
    """
    out = []
    n = len(data)
    if n < 8:
        return out
    for klen in range(1, min(maxlen, n // 2) + 1):
        blocks = [data[i:i + klen] for i in range(0, min(n, klen * 8), klen)]
        blocks = [b for b in blocks if len(b) == klen]
        if len(blocks) < 2:
            continue
        dists = []
        for i in range(len(blocks) - 1):
            dists.append(hamming(blocks[i], blocks[i + 1]) / float(klen))
        avg = sum(dists) / len(dists)
        out.append((avg, klen))
    out.sort()
    return out


def brute_single_freq(col, top=3):
    """逐列专用：用**纯频率**打分器排 0x00~0xFF。

    不能复用 brute_single —— 那个用的是词表打分，而抽样出来的列
    根本不成词（见 score_frequency 的说明）。
    """
    results = []
    for k in range(256):
        results.append((score_frequency(bytes(b ^ k for b in col)), k))
    results.sort(reverse=True)
    return results[:top]


def beam_seeds(data, columns, beam=8, per_col=6):
    """束搜索生成种子密钥：逐列扩展前缀，每步只留整段得分最高的 beam 个。

    为什么需要它：密钥长 12、每列 100 字节时，正确字节确实在每列前 20 名
    内（实测 12/12），但「每列取前 N 个做笛卡尔积」会立刻爆炸。束搜索
    每扩展一列就把所有前缀按「已确定部分的整段得分」排序，只保留最好的
    beam 个，于是 12 列 × 6 候选 × 8 beam 也只有几百次打分。

    打分时未确定的位置按 0 处理 —— 前缀越长，得分越接近真实整段得分，
    所以排序是有意义的。
    """
    if not columns:
        return []
    cand_lists = []
    for col in columns:
        if not col:
            cand_lists.append([0])
        else:
            cand_lists.append([k for _s, k in brute_single_freq(bytes(col),
                                                               top=per_col)])

    prefixes = [b""]
    for opts in cand_lists:
        expanded = []
        for pref in prefixes:
            for k in opts:
                expanded.append(pref + bytes([k]))
        # 用「前缀 + 其余补 0」的整段得分排序，只留 beam 个
        # 注意排序方向：要「得分最高」的 beam 个，所以用 reverse=True。
        # 早期版本写成 key=-score 配 reverse=False，负号与升序叠加后
        # 实际留下的是得分**最低**的 beam 个，束搜索等于反向工作。
        expanded.sort(
            key=lambda p: score_with_flag(
                apply_key(data, p + bytes(len(columns) - len(p)))),
            reverse=True)
        prefixes = expanded[:beam]
    return [p for p in prefixes if len(p) == len(columns)]


def break_repeating(data, klen, top=3):
    """已知密钥长度，拼出密钥与明文。

    做法：
      1. 用多种**互补的种子**覆盖搜索空间：
         - 逐列频率最优（score_frequency，适合长样本）；
         - 逐列词表最优（brute_single，适合短样本里碰巧成词的情况）；
         - 全 0 起点；
         - 若干随机起点（打破频率分析的误导）。
      2. 每个种子做整段爬山（hill_climb：逐字节全遍历 0x00~0xFF，
         以 score_with_flag 整段打分择优）。
      3. 得分最高的种子再深挖一次。

    为什么种子必须多样：短样本（如 24 字节、密钥长 3）里每列只有 8 个
    字节，正确密钥字节在逐列打分里连前 5 名都排不进（实测 0x4B/0x45/
    0x59 全部落榜）。只有靠**整段打分 + 逐字节全遍历**才能把它救回来，
    而整段爬山的结果高度依赖起点，所以起点必须足够杂。
    """
    if klen <= 0:
        return []
    columns = [bytearray() for _ in range(klen)]
    for i, b in enumerate(data):
        columns[i % klen].append(b)

    seeds = []

    # 种子 A：逐列频率最优
    freq_seed = bytearray()
    for col in columns:
        cands = brute_single_freq(bytes(col), top=1) if col else []
        freq_seed.append(cands[0][1] if cands else 0)
    seeds.append(bytes(freq_seed))

    # 种子 B：逐列词表最优（短样本时可能比频率更准）
    word_seed = bytearray()
    for col in columns:
        cands = brute_single(bytes(col), top=1) if col else []
        word_seed.append(cands[0][1] if cands else 0)
    seeds.append(bytes(word_seed))

    # 种子 C：全 0
    seeds.append(bytes(klen))

    # 种子 D：若干随机起点（固定种子，保证可复现）
    rng = random.Random(0xC0FFEE ^ klen)
    for _ in range(6):
        seeds.append(bytes(rng.randrange(256) for _ in range(klen)))

    # 种子 E：按「明文是 flag{...}」反推的密钥前缀（短样本最关键的一招）
    seeds.extend(prefix_seeds(data, klen))

    # 种子 F：逐列前若干候选做**束搜索**（beam search）。
    # 长密钥（12、16 字节）时，正确字节常常在每列的前 20 名里，但
    # 笛卡尔积会爆炸（20^12）。束搜索逐列扩展、每步只保留整段得分
    # 最高的 beam 个前缀，既覆盖了正确组合，代价又是线性的。
    seeds.extend(beam_seeds(data, columns, beam=8, per_col=6))

    scored = []
    best = None
    for seed in seeds:
        key = hill_climb(data, seed, rounds=4, restarts=1)
        dec = apply_key(data, key)
        sc = score_with_flag(dec)
        scored.append((sc, key, dec))
        if best is None or sc > best[0]:
            best = (sc, key)

    # 对最好的种子再深挖一次，跳出浅爬山的局部最优
    key = hill_climb(data, best[1], rounds=8, restarts=10)
    dec = apply_key(data, key)
    scored.append((score_with_flag(dec), key, dec))

    # 去重后按分数排序
    seen = set()
    results = []
    for item in sorted(scored, key=lambda x: -x[0]):
        if item[1] in seen:
            continue
        seen.add(item[1])
        results.append(item)
    return results[:top]


def hill_climb(data, key, rounds=4, restarts=6, rng=None):
    """整段爬山优化密钥：逐字节穷举 0x00~0xFF，保留让整段得分最高的值。

    单次爬山会卡在局部最优（实测密钥长 3、密文 74 字节时，每列只有
    25 字节，单字节打分的正确密钥可能只排到第 12 名）。所以这里做
    **多次随机重启**：每次从初始密钥出发、按随机顺序遍历各字节位置，
    取所有结果里整段得分最高的那个。代价是 256×klen×rounds×restarts
    次打分，对 CTF 的常见长度（几十~几百字节）仍然是瞬间完成。
    """
    key = bytearray(key)
    klen = len(key)
    if klen == 0:
        return bytes(key)
    if rng is None:
        rng = random.Random(0x5EED)

    best_key = bytes(key)
    best_score = score_with_flag(apply_key(data, best_key))

    for _ in range(restarts):
        cur = bytearray(key)
        # 后续重启从随机密钥出发，探索不同的盆地
        if _ > 0:
            for i in range(klen):
                cur[i] = rng.randrange(256)
        cur_score = score_with_flag(apply_key(data, bytes(cur)))
        for _r in range(rounds):
            improved = False
            order = list(range(klen))
            rng.shuffle(order)
            for pos in order:
                old = cur[pos]
                local_best = old
                local_score = cur_score
                for cand in range(256):
                    if cand == old:
                        continue
                    cur[pos] = cand
                    sc = score_with_flag(apply_key(data, bytes(cur)))
                    if sc > local_score:
                        local_score = sc
                        local_best = cand
                cur[pos] = local_best
                if local_best != old:
                    improved = True
                cur_score = local_score
            if not improved:
                break
        if cur_score > best_score:
            best_score = cur_score
            best_key = bytes(cur)
    return best_key


def break_repeating_auto(data, maxlen=40, top=5):
    """不指定密钥长度：把候选长度都解一遍，按**实际解密得分**排序。

    不能只信汉明距离：密文只有几十字节时（CTF 里很常见），汉明距离法
    基本失效——实测 24 字节密文、真实密钥长 3，正确长度连前 8 名都进不去。
    所以这里把候选放宽：短密钥（1..min(12, n//2)）一律纳入，再加上汉明
    距离排前几名的长度，全部解一遍后按明文可读性得分定输赢。
    """
    n = len(data)
    cands = []
    seen = set()

    # 1) 短密钥无条件纳入（短密钥在 CTF 里占比最高，且样本少时最稳）
    for klen in range(1, min(12, max(1, n // 2)) + 1):
        if klen not in seen:
            seen.add(klen)
            cands.append(klen)

    # 2) 汉明距离排前几名的长度
    for _avg, klen in guess_keylen(data, maxlen)[:top]:
        if klen not in seen:
            seen.add(klen)
            cands.append(klen)

    results = []
    for klen in cands:
        for sc, key, dec in break_repeating(data, klen, top=1):
            results.append((sc, key, dec, klen))

    # 奥卡姆剃刀：过长的密钥往往只是「用更长的周期拟合同一段明文」，
    # 属于过度拟合。判据是**密钥自身是否含更短周期**——真密钥 b"KEY"
    # 长度 3 能解释全部 24 字节；而长度 12 的 b"KEYKET`h+KEY" 里 KEY
    # 重复出现，本质周期仍是 3。所以：能约简成更短周期且解密结果不变
    # 的，就按更短的那个报，避免把过度拟合的结果当成答案。
    def simplify(key, dec):
        """把密钥约简到最小周期，若解密结果不变则返回更短密钥。"""
        n = len(key)
        for p in range(1, n):
            if n % p:
                continue
            if all(key[i] == key[i % p] for i in range(n)):
                short = key[:p]
                if apply_key(data, short) == dec:
                    return short
        return key

    simplified = []
    for sc, key, dec, klen in results:
        sk = simplify(key, dec)
        simplified.append((sc, sk, dec, len(sk)))

    # 同分时优先短密钥（更可能是真实密钥）
    simplified.sort(key=lambda x: (-x[0], x[3]))
    return simplified[:top]


# ====================================================================
# 已知明文攻击
# ====================================================================

def known_plaintext_key(data, known):
    """已知明文在开头时，直接异或出密钥前缀。返回 (密钥片段, 是否对齐)。"""
    n = min(len(data), len(known))
    if n == 0:
        return b"", False
    key = bytes(data[i] ^ known[i] for i in range(n))
    # 如果密钥是单字节重复的，检查一下周期性
    periodic = len(set(key)) == 1
    return key, periodic


def apply_key(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ====================================================================
# 输入解析
# ====================================================================

def parse_input(text, as_hex):
    """把命令行/文件内容转成 bytes。

    as_hex=True 时按十六进制解析（允许空格、0x、\\x 分隔）。
    """
    if as_hex:
        cleaned = re.sub(r"(0x|\\x|[\s,;:])", "", text)
        if len(cleaned) % 2:
            raise ValueError("十六进制串长度必须是偶数（当前 %d 个字符）"
                             % len(cleaned))
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            raise ValueError("不是合法的十六进制串")
    return text.encode("utf-8")


def looks_like_hex(text):
    """判断一串文本是不是「像十六进制」。"""
    t = re.sub(r"(0x|\\x|[\s,;:])", "", text)
    return bool(t) and len(t) % 2 == 0 and re.match(r"^[0-9A-Fa-f]+$", t)


def render(data):
    """把 bytes 变成可打印形式：优先文本，否则 hex。"""
    for enc in ("utf-8", "gb18030"):
        try:
            s = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        good = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
        if good / float(len(s) or 1) >= 0.85:
            return s
    return None


USAGE = """\
xor.py -- XOR 分析器：单字节爆破 / 多字节频率分析 / 已知明文攻击

做什么：CTF 里遇到「一串密文，怀疑是 XOR」时：
        1. 单字节密钥：0x00-0xFF 全试，按英文/中文可读性排序，列出前 N 个；
        2. 多字节密钥：先用汉明距离猜密钥长度，再逐列爆破；
        3. 已知明文（如 flag{、PNG 文件头）：直接异或出密钥。

用法：
    python -X utf8 xor.py "1b1b1b1b1b1b"
    python -X utf8 xor.py -f 密文.bin
    python -X utf8 xor.py -f 密文.bin --keylen 8
    python -X utf8 xor.py -f 密文.bin --key "abcd"
    python -X utf8 xor.py -f 密文.bin --known-plaintext "flag{"
    python -X utf8 xor.py "686578" --hex --top 20

参数：
    data                密文（默认自动判断是 hex 还是纯文本）
    -f/--file FILE      从文件读（二进制安全）
    --hex               强制把输入当十六进制串
    --text              强制把输入当文本（UTF-8）
    --key K             已知密钥（文本），直接解密
    --keylen N          指定密钥长度，跳过长度推测
    --known-plaintext S 已知明文片段（要求出现在开头）
    --top N             显示前 N 个候选（默认 10）
    --raw               结果按原始字节输出（不转文本）

已知限制：
    * 打分是启发式的，短于 8 字节的密文基本无法可靠排序；
    * 多字节长度推测在明文短于 32 字节时很不准，建议手动 --keylen；
    * 已知明文攻击假定明文片段出现在密文**开头**；
    * 中文打分覆盖 UTF-8 与 GB18030，其他编码（如 Big5）会失分。
"""


def main():
    ap = argparse.ArgumentParser(add_help=True, description="XOR 分析器")
    ap.add_argument("data", nargs="?", help="密文（hex 或文本）")
    ap.add_argument("-f", "--file", help="从文件读取（二进制安全）")
    ap.add_argument("--hex", action="store_true", help="强制按十六进制解析输入")
    ap.add_argument("--text", action="store_true", help="强制按文本解析输入")
    ap.add_argument("--key", help="已知密钥")
    ap.add_argument("--keylen", type=int, help="指定密钥长度")
    ap.add_argument("--known-plaintext", help="已知明文片段")
    ap.add_argument("--top", type=int, default=10, help="显示前 N 个候选")
    ap.add_argument("--raw", action="store_true", help="按原始字节输出")
    args = ap.parse_args()

    # ---- 读输入 ----
    if args.file:
        try:
            with open(args.file, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print("错误：读不了文件 %r —— %s" % (args.file, exc), file=sys.stderr)
            return 1
    elif args.data:
        text = args.data
        if args.hex or (not args.text and looks_like_hex(text)):
            try:
                data = parse_input(text, True)
            except ValueError as exc:
                print("错误：%s" % exc, file=sys.stderr)
                return 1
        else:
            data = parse_input(text, False)
    else:
        print(USAGE)
        return 0

    if not data:
        print("错误：输入是空的。", file=sys.stderr)
        return 1

    print("输入长度: %d 字节" % len(data))
    if len(data) <= 64:
        print("输入 hex : %s" % data.hex())

    # ---- 已知密钥 ----
    if args.key:
        key = args.key.encode("utf-8")
        if not key:
            print("错误：--key 不能为空。", file=sys.stderr)
            return 1
        dec = apply_key(data, key)
        print("")
        print("== 用已知密钥解密 ==")
        print("密钥     : %r (%d 字节, hex %s)" % (key, len(key), key.hex()))
        print_result(dec, args.raw)
        return 0

    # ---- 已知明文 ----
    if args.known_plaintext:
        known = args.known_plaintext.encode("utf-8")
        keyfrag, periodic = known_plaintext_key(data, known)
        print("")
        print("== 已知明文攻击 ==")
        print("已知明文 : %r" % known)
        print("推出密钥 : %r (hex %s)" % (keyfrag, keyfrag.hex()))
        if periodic:
            print("注意：推出的密钥是单字节重复的（%r），可以直接整段解密。"
                  % keyfrag[:1])
            dec = xor_single(data, keyfrag[0])
        else:
            print("密钥前 %d 字节已知；若密钥长度小于它，下面按周期套用。"
                  % len(keyfrag))
            dec = apply_key(data, keyfrag)
        print_result(dec, args.raw)
        return 0

    # ---- 多字节 ----
    if args.keylen is not None:
        if args.keylen <= 0:
            print("错误：--keylen 必须大于 0。", file=sys.stderr)
            return 1
        if args.keylen > len(data):
            print("错误：--keylen (%d) 比密文还长 (%d)，无意义。"
                  % (args.keylen, len(data)), file=sys.stderr)
            return 1
        print("")
        print("== 指定密钥长度 %d 的解密 ==" % args.keylen)
        for sc, key, dec in break_repeating(data, args.keylen):
            print("密钥     : %r (%d 字节, hex %s)" % (key, len(key), key.hex()))
            print("得分     : %.1f" % sc)
            print_result(dec, args.raw)
        return 0

    # ---- 单字节 ----
    print("")
    print("== 单字节 XOR 爆破（前 %d 个）==" % args.top)
    single = brute_single(data, args.top)
    for i, (sc, k, dec) in enumerate(single, 1):
        show = render(dec)
        preview = show if show is not None else dec.hex()
        if preview is not None and len(preview) > 120:
            preview = preview[:120] + "..."
        print("%2d. 密钥 0x%02X (%3d)  得分 %6.1f  -> %s"
              % (i, k, k, sc, repr(preview)))
    best = single[0]
    print("")
    print("最可能是 密钥 0x%02X (%d)，明文：" % (best[1], best[1]))
    print_result(best[2], args.raw)

    # 若单字节结果已经是完整的 flag{...}，说明这就是单字节 XOR，收尾。
    # 否则继续往下做多字节推测——但多字节会用更长的周期拟合出分数
    # 略高的假明文（实测 'flag{spngle_byte_or}' 757 分压过正确的
    # 单字节结果 748 分），把正确答案挤掉，所以这里必须提前判断。
    if flag_bonus(best[2]) >= 600.0 and len(data) >= 16:
        print("")
        print("（单字节密钥已解出完整 flag{...}，不再做多字节推测）")
        return 0

    # ---- 多字节推测 ----
    if len(data) >= 16:
        print("")
        print("== 多字节密钥长度推测（汉明距离法，仅供参考）==")
        lengths = guess_keylen(data)
        if lengths:
            for avg, klen in lengths[:5]:
                print("  长度 %2d  归一化汉明距离 %.3f" % (klen, avg))
            print("  注意：密文较短时汉明距离法不可靠，下面是各长度实际解密结果。")
            print("")
            print("== 各候选长度实际解密（按明文得分排序）==")
            multi = break_repeating_auto(data, top=3)
            for i, (sc, key, dec, klen) in enumerate(multi, 1):
                print("%d. 长度 %d 密钥 %r (hex %s) 得分 %.1f"
                      % (i, klen, key, key.hex(), sc))
                show = render(dec)
                preview = show if show is not None else dec.hex()
                if preview is not None and len(preview) > 100:
                    preview = preview[:100] + "..."
                print("   明文：%s" % repr(preview))
            if multi:
                print("")
                print("最可能是 长度 %d、密钥 %r，明文："
                      % (multi[0][3], multi[0][1]))
                print_result(multi[0][2], args.raw)
        else:
            print("  密文太短，无法推测。")

    return 0


def print_result(data, raw):
    if raw:
        sys.stdout.write(data.decode("latin-1"))
        sys.stdout.write("\n")
        return
    show = render(data)
    if show is None:
        print("（解出来不是可读文本，按 hex 显示）")
        print(data.hex())
    else:
        print(show)


if __name__ == "__main__":
    sys.exit(main())
