# 二、编码识别

> 题目给你一串「不知道是什么」的字符时，从这里开始。

## 什么时候来这一页

| 题目信号 | 大概率是 |
| --- | --- |
| 一串字母数字，结尾有 `=` | Base64 / Base32 |
| 只有 `0-9a-f` | Hex |
| 只有 `0` 和 `1` | 二进制，或 Bacon |
| 有 `%` 和数字 | URL 编码 |
| 有 `&#` 或 `&xxx;` | HTML 实体 |
| `\u` 开头 | Unicode 转义 |
| `.` `-` `/` 空格 | 摩斯电码 |
| 一堆 `+` `>` `<` `[` `]` | Brainfuck / Ook |
| 只有大写字母，读起来像句子但错位 | 凯撒 / Atbash / 栅栏 |
| 一堆看不懂的汉字，像佛经 | 与佛论禅 |
| 表情符号 | AAencode / JSFuck / base100 |

## 主力工具：CyberChef

**CyberChef 是编码识别的事实标准**，本工具箱内置离线版（v11.5.0，不联网也能用）。

### 打开方式

双击启动器 → 左侧「编码识别」→ 卡片「CyberChef」→「打开工具」。
浏览器会载入本地 `CyberChef_v11.5.0.html`，完全离线。

### 三种用法

**1. Magic（最省事）**

把乱码粘进左上 Input 框 → 点 **Magic** 按钮。它会自动推测编码、
给出候选操作并直接预览结果。**80% 的编码题第一步就该点它。**

**2. 手动指定操作**

Operations 搜索框里输入操作名，双击加入 Recipe：

```
From Base64          Base64 解码
From Base32          Base32 解码
From Base58          Base58（比特币风格）
From Base62          Base62
From Hex             Hex 转字节
From Morse Code      摩斯电码
ROT13 / ROT47        凯撒位移
Atbash Cipher        字母表反转
Bacon Cipher Decode  培根密码
From Charcode        字符码转文本
URL Decode           URL 解码
From HTML Entity     HTML 实体
From Quoted Printable
```

**3. Recipe 链式解码（多层编码）**

题目经常套多层（比如 Base64 → Hex → 凯撒）。把多个操作**按顺序**拖进 Recipe 栏，
点 **Bake!** 一次跑完。中途想看得点 **Step** 逐步执行，看每一层的中间结果。

### 关键参数

| 操作 | 要点 |
| --- | --- |
| `From Base64` | 勾选 `Remove non-alphabet chars` 可自动清理换行/空格 |
| `From Hex` | 分隔符选 `Auto` 或 `Space`，看题目格式 |
| `ROT13` | 位移量可改，暴力时用 `Brute Force` 操作遍历 1-25 |
| `Magic` | 可调 `Depth`（尝试层数）和 `Intensity`（候选广度） |

## 本地补充工具

`imgsize.py` 也能处理部分文本场景（比如 `.txt` 里塞的是图片字节流时，先看长度规律）。

## 常见 CTF 题型与对应解法

下面这些是 Misc 编码题出现频率最高的形态，按「看到什么 → 怎么下手」整理：

| 题面特征 | 解法 | CyberChef 操作 |
| --- | --- | --- |
| 一串 `%E4%BD%A0%E5%A5%BD` | URL 解码一次 | `URL Decode` |
| `%25E4%25BD%25A0` | 被 URL 编码了两次，解两遍 | `URL Decode` ×2 |
| 全大写 + `=` 结尾，字符集是 `A-Z2-7` | Base32 | `From Base32` |
| 含 `+` `/` 和 `=`，长度是 4 的倍数 | Base64 | `From Base64` |
| 含 `-` `_` 而非 `+` `/` | URL-safe Base64 | `From Base64` 勾 `Alphabet: A-Za-z0-9-_` |
| 只含 `0-9A-F`，长度偶数 | Hex | `From Hex` |
| 只有 `.` `-` 空格 `/` | 摩斯电码 | `From Morse Code` |
| 一堆 `+-<>[].,` | Brainfuck | `Brainfuck` |
| 一堆 `Ook. Ook?` | Ook! | `Ook!` |
| `%u0061%u0062` | Unicode 转义 | `Unescape Unicode Characters` |
| `&#20320;&#22909;` | HTML 实体（十进制） | `From HTML Entity` |
| `&#x4F60;&#x597D;` | HTML 实体（十六进制） | `From HTML Entity` |
| 全是 emoji | base100 / AAencode | `From Base100` 或先转义 |
| 中文「佛曰」「如是我闻」 | 与佛论禅 | 在线工具（CyberChef 无内置） |
| 一串数字 `12 34 56` | 可能是 ASCII 十进制 | `From Decimal` |
| `\x41\x42` | 十六进制转义串 | `From Escape Sequence` |

### 多层嵌套怎么剥

CTF 常把 3~5 层编码串起来。**不要凭感觉猜顺序**，按这个流程走：

1. 先把密文粘进 CyberChef，点一次 **Magic**，看它给出的候选里有没有「输出看起来像另一种编码」的。
2. 如果没有，就看**字符集**判断最外层：
   - 只有 `0-9a-f` → 先 `From Hex`
   - 有 `=` 结尾、字符集是 Base64 → 先 `From Base64`
   - 全是 `%XX` → 先 `URL Decode`
3. 解一层后，把结果**再粘回 Input 重新 Magic**。很多人失败是因为在同一个 Recipe 里硬拖，
   中间结果不对时无法回头。
4. 解到出现 `flag{` / `ctf{` / 可读英文就停。

### 编码识别不了时的兜底

- **看熵**：CyberChef 的 `Entropy` 操作能看信息熵，高熵多半是加密/压缩过，不是简单编码。
- **看长度规律**：长度是 4 的倍数 → Base64 家族；是 8 的倍数 → 可能是 DES 块；
  奇数长度 → 大概率 Hex 缺位或自定义码表。
- **自定义码表**：题目给一张映射表（比如 A→Q）时，用 `Substitute` 操作按表替换，
  不要手动一个个改。

## 本地补充工具（命令行脚本）

除了 CyberChef，本分类还带 5 个纯 Python 脚本，**不联网、不用装依赖**，
适合「题目能直接给字符串、我想在命令行里一把跑完」的场景。
每个脚本所在目录都有同名 `.bat`，双击即可运行（会提示你拖入文件或输入内容）。

| 脚本 | 什么时候用它 |
| --- | --- |
| `encscan.py` | 一串字符不知道是什么编码，先让它猜，并自动剥多层 |
| `bases.py` | 明确是 Base 家族（16/32/58/64/85/91/100），要互转或批量解 |
| `xor.py` | 怀疑 XOR 加密，要爆破单字节密钥或恢复多字节密钥 |
| `hashcrack.py` | 拿到一串哈希，要先认算法再撞明文 |
| `qrcode.py` | 有一张二维码图片要解内容 |

### encscan.py · 编码识别器

```bat
python -X utf8 encscan.py "ZmxhZ3t0ZXN0fQ=="
```

- 自动列出可能的编码并给出置信度，再尝试逐层解码直到出现可读文本
- 用 `--chain` 强制多层剥离，用 `--top` 控制显示几个候选
- 认不出来时会明说「不确定」，不会硬猜一个错答案

### bases.py · Base 系列互转

```bat
python -X utf8 bases.py ZmxhZ3tiYXNlNjRfb2t9
python -X utf8 bases.py ZmxhZ3tiYXNlNjRfb2t9 -d base64
python -X utf8 bases.py --encode base64 flag{test}
```

- 支持 Base16/32/58/64/85/91/100
- 自动识别给的是**置信度**，不是断言；Base32 和 Base58 的字符集有重叠，短密文会歧义
- 变种题用 `--alphabet` 传自定义字母表

### xor.py · XOR 分析与破解

```bat
python -X utf8 xor.py 3c363b3d21223528 --hex
python -X utf8 xor.py 密文.hex --hex --keylen 3
python -X utf8 xor.py 密文.hex --hex --key KEY
```

- 单字节 0x00-0xFF 全爆破，按明文可读性排序
- 多字节用汉明距离猜长度 + 整段爬山恢复密钥
- 已知明文（如开头是 `flag{`）时用 `--known-plaintext` 反推，这是短密文唯一可靠的办法

### hashcrack.py · 哈希识别与爆破

```bat
python -X utf8 hashcrack.py 5f4dcc3b5aa765d61d8327deb882cf99
python -X utf8 hashcrack.py <hash> --builtin
python -X utf8 hashcrack.py <hash> --mask "flag{?l?l?d?d}"
```

- 先按长度和格式特征识别算法，再离线撞
- 内置约 300 条弱口令，也支持外部字典和掩码
- bcrypt / Argon2 / *-crypt 只识别不爆破（它们是故意设计成慢的）

### qrcode.py · 二维码识别

```bat
python -X utf8 qrcode.py 题目.png
python -X utf8 qrcode.py 反色.png --invert
```

- 纯标准库实现，不依赖 zbar/opencv
- 支持 PNG/BMP，含 RGB 和调色板 PNG（不支持 JPG）
- 只做解码，不生成二维码
- 解码失败会说明原因（找不到定位图案 / 纠错失败 / 比特流不足）

## 常见陷阱

1. **Base64 的 `=` 不一定在结尾**：URL-safe Base64 用 `-_` 替代 `+/`，CyberChef 选 `From Base64` 时注意勾 `Alphabet`。
2. **摩斯电码的分隔**：单词间是 `/` 或 ` / `，字母间是空格。分隔符识别错会全乱。
3. **凯撒不知道位移多少**：直接用 `ROT13 Brute Force`，输出里挑可读的那条。
4. **多层编码不要跳步**：每解一层看一眼输出，跳步容易把中间结果当成最终答案。
5. **中文乱码先试 GBK**：CyberChef 的 `Decode text` 操作里可切字符集。
6. **短密文的 XOR 别指望自动解**：密钥长 3、密文只有 24 字节时，每列只有 8 个字节，
   逐列统计里正确密钥字节连前 5 名都排不进。这种题必须用 `--known-plaintext` 或 `--keylen` 辅助。
7. **哈希长度不等于算法**：32 位 hex 可能是 MD5、NTLM 或 MD4，64 位可能是 SHA256、SHA3-256
   或 Keccak-256。撞不出来时换个 `--algo` 再试，别断定工具坏了。

## 下一步

解出来的如果是图片/压缩包字节流 → 去 **隐写** 或 **压缩包与文件修复**。
解出来是一段 base64 的 pcap → 去 **流量分析**。

## 本分类工具一览

| 工具 | 版本 | 一句话说明 |
| --- | --- | --- |
| [CyberChef](#cyberchef) | 11.5.0 | 「网络瑞士军刀」：300+ 操作，离线单页，Magic 自动识别编码并链式解码。 |
| [encscan](#encscan) | 1.0 | 编码识别器，猜编码并自动剥多层。 |
| [bases](#bases) | 1.0 | Base16/32/58/64/85/91/100 互转与识别。 |
| [xor](#xor) | 1.0 | XOR 单字节爆破与多字节密钥恢复。 |
| [hashcrack](#hashcrack) | 1.0 | 哈希识别与离线爆破（弱口令/字典/掩码）。 |
| [qrcode](#qrcode) | 1.0 | 纯标准库二维码解码器（只解不生成）。 |


---

<a id="cyberchef"></a>

## CyberChef · CyberChef

**版本**：11.5.0  
**类型**：web  
**位置**：`02-编码识别/CyberChef/CyberChef_v11.5.0.html`

> 「网络瑞士军刀」：300+ 操作，离线单页，Magic 自动识别编码并链式解码。

### 什么时候用

一堆乱码不知道是什么编码、需要多层解码、或做 Base/XX/摩斯/培根/凯撒等变换时，第一个打开它。

### 怎么用

**图形方式**

1. 双击卡片「打开工具」→ 浏览器载入本地页面
2. 左侧输入乱码 → 点「Magic」或从 Operations 搜操作名
3. 右侧 Output 实时出结果；可用「Bake」逐步调试

**常用操作名（搜索框直接输入）**

```
From Base64 / From Base32 / From Base58 / From Hex
From Morse Code / ROT13 / Atbash Cipher / Bacon Cipher Decode
Magic（自动识别） / From Charcode / URL Decode / From HTML Entity
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `Magic` | 自动推测编码并给出候选操作，最省事 |
| `Recipe` | 把多个操作串成流水线，一次跑完多层解码 |
| `Fork` | 对多行输入分别执行后续操作 |

### 踩坑提醒

- 离线版不会自动更新，需要新版本时重新下载替换
- 显示层压缩（.br/.gz）文件可忽略，浏览器会直接读未压缩版
- 极大数据（>1MiB）会转为文件下载形式展示

---

<a id="encscan"></a>

## encscan · 编码识别器

**类型**：script  
**位置**：`02-编码识别/scripts/encscan.py`

> 猜一串字符用的是什么编码，并尝试逐层解码直到出现可读文本。

### 什么时候用

题目直接给了一串字符串（不是文件），不知道是什么编码，又懒得开 CyberChef。

### 怎么用

```bat
python -X utf8 encscan.py "ZmxhZ3t0ZXN0fQ=="
python -X utf8 encscan.py -f 密文.txt --chain
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--chain` | 强制逐层剥离，直到解不动为止 |
| `--top` | 显示前 N 个候选，默认 5 |
| `-f` | 从文件读输入 |

### 踩坑提醒

- 置信度低时（< 0.5）说明这串字符太短或有歧义，看第二名
- 它是「识别 + 试探解码」，不是密码分析；真正的加密它认不出来

---

<a id="bases"></a>

## bases · Base 系列编解码

**类型**：script  
**位置**：`02-编码识别/scripts/bases.py`

> Base16/32/58/64/85/91/100 一键互转，还能自动识别是哪种 Base。

### 什么时候用

明确知道是 Base 家族，要精确解码或编码；或者变种题要传自定义字母表。

### 怎么用

```bat
python -X utf8 bases.py ZmxhZ3tiYXNlNjRfb2t9
python -X utf8 bases.py ZmxhZ3tiYXNlNjRfb2t9 -d base64
python -X utf8 bases.py --encode base32 flag{test}
python -X utf8 bases.py 密文 -d base64 --alphabet "自定义表"
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-d / --decode` | 指定解码方式 |
| `--encode` | 编码，后面跟方式名 |
| `--alphabet` | 自定义字母表（变种题必用） |
| `-f / -o` | 文件输入 / 输出 |
| `--all` | 把所有能解的 Base 都解一遍 |

### 踩坑提醒

- Base32（A-Z2-7）和 Base58 字符集有重叠，短密文两个都像
- Base100 用 emoji 编码，粘贴时被聊天软件吃掉字符就解不出来，用文件传
- 解出二进制时用 `-o` 存文件，再用 `filetype.py` 看真实类型

---

<a id="xor"></a>

## xor · XOR 分析与破解

**类型**：script  
**位置**：`02-编码识别/scripts/xor.py`

> 单字节爆破、多字节密钥恢复、已知明文攻击，自动判断明文可读性。

### 什么时候用

拿到一段二进制或 hex，怀疑是 XOR（可打印率不低但读不通、高频字节重复出现）。

### 怎么用

```bat
python -X utf8 xor.py 3c363b3d21223528 --hex
python -X utf8 xor.py 密文.hex --hex --keylen 3
python -X utf8 xor.py 密文.hex --hex --key KEY
python -X utf8 xor.py 密文.hex --hex --known-plaintext "flag{"
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--hex` | 输入按十六进制解析 |
| `-f / --file` | 从文件读二进制 |
| `--key` | 直接用这个密钥解密 |
| `--keylen` | 指定密钥长度 |
| `--known-plaintext` | 已知明文片段，反推密钥 |
| `--top` | 单字节爆破显示前 N 个 |

### 踩坑提醒

- **短密文的多字节恢复不可靠**，这是数学限制：密钥长 3、密文 24 字节时每列只有 8 个字节，
  正确密钥字节连前 5 名都排不进。脚本靠「假设明文以 flag{ 开头」才救得回来。
- 明文不是 flag{} 开头时，短密文请手动用 `--keylen` + `--known-plaintext`
- 长密钥（如 12）常是过度拟合，脚本会做奥卡姆剃刀约简，但只在密钥严格周期重复时生效
- 明文是纯二进制（图片/压缩片段）时所有候选分数都低，别信排序，改用已知明文攻击

---

<a id="hashcrack"></a>

## hashcrack · 哈希识别与爆破

**类型**：script  
**位置**：`02-编码识别/scripts/hashcrack.py`

> 先认出哈希是什么算法，再用弱口令表/字典/掩码撞出来，全程离线。

### 什么时候用

题目给一串 32/40/64/128 位 hex 要还原明文；或拿到 shadow、SAM 里的哈希要撞密码。

### 怎么用

```bat
python -X utf8 hashcrack.py 5f4dcc3b5aa765d61d8327deb882cf99
python -X utf8 hashcrack.py <hash> --builtin
python -X utf8 hashcrack.py <hash> -w rockyou.txt
python -X utf8 hashcrack.py <hash> --mask "flag{?l?l?d?d}"
python -X utf8 hashcrack.py --list-algos
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--builtin` | 内置弱口令表（约 300 条） |
| `-w / --wordlist` | 外部字典 |
| `--mask` | 掩码穷举：`?l` 小写 `?u` 大写 `?d` 数字 `?a` 全部 |
| `--algo` | 只按指定算法试 |
| `--limit` | 字典最多试 N 条 |
| `--identify` | 只识别不爆破 |

### 踩坑提醒

- 掩码组合数上限 500 万，超过直接拒绝；`?a?a?a?a?a` 就有 9.1 亿，别写长了
- bcrypt / Argon2 / *-crypt / PBKDF2 / SSHA 只识别不爆破（它们是故意慢的），
  这类请用 hashcat/john 配 GPU
- 32 位 hex 无法只凭长度区分 MD5/NTLM/MD4，脚本默认三个都试
- NTLM 需要 MD4，标准库没有，脚本自带纯 Python 实现（已用 RFC 1320 向量验证），
  但比 hashlib 慢很多，字典超 10 万条会明显变慢

---

<a id="qrcode"></a>

## qrcode · 二维码识别

**类型**：script  
**位置**：`02-编码识别/scripts/qrcode.py`

> 纯标准库的二维码解码器，不依赖 zbar/opencv，能从 PNG/BMP 里解出内容。

### 什么时候用

题目给了一张二维码图片要解内容，但环境里没装扫码库；或者要确认二维码里到底藏了什么。

### 怎么用

```bat
python -X utf8 qrcode.py 题目.png
python -X utf8 qrcode.py 反色.png --invert
python -X utf8 qrcode.py 模糊.png --threshold 128
python -X utf8 qrcode.py 题目.png --hex
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `file` | PNG 或 BMP 图片路径（位置参数） |
| `--dump` | 打印二值化后的模块矩阵，用于确认采样有没有错位 |
| `--invert` | 强制反色，处理黑底白码的图 |
| `--threshold` | 手动二值化阈值 0-255，默认自动 |
| `--hex` | 打印原始数据码字，用于判断纠错是否失败 |

### 踩坑提醒

- **本工具只做解码，不生成二维码。** 要生成请用 CyberChef 的 Generate QR Code 操作
- 容量有硬上限：版本 1-L 字节模式只能放 17 字节。18 字节的内容报
  「比特流不足（需要 8 位，剩余 4 位）」不是 bug，是内容超了版本 1 的容量
- 只支持 PNG 和 BMP，**不接受 JPG**（有损压缩会破坏模块边界，先转 PNG）
- 手机拍的、有透视变形或反光的照片大概率解不出来，先裁正放大
- 彩色二维码支持，但要求对比明显；低对比度会二值化失败
- 调色板 PNG 里有透明色时，透明区会被当背景，可能吃掉部分模块

---


← 返回 [工具箱总览](../README.md)
