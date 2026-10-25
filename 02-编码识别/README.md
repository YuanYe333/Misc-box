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

## 常见陷阱

1. **Base64 的 `=` 不一定在结尾**：URL-safe Base64 用 `-_` 替代 `+/`，CyberChef 选 `From Base64` 时注意勾 `Alphabet`。
2. **摩斯电码的分隔**：单词间是 `/` 或 ` / `，字母间是空格。分隔符识别错会全乱。
3. **凯撒不知道位移多少**：直接用 `ROT13 Brute Force`，输出里挑可读的那条。
4. **多层编码不要跳步**：每解一层看一眼输出，跳步容易把中间结果当成最终答案。
5. **中文乱码先试 GBK**：CyberChef 的 `Decode text` 操作里可切字符集。

## 下一步

解出来的如果是图片/压缩包字节流 → 去 **隐写** 或 **压缩包与文件修复**。
解出来是一段 base64 的 pcap → 去 **流量分析**。

## 本分类工具一览

| 工具 | 版本 | 一句话说明 |
| --- | --- | --- |
| [CyberChef](#cyberchef) | 11.5.0 | 「网络瑞士军刀」：300+ 操作，离线单页，Magic 自动识别编码并链式解码。 |

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


← 返回 [工具箱总览](../README.md)
