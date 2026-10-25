"""从 tools.json 生成七大分类说明文档。

用法：python gen_docs.py
输出：<root>/01-环境配置/README.md ... 07-OSINT/README.md
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import core  # noqa: E402

CAT_HEADER = {
    "env": """# 一、环境配置

> 工具箱开箱第一站。所有其他分类的工具能不能跑，取决于这一页的自检结果。

## 这一页解决什么问题

拿到一台新电脑、重装系统、或者某个工具突然双击没反应时，**先跑环境自检**，
它会告诉你「哪个组件缺了、缺的到底是什么、该怎么补」，而不是让你一个个试。

## 目录结构

| 路径 | 内容 |
| --- | --- |
| `_box\\setup.ps1` | 环境自检脚本（纯 ASCII，输出红黄绿清单 + `env-report.json`） |
| `_box\\检查环境.bat` | 双击即跑自检并停留窗口 |
| `_box\\启动器.bat` | 图形启动器入口 |
| `_box\\tools.json` | **唯一数据源**：所有分类、工具、路径、说明都在这里 |

## 自检覆盖的内容

- **运行时**：Python 3.14（主）/ 3.12（虚拟环境底座）、Pillow、tkinter、Java、Node
- **工具就位**：按分类逐项检查可执行文件是否存在
- **可写目录**：theHarvester / Volatility 需要的配置目录（首次运行会自动创建）
- **驱动**：Npcap 是否安装（只有实时抓包需要，分析 pcap 文件不需要）

## 自检的三种跑法

```powershell
# 1. 完整清单（人看）
powershell -NoProfile -ExecutionPolicy Bypass -File D:\\杂项工具\\_box\\setup.ps1

# 2. 只看问题项
powershell -NoProfile -ExecutionPolicy Bypass -File D:\\杂项工具\\_box\\setup.ps1 -Quiet

# 3. JSON 输出（给脚本/CI 用）
powershell -NoProfile -ExecutionPolicy Bypass -File D:\\杂项工具\\_box\\setup.ps1 -Json
```

## 状态含义

| 标记 | 含义 | 要不要管 |
| --- | --- | --- |
| `OK` | 就绪 | 不用 |
| `WARN` | 缺了，但只影响部分功能 | 看你的题需不需要该功能 |
| `MISS` | 缺了，对应工具无法使用 | 要补 |
| `INFO` | 可选组件，没有也不影响 | 不用 |

## 本机环境备忘（踩过的坑）

| 现象 | 真实原因 | 处理 |
| --- | --- | --- |
| `curl`/`Invoke-WebRequest` 报 TLS 凭证错误 | 沙箱限制，不是网络不通 | 换更宽的权限，或直接用 `curl.exe` |
| `.ps1` 直接跑报语法错误，且错误行附近有中文 | PS 5.1 无 BOM 时按 GBK 读 | 存成 **UTF-8 with BOM**，或正文保持纯 ASCII |
| `pip install --upgrade pip` 长时间空转 | 本机已知问题 | 跳过升级，直接装目标包 |
| GitHub 直连只有 20 KB/s 甚至 0 | 线路问题 | 用 `ghfast.top` / `gh-proxy.com` 前缀加速，并用官方 SHA256 校验 |
| 中文路径下 Perl 的 XS 模块加载失败 | 非 ASCII 路径 + PATH 缺 `perl\\bin` | 两个 `bin` 都加进 PATH；必要时用 ASCII 目录联接 |
| `vol` 报 `unable to open database file` | `%APPDATA%` 不可写 | 启动脚本已把 `APPDATA` 指到 `_box\\cache` |

## 怎么补装（按需，逐条执行）

```powershell
# Pillow（图片处理）
C:\\Users\\<你>\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe -m pip install pillow ^
  -i https://pypi.tuna.tsinghua.edu.cn/simple

# Volatility 3
D:\\websec\\python\\python.exe -m venv D:\\杂项工具\\06-取证\\volatility3\\venv
D:\\杂项工具\\06-取证\\volatility3\\venv\\Scripts\\python.exe -m pip install volatility3 ^
  -i https://pypi.tuna.tsinghua.edu.cn/simple

# theHarvester（必须从源码装，PyPI 上的是抢注空壳）
... -m pip install https://github.com/laramies/theHarvester/archive/refs/tags/4.11.1.tar.gz
```

## 下一步

自检全绿之后，按题目类型进入对应分类：拿到乱码去 **编码识别**，拿到图片去 **隐写**，
拿到压缩包去 **压缩包与文件修复**。
""",
    "code": """# 二、编码识别

> 题目给你一串「不知道是什么」的字符时，从这里开始。

## 什么时候来这一页

| 题目信号 | 大概率是 |
| --- | --- |
| 一串字母数字，结尾有 `=` | Base64 / Base32 |
| 只有 `0-9a-f` | Hex |
| 只有 `0` 和 `1` | 二进制，或 Bacon |
| 有 `%` 和数字 | URL 编码 |
| 有 `&#` 或 `&xxx;` | HTML 实体 |
| `\\u` 开头 | Unicode 转义 |
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

## 常见陷阱

1. **Base64 的 `=` 不一定在结尾**：URL-safe Base64 用 `-_` 替代 `+/`，CyberChef 选 `From Base64` 时注意勾 `Alphabet`。
2. **摩斯电码的分隔**：单词间是 `/` 或 ` / `，字母间是空格。分隔符识别错会全乱。
3. **凯撒不知道位移多少**：直接用 `ROT13 Brute Force`，输出里挑可读的那条。
4. **多层编码不要跳步**：每解一层看一眼输出，跳步容易把中间结果当成最终答案。
5. **中文乱码先试 GBK**：CyberChef 的 `Decode text` 操作里可切字符集。

## 下一步

解出来的如果是图片/压缩包字节流 → 去 **隐写** 或 **压缩包与文件修复**。
解出来是一段 base64 的 pcap → 去 **流量分析**。
""",
    "stego": """# 三、隐写

> 题目给了一张图片（或音频、文档），肉眼看不出问题——flag 藏在文件结构或像素里。

## 图片隐写的排查顺序（照这个顺序走，别乱试）

```
1. file / exiftool      看真实类型 + 元数据        ← 30 秒，最容易被忽略
2. pngcheck -v          看 chunk 结构是否异常      ← PNG 必做
3. imgsize              看长宽有没有被改          ← 显示异常时必做
4. StegSolve            翻通道 / 位平面            ← 怀疑 LSB 时
5. binwalk              看文件里是否嵌了别的文件   ← 图片尾部有附加数据时
6. foremost             暴力雕刻兜底
```

**这个顺序的依据**：前 3 步都是秒级且不需要判断，第 4 步开始才需要人眼观察，
第 5-6 步是「前面都没结果」时的兜底。

## 工具速查

### 1. 元数据：ExifTool

```powershell
.\\exiftool.exe 图片.png              # 全部元数据
.\\exiftool.exe -a -G1 图片.png       # 分组显示，不漏重复标签
.\\exiftool.exe -b -Comment 图片.png  # 只取值，便于管道
```

flag 常见藏匿点：`Comment`、`Artist`、`ImageDescription`、`GPS*`、`UserComment`。

### 2. PNG 结构：pngcheck 套件

```powershell
.\\pngcheck.exe 图片.png          # 基本校验
.\\pngcheck.exe -v 图片.png       # 逐 chunk 结构
.\\pngcheck.exe -t 图片.png       # 打印 tEXt 文本块 ← 藏 flag 必查
.\\pngcheck.exe -7 图片.png       # 乱码时转义高位字符
.\\pngcheck.exe -p 图片.png       # 调色板 / 透明度
.\\pngcheck.exe -s 文件.bin       # 在任意文件里搜 PNG 签名
.\\pngcheck.exe -x 文件.bin       # 搜索并提取
```

**⚠️ 关键认知**：pngcheck **只验 CRC**。如果题目改了长宽并重算了 CRC，
pngcheck 会报 `No errors detected`——完全查不出来。**所以必须配合 imgsize。**

### 3. 长宽篡改：imgsize.py

```powershell
# 拖拽：把图片拖到 _脚本\\imgsize.bat 上
# 命令行：
C:\\Users\\<你>\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe -X utf8 ^
  D:\\杂项工具\\_脚本\\imgsize.py 题目.png
```

原理：用「实际像素数据量 ÷ 每像素字节数」反推真实高度，
与文件头声明的长宽对账。**PNG/BMP 严格，JPG 启发式**（JPG 没有像素长度字段）。

### 4. 位平面 / 通道：StegSolve

双击 `StegSolve\\启动StegSolve.bat`（需要 Java）。

| 功能 | 用途 |
| --- | --- |
| `Red/Green/Blue plane` | 单通道查看，颜色通道可能各藏一部分 |
| `Bit planes 0-7` | 逐位平面，**低位平面（0-2）常藏 LSB 数据** |
| `Frame Browser` | 多帧 GIF 逐帧浏览 |
| `Stereogram Solver` | 立体图/随机点图解码 |

### 5. 附加数据 / 嵌套文件：binwalk + foremost

```powershell
.\\binwalk\\binwalk.bat 题目.png        # 看有没有嵌别的文件
.\\binwalk\\binwalk.bat -e 题目.png     # 自动提取
# binwalk 失败时用 foremost 兜底：
cd D:\\杂项工具\\foremost
.\\foremost.exe -t png -i 题目.png -o 输出目录
```

## 常见隐写类型对照

| 类型 | 识别信号 | 工具 |
| --- | --- | --- |
| LSB 低位隐写 | 图片看起来完全正常 | StegSolve 位平面 0-2 |
| 长宽篡改 | 图片显示异常/下半截噪点 | imgsize.py + 手工改回 |
| 尾部附加数据 | 文件比正常大很多 | binwalk / foremost |
| tEXt 藏 flag | 元数据空白但文件偏大 | pngcheck -t |
| 多帧藏图 | GIF 帧数异常 | StegSolve Frame Browser |
| 调色板隐写 | PNG 索引色图 | pngcheck -p + StegSolve |
| 双图盲水印 | 给了两张相似图 | 需专门的盲水印脚本 |
| 立体图 | 图看起来是噪点 | StegSolve Stereogram Solver |

## 常见陷阱

1. **只跑 pngcheck 就下结论**——CRC 重算后它查不出长宽篡改，必须配 imgsize。
2. **imgsize 忘了 `-X utf8`**——中文路径会乱码导致找不到文件。
3. **StegSolve 双击没反应**——先 `java -version` 确认 Java 在。
4. **改长宽后要重算 CRC**——否则 pngcheck 报错，等于告诉出题人你改过。
5. **binwalk -e 在 Windows 上部分规则失败**——失败不是工具坏了，换 foremost。

## 下一步

提取出的压缩包 → **压缩包与文件修复**。
提取出的 pcap → **流量分析**。
解出的乱码 → **编码识别**。
""",
    "archive": """# 四、压缩包与文件修复

> CTF 里最高频的一类。压缩包本身往往就是题目。

## 排查顺序（先诊断再动手）

```
1. 7z l            看里面有什么（不解压）
2. 7z l -slt       看加密标记 / 压缩方式 / CRC
3. 7z t            测完整性，判断是不是文件损坏
4. 判断类型：
   ├─ 伪加密     → 改标志位（见下）
   ├─ 真加密     → john 提哈希 → hashcat / ARCHPR
   ├─ 分卷缺失   → 补全分卷
   ├─ 头部损坏   → 手工修文件头
   └─ 嵌套       → 逐层解
```

## 工具速查

### 7-Zip：诊断主力

```powershell
7z l 题目.zip                  # 列表
7z l -slt 题目.zip             # 技术详情（看 Encrypted / Method / CRC）
7z t 题目.zip                  # 完整性测试
7z x 题目.zip -o输出           # 解压（-o 后无空格！）
7z x -p密码 题目.zip           # 带密码
7z x 题目.zip flag.txt         # 只解单个文件
```

### 伪加密：不用爆破

ZIP 伪加密的本质是**通用位标记（general purpose bit flag）第 0 位被置 1**，
数据其实没加密。

**判断方法**：
```powershell
7z l -slt 题目.zip | findstr /i "Encrypted"
# 显示 Encrypted = + 但解压时 7z 直接成功 → 伪加密
# 或：用 010Editor 看本地文件头 offset 6-7 字节
```

**修复方法**（任一）：
1. 用 010Editor / HxD 打开 zip，找到每个文件的本地文件头，
   把第 6-7 字节（flag）的 bit0 清掉（`09 00` → `00 00`，或 `01 00` → `00 00`）。
2. 注意**中央目录里也有同样的 flag**，两处都要改。
3. 改完 `7z t` 验证。

### 真加密：两条路线

**路线 A：ARCHPR（图形，快）**

双击 `ARCHPR\\ARCHPR.loader.exe` → 打开压缩包 → 选字典/掩码/暴力 → 开始。
字典在 `ARCHPR\\dict\\`（拼音、键盘序、弱口令），大字典 `dict.txt`（133 MB）。

**路线 B：john 提哈希 → hashcat 爆破（GPU，快得多）**

```powershell
cd D:\\杂项工具\\john\\john-1.9.0-jumbo-1-win64\\run
.\\zip2john.exe D:\\work\\secret.zip > h.txt      # ZIP
.\\rar2john.exe D:\\work\\secret.rar > h.txt      # RAR
perl 7z2john.pl D:\\work\\secret.7z > h.txt       # 7z（需 Perl）

cd D:\\杂项工具\\hashcat
.\\hashcat.exe -m 17200 -a 0 h.txt 字典.txt       # PKZIP deflate
.\\hashcat.exe -m 17210 -a 0 h.txt 字典.txt       # PKZIP store
.\\hashcat.exe -m 13000 -a 0 h.txt 字典.txt       # RAR5
.\\hashcat.exe -m 11600 -a 0 h.txt 字典.txt       # 7-Zip
.\\hashcat.exe -m 17200 h.txt --show              # 看结果
```

**⚠️ 压缩类型对应表**（选错会报 unsupported compression type）

| 压缩包 | hashcat -m | 备注 |
| --- | --- | --- |
| ZIP (deflate) | 17200 | 最常见 |
| ZIP (store/不压缩) | 17210 | 无压缩时 |
| ZIP (AES) | 13600 | WinZip AES |
| RAR3 | 23700 | 老版本 RAR |
| RAR5 | 13000 | 新版 RAR |
| 7-Zip | 11600 | 需 Perl 提哈希 |

**路线 C：Hashcat 面板（图形，最省事）**

双击 `hashcat面板\\程序\\HashcatPanel.exe` → 选压缩包 → 点「提取哈希」
（自动调 john 并选好 -m）→ 选字典 → 开始破解。

### 文件头修复

| 损坏类型 | 表现 | 修法 |
| --- | --- | --- |
| ZIP 头被改 | `7z l` 报 Cannot open as archive | 改回 `50 4B 03 04` |
| PNG 头被改 | 图片打不开 | 改回 `89 50 4E 47 0D 0A 1A 0A` |
| PNG 长宽被改 | 显示异常 | 用 imgsize.py 反推真实值 |
| CRC 错误 | `7z t` 报 CRC Failed | 换 7z 的 `-memuse` 或跳过该文件 |

### 分卷合并

```powershell
# 分卷命名通常是 xxx.z01, xxx.z02 ... xxx.zip
7z x 题目.zip            # 7z 会自动识别同目录的分卷
# 或先合并：
cmd /c copy /b 题目.zip.001 + 题目.zip.002 合并.zip
```

## 常见陷阱

1. **`-o` 后面不能有空格**：`-o输出` 正确，`-o 输出` 会把「输出」当成文件参数。
2. **zip2john 不支持中文路径**：它是 cygwin 编译的，先复制到 `D:\\work` 这类纯 ASCII 目录。
3. **7z2john 需要 Perl 且 PATH 要含 `perl\\bin`**：否则报 XS 模块加载失败。
4. **hashcat 必须在自己的目录下运行**：否则找不到 `OpenCL\\`。
5. **hashcat 吃不了 .zip**：必须先提哈希，直接丢 zip 会报 `Signature unmatched`。
6. **ARCHPR 是绿化版**：目录里有历史 CrashLog，崩溃就换 hashcat 路线。

## 下一步

解出的图片 → **隐写**。
解出的 pcap → **流量分析**。
解出的乱码文本 → **编码识别**。
""",
    "traffic": """# 五、流量分析

> 题目给你一个 `.pcap` / `.pcapng`，要你还原通信内容、提取文件、找出 flag。

## 第一件事：先摸底，别急着看包

```powershell
# 1. 协议分层统计——先知道这包在干什么
tshark -r 题目.pcap -q -z io,phs

# 2. 会话统计——看谁和谁通信最多
tshark -r 题目.pcap -q -z conv,tcp
```

**为什么先做这一步**：一上来全量渲染大 pcap 会卡死，而且看不出重点。
`io,phs` 能在 1 秒内告诉你「这题是 HTTP 还是 DNS 还是 USB」。

## 按协议找 flag

### HTTP

```powershell
# 所有请求的 Host + URI
tshark -r 题目.pcap -Y http.request -T fields -e http.host -e http.request.uri

# 导出所有 HTTP 对象（文件）
tshark -r 题目.pcap --export-objects http,输出目录

# 看 POST 内容（提交的 flag）
tshark -r 题目.pcap -Y http.request.method==POST -T fields -e http.file_data

# 追踪某条 TCP 流（第 0 条）
tshark -r 题目.pcap -q -z follow,tcp,ascii,0
```

### DNS

```powershell
# 所有查询的域名（DNS 隧道题必看）
tshark -r 题目.pcap -Y dns -T fields -e dns.qry.name

# 只看响应
tshark -r 题目.pcap -Y "dns.flags.response==1" -T fields -e dns.qry.name -e dns.txt
```

DNS 题常见套路：域名前缀是 base64 编码的分片，拼起来再解码。

### TLS / HTTPS

```powershell
# 看 SNI（目标域名）
tshark -r 题目.pcap -Y tls.handshake.type==1 -T fields -e tls.handshake.extensions_server_name

# 有私钥时解密
tshark -r 题目.pcap -o "tls.keys_list:0.0.0.0,443,http,key.pem"
```

### USB / 键盘流量

```powershell
# USB 中断传输数据（键盘/鼠标题）
tshark -r 题目.pcap -Y "usb.transfer_type==0x01" -T fields -e usb.capdata
```

键盘流量题：`usb.capdata` 里的字节查 HID 键码表还原按键。

### 文件提取（通用）

```powershell
# 按 TCP 流导出
tshark -r 题目.pcap -q -z follow,tcp,raw,0

# 全协议对象导出
tshark -r 题目.pcap --export-objects http,out
tshark -r 题目.pcap --export-objects smb,out
tshark -r 题目.pcap --export-objects tftp,out
```

## 图形界面

双击卡片「打开工具」→ Wireshark 图形界面。

| 功能 | 位置 | 用途 |
| --- | --- | --- |
| 统计 → 协议分级 | Statistics → Protocol Hierarchy | 同 `-z io,phs` |
| 统计 → 会话 | Statistics → Conversations | 找通信最多的 IP |
| 追踪流 | 右键包 → Follow → TCP/UDP Stream | 看完整会话内容 |
| 导出对象 | File → Export Objects → HTTP | 导出传输的文件 |
| 过滤器 | 顶部输入框 | `http`、`dns`、`ip.addr==1.2.3.4` |

## nmap（流量题里的辅助）

如果题目给了 IP 或要还原目标服务：

```powershell
cd D:\\杂项工具\\05-流量分析\\nmap
.\\nmap.exe -sV -p 1-1000 目标IP
.\\nmap.exe -p- --min-rate 1000 目标IP
```

## ⚠️ 关于 Npcap

| 场景 | 需要 Npcap 吗 |
| --- | --- |
| 分析已有 `.pcap` 文件 | **不需要**（tshark 直接读文件） |
| 实时抓包 / nmap 的 SYN 扫描 / OS 指纹 | 需要 |

**Npcap 免费版不支持静默安装**（`/S` 会弹提示），必须手动跑安装程序点界面。
不装也不影响做题——CTF 流量题都是给现成的 pcap。

## 常见陷阱

1. **大 pcap 直接全量打开会卡死**：先用 `-q -z io,phs` 摸底。
2. **`tshark` 不在 PATH**：用完整路径 `C:\\Program Files\\Wireshark\\tshark.exe`。
3. **`follow,tcp,ascii,N` 的 N 是流序号**，不是包序号。
4. **HTTP 是分块传输时** `http.file_data` 可能为空，要用 `--export-objects`。
5. **USB 题要先确定设备类型**（键盘/鼠标/存储），用 `usb.src` 过滤。

## 下一步

导出的文件 → 按类型去 **隐写** / **压缩包与文件修复** / **取证**。
""",
    "forensics": """# 六、取证

> 固件、磁盘镜像、内存镜像——「从一个二进制大文件里把东西挖出来」。

## 分诊：先判断你拿到的是什么

| 文件特征 | 类型 | 主力工具 |
| --- | --- | --- |
| 几 KB ~ 几 MB，头部乱 | 单文件藏数据 | binwalk + foremost |
| 几十 MB+，有分区结构 | 磁盘镜像 | binwalk + foremost |
| `.raw` / `.mem` / `.vmem`，GB 级 | 内存镜像 | **Volatility 3** |
| 路由器固件（`.bin`、`.trx`） | 固件 | binwalk -e |

## 1. binwalk：结构扫描

```powershell
.\\binwalk\\binwalk.bat 题目.bin          # 签名扫描（看有几个文件）
.\\binwalk\\binwalk.bat -e 题目.bin       # 自动提取
.\\binwalk\\binwalk.bat -E 题目.bin       # 熵分析（找加密/压缩段）
.\\binwalk\\binwalk.bat -A 题目.bin       # 找可执行代码段
```

**熵分析怎么读**：熵接近 8.0 = 加密或已压缩；熵接近 0 = 全零填充。
熵图上的突变点往往就是文件边界。

⚠️ `-e` 的提取依赖外部工具（7z、dd），Windows 上部分规则会失败。
**失败时用 foremost 兜底，不是工具坏了。**

## 2. foremost：文件雕刻

```powershell
cd D:\\杂项工具\\foremost
.\\foremost.exe -t png -i 题目.bin -o 输出目录        # 只找 png
.\\foremost.exe -t all -i 题目.bin -o 输出目录        # 全类型
.\\foremost.exe -t jpg,png,gif -i 题目.bin -o 输出目录
```

结果：`输出目录\\类型\\` 下是文件本体，`audit.txt` 记录偏移与大小。

**必须在 foremost 自己目录下跑**（要读同目录的 `foremost.conf`），
**输出目录必须为空**，否则报错。

## 3. Volatility 3：内存取证

```powershell
# 启动（已配置好 APPDATA 与缓存路径）
D:\\杂项工具\\06-取证\\volatility3\\启动Volatility.bat

# 或者直接调用：
vol -f memory.raw windows.info          # 第一步永远先跑这个
```

### 常用插件（Windows）

| 插件 | 作用 |
| --- | --- |
| `windows.info` | 系统版本、内核基址（**先跑这个**） |
| `windows.pslist` | 进程列表 |
| `windows.pstree` | 进程树（看父子关系，找隐藏进程） |
| `windows.cmdline` | 进程命令行（找执行过的命令） |
| `windows.netscan` | 网络连接（找 C2 地址） |
| `windows.filescan` | 扫描内存中的文件对象 |
| `windows.dumpfiles` | 导出文件（需 `--virtaddr`） |
| `windows.registry.hivelist` | 注册表配置单元列表 |
| `windows.hashdump` | 导出密码哈希 |
| `windows.malfind` | 找注入的内存段 |

```powershell
vol -f memory.raw windows.pslist
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.netscan
vol -f memory.raw windows.dumpfiles --virtaddr 0x7ff...
vol -f memory.raw -o 输出目录 windows.filescan
```

### Linux / Mac

把 `windows.` 换成 `linux.` / `mac.`，插件名类似（`linux.pslist`、`linux.bash`）。

## 4. 其他取证工具

| 工具 | 用途 |
| --- | --- |
| ExifTool | 文档/图片元数据、GPS、作者 |
| 010Editor | 十六进制手工修补（模板功能强） |
| `file`（Git 自带） | 快速判断真实类型 |

```powershell
& 'C:\\Program Files\\Git\\usr\\bin\\file.exe' 题目.bin
```

## 常见陷阱

1. **binwalk -e 失败 ≠ 工具坏**：Windows 上提取规则依赖 7z/dd，失败换 foremost。
2. **foremost 输出目录必须空**：否则直接报错退出。
3. **Volatility 首次跑某系统版本要下载符号表**：需要网络，离线环境要预置 symbols。
4. **`vol` 报 `unable to open database file`**：`%APPDATA%` 不可写，用工具箱的启动 bat（已把缓存指到 `_box\\cache`）。
5. **内存镜像动辄数 GB**：插件跑几分钟是正常的，别以为卡死了。
6. **取证先做只读副本**：对原始镜像只读操作，别在原文件上改。

## 下一步

提取出的文件 → 按类型分流到 **隐写** / **压缩包与文件修复** / **编码识别**。
""",
    "osint": """# 七、OSINT

> 公开信息收集。**仅用于自有资产、授权测试、CTF 题目的公开信息面**。

## ⚠️ 合规底线（先读这一条）

- 只对**你自己的资产**或**明确授权**的目标做信息收集。
- 只收集**公开可获取**的信息（搜索引擎、证书透明度日志、WHOIS 等公开库）。
- 不绕过任何访问控制、不进行社工、不触碰个人隐私数据。
- 国内对「非法获取公民个人信息」有明确法律边界，越界不是技术问题。

## 这一页的工具

### theHarvester：域名信息收集

从公开来源收集**邮箱、子域、主机、员工名**。

```powershell
# 启动（会先确保配置目录存在）
D:\\杂项工具\\07-OSINT\\theharvester\\启动theHarvester.bat

# 基础收集
theHarvester -d example.com -b duckduckgo,crtsh

# 子域为主
theHarvester -d example.com -b crtsh,anubis -l 200

# 输出到文件（生成 .html / .json / .xml）
theHarvester -d example.com -b duckduckgo -f 结果
```

| 参数 | 作用 |
| --- | --- |
| `-d` | 目标域名 |
| `-b` | 数据源，逗号分隔 |
| `-l` | 结果数量上限 |
| `-f` | 输出文件名 |

**常用数据源**：`duckduckgo`（无需 key）、`crtsh`（证书透明度，找子域神器）、
`anubis`、`otx`、`urlscan`。需要 API key 的源在 `~/.theHarvester/api-keys.yaml` 里填。

### 轻量查询（无需额外工具）

```powershell
# DNS
nslookup example.com
nslookup -type=MX example.com
nslookup -type=TXT example.com

# WHOIS（Windows 自带无此命令，用网页版或 PowerShell 模块）
# 证书透明度：浏览器打开 crt.sh/?q=example.com

# HTTP 响应头（看技术栈）
curl.exe -sSI https://example.com

# TLS 证书信息
& 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' s_client -connect example.com:443 -servername example.com
```

## 常见 CTF OSINT 套路

| 题目给的信息 | 思路 |
| --- | --- |
| 一张照片 | 元数据 GPS → 地图定位；建筑/路牌识别 |
| 一个用户名 | 跨平台搜同名账号（GitHub、微博、贴吧等） |
| 一个域名 | crt.sh 找子域、WHOIS 找注册人、DNS TXT 找验证串 |
| 一段文字 | 搜索原文找来源、翻译、找发布者 |
| 一个邮箱 | 反查注册过的平台、GitHub commit 里的作者邮箱 |

## 常见陷阱

1. **首次运行报权限错误**：theHarvester 要在 `~/.theHarvester` 和 `~/.local/share/theHarvester` 建目录，
   工具箱启动脚本已预建，若手动跑 `theHarvester.exe` 可能触发。
2. **部分数据源需要 playwright 浏览器内核**：首次用 `playwright install chromium`。
3. **免费数据源结果少**：`duckduckgo` 经常被限流，多用 `crtsh`。
4. **结果里的邮箱要二次验证**：theHarvester 的结果包含推测值，不是全部真实。

## 下一步

收集到的子域/主机 → 授权范围内可用 **流量分析** 里的 nmap 做端口确认。
""",
}


def build_doc(cat: dict, tools: list[core.Tool]) -> str:
    header = CAT_HEADER.get(cat["id"], "")
    lines = [header.rstrip(), ""]

    lines.append("## 本分类工具一览")
    lines.append("")
    lines.append("| 工具 | 版本 | 一句话说明 |")
    lines.append("| --- | --- | --- |")
    for t in tools:
        lines.append(f"| [{t.name}](#{t.id}) | {t.version} | {t.summary} |")
    lines.append("")

    lines.append("---")
    lines.append("")

    for t in tools:
        lines.append(f'<a id="{t.id}"></a>')
        lines.append("")
        lines.append(f"## {t.name}" + (f" · {t.name_en}" if t.name_en else ""))
        lines.append("")
        lines.append(f"**版本**：{t.version}  ")
        lines.append(f"**类型**：{t.type}  ")
        lines.append(f"**位置**：`{t.raw.get('path','')}`")
        lines.append("")
        lines.append(f"> {t.summary}")
        lines.append("")

        if t.when:
            lines.append("### 什么时候用")
            lines.append("")
            lines.append(t.when)
            lines.append("")

        if t.usage:
            lines.append("### 怎么用")
            lines.append("")
            for u in t.usage:
                lines.append(f"**{u.get('title','用法')}**")
                lines.append("")
                if u.get("steps"):
                    for i, s in enumerate(u["steps"], 1):
                        lines.append(f"{i}. {s}")
                    lines.append("")
                if u.get("code"):
                    lines.append("```")
                    lines.append(u["code"])
                    lines.append("```")
                    lines.append("")

        if t.params:
            lines.append("### 参数速查")
            lines.append("")
            lines.append("| 参数 | 说明 |")
            lines.append("| --- | --- |")
            for p in t.params:
                flag = str(p.get("flag", "")).replace("|", "\\|")
                desc = str(p.get("desc", "")).replace("|", "\\|")
                lines.append(f"| `{flag}` | {desc} |")
            lines.append("")

        if t.pitfalls:
            lines.append("### 踩坑提醒")
            lines.append("")
            for x in t.pitfalls:
                lines.append(f"- {x}")
            lines.append("")

        if t.next_ids:
            names = []
            for nid in t.next_ids:
                nt = next((x for x in tools if x.id == nid), None)
                if nt:
                    names.append(f"{nt.name}")
            if names:
                lines.append("### 下一步")
                lines.append("")
                lines.append(" → ".join(names))
                lines.append("")

        lines.append("---")
        lines.append("")

    lines.append("")
    lines.append("← 返回 [工具箱总览](../README.md)")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    cfg = core.load_config()
    root = core.project_root(cfg)
    tools = core.build_tools(cfg)
    cats = core.categories(cfg)

    written = []
    for cat in cats:
        cat_tools = [t for t in tools if t.category == cat["id"]]
        if not cat_tools:
            continue
        guide_rel = cat.get("guide", "")
        if not guide_rel:
            continue
        out = root / guide_rel.replace("/", "\\")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(build_doc(cat, cat_tools), encoding="utf-8")
        written.append((str(out), len(cat_tools)))

    for path, n in written:
        print(f"  {n:2d} tools -> {path}")
    print(f"\n{len(written)} category docs generated.")


if __name__ == "__main__":
    main()
