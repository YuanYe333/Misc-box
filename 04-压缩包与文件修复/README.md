# 四、压缩包与文件修复

> CTF 里最高频的一类。压缩包本身往往就是题目。

## 排查顺序（先诊断再动手）

> **命令里的 `7z` 是简写。** 本工具箱**不改系统 PATH**，所以直接敲 `7z` 会报
> 「不是内部或外部命令」。两种正确用法：
>
> - 本机已装 7-Zip：用完整路径 `& 'C:\Program Files\7-Zip\7z.exe'`
> - 只用便携版：`& 'D:\杂项工具\CTF-tools\7zip\7z.exe'`
>
> 下面的示例为了可读性都写成 `7z`，请按上面的方式替换。

```powershell
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
# 先把路径存成变量，后面照抄就不会踩 PATH 的坑
$7z = 'C:\Program Files\7-Zip\7z.exe'      # 或便携版 CTF-tools\7zip\7z.exe

& $7z l 题目.zip                  # 列表
& $7z l -slt 题目.zip             # 技术详情（看 Encrypted / Method / CRC）
& $7z t 题目.zip                  # 完整性测试
& $7z x 题目.zip -o输出           # 解压（-o 后无空格！）
& $7z x -p密码 题目.zip           # 带密码
& $7z x 题目.zip flag.txt         # 只解单个文件
```

### 伪加密：不用爆破

ZIP 伪加密的本质是**通用位标记（general purpose bit flag）第 0 位被置 1**，
数据其实没加密。

**判断方法**：
```powershell
& $7z l -slt 题目.zip | findstr /i "Encrypted"
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

双击 `ARCHPR\ARCHPR.loader.exe` → 打开压缩包 → 选字典/掩码/暴力 → 开始。
字典在 `ARCHPR\dict\`（拼音、键盘序、弱口令），大字典 `dict.txt`（133 MB）。

**路线 B：john 提哈希 → hashcat 爆破（GPU，快得多）**

```powershell
cd D:\杂项工具\john\john-1.9.0-jumbo-1-win64\run
.\zip2john.exe D:\work\secret.zip > h.txt      # ZIP
.\rar2john.exe D:\work\secret.rar > h.txt      # RAR
perl 7z2john.pl D:\work\secret.7z > h.txt       # 7z（需 Perl）

cd D:\杂项工具\hashcat
.\hashcat.exe -m 17200 -a 0 h.txt 字典.txt       # PKZIP deflate
.\hashcat.exe -m 17210 -a 0 h.txt 字典.txt       # PKZIP store
.\hashcat.exe -m 13000 -a 0 h.txt 字典.txt       # RAR5
.\hashcat.exe -m 11600 -a 0 h.txt 字典.txt       # 7-Zip
.\hashcat.exe -m 17200 h.txt --show              # 看结果
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

双击 `hashcat面板\程序\HashcatPanel.exe` → 选压缩包 → 点「提取哈希」
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
2. **zip2john 不支持中文路径**：它是 cygwin 编译的，先复制到 `D:\work` 这类纯 ASCII 目录。
3. **7z2john 需要 Perl 且 PATH 要含 `perl\bin`**：否则报 XS 模块加载失败。
4. **hashcat 必须在自己的目录下运行**：否则找不到 `OpenCL\`。
5. **hashcat 吃不了 .zip**：必须先提哈希，直接丢 zip 会报 `Signature unmatched`。
6. **ARCHPR 是绿化版**：目录里有历史 CrashLog，崩溃就换 hashcat 路线。

## 下一步

解出的图片 → **隐写**。
解出的 pcap → **流量分析**。
解出的乱码文本 → **编码识别**。

## 本分类工具一览

| 工具 | 版本 | 一句话说明 |
| --- | --- | --- |
| [7-Zip](#7zip) | 26.03（系统）/ 24.09（便携） | 解压/打包 zip、7z、rar、tar；处理伪加密、分卷、嵌套压缩包。 |
| [ARCHPR](#archpr) | 4.66 | 压缩包口令恢复：字典/掩码/暴力/明文攻击，图形界面直接选包。 |
| [John the Ripper](#john) | 1.9.0-jumbo-1 | 提供 zip2john / rar2john / 7z2john 等哈希提取器，把加密压缩包转成 hashcat 能吃的哈希。 |
| [hashcat](#hashcat) | 7.1.2 | GPU 口令爆破：字典/掩码/规则/组合，支持 300+ 哈希类型。 |
| [Hashcat 面板](#hashcat-panel) | 1.0 | hashcat 图形外壳：自动识别 -m、内置「压缩包 → 提取哈希」、实时进度与日志。 |
| [Strawberry Perl](#perl) | 5.42.3.1 | 便携版 Perl，用于运行 john 的 7z2john.pl、pdf2john.pl 等 Perl 脚本。 |
| [CRC32 反推/修复](#crc32bf) | 1.0 | 已知 CRC32 反推短未知字节，或修 PNG 的 CRC。 |
| [伪加密判定](#fakeenc) | 1.0 | 区分 ZIP/RAR 的伪加密与真加密。 |
| [文件雕取](#filecarve) | 1.0 | 按文件头尾雕刻内嵌文件，轻量 binwalk 替代。 |
| [文件类型识别](#filetype) | 1.0 | 按魔数识别真实类型，戳穿伪装扩展名。 |
| [ZIP 结构体检](#zipfix) | 1.0 | ZIP 结构体检与中央目录重建。 |

---

<a id="7zip"></a>

## 7-Zip · 7-Zip

**版本**：26.03（系统）/ 24.09（便携）  
**类型**：cli-gui  
**位置**：`CTF-tools/7zip/7z.exe`

> 解压/打包 zip、7z、rar、tar；处理伪加密、分卷、嵌套压缩包。

### 什么时候用

拿到压缩包第一步永远是 `7z l` 看结构，而不是直接解压。

### 怎么用

**列目录（不解压）**

```
7z l 题目.zip
```

**解压到指定目录**

```
7z x 题目.zip -o输出
```

**带密码解压**

```
7z x -p密码 题目.zip
```

**测试完整性**

```
7z t 题目.zip
```

**只解某个文件**

```
7z x 题目.zip flag.txt
```

**查看是否加密（伪加密判断）**

```
7z l -slt 题目.zip | findstr /i "Encrypted Method"
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `l` | 列出内容（含 CRC、加密标记） |
| `x` | 解压并保留目录结构 |
| `e` | 解压到当前目录（丢弃路径） |
| `t` | 完整性测试 |
| `-p` | 指定密码，-p 后直接跟密码 |
| `-o` | 指定输出目录（注意 -o 后无空格） |
| `-slt` | 技术信息详细列表 |

### 踩坑提醒

- -o 与路径之间不能有空格：-o输出 而非 -o 输出
- 中文密码/中文路径在命令行下需 UTF-8 控制台，建议用 Windows Terminal
- CTF-tools/7zip 是 24.09 便携副本，系统另有 26.03，两者都能用

### 下一步

ARCHPR → John the Ripper → hashcat

---

<a id="archpr"></a>

## ARCHPR · Advanced Archive Password Recovery

**版本**：4.66  
**类型**：gui  
**位置**：`ARCHPR/ARCHPR.loader.exe`

> 压缩包口令恢复：字典/掩码/暴力/明文攻击，图形界面直接选包。

### 什么时候用

压缩包有密码且字典可能命中时；不想折腾 hashcat 提取哈希就用它。

### 怎么用

**图形方式**

1. 双击 ARCHPR/ARCHPR.loader.exe
2. 「打开」选压缩包 → 选「暴力」或「字典」
3. 字典选 ARCHPR/dict/ 下的弱口令/拼音/键盘序，或根目录 dict.txt
4. 「开始」等待结果

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `字典攻击` | 按字典逐条尝试，最快 |
| `掩码攻击` | 已知格式（如 4 位数字）时极快 |
| `暴力攻击` | 穷举所有组合，慢但保证覆盖 |
| `明文攻击` | 已知包内某文件明文时可秒破 ZIP |

### 踩坑提醒

- 本机这份是绿化版，目录内有历史 CrashLog，若启动崩溃可改用 hashcat 路线
- 中文界面：Options → Language → chinese_simp.lng
- 商业软件，仅限自有题目与授权场景；不要公开分发

### 下一步

John the Ripper → hashcat

---

<a id="john"></a>

## John the Ripper · John the Ripper jumbo

**版本**：1.9.0-jumbo-1  
**类型**：cli  
**位置**：`john/john-1.9.0-jumbo-1-win64/run/john.exe`

> 提供 zip2john / rar2john / 7z2john 等哈希提取器，把加密压缩包转成 hashcat 能吃的哈希。

### 什么时候用

要用 GPU（hashcat）跑压缩包口令时，先用它提取哈希。

### 怎么用

**ZIP → 哈希**

```
cd D:\杂项工具\john\john-1.9.0-jumbo-1-win64\run
.\zip2john.exe D:\work\secret.zip > h.txt
```

**RAR → 哈希**

```
.\rar2john.exe D:\work\secret.rar > h.txt
```

**7z → 哈希（需 Perl，见 perl 条目）**

```
perl 7z2john.pl D:\work\secret.7z > h.txt
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `zip2john` | ZIP 提取（deflate/store 都支持） |
| `rar2john` | RAR3/RAR5 提取 |
| `7z2john.pl` | 7z 提取，Perl 脚本 |
| `office2john.py` | Office 文档提取 |
| `pdf2john.pl` | PDF 提取 |

### 踩坑提醒

- zip2john 是 cygwin 编译，不支持中文路径，先复制到纯 ASCII 目录（如 D:\work）
- 7z2john.pl 需要 Perl 且 PATH 要含 perl/bin，见工具箱 perl 条目
- --potfile-path 传绝对路径会 Permission denied，用默认或相对路径

### 下一步

hashcat → Strawberry Perl

---

<a id="hashcat"></a>

## hashcat · hashcat

**版本**：7.1.2  
**类型**：cli  
**位置**：`hashcat/hashcat.exe`

> GPU 口令爆破：字典/掩码/规则/组合，支持 300+ 哈希类型。

### 什么时候用

压缩包、Office、PDF、系统哈希等需要高速爆破时；本机 RTX 5060 实测 MD5 约 17345 MH/s。

### 怎么用

**字典攻击（最常用）**

```
cd D:\杂项工具\hashcat
.\hashcat.exe -m 0 -a 0 hash.txt 字典.txt
```

**掩码爆破**

```
.\hashcat.exe -m 0 -a 3 hash.txt ?a?a?a?a?a?a
```

**字典 + 规则变形**

```
.\hashcat.exe -m 0 -a 0 hash.txt 字典.txt -r rules\best66.rule
```

**字典 + 掩码混合**

```
.\hashcat.exe -m 0 -a 6 hash.txt 字典.txt ?d?d
```

**逐位加长**

```
.\hashcat.exe -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a --increment --increment-min 1
```

**查看结果**

```
.\hashcat.exe -m 0 hash.txt --show
```

**查哈希类型编号**

```
.\hashcat.exe -m 17200 --example-hashes
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-m` | 哈希类型：0=MD5 100=SHA1 1400=SHA256 17200=PKZIP 17210=PKZIP-store 13000=RAR5 23700=RAR3 11600=7-Zip 10500=PDF |
| `-a` | 攻击模式：0=字典 1=组合 3=掩码 6=字典+掩码 7=掩码+字典 |
| `--show / --left` | 查看已破解 / 未破解 |
| `--increment` | 掩码逐位加长 |
| `-O` | 优化内核，更快但密码长度受限（≤31） |
| `-w` | 工作负载 1~4（默认 2，3 更激进） |
| `-D 1` | 只用 GPU |
| `--runtime` | 限时秒数后自动停止 |
| `--session + --restore` | 长任务断点续跑 |

### 踩坑提醒

- 必须在 hashcat 目录下运行，否则找不到 OpenCL/
- hashcat 不能直接吃 .zip/.rar，必须先用 john 提取哈希
- PKZIP deflate 用 17200，store 用 17210，选反会报 unsupported compression type
- 启动打印 CUDA SDK Toolkit not installed 并回退 OpenCL 属正常现象
- --potfile-path 绝对路径在 Windows 版有 Permission denied 的 bug

### 下一步

John the Ripper → Hashcat 面板

---

<a id="hashcat-panel"></a>

## Hashcat 面板 · HashcatPanel

**版本**：1.0  
**类型**：gui  
**位置**：`hashcat面板/程序/HashcatPanel.exe`

> hashcat 图形外壳：自动识别 -m、内置「压缩包 → 提取哈希」、实时进度与日志。

### 什么时候用

不想记 -m 编号、或想一键完成 zip/rar 提取哈希再爆破。

### 怎么用

**破解加密压缩包**

1. 双击 程序/HashcatPanel.exe
2. 「压缩包」行选 .zip/.rar/.7z
3. 点「提取哈希」→ 自动调 john 并选好 -m
4. 选字典 → 「开始破解」→ 「查看结果」

### 踩坑提醒

- 程序/ 整个文件夹必须保留，exe 依赖同目录 _internal/
- 7z 的 7z2john.pl 需 Perl；装了工具箱的 perl 条目即可用
- 中文路径会先自动转到临时 ASCII 目录处理

### 下一步

hashcat → John the Ripper

---

<a id="perl"></a>

## Strawberry Perl · Strawberry Perl portable

**版本**：5.42.3.1  
**类型**：cli  
**位置**：`04-压缩包与文件修复/perl/perl/bin/perl.exe`

> 便携版 Perl，用于运行 john 的 7z2john.pl、pdf2john.pl 等 Perl 脚本。

### 什么时候用

遇到 7z 加密包想走 hashcat -m 11600，或需要跑任何 .pl 脚本时。

### 怎么用

**7z → 哈希（关键路径）**

```
$env:PATH = 'D:\杂项工具\04-压缩包与文件修复\perl\perl\bin;D:\杂项工具\04-压缩包与文件修复\perl\c\bin;' + $env:PATH
& 'D:\杂项工具\04-压缩包与文件修复\perl\perl\bin\perl.exe' 'D:\杂项工具\john\john-1.9.0-jumbo-1-win64\run\7z2john.pl' 'D:\work\secret.7z'
```

**验证环境**

```
perl -v
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `portableshell.bat` | 进入已配置好 PATH 的 Perl 交互环境（推荐） |

### 踩坑提醒

- 必须把 perl/bin 和 c/bin 都加进 PATH，否则 XS 模块（Lzma.xs.dll）加载失败
- Perl 的 XS 模块对中文路径敏感，必要时用纯 ASCII 路径或目录联接
- 本机原无 Perl，此条目为 2026-10 补齐，解锁了 7z2john

### 下一步

John the Ripper → hashcat

---


<a id="crc32bf"></a>

## CRC32 反推/修复 · crc32bf.py

**类型**：script  
**位置**：`04-压缩包与文件修复/scripts/crc32bf.py`

> 暴力反推 CRC32 缺失的短字节，或一键修复 PNG 所有块 CRC。

### 什么时候用

PNG 块 CRC 被改导致打不开，或已知 CRC 缺几个字符要还原。

### 怎么用

**反推缺失字节**

```bat
python -X utf8 crc32bf.py --prefix "AB" --crc 0x112787e6 --len 2
```

**修 PNG 的 CRC**

```bat
python -X utf8 crc32bf.py --fix-png 坏图.png -o 修好.png
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--prefix` | 已知的前缀内容 |
| `--crc` | 目标 CRC32（0x 开头或十进制） |
| `--len` | 缺失字节数（默认 2，超过 4 会很慢） |
| `--charset` | printable/lower/upper/digit/alnum/hex/flag |

### 踩坑提醒

- 暴力枚举限制在 4 字节以内；4 字节 95^4 要跑几分钟
- 只支持 CRC32（IEEE 0xEDB88320），不支持 CRC16/CRC64
- --fix-png 只修 CRC，修不了「数据本身被改坏」

---

<a id="fakeenc"></a>

## 伪加密判定 · fakeenc.py

**类型**：script  
**位置**：`04-压缩包与文件修复/scripts/fakeenc.py`

> 判定 ZIP/RAR 是不是伪加密，ZIP 可一键清标志位直接解压。

### 什么时候用

压缩包要密码，但怀疑只是标志位被改（CTF 十次有八次是假的）。

### 怎么用

**先判定**

```bat
python -X utf8 fakeenc.py 可疑.zip
```

**清除伪加密**

```bat
python -X utf8 fakeenc.py 可疑.zip -o 明文.zip
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-o` | 清除伪加密后另存（仅 ZIP） |
| `--force` | 允许覆盖已存在的输出文件 |

### 踩坑提醒

- 真加密（数据区确实是密文）无法破解，只报告
- ZIP 的 AES 加密（method 99）不处理
- RAR 只做检测不做修复（改了容易彻底坏掉）

---

<a id="filecarve"></a>

## 文件雕取 · filecarve.py

**类型**：script  
**位置**：`04-压缩包与文件修复/scripts/filecarve.py`

> 从裸数据里按魔数找出内嵌文件并切出来（binwalk 的轻量替代）。

### 什么时候用

镜像文件、内存转储、图片尾部疑似藏了 ZIP/PNG。

### 怎么用

**先扫描看有什么**

```bat
python -X utf8 filecarve.py 镜像.bin
```

**实际切出来**

```bat
python -X utf8 filecarve.py 镜像.bin -o 输出目录
```

**只看尾部附加数据**

```bat
python -X utf8 filecarve.py 图片.png --tail
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-o` | 把雕出的文件写到这个目录 |
| `--tail` | 只显示第一个文件结束之后的附加数据 |
| `--min-size` | 小于这个字节数的片段不雕（默认 16） |

### 踩坑提醒

- 只雕自带明确结束标记的格式（PNG/JPG/GIF/ZIP/PDF 等）
- 没有长度字段又没结束标记的（如原始 PE 段）只报位置不雕
- 一个文件被分成两段时会各雕一半，需要人工拼接

---

<a id="filetype"></a>

## 文件类型识别 · filetype.py

**类型**：script  
**位置**：`04-压缩包与文件修复/scripts/filetype.py`

> 按魔数判断文件真实类型，并检查扩展名是否骗人。

### 什么时候用

拿到可疑文件，第一步就该跑它——CTF 里扩展名几乎不可信。

### 怎么用

**看单个文件**

```bat
python -X utf8 filetype.py 可疑文件
```

**整目录递归**

```bat
python -X utf8 filetype.py 题目目录 -r
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-r` | 递归子目录 |
| `-f` | 额外打印开头 32 字节的 hex |

### 踩坑提醒

- 魔数只是开头几字节，精心构造的文件可以让它撒谎
- .txt 里其实是 PNG 是最典型的「扩展名骗人」，脚本会明确报出来
- 分卷压缩包 .z01/.z02 的魔数和主包不同，已单独处理

---

<a id="zipfix"></a>

## ZIP 结构体检 · zipfix.py

**类型**：script  
**位置**：`04-压缩包与文件修复/scripts/zipfix.py`

> 逐条对账 ZIP 的中央目录/CRC/大小字段，能重建被删的中央目录。

### 什么时候用

解压报「压缩包已损坏」，或中央目录被截断、条目偏移错乱。

### 怎么用

**只体检**

```bat
python -X utf8 zipfix.py 坏包.zip
```

**重建中央目录**

```bat
python -X utf8 zipfix.py 坏包.zip --rebuild -o 重建.zip
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-o` | 修复后另存为这个文件 |
| `--rebuild` | 按本地文件头重建中央目录 |
| `--force` | 允许覆盖已存在的输出文件 |

### 踩坑提醒

- 不处理 ZIP64（超过 4GB 的包）
- 数据区本身被破坏（压缩流残缺）无法还原，只能报告受影响条目
- 重建只能恢复结构，恢复不了被覆盖的数据

---

← 返回 [工具箱总览](../README.md)
