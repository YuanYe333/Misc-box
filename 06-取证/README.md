# 六、取证

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
.\binwalk\binwalk.bat 题目.bin          # 签名扫描（看有几个文件）
.\binwalk\binwalk.bat -e 题目.bin       # 自动提取
.\binwalk\binwalk.bat -E 题目.bin       # 熵分析（找加密/压缩段）
.\binwalk\binwalk.bat -A 题目.bin       # 找可执行代码段
```

**熵分析怎么读**：熵接近 8.0 = 加密或已压缩；熵接近 0 = 全零填充。
熵图上的突变点往往就是文件边界。

⚠️ `-e` 的提取依赖外部工具（7z、dd），Windows 上部分规则会失败。
**失败时用 foremost 兜底，不是工具坏了。**

## 2. foremost：文件雕刻

```powershell
cd D:\杂项工具\foremost
.\foremost.exe -t png -i 题目.bin -o 输出目录        # 只找 png
.\foremost.exe -t all -i 题目.bin -o 输出目录        # 全类型
.\foremost.exe -t jpg,png,gif -i 题目.bin -o 输出目录
```

结果：`输出目录\类型\` 下是文件本体，`audit.txt` 记录偏移与大小。

**必须在 foremost 自己目录下跑**（要读同目录的 `foremost.conf`），
**输出目录必须为空**，否则报错。

## 3. Volatility 3：内存取证

```powershell
# 启动（已配置好 APPDATA 与缓存路径）
D:\杂项工具\06-取证\volatility3\启动Volatility.bat

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
& 'C:\Program Files\Git\usr\bin\file.exe' 题目.bin
```

## 常见陷阱

1. **binwalk -e 失败 ≠ 工具坏**：Windows 上提取规则依赖 7z/dd，失败换 foremost。
2. **foremost 输出目录必须空**：否则直接报错退出。
3. **Volatility 首次跑某系统版本要下载符号表**：需要网络，离线环境要预置 symbols。
4. **`vol` 报 `unable to open database file`**：`%APPDATA%` 不可写，用工具箱的启动 bat（已把缓存指到 `_box\cache`）。
5. **内存镜像动辄数 GB**：插件跑几分钟是正常的，别以为卡死了。
6. **取证先做只读副本**：对原始镜像只读操作，别在原文件上改。

## 下一步

提取出的文件 → 按类型分流到 **隐写** / **压缩包与文件修复** / **编码识别**。

## 本分类工具一览

| 工具 | 版本 | 一句话说明 |
| --- | --- | --- |
| [binwalk](#binwalk) | 2.3.4 | 文件签名扫描、自动提取嵌套文件、熵分析找加密/压缩段。 |
| [foremost](#foremost) | 1.5.7 | 按文件头尾雕刻恢复，比 binwalk -e 更激进的 carve 工具。 |
| [Volatility 3](#volatility3) | 2.28.2 | 内存镜像取证事实标准：进程、网络连接、注册表、凭据、文件系统全可挖。 |
| [NTFS 已删除文件枚举](#deleted) | 1.0 | 分析已删除文件痕迹与可恢复性。 |
| [十六进制查看器](#hexview) | 1.0 | 带 ASCII 侧栏的十六进制查看器，支持跳转与搜索。 |
| [元数据体检/清除](#metawipe) | 1.0 | 读/清元数据，检查 GPS、作者、注释等隐藏字段。 |
| [增强版 strings](#strings) | 1.0 | 增强版 strings，同时抓 ASCII/UTF-8/UTF-16LE/BE。 |
| [文件时间线](#timeline) | 1.0 | 按时间戳排序文件，重建操作时间线，可导出 CSV。 |

---

<a id="binwalk"></a>

## binwalk · binwalk

**版本**：2.3.4  
**类型**：cli  
**位置**：`binwalk/binwalk.bat`

> 文件签名扫描、自动提取嵌套文件、熵分析找加密/压缩段。

### 什么时候用

一个文件里疑似藏了多个文件，或拿到固件/镜像要先摸清结构。

### 怎么用

**签名扫描**

```
.\binwalk\binwalk.bat 题目.bin
```

**自动提取**

```
.\binwalk\binwalk.bat -e 题目.bin
```

**熵分析**

```
.\binwalk\binwalk.bat -E 题目.bin
```

**找可执行代码段**

```
.\binwalk\binwalk.bat -A 题目.bin
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-e` | 自动提取（结果在 _题目.bin.extracted/） |
| `-E` | 熵分析 |
| `-A` | 找 CPU 架构签名 |
| `-D` | 自定义签名类型 |

### 踩坑提醒

- 必须用 binwalk.bat（自带 UTF-8 环境，能处理中文路径）
- 装在独立虚拟环境 binwalk/Scripts/python.exe，不要 pip 装进系统 Python
- -e 依赖外部工具（7z/dd），Windows 上部分规则失败，失败时用 foremost 兜底

### 下一步

foremost

---

<a id="foremost"></a>

## foremost · foremost

**版本**：1.5.7  
**类型**：cli  
**位置**：`foremost/foremost.exe`

> 按文件头尾雕刻恢复，比 binwalk -e 更激进的 carve 工具。

### 什么时候用

binwalk 提取失败、文件头被破坏、或要从镜像里批量捞图片/文档。

### 怎么用

**只找 PNG**

```
cd D:\杂项工具\foremost
.\foremost.exe -t png -i 题目.bin -o 输出目录
```

**全类型**

```
.\foremost.exe -t all -i 题目.bin -o 输出目录
```

**指定多类型**

```
.\foremost.exe -t jpg,png,gif -i 题目.bin -o 输出目录
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-t` | 文件类型（all/jpg/png/gif/pdf/zip...） |
| `-i` | 输入文件或设备 |
| `-o` | 输出目录（必须不存在或为空） |
| `-T` | 带时间戳的子目录 |

### 踩坑提醒

- 必须在 foremost 自己目录下跑，要读同目录 foremost.conf
- 输出目录必须为空，否则报错
- 结果：输出目录/类型/ 下是文件本体，audit.txt 是偏移与大小报告

### 下一步

binwalk

---

<a id="volatility3"></a>

## Volatility 3 · Volatility 3

**版本**：2.28.2  
**类型**：cli  
**位置**：`06-取证/volatility3/venv/Scripts/vol.exe`

> 内存镜像取证事实标准：进程、网络连接、注册表、凭据、文件系统全可挖。

### 什么时候用

拿到 .raw/.mem/.vmem 内存镜像，或需要从内存里找 flag、密码、进程。

### 怎么用

**识别镜像信息（第一步永远先跑）**

```
vol -f memory.raw windows.info
```

**列进程**

```
vol -f memory.raw windows.pslist
```

**进程树**

```
vol -f memory.raw windows.pstree
```

**网络连接**

```
vol -f memory.raw windows.netscan
```

**命令行历史**

```
vol -f memory.raw windows.cmdline
```

**扫文件**

```
vol -f memory.raw windows.filescan
```

**导出文件**

```
vol -f memory.raw windows.dumpfiles --virtaddr 0x...
```

**注册表**

```
vol -f memory.raw windows.registry.hivelist
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-f` | 内存镜像文件 |
| `-o` | 输出目录 |
| `--cache-path` | 符号缓存目录（默认 APPDATA） |
| `-u / --offline` | 允许/禁止联网下载符号表 |
| `--parallelism` | 并行模式 processes/threads/off |

### 踩坑提醒

- 首次跑某系统版本会自动下载符号表，需要网络；离线环境要预置 symbols
- APPDATA 不可写时用 --cache-path 指到可写目录（本机启动脚本已处理）
- 内存镜像动辄数 GB，插件跑得慢是正常的

### 下一步

binwalk

---


<a id="deleted"></a>

## NTFS 已删除文件枚举 · deleted.py

**类型**：script  
**位置**：`06-取证/scripts/deleted.py`

> 直接解析 $MFT，列出已删除但记录还在的文件名/大小/时间。

### 什么时候用

取证要查「这个盘上原来有什么、被删了什么」。

### 怎么用

**读卷（需管理员）**

```bat
python -X utf8 deleted.py --drive D
```

**解析 MFT 镜像**

```bat
python -X utf8 deleted.py --mft MFT.dd --csv 已删除.csv
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--drive` | 盘符，如 D（需管理员权限） |
| `--mft` | MFT 镜像文件 |
| `--csv` | 输出 CSV |
| `--all` | 连在用的记录一起列出 |

### 踩坑提醒

- --drive 需要管理员权限，否则明确报错
- 只列出记录，不恢复数据；能否恢复取决于数据簇是否被覆盖
- 只支持 NTFS，FAT/exFAT 不适用

---

<a id="hexview"></a>

## 十六进制查看器 · hexview.py

**类型**：script  
**位置**：`06-取证/scripts/hexview.py`

> 看字节、跳偏移、搜十六进制/文本，带 ASCII 侧栏。

### 什么时候用

要确认某个偏移是什么、搜 flag 在哪、改文件头前先看一眼。

### 怎么用

**看开头**

```bat
python -X utf8 hexview.py 文件.bin
```

**跳偏移看一段**

```bat
python -X utf8 hexview.py 文件.bin -o 0x100 -n 512
```

**搜字节/文本**

```bat
python -X utf8 hexview.py 文件.bin -s 504b0304
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-o` | 起始偏移（支持 0x100） |
| `-n` | 显示字节数（默认 256） |
| `-s` | 搜索十六进制字节串 |
| `-t` | 搜索文本（UTF-8 与 UTF-16LE 都试） |

### 踩坑提醒

- 只读，不能改字节（改字节请用专门的编辑器）
- 超大文件搜索会全量读入内存

---

<a id="metawipe"></a>

## 元数据体检/清除 · metawipe.py

**类型**：script  
**位置**：`06-取证/scripts/metawipe.py`

> 挖出 JPEG/PNG/GIF 里的 EXIF/GPS/注释/缩略图，并可无损清除。

### 什么时候用

怀疑图片藏了 GPS/设备信息/内嵌缩略图，或发图前要去隐私。

### 怎么用

**体检**

```bat
python -X utf8 metawipe.py 图片.jpg
```

**清除并另存**

```bat
python -X utf8 metawipe.py 图片.jpg --strip -o 干净.jpg
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--strip` | 清除元数据（需配 -o） |
| `-o` | 清除后另存为这个文件 |
| `--force` | 允许覆盖已存在的输出文件 |

### 踩坑提醒

- EXIF 里的缩略图常是原图副本，能还原被裁剪掉的内容
- --strip 只删元数据段不动图像数据，所以画质无损
- 不处理 HEIC/RAW/PDF（这些用 exiftool）

---

<a id="strings"></a>

## 增强版 strings · strings.py

**类型**：script  
**位置**：`06-取证/scripts/strings.py`

> 同时扫 ASCII/UTF-8/UTF-16LE/BE 四种编码，支持正则过滤。

### 什么时候用

在内存转储、PE、图片里找 flag；系统 strings 只认 ASCII 会漏一半。

### 怎么用

**全编码扫描**

```bat
python -X utf8 strings.py 文件.bin
```

**正则过滤**

```bat
python -X utf8 strings.py 文件.bin -r "flag\{.*\}"
```

**只看 UTF-16 + 带偏移**

```bat
python -X utf8 strings.py 文件.bin --enc utf16 --with-offset
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-m` | 最短字符串长度（默认 4） |
| `-r` | 只输出匹配这个正则的 |
| `--enc` | all/ascii/utf16/utf16be/cjk |
| `--with-offset` | 显示每条的字节偏移 |

### 踩坑提醒

- 只提取连续可打印字符，被拆散的数据要先解密/解压
- UTF-16 数据不一定 2 字节对齐，脚本两种相位都扫
- 不处理 GBK 等双字节编码

---

<a id="timeline"></a>

## 文件时间线 · timeline.py

**类型**：script  
**位置**：`06-取证/scripts/timeline.py`

> 把目录下所有文件的 mtime/atime/ctime 汇总成一条可排序时间线。

### 什么时候用

要还原「先创建了哪个、后来改了什么」的操作顺序。

### 怎么用

**按修改时间排序**

```bat
python -X utf8 timeline.py 目录
```

**按访问时间**

```bat
python -X utf8 timeline.py 目录 --sort atime
```

**限时间区间 + 导出 CSV**

```bat
python -X utf8 timeline.py 目录 --since 2026-01-01 --csv 时间线.csv
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--sort` | mtime/atime/ctime |
| `--since/--until` | 时间区间过滤 |
| `--csv` | 导出 CSV 便于 Excel 分析 |

### 踩坑提醒

- Windows 的 ctime 是「创建时间」，Linux 上是「inode 变更时间」，含义不同
- 不解析 NTFS 的双时间戳（那要直接读 MFT，见 deleted.py）
- 时间戳可被程序伪造，不能作为唯一证据

---

← 返回 [工具箱总览](../README.md)
