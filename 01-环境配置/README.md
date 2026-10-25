# 安装与配置

> 从零到能用，大约 10 分钟（其中大部分是等 Perl 下载）。

## 0. 先确认你缺什么

| 项 | 检查命令 | 期望 |
| --- | --- | --- |
| PowerShell | `$PSVersionTable.PSVersion` | 5.1 或更高 |
| Python | `python -V` | 3.10+ |
| Python 有 tkinter | `python -c "import tkinter"` | 无报错 |
| Java | `java -version` | 8+（StegSolve 需要） |
| 磁盘 | — | D 盘至少 3 GB 空闲 |

Python 一定要**官方安装包**（python.org），因为它自带 Tk。
Microsoft Store 版或精简版可能没有 tkinter，启动器就跑不起来。

## 1. 拿到代码

```powershell
# 方式一：git
git clone https://github.com/YuanYe333/Misc-box.git D:\杂项工具

# 方式二：下载 ZIP 后解压到 D:\杂项工具
```

**建议放在 D 盘**，不要放 `C:\Program Files`：部分工具会在自己目录下写缓存/配置，
放在需要管理员权限的目录会导致写入失败。

## 2. 看看现状

```powershell
cd D:\杂项工具
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

输出会告诉你每个工具装没装、哪些能自动下、哪些得手动拿：

```
============== MiscBox tools status ==============
  [MISS] CyberChef 离线版        11.5.0
  [MISS] nmap                  7.992
  [OK  ] Wireshark             4.7.4             [manual]
  [MISS] pngcheck              3.0.3             [manual]
  ...
==================================================
  installed 1 / 15   auto-downloadable missing: 9   manual: 5
```

这一步**不下载任何东西**，只是报告。

## 3. 下载工具

### 全部自动下载（会逐项问 y/N）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 -Interactive
```

### 只装某几个

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 `
  -Only cyberchef,nmap,exiftool -Interactive
```

### 全自动（不问，全部 auto=true 的都装）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 -Yes
```

**下载体积参考**：

| 工具 | 大小 | 说明 |
| --- | --- | --- |
| Strawberry Perl | ~1 GB | 最大，只为 `7z2john.pl` |
| CyberChef | 79 MB | |
| hashcat | 380 MB | 含 300+ 内核 |
| john | 50 MB | |
| ExifTool | 10 MB | |
| nmap | 30 MB | |
| Volatility 3 | ~20 MB | pip |
| theHarvester | ~40 MB | pip，含 60 个依赖 |

如果只做图片/压缩包题，先装 CyberChef + 7-Zip + ExifTool 就够了，Perl 可以最后装。

## 4. 手动补装的部分

这几个**脚本不会下**（许可或编译原因），按提示自己拿：

### StegSolve（隐写必备）

作者未声明开源许可，所以不随仓库分发。从原作者处或你信任的 CTF 资源站获取 `StegSolve-1.4.jar`，
放到 `D:\杂项工具\StegSolve\`，并在同目录建一个 `启动StegSolve.bat`：

```bat
@echo off
cd /d "%~dp0"
java -jar StegSolve-1.4.jar
```

### pngcheck（隐写必备）

上游只发布源码。两条路：

```powershell
# A. 用 MSYS2 / MinGW 自己编译
git clone https://github.com/pnggroup/pngcheck.git
cd pngcheck && make -f Makefile.win

# B. 从你信任的 CTF 工具整合包拿现成 exe，放到 D:\杂项工具\pngcheck\
```

### foremost（取证）

同样只有源码，需要 MinGW 编译：

```powershell
git clone https://github.com/korczis/foremost.git
cd foremost
make
```

编译出的 `foremost.exe` 要和 `foremost.conf` 放在同一目录。

### binwalk（取证）

Windows 上装 binwalk 需要打补丁（上游对 Windows 支持不完整）。
详见 [06-取证.md](../06-取证/README.md) 里的 binwalk 章节。

### Wireshark（流量分析）

```powershell
# 下载后手动运行安装程序（需要管理员）
# https://www.wireshark.org/download.html
```

安装时会一并装 Npcap（实时抓包驱动）。**免费版 Npcap 不支持静默安装**，
必须点安装向导。只分析 pcap 文件的话，跳过 Npcap 也没关系。

### ARCHPR（压缩包）

商业软件，需自行购买。没有它也能做压缩包题——用 john + hashcat 路线，
或用 Hashcat 面板。

## 5. 验证

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File _box\setup.ps1
```

看到 `miss=0`（或只剩你确定不需要的项）就说明装好了。

```
================ MiscBox environment ================
  root: D:\杂项工具
  ok=26  warn=1  miss=0
=====================================================
```

## 6. 开始用

```powershell
# 图形界面
double-click _box\启动器.bat
```

界面操作：

| 位置 | 作用 |
| --- | --- |
| 左侧分类 | 按用途过滤工具 |
| 搜索框 | 搜工具名、功能、参数（如搜 `-m` 能搜到 hashcat） |
| 卡片 | 单击看详情，**双击直接启动** |
| 红点 / 绿点 | 该工具文件在不在 |
| 「📎 选择文件推荐工具」 | 选一个题目文件，自动推荐该用哪些工具、什么顺序 |
| 「⚙ 环境自检」 | 左下角，跑 setup.ps1 |

## 常见安装问题

**Q：脚本报「无法加载文件，未对文件进行数字签名」**

PowerShell 执行策略限制。用 `-ExecutionPolicy Bypass`（本仓库所有命令都带了），
或一次性放开：

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**Q：`setup.ps1` 报奇怪的语法错误**

如果你改过脚本并加了中文，**必须存成 UTF-8 with BOM**。
PS 5.1 读无 BOM 的 `.ps1` 时按 GBK 解码，中文会把后面的引号/括号吃掉，
报出来的错误行号往往和真正的问题无关。原始脚本是纯 ASCII 的，就是为了避开这个坑。

**Q：下载卡住或很慢**

GitHub 直连在国内经常只有 20 KB/s。`fetch.ps1` 在失败时会自动换镜像
（`ghfast.top` / `gh-proxy.com`）。也可以手动：

```powershell
.\scripts\fetch.ps1 -Url "https://github.com/..." -Out "D:\杂项工具\_下载包\x.zip" -Proxy
```

**Q：pip 装 Volatility 3 / theHarvester 失败**

脚本默认用清华镜像。如果还是失败，检查：

1. Python 版本是否 ≥ 3.10
2. 是否有网络代理干扰
3. 手动重试：
   ```powershell
   D:\杂项工具\06-取证\volatility3\venv\Scripts\python.exe -m pip install volatility3 `
     -i https://pypi.tuna.tsinghua.edu.cn/simple
   ```

**Q：theHarvester 首次运行报 PermissionError**

它要在 `%USERPROFILE%\.theHarvester` 和 `%USERPROFILE%\.local\share\theHarvester` 建目录。
`启动theHarvester.bat` 会自动建；直接跑 `theHarvester.exe` 则会失败。

**Q：`vol` 报 `unable to open database file`**

Volatility 的符号缓存默认写 `%APPDATA%\volatility3`。
用 `启动Volatility.bat`（已把 `APPDATA` 指到 `_box\cache`），
或手动加 `--cache-path`。

## 卸载

删掉整个目录即可。**没有任何注册表项、服务或系统 PATH 修改**，
所以卸载就是删文件夹。

例外：如果你自己跑了 Wireshark 安装程序，它会在「应用和功能」里留一条记录，
从那里正常卸载。

---

# 一、环境配置（工具说明）
> 工具箱开箱第一站。所有其他分类的工具能不能跑，取决于这一页的自检结果。

## 这一页解决什么问题

拿到一台新电脑、重装系统、或者某个工具突然双击没反应时，**先跑环境自检**，
它会告诉你「哪个组件缺了、缺的到底是什么、该怎么补」，而不是让你一个个试。

## 目录结构

| 路径 | 内容 |
| --- | --- |
| `_box\setup.ps1` | 环境自检脚本（纯 ASCII，输出红黄绿清单 + `env-report.json`） |
| `_box\检查环境.bat` | 双击即跑自检并停留窗口 |
| `_box\启动器.bat` | 图形启动器入口 |
| `_box\tools.json` | **唯一数据源**：所有分类、工具、路径、说明都在这里 |

## 自检覆盖的内容

- **运行时**：Python 3.14（主）/ 3.12（虚拟环境底座）、Pillow、tkinter、Java、Node
- **工具就位**：按分类逐项检查可执行文件是否存在
- **可写目录**：theHarvester / Volatility 需要的配置目录（首次运行会自动创建）
- **驱动**：Npcap 是否安装（只有实时抓包需要，分析 pcap 文件不需要）

## 自检的三种跑法

```powershell
# 1. 完整清单（人看）
powershell -NoProfile -ExecutionPolicy Bypass -File D:\杂项工具\_box\setup.ps1

# 2. 只看问题项
powershell -NoProfile -ExecutionPolicy Bypass -File D:\杂项工具\_box\setup.ps1 -Quiet

# 3. JSON 输出（给脚本/CI 用）
powershell -NoProfile -ExecutionPolicy Bypass -File D:\杂项工具\_box\setup.ps1 -Json
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
| 中文路径下 Perl 的 XS 模块加载失败 | 非 ASCII 路径 + PATH 缺 `perl\bin` | 两个 `bin` 都加进 PATH；必要时用 ASCII 目录联接 |
| `vol` 报 `unable to open database file` | `%APPDATA%` 不可写 | 启动脚本已把 `APPDATA` 指到 `_box\cache` |

## 怎么补装（按需，逐条执行）

```powershell
# Pillow（图片处理）
$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe -m pip install pillow ^
  -i https://pypi.tuna.tsinghua.edu.cn/simple

# Volatility 3
C:\Python312\python.exe -m venv D:\杂项工具\06-取证\volatility3\venv
D:\杂项工具\06-取证\volatility3\venv\Scripts\python.exe -m pip install volatility3 ^
  -i https://pypi.tuna.tsinghua.edu.cn/simple

# theHarvester（必须从源码装，PyPI 上的是抢注空壳）
... -m pip install https://github.com/laramies/theHarvester/archive/refs/tags/4.11.1.tar.gz
```

## 关于中文路径（`D:\杂项工具`）

**结论先说：中文路径本身不影响工具运行。** 本机实测：在 `D:\杂项工具\06-取证\`
下直接用 `python -m venv` 建的虚拟环境，`tempfile.gettempdir()` 返回正常，
`sqlite3` 能建库，Volatility 3 和 theHarvester 都能跑。

`pyvenv.cfg` 里那行 `command = ... -m venv D:\鏉傞」宸ュ叿\...` 看起来像乱码，
但那只是该文件里**路径的显示形式**（创建时按控制台代码页写入），
Python 运行时不靠这行定位，所以**看到乱码不等于坏了**，不用去修它。

判断一个 venv 是否健康，看实际行为而不是看 `pyvenv.cfg`：

```powershell
# 应输出 $env:TEMP（即 C:\Users\<你的用户名>\AppData\Local\Temp）
# 若输出的是工具箱目录本身，才是真的坏了
D:\杂项工具\06-取证\volatility3\venv\Scripts\python.exe -c "import tempfile; print(tempfile.gettempdir())"
```

如果确实遇到 `tempfile` 指向工作目录、`sqlite3.OperationalError: unable to open
database file` 这类症状，再按下面处理（把 venv 实体放到英文路径 + junction 挂回）：

```powershell
# 1. 在英文路径建 venv
C:\Python312\python.exe -m venv D:\miscbox-venvs\volatility3
D:\miscbox-venvs\volatility3\Scripts\python.exe -m pip install volatility3 ^
  -i https://pypi.tuna.tsinghua.edu.cn/simple

# 2. 原中文路径的 venv 改名备份（确认新 venv 可用后再删）
Rename-Item 'D:\杂项工具\06-取证\volatility3\venv' 'venv_old_cnpath'

# 3. 建 junction（不需要管理员）
cmd /c mklink /J "D:\杂项工具\06-取证\volatility3\venv" "D:\miscbox-venvs\volatility3"

# 4. 验证
D:\杂项工具\06-取证\volatility3\venv\Scripts\python.exe -c "import tempfile; print(tempfile.gettempdir())"
```

> **如果想让工具箱更省心**：放在纯英文路径（如 `D:\miscbox`）能少一类问题，
> 但这是可选项，不是必须。中文路径在实测中工作正常。

**Volatility 3 的符号缓存**默认写到 `%APPDATA%\volatility3\`
（`$env:APPDATA\volatility3\`）。首次运行会生成
`identifier.cache`；若该目录不可写，才会出现 `unable to open database file`。
可以用 `--cache-path` 指定别处。

## 下一步

自检全绿之后，按题目类型进入对应分类：拿到乱码去 **编码识别**，拿到图片去 **隐写**，
拿到压缩包去 **压缩包与文件修复**。

## 本分类工具一览

| 工具 | 版本 | 一句话说明 |
| --- | --- | --- |
| [环境自检](#setup) | 1.0.0 | 一键探测本机运行时与全部工具是否就绪，输出红黄绿清单并生成环境报告。 |
| [Python 运行时](#python-runtime) | 3.14.8 / 3.12.10 | 工具箱内自研脚本与 Python 系工具的基础运行时，两个版本并存。 |
| [Java 运行时](#java-runtime) | 17 | StegSolve、部分 JAR 版工具的依赖。 |

---

<a id="setup"></a>

## 环境自检 · MiscBox Setup

**版本**：1.0.0  
**类型**：internal  
**位置**：`_box/setup.ps1`

> 一键探测本机运行时与全部工具是否就绪，输出红黄绿清单并生成环境报告。

### 什么时候用

第一次使用工具箱、换电脑、重装系统、或某个工具突然打不开时。

### 怎么用

**图形方式**

1. 双击 _box\启动器.bat
2. 左侧点「环境配置」→ 卡片「环境自检」→「打开工具」
3. 或直接双击 _box\检查环境.bat

**命令行**

```
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\杂项工具\_box\setup.ps1"
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-Fix` | 对可自动补齐的缺失项执行安装（会逐项询问） |
| `-Json` | 以 JSON 输出，便于脚本消费 |
| `-Quiet` | 只输出问题项，不打印全量清单 |

### 踩坑提醒

- 本机 PowerShell 执行策略较严，.ps1 需用 -ExecutionPolicy Bypass 运行
- 脚本正文含中文时务必保存为 UTF-8 with BOM，否则 PS 5.1 按 GBK 读会报语法错误
- pip 自我升级（pip install --upgrade pip）在本机曾出现长时间空转，建议跳过

---

<a id="python-runtime"></a>

## Python 运行时 · Python

**版本**：3.14.8 / 3.12.10  
**类型**：runtime  
**位置**：`%LOCALAPPDATA%/Python/pythoncore-3.14-64/python.exe`

> 工具箱内自研脚本与 Python 系工具的基础运行时，两个版本并存。

### 什么时候用

运行 _脚本/imgsize.py、CyberChef 之外的本地 Python 工具时。

### 怎么用

**3.14（主运行时，含 Pillow）**

```
python -X utf8 脚本.py
```

**3.12（供 binwalk/volatility3/theHarvester 虚拟环境）**

```
python -V
```

### 踩坑提醒

- 调用 Python 脚本务必加 -X utf8，否则中文路径与中文输出会乱码
- 不要把 binwalk 装进系统 Python，它有自己的独立虚拟环境

---

<a id="java-runtime"></a>

## Java 运行时 · OpenJDK

**版本**：17  
**类型**：runtime  
**位置**：`C:/Program Files/Microsoft/jdk-17.0.20.101-hotspot/bin/java.exe`

> StegSolve、部分 JAR 版工具的依赖。

### 什么时候用

StegSolve 双击无反应，或提示找不到 java 时。

### 怎么用

**验证**

```
java -version
```

### 踩坑提醒

- StegSolve 需要 Java 8+，本机 17 可用

---


← 返回 [工具箱总览](../README.md)
