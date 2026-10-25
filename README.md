# 杂项工具箱 · MiscBox

> CTF「杂项（Misc）」一站式工具箱 —— **一键配置环境，点开即用**。
>
> 七大分类、20 个工具，每个工具都带功能说明、使用教程和踩坑提醒。

<p align="center">
  <b>环境配置</b> · <b>编码识别</b> · <b>隐写</b> · <b>压缩包与文件修复</b> · <b>流量分析</b> · <b>取证</b> · <b>OSINT</b>
</p>

---

## 三分钟上手

```
1. 双击  _box\启动器.bat          ← 图形界面，左侧选分类
2. 点「⚙ 环境自检」              ← 检查本机缺什么，给出补装命令
3. 左侧选一个工具 → 把文件拖进窗口 → 点「▶ 运行」→ 看输出
```

**图形界面里能直接跑工具**：选中卡片后，右侧「▶ 运行」页有一个拖放区。
把文件从资源管理器拖进窗口（或点拖放区选文件），选好运行方式，点「▶ 运行」，
命令的输出会实时刷在下方面板，跑出来的文件列在下面，点「📂 输出目录」直接打开。

> 工具箱**不会自动猜该用哪个工具**——拖进来的文件只会填进你当前选中的那个工具。
> 跑错工具的代价比多点一下高得多，所以这一步留给你自己决定。

不想用图形界面也可以：

```powershell
# 环境自检（红黄绿清单 + env-report.json）
powershell -NoProfile -ExecutionPolicy Bypass -File D:\杂项工具\_box\setup.ps1

# 也可以直接跑脚本本身，用法见各分类 README
python -X utf8 03-隐写\pngcheck\...   # 例：见具体工具页
```

**没有任何工具需要安装、写注册表或改系统 PATH。** 全部是便携版，删目录即卸载。

---

## 七大分类

| # | 分类 | 什么时候来这一页 | 主力工具 |
| --- | --- | --- | --- |
| 1 | [环境配置](01-环境配置/README.md) | 第一次用、换电脑、某个工具突然打不开 | 环境自检、Python、Java |
| 2 | [编码识别](02-编码识别/README.md) | 拿到一堆不知是什么的乱码 | **CyberChef**（离线版） |
| 3 | [隐写](03-隐写/README.md) | 拿到图片/音频，肉眼看不出问题 | pngcheck、imgsize、StegSolve、ExifTool |
| 4 | [压缩包与文件修复](04-压缩包与文件修复/README.md) | 拿到压缩包（最高频） | 7-Zip、ARCHPR、john、hashcat、Perl |
| 5 | [流量分析](05-流量分析/README.md) | 拿到 `.pcap` / `.pcapng` | **Wireshark / tshark**、nmap |
| 6 | [取证](06-取证/README.md) | 固件、磁盘镜像、内存镜像 | binwalk、foremost、**Volatility 3** |
| 7 | [OSINT](07-OSINT/README.md) | 域名/邮箱/子域公开信息收集 | theHarvester |

> 每份分类文档都包含：**这一页解决什么问题** → **排查顺序** → **工具速查** → **常见陷阱**。

---

## 工具清单

### 1. 环境配置

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| 环境自检 `setup.ps1` | 1.0.0 | 一键探测运行时与全部工具是否就绪，输出红黄绿清单 |
| Python | 3.14.8 / 3.12.10 | 3.14 为主运行时（含 Pillow）；3.12 供虚拟环境底座 |
| Java (OpenJDK) | 17 | StegSolve 等 JAR 工具依赖 |

### 2. 编码识别

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| **CyberChef** | 11.5.0 离线版 | 300+ 操作，Magic 自动识别编码并链式解码 |

### 3. 隐写

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| pngcheck 套件 | 3.0.3 | PNG 结构校验、chunk 拆分、IDAT 修复、任意文件搜 PNG |
| imgsize.py | 1.0 | **反推被篡改的真实宽高**（pngcheck 会漏检的情况） |
| StegSolve | 1.4 | 逐通道/逐位平面查看、Frame Browser、Stereogram Solver |
| ExifTool | 13.59 | 读/写元数据：GPS、作者、注释、隐藏字段 |

### 4. 压缩包与文件修复

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| 7-Zip | 26.03 系统 / 24.09 便携 | 解压、诊断结构、伪加密判断 |
| ARCHPR | 4.66 | 图形界面口令恢复（字典/掩码/暴力/明文攻击） |
| john the Ripper | 1.9.0-jumbo-1 | `zip2john` / `rar2john` / `7z2john` 提取哈希 |
| hashcat | 7.1.2 | GPU 爆破，300+ 哈希类型 |
| Hashcat 面板 | 1.0 | hashcat 图形外壳，内置「压缩包 → 提取哈希」 |
| Strawberry Perl | 5.42.3.1 便携 | 跑 `7z2john.pl` / `pdf2john.pl` 等 Perl 脚本 |

### 5. 流量分析

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| **Wireshark / tshark** | 4.7.4 | 图形看包 + 命令行批量处理、导出对象、追踪流 |
| nmap | 7.992 便携 | 端口扫描、服务识别、NSE 脚本 |

### 6. 取证

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| binwalk | 2.3.4 | 文件签名扫描、自动提取、熵分析 |
| foremost | 1.5.7 | 按文件头尾雕刻恢复（binwalk 失败时兜底） |
| **Volatility 3** | 2.28.2 | 内存取证：进程、网络、注册表、凭据、文件 |

### 7. OSINT

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| theHarvester | 4.11.1 | 从公开来源收集邮箱、子域、主机、员工名 |

---

## 目录结构

```
D:\杂项工具\
├── README.md                    ← 你在这里（总览）
├── 01-环境配置\README.md         ← 自检脚本 + 运行时说明
├── 02-编码识别\README.md
│   └── CyberChef\               ← 离线版单页应用
├── 03-隐写\README.md
├── 04-压缩包与文件修复\README.md
│   └── perl\                    ← Strawberry Perl 便携版
├── 05-流量分析\README.md
│   └── nmap\                    ← nmap 便携版
├── 06-取证\README.md
│   └── volatility3\             ← 含独立 venv
├── 07-OSINT\README.md
│   └── theharvester\            ← 含独立 venv
│
├── _box\                        ← 导航层（分类是逻辑概念，不是文件夹）
│   ├── 启动器.bat                ← 图形启动器
│   ├── 检查环境.bat              ← 双击跑自检
│   ├── setup.ps1                ← 自检脚本（纯 ASCII）
│   ├── tools.json               ← ★ 唯一数据源：分类/工具/说明/运行参数全在这
│   ├── app\
│   │   ├── core.py              ← 路径解析、启动、搜索
│   │   ├── runner.py            ← 运行层：拼命令行、起进程、收输出、管产物
│   │   ├── dnd.py               ← 原生文件拖放（WM_DROPFILES，纯 stdlib）
│   │   ├── gui.py               ← tkinter 界面（运行页 / 说明页）
│   │   └── gen_docs.py          ← 从 tools.json 生成分类文档
│   ├── cache\                   ← Volatility 符号缓存等
│   └── work\                    ← 临时工作区；runs\ 下是每次运行的输出
│
├── ARCHPR\  binwalk\  foremost\  hashcat\  hashcat面板\
├── john\    pngcheck\ StegSolve\ CTF-tools\
├── _脚本\                       ← imgsize.py 等自研脚本
├── _下载包\                     ← 下载脚本（fetch.ps1 等）
├── _安装包\                     ← 留作复装用
└── _迁移记录\                   ← SHA256 清单
```

### 为什么分类不是文件夹？

工具的**物理位置不能随便挪**：

| 工具 | 约束 |
| --- | --- |
| hashcat | 必须在自己目录下跑，否则找不到 `OpenCL\` |
| foremost | 要读同目录的 `foremost.conf` |
| binwalk.bat | 用 `%~dp0..\binwalk` 定位虚拟环境 |
| Hashcat 面板 | exe 依赖同目录 `_internal\` |

所以**分类做在导航层**（`tools.json` + 启动器），文件留在原位不动。
好处：桌面快捷方式、历史命令、脚本里的硬编码路径全部继续有效。

---

## 加新工具：只改一个文件

`_box\tools.json` 是**唯一数据源**。加一条记录，界面、文档、搜索、推荐全都自动更新：

```json
{
  "id": "mytool",
  "category": "stego",
  "name": "我的工具",
  "name_en": "MyTool",
  "version": "1.0",
  "type": "cli",
  "path": "03-隐写/mytool/mytool.exe",
  "launch": { "kind": "dir", "target": "03-隐写/mytool" },
  "summary": "一句话说明这个工具干什么。",
  "when": "什么时候该用它。",
  "usage": [
    { "title": "基本用法", "code": "mytool.exe -i 输入.png" }
  ],
  "params": [ { "flag": "-i", "desc": "输入文件" } ],
  "pitfalls": ["踩过的坑写在这里"],
  "next": ["pngcheck"]
}
```

然后重新生成文档：

```powershell
C:\Users\<你>\AppData\Local\Python\pythoncore-3.14-64\python.exe -X utf8 _box\app\gen_docs.py
```

**`launch.kind` 可选值**：`exe`（直接启动）、`bat`（跑批处理）、`cli`（开命令行）、
`html`（浏览器打开）、`script`（Python 脚本）、`shell`（进交互环境）、
`powershell`（跑 ps1）、`dir`（打开目录）、`none`（仅说明，无需启动）。

---

## 让工具能在界面里直接跑：`run` 块

只配 `launch` 的话，卡片只能「打开工具」；加一个 `run` 块，它就能在运行页里
**拖文件 → 点运行 → 看输出**：

```json
"run": {
  "kind": "python",
  "input": "files",
  "accept": [".png", ".jpg"],
  "multi": false,
  "argv": ["{file}", "-o", "{outdir}/out.png"],
  "intro": "一句话说明这个运行入口干什么。",
  "cwd": "run",
  "presets": [
    { "title": "检查结构", "argv": ["-v", "{file}"] },
    { "title": "只报错",   "argv": ["-q", "{file}"] },
    { "title": "不需要文件的用法", "argv": ["--list"], "no_file": true }
  ]
}
```

| 字段 | 含义 |
| --- | --- |
| `kind` | `python` / `exe` / `bat` / `perl` |
| `input` | `files`（拖文件）/ `text`（填输入框）/ `none`（都不需要） |
| `accept` | 拖放区显示的接受扩展名，只是提示，不做强制过滤 |
| `multi` | 是否接受多文件（`true` 时 `{files}` 展开为全部路径） |
| `argv` | 参数模板；`presets` 里的 `argv` 会覆盖它 |
| `cwd` | `run`（在本次运行目录里跑，默认）/ `tool`（在工具目录里跑） |
| `presets` | 预设，界面「运行方式」下拉里一项一条 |

**占位符**（在 `argv` 里写，运行时替换成真实值）：

| 占位符 | 替换为 |
| --- | --- |
| `{file}` | 第一个文件的完整路径 |
| `{files}` | 全部文件路径（需 `multi: true`） |
| `{stem}` `{name}` `{ext}` | 文件去扩展名 / 文件名 / 扩展名 |
| `{text}` | 输入框里的内容 |
| `{outdir}` | 本次运行的输出目录 |
| `{root}` | 工具箱根目录 |
| `{args}` | 用户在界面里追加的原始参数 |
| 其他 `{xxx}` | 当成自定义字段，界面自动生成对应输入框 |

**`cwd` 什么时候要设成 `tool`**：工具要从自己目录读配置或数据的，
比如 `foremost`（找 `foremost.conf`）、`hashcat`（找 `OpenCL\`）、
`john`、`binwalk`、`volatility3`、`theharvester`。设错了会报「找不到配置文件」。

**每次运行都会新建一个目录**：`_box\work\runs\<日期时间>_<工具id>\`。
工具的产出写在这里，不污染原文件；只保留最近 40 次，自动清理旧的。
`{outdir}` 就指向它，所以 `-o {outdir}/x.png` 是标准写法。

---

## 环境要求

| 项 | 要求 | 说明 |
| --- | --- | --- |
| 系统 | Windows 10 / 11 x64 | 全部工具为 Windows 版 |
| PowerShell | 5.1 | 系统自带即可 |
| Python | 3.10+（含 tkinter） | 启动器需要；Python 官方安装包自带 Tk |
| 磁盘 | 约 3 GB | 大头是 Perl（1 GB）、hashcat（380 MB）、john、CyberChef |

**不需要**：管理员权限、系统 PATH 修改、注册表写入、联网（工具本身全离线）。

---

## 常见问题

**Q：启动器双击闪退？**
先双击 `_box\检查环境.bat`，看 `Python` 和 `tkinter` 两行是不是 `OK`。
没有 Python 就装一个 python.org 的官方包（自带 Tk）。

**Q：某个工具卡片是红点？**
红点 = 该工具的可执行文件不存在。跑一次环境自检看具体缺什么、怎么补。

**Q：`tshark` 说找不到 Npcap？**
分析 `.pcap` 文件**不需要** Npcap。只有实时抓包、nmap 的 SYN 扫描才需要，
而且 Npcap 免费版不支持静默安装，得手动点安装向导。

**Q：中文路径报错？**
少数工具（`zip2john` 等 cygwin 编译的）不支持中文路径，
先复制到 `D:\work` 这类纯 ASCII 目录再处理。
界面里跑的时候，工具的参数会带上原始路径（可能含中文），
遇到这类工具就把它复制出来再拖。

**Q：运行按钮点了没反应 / 输出区一直空着？**
先看按钮右边的状态是不是「运行中…」。有输出的工具会立刻刷内容；
个别工具（`foremost` 扫大文件、`hashcat` 跑字典）要等一会才有第一行。
要中途放弃点「■ 停止」。

**Q：`vol` 报 `unable to open database file`？**
Volatility 的符号缓存默认写在 `%APPDATA%`，不可写时会崩。
用工具箱的 `启动Volatility.bat`（已把缓存指到 `_box\cache`），
或手动加 `--cache-path D:\杂项工具\_box\cache`。

---

## 许可

本仓库的**框架、文档与脚本**以 MIT 许可发布，全文见 [LICENSE](LICENSE)。

第三方工具遵循其各自许可，详见下方清单与各分类目录的 README。本仓库不包含任何第三方二进制。

---

## 关于第三方工具

本仓库**只包含框架、文档和自动下载脚本**，不包含第三方二进制。

各工具遵循其自身许可：

| 工具 | 许可 |
| --- | --- |
| CyberChef / Volatility 3 / theHarvester / nmap | Apache-2.0 / GPL / NPSL 等，见各自仓库 |
| 7-Zip / pngcheck / foremost / binwalk | LGPL / MIT / 自定义开源许可 |
| hashcat / john the Ripper | MIT / GPL-2.0 |
| Strawberry Perl | Perl Artistic License |
| Wireshark | GPL-2.0 |

**不随仓库分发**（需自行获取，且多为商业软件）：

- `ARCHPR`（Advanced Archive Password Recovery）—— 商业软件，仅限自有题目与授权场景
- `StegSolve-1.4.jar` —— 作者未声明开源许可，请从原作者处获取
- `010Editor` —— 商业软件

**合法用途**：仅用于自己的题目、CTF 比赛、授权的安全测试与密码恢复。
不要用于他人系统或未授权的目标。

---

## 致谢

工具全部来自各自的上游作者与开源社区，本工具箱只做集成、说明与自动化。
遇到工具本身的 bug，请反馈给上游仓库。
