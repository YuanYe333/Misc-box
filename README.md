# MiscBox · 杂项工具箱

> CTF「杂项（Misc）」一站式工具箱：**一键配置环境，点开即用**。
>
> 七大分类 · 20 个工具 · 每个工具都带功能说明、使用教程和踩坑提醒。

**环境配置** · **编码识别** · **隐写** · **压缩包与文件修复** · **流量分析** · **取证** · **OSINT**

---

## 这个仓库是什么

只放**框架 + 文档 + 自动下载脚本**，不放第三方二进制（体积太大，且许可各异）。

下载本仓库后跑一个脚本，工具会从各自官方源拉到本地；然后双击启动器就能用。

> 下面的 `YOUR-NAME` 是占位符，换成你实际 fork 或 clone 的仓库地址即可。
> 如果只是本地使用，也可以直接下载 ZIP 解压，跳过 git。

```
git clone https://github.com/YOUR-NAME/miscbox.git D:\杂项工具
cd D:\杂项工具
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

`bootstrap.ps1` 会：

1. 检查 Python / Java / 磁盘空间
2. 列出所有需要下载的工具（含官方 URL 与 SHA256）
3. **逐项询问**确认后才下载（默认全部跳过，不会静默安装）
4. 下载完自动解包到对应分类目录
5. 跑一次环境自检，输出红黄绿清单

---

## 快速开始

### 方式 A：只想要框架（自己已有工具）

```powershell
git clone https://github.com/YOUR-NAME/miscbox.git D:\杂项工具
# 把你的工具按分类目录放进去，或用 tools.json 指向已有路径
double-click D:\杂项工具\_box\启动器.bat
```

启动器会告诉你哪些工具缺失（红点），缺的可以手动补，也可以跑 bootstrap。

### 方式 B：从零一键配置

```powershell
git clone https://github.com/YOUR-NAME/miscbox.git D:\杂项工具
cd D:\杂项工具
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 -Interactive
```

### 方式 C：先看环境再决定

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File _box\setup.ps1
```

输出示例：

```
================ MiscBox environment ================
  root: D:\杂项工具
  ok=26  warn=1  miss=0
=====================================================

--- RUNTIME ---
  [OK  ] Python 3.14 (main runtime)
         Python 3.14.8  C:\...\python.exe
  [OK  ] tkinter (launcher GUI)
         Tk 9.0
--- STEGO ---
  [OK  ] pngcheck suite
         D:\杂项工具\pngcheck\pngcheck.exe
--- TRAFFIC ---
  [WARN] Npcap (live capture driver)
         not installed - pcap FILE analysis still works
```

---

## 七大分类

| # | 分类 | 什么时候用 | 主力工具 |
| --- | --- | --- | --- |
| 1 | 环境配置 | 第一次用、换电脑、工具打不开 | 环境自检、Python、Java |
| 2 | 编码识别 | 拿到一堆不知是什么的乱码 | **CyberChef**（离线版） |
| 3 | 隐写 | 图片/音频肉眼看不出问题 | pngcheck、imgsize、StegSolve、ExifTool |
| 4 | 压缩包与文件修复 | 拿到压缩包（最高频） | 7-Zip、ARCHPR、john、hashcat、Perl |
| 5 | 流量分析 | 拿到 `.pcap` / `.pcapng` | **Wireshark / tshark**、nmap |
| 6 | 取证 | 固件、磁盘镜像、内存镜像 | binwalk、foremost、**Volatility 3** |
| 7 | OSINT | 域名/邮箱/子域公开信息收集 | theHarvester |

每份分类文档都包含：**这一页解决什么问题** → **排查顺序** → **工具速查** → **常见陷阱**。

---

## 工具清单与获取方式

| 工具 | 版本 | 分类 | 许可 | 自动下载 |
| --- | --- | --- | --- | --- |
| CyberChef | 11.5.0 | 编码识别 | Apache-2.0 | ✅ |
| Wireshark + Npcap | 4.7.4 | 流量分析 | GPL-2.0 | ⚠️ 需手动点安装向导 |
| Volatility 3 | 2.28.2 | 取证 | VSL | ✅ pip |
| theHarvester | 4.11.1 | OSINT | GPL-2.0 | ✅ pip |
| nmap | 7.992 | 流量分析 | NPSL | ✅ |
| Strawberry Perl | 5.42.3.1 | 压缩包 | Artistic | ✅ |
| 7-Zip | 26.03 | 压缩包 | LGPL | ✅ |
| hashcat | 7.1.2 | 压缩包 | MIT | ✅ |
| john the Ripper | 1.9.0-jumbo-1 | 压缩包 | GPL-2.0 | ✅ |
| binwalk | 2.3.4 | 取证 | MIT | ✅ pip |
| foremost | 1.5.7 | 取证 | 自定义 | ⚠️ 需自行编译 |
| pngcheck | 3.0.3 | 隐写 | 自定义 | ⚠️ 需自行编译 |
| ExifTool | 13.59 | 隐写 | Perl Artistic | ✅ |
| StegSolve | 1.4 | 隐写 | 未声明 | ❌ 自行获取 |
| ARCHPR | 4.66 | 压缩包 | 商业 | ❌ 自行购买 |

> `❌` 和 `⚠️` 的项会在 bootstrap 时打印说明与官方链接，不会尝试下载。

---

## 目录结构

```
miscbox/
├── README.md                 ← 你在这里
├── LICENSE
├── .gitignore
├── 01-环境配置\README.md      ← 安装指南 + 自检说明
├── 02-编码识别\README.md      ← 每份含：功能说明 + 排查顺序 + 教程 + 踩坑
├── 03-隐写\README.md
├── 04-压缩包与文件修复\README.md
├── 05-流量分析\README.md
├── 06-取证\README.md
└── 07-OSINT\README.md
├── _box/                     ← 导航层
│   ├── 启动器.bat             ← 图形启动器
│   ├── 检查环境.bat
│   ├── setup.ps1             ← 环境自检（纯 ASCII）
│   ├── tools.json            ← ★ 唯一数据源
│   └── app/
│       ├── core.py
│       ├── gui.py
│       └── gen_docs.py
└── scripts/                  ← 自动下载
    ├── bootstrap.ps1         ← 总入口，逐项询问
    ├── fetch.ps1             ← 通用下载器（重试 + .part + SHA256）
    └── tools-manifest.json   ← 下载清单：URL / SHA256 / 解包方式
```

工具下载后落在：

```
01-环境配置\  02-编码识别\CyberChef\  03-隐写\  04-压缩包与文件修复\
05-流量分析\nmap\  06-取证\  07-OSINT\
```

---

## 加新工具

`_box/tools.json` 是唯一数据源。加一条记录，界面、文档、搜索、推荐全都自动更新：

```json
{
  "id": "mytool",
  "category": "stego",
  "name": "我的工具",
  "version": "1.0",
  "type": "cli",
  "path": "03-隐写/mytool/mytool.exe",
  "launch": { "kind": "dir", "target": "03-隐写/mytool" },
  "summary": "一句话说明这个工具干什么。",
  "when": "什么时候该用它。",
  "usage": [{ "title": "基本用法", "code": "mytool.exe -i 输入.png" }],
  "params": [{ "flag": "-i", "desc": "输入文件" }],
  "pitfalls": ["踩过的坑写在这里"],
  "next": ["pngcheck"]
}
```

再重新生成文档：

```powershell
python -X utf8 _box\app\gen_docs.py
```

---

## 环境要求

| 项 | 要求 |
| --- | --- |
| 系统 | Windows 10 / 11 x64 |
| PowerShell | 5.1（系统自带） |
| Python | 3.10+，**必须含 tkinter** |
| 磁盘 | 约 3 GB（Perl 1 GB + hashcat 380 MB + 其余） |
| 权限 | 普通用户即可，**不需要管理员** |

**不需要**：系统 PATH 修改、注册表写入、联网（工具跑起来后全离线）。

---

## 常见问题

**启动器闪退？**
跑 `_box\检查环境.bat`，看 `Python` 与 `tkinter` 是否 `OK`。没有就装 python.org 官方包（自带 Tk）。

**卡片是红点？**
该工具可执行文件不存在。跑环境自检看缺什么，或 `bootstrap.ps1` 补装。

**`tshark` 说找不到 Npcap？**
分析 `.pcap` 文件不需要 Npcap。只有实时抓包和 nmap SYN 扫描需要，且免费版不支持静默安装。

**中文路径报错？**
少数 cygwin 编译的工具（`zip2john` 等）不支持中文路径，先复制到 `D:\work` 这类纯 ASCII 目录。

**`vol` 报 `unable to open database file`？**
符号缓存默认写 `%APPDATA%`。用 `启动Volatility.bat`（已指到 `_box\cache`），或加 `--cache-path`。

---

## 合法用途

仅用于**自己的题目、CTF 比赛、授权的安全测试与密码恢复**。
不要用于他人系统或未授权的目标。使用者对自己的行为负责。

---

## 许可

本仓库的**框架、文档、脚本**以 MIT 许可发布（见 [LICENSE](LICENSE)）。

第三方工具遵循其各自许可，详见各分类目录下 `README.md` 中每个工具的说明与上方清单。
本仓库不包含任何第三方二进制。

---

## 致谢

工具全部来自各自的上游作者与开源社区，本项目只做集成、说明与自动化。
遇到工具本身的 bug，请反馈给上游仓库。
