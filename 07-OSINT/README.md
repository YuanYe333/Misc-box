# 七、OSINT

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
D:\杂项工具\07-OSINT\theharvester\启动theHarvester.bat

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
& 'C:\Program Files\Git\usr\bin\openssl.exe' s_client -connect example.com:443 -servername example.com
```

## 常见 CTF OSINT 套路

| 题目给的信息 | 思路 |
| --- | --- |
| 一张照片 | 元数据 GPS → 地图定位；建筑/路牌识别 |
| 一个用户名 | 跨平台搜同名账号（GitHub、微博、贴吧等） |
| 一个域名 | crt.sh 找子域、WHOIS 找注册人、DNS TXT 找验证串 |
| 一段文字 | 搜索原文找来源、翻译、找发布者 |
| 一个邮箱 | 反查注册过的平台、GitHub commit 里的作者邮箱 |

### 拿到照片先做这三步

1. **读元数据**：`exiftool 照片.jpg`（ExifTool 在「隐写」分类里）。
   重点看 `GPS Latitude` / `GPS Longitude` / `Create Date` / `Software`。
   很多题的答案直接就是 GPS 坐标。
2. **GPS 转可读地址**：把十进制度数粘到地图（Google Maps / OpenStreetMap）搜索框。
   注意 ExifTool 输出是 `deg min sec` 格式时，要先换算成十进制。
3. **没有 GPS 就看画面**：路牌文字、车牌制式、插座形状、店招语言、太阳角度。

### 拿到域名按这个顺序查

```powershell
# 1. 证书透明度日志：找所有签发过证书的子域，最有效
#    浏览器打开 https://crt.sh/?q=example.com&output=json

# 2. DNS 记录：TXT 里常藏 SPF / 验证串 / flag
nslookup -type=TXT example.com
nslookup -type=MX example.com
nslookup -type=NS example.com

# 3. HTTP 头：看服务器、框架、CDN
curl.exe -sSI https://example.com

# 4. 证书主体：看组织名、备用域名
& 'C:\Program Files\Git\usr\bin\openssl.exe' s_client -connect example.com:443 -servername example.com 2>&1 | Select-String 'subject=|DNS:'
```

### 用户名 / 邮箱怎么追

- **同名账号**：把用户名分别拼到各平台域名后直接访问（`github.com/<name>`、
  `weibo.com/<name>`），或用 namechk 类聚合站。**注意**：只查公开主页，不尝试登录。
- **邮箱溯源**：GitHub 上搜 `author:<email>` 能找到该邮箱提交过的仓库；
  仓库的 `git log` 里作者邮箱常是真实工作邮箱。
- **头像反查**：同一张头像在多个平台复用时，用图片反向搜索能串起账号。

### CTF 里最常见的三种答案形态

1. **flag 藏在元数据里**：`exiftool` 直接读出来。
2. **flag 藏在公开页面**：题目给一个域名/账号，去对应平台主页的简介、历史 commit、
   issue 评论里找。
3. **flag 藏在时间线**：题目给若干时间戳，去对应平台的发布记录里定位那条内容。

## 公开数据源速查

| 用途 | 地址 | 说明 |
| --- | --- | --- |
| 子域枚举 | `crt.sh` | 证书透明度日志，免费无需 key，最推荐 |
| 子域补充 | `otx.alienvault.com` | 被动 DNS 历史 |
| URL 扫描历史 | `urlscan.io` | 查某域名被扫过的页面快照 |
| 域名注册 | `whois` 网页版 | 注册人、注册时间、DNS 服务器 |
| 网页存档 | `web.archive.org` | 查已删除页面的历史快照 |
| DNS 全家桶 | `dnsdumpster.com` | 图形化 DNS 关系 |
| 邮箱格式验证 | `hunter.io` 免费额度 | 企业邮箱格式规律 |

⚠️ 这些站点多数需要联网。**CTF 断网环境**下，优先用本地能做的：
`nslookup`、`exiftool`、`openssl s_client`、`curl -I`。

## 常见陷阱

1. **首次运行报权限错误**：theHarvester 要在 `~/.theHarvester` 和 `~/.local/share/theHarvester` 建目录，
   工具箱启动脚本已预建，若手动跑 `theHarvester.exe` 可能触发。
2. **部分数据源需要 playwright 浏览器内核**：首次用 `playwright install chromium`。
3. **免费数据源结果少**：`duckduckgo` 经常被限流，多用 `crtsh`。
4. **结果里的邮箱要二次验证**：theHarvester 的结果包含推测值，不是全部真实。

## 下一步

收集到的子域/主机 → 授权范围内可用 **流量分析** 里的 nmap 做端口确认。

## 本分类工具一览

| 工具 | 版本 | 一句话说明 |
| --- | --- | --- |
| [theHarvester](#theharvester) | 4.11.1 | 从公开来源收集域名相关的邮箱、子域、主机、员工名。 |
| [IP 地理位置查询](#geoip) | 1.0 | IP 归属地查询，优先本地 mmdb，离线不外传。 |
| [Shodan/FOFA 导出解析](#shodanparse) | 1.0 | Shodan/FOFA 导出离线聚合：端口、国家、产品、CVE。 |
| [用户名跨平台核查](#socmint) | 1.0 | 跨平台用户名存在性核查，不确定时如实标注。 |
| [域名/IP 归属查询](#whois) | 1.0 | 域名/IP 注册信息查询，支持离线解析 whois 存档。 |

---

<a id="theharvester"></a>

## theHarvester · theHarvester

**版本**：4.11.1  
**类型**：cli  
**位置**：`07-OSINT/theharvester/venv/Scripts/theHarvester.exe`

> 从公开来源收集域名相关的邮箱、子域、主机、员工名。

### 什么时候用

OSINT 题要给目标域名做信息面梳理，或授权测试的侦察阶段。

### 怎么用

**基础收集**

```
theHarvester -d example.com -b duckduckgo,crtsh
```

**子域为主**

```
theHarvester -d example.com -b crtsh,anubis -l 200
```

**输出文件**

```
theHarvester -d example.com -b duckduckgo -f 结果
```

### 界面里怎么跑

公开信息收集。填域名。仅用于授权目标。

选中后在「输入内容」框里填数据，点「▶ 运行」。

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 全源收集 | `-d {text} -b all` |
| 只搜子域 | `-d {text} -b duckduckgo` |
| 限制结果数 | `-d {text} -b all -l 200` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-d` | 目标域名 |
| `-b` | 数据源（duckduckgo/crtsh/anubis/otx/urlscan...） |
| `-l` | 结果数量上限 |
| `-f` | 输出文件名（生成 .html/.json/.xml） |

### 踩坑提醒

- 首次运行会在 ~/.theHarvester 与 ~/.local/share/theHarvester 建配置与数据库，目录权限不足会报错（工具箱已预置）
- 很多数据源需要 API key，在 ~/.theHarvester/api-keys.yaml 里填
- 部分源依赖 playwright 浏览器内核，首次用需 playwright install
- 仅用于公开信息收集与授权场景

---


<a id="geoip"></a>

## IP 地理位置查询 · geoip.py

**类型**：script  
**位置**：`07-OSINT/scripts/geoip.py`

> 查 IP 的国家、城市、ISP、ASN：自动找本地 .mmdb 离线库，找不到才降级在线 API。

### 什么时候用

有一批 IP 想知道它们在地理上分布在哪，或者想确认某个 IP 是不是来自某国。

### 怎么用

**用本地离线库查（不外发数据）**

```bat
python -X utf8 geoip.py 8.8.8.8 --db GeoLite2-City.mmdb
```

**批量查一批 IP 并输出 JSON**

```bat
python -X utf8 geoip.py --batch ips.txt --db Country.mmdb --json
```

**先看库的元数据确认能用**

```bat
python -X utf8 geoip.py --db Country.mmdb --info
```

### 界面里怎么跑

填 IP。有本地 .mmdb 库就离线查，没有会降级在线并明确提示。

选中后在「输入内容」框里填数据，点「▶ 运行」。

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 查单个 IP | `{text}` |
| 批量查（填文件路径或拖文件） | `--batch {file}` |
| 看本机离线库状态 | `--info` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--db` | 本地 MaxMind .mmdb 路径，给了就走离线（推荐） |
| `--api` | 在线接口：ip-api（默认）或 ipinfo |
| `--batch` | 从文件批量读 IP，每行一个，# 开头为注释 |
| `--info` | 只打印 mmdb 元数据后退出 |
| `--timeout` | 在线请求超时秒数，默认 10 |
| `--delay` | 在线批量查询间隔，默认 1.5 秒 |

### 踩坑提醒

- mmdb 是二进制格式，标准库没有解析器，脚本自己实现了读取；只支持 MaxMind 的 .mmdb，IP2Location 的 .bin 和纯真库的 .dat 一律不支持，会明确报错而不是硬猜。
- GeoLite2-Country 库里只有国家和少量大洲信息，查不到城市、经纬度是正常的（没这个数据，不是解析失败）；要城市级信息得用 GeoLite2-City。
- 不带 --db 时会把要查的 IP 发给 ip-api.com / ipinfo.io 这类第三方，敏感目标请自备离线库；脚本运行前会往 stderr 打一行警告。
- 内网/保留地址（10.x、192.168.x、127.x）在任何 GeoIP 库里都是查不到的，脚本会直接说明而不去调在线 API 浪费额度。
- IP 地理位置是「注册地/出口地」不是「人在哪」，用代理或 CDN 时完全不准，CTF 里只能当线索不能当证据。

---

<a id="shodanparse"></a>

## Shodan/FOFA 导出解析 · shodanparse.py

**类型**：script  
**位置**：`07-OSINT/scripts/shodanparse.py`

> 离线统计 Shodan、FOFA 导出的资产表：端口、国家、产品、CVE、证书主体分布，可按端口或 CVE 过滤。

### 什么时候用

题目或渗透测试给了 Shodan/FOFA 导出的 JSON，需要快速看清资产面而不是一条条翻。

### 怎么用

**看整体资产画像**

```bat
python -X utf8 shodanparse.py shodan.json --top 15
```

**筛出开了 22 端口的主机并导出 CSV**

```bat
python -X utf8 shodanparse.py export.json --port 22 --csv -o hosts.csv
```

**查哪些主机受某 CVE 影响**

```bat
python -X utf8 shodanparse.py export.json --cve CVE-2021-44228
```

### 界面里怎么跑

解析 Shodan 导出的 JSON，聚合端口/产品/漏洞。

把文件拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.json`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 总览 | `{file}` |
| 只看主机列表 | `{file} --hosts` |
| 导出 CSV | `{file} --csv {outdir}/shodan.csv` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--port` | 按端口过滤，支持单值或范围如 80,443,8000-8100 |
| `--cve` | 按 CVE 编号过滤，只留 vulns 里含该编号的主机 |
| `--csv` | 导出 CSV（Excel 可直接打开，带 BOM 不乱码） |
| `--hosts` | 只列出主机清单（IP/端口/产品） |
| `--json` | 输出结构化 JSON |
| `--top` | 分布榜取前 N 条，默认 15 |

### 踩坑提醒

- Shodan 导出有三种形态：JSON 数组、JSONL（每行一个对象）、以及带 matches 包装的字典；格式不对会直接报错并提示是哪一种，别手工改文件。
- FOFA 的导出是 fields 数组加 results 二维数组，字段顺序由 fields 决定，脚本会按 fields 建映射；改了 fields 顺序仍能正确解析，但删掉字段会导致对应列为空。
- vulns 字段是「CVE 编号 → 详情」的字典，只出现在付费账号的导出里；免费账号没有这个字段，所以 --cve 查不到不代表没有漏洞。
- 同一 IP 的多个端口算多条记录，统计主机数要看「独立主机」而不是「记录数」，否则会高估资产规模。

---

<a id="socmint"></a>

## 用户名跨平台核查 · socmint.py

**类型**：script  
**位置**：`07-OSINT/scripts/socmint.py`

> 查一个用户名在 GitHub、GitLab、Reddit、Keybase、npm 等平台是否注册过。

### 什么时候用

CTF 里拿到一个昵称或 ID，想快速知道这个人在哪些技术平台留过痕迹。

### 怎么用

**查全部平台**

```bat
python -X utf8 socmint.py someuser
```

**只查能给出确定结论的几个**

```bat
python -X utf8 socmint.py someuser --sites github,gitlab,keybase,npm --json
```

**先看支持哪些平台**

```bat
python -X utf8 socmint.py --list
```

### 界面里怎么跑

填用户名，只发 HEAD 请求检查各平台是否存在。

选中后在「输入内容」框里填数据，点「▶ 运行」。

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 查全部平台 | `{text}` |
| 只查常见几个 | `{text} --sites github,reddit,keybase` |
| 列出支持的平台 | `--list` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--sites` | 逗号分隔的平台名，默认全部（--list 可看名字） |
| `--timeout` | 单次请求超时秒数，默认 8 |
| `--delay` | 平台间隔秒数，默认 1.0，不能小于 1.0 |
| `--json` | 输出结构化 JSON |
| `--list` | 列出支持的平台后退出 |
| `-o/--output` | 写入文件，已存在需加 --force |

### 踩坑提醒

- Twitter/X、Instagram、Telegram 未登录时对「任意用户名」都返回 200 或跳登录页，靠状态码必然误判；脚本对这三个平台只报「不确定」，这是故意的，别当成漏报去改代码。
- 三种状态要分清：存在、不存在、不确定（被限流/超时/平台无法区分）。「不确定」不等于「没有这个人」。
- GitHub 匿名 API 每小时只有 60 次额度，批量查会 403；此时脚本报「不确定」而不是「不存在」。
- npm 没有公开的查用户接口（官方 /-/user/ 端点恒回 401），脚本改查「该用户名是不是某个包的维护者」，因此从不发包的用户查不到，会显示不存在。
- 平台之间有强制 1 秒间隔且串行执行，查满 10 个平台至少要 10 秒以上，慢是正常的（避免被封）。
- 同名不等于同一个人，结论必须结合其他线索；本脚本仅用于公开信息查询，不要用于骚扰或跟踪他人。

---

<a id="whois"></a>

## 域名/IP 归属查询 · whois.py

**类型**：script  
**位置**：`07-OSINT/scripts/whois.py`

> 查域名或 IP 的注册人、注册商、注册/到期时间，支持 WHOIS 与 RDAP 双通道和 ASN 归属。

### 什么时候用

题目给了一个域名或 IP，想知道它属于谁、什么时候注册的、解析到哪个网段。

### 怎么用

**查域名注册信息**

```bat
python -X utf8 whois.py example.com
```

**查 IP 的归属网段与 ASN**

```bat
python -X utf8 whois.py 8.8.8.8
```

**WHOIS 被墙时改走 RDAP**

```bat
python -X utf8 whois.py example.com --rdap --json
```

### 界面里怎么跑

填域名或 IP。TCP 43 被封时用「走 RDAP」。

选中后在「输入内容」框里填数据，点「▶ 运行」。

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| WHOIS 查询 | `{text}` |
| 走 RDAP（HTTPS，更通） | `{text} --rdap` |
| 只看原始响应 | `{text} --raw` |
| 离线解析已保存的响应 | `--file {file}` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--rdap` | 改用 HTTPS 的 RDAP 接口（TCP 43 被防火墙拦时用这个） |
| `--json` | 输出结构化 JSON，方便后续脚本处理 |
| `--timeout` | 单次查询超时秒数，默认 10 |
| `-o/--output` | 写入文件，已存在需加 --force |

### 踩坑提醒

- 很多网络环境会封掉 TCP 43 端口，此时纯 WHOIS 必然超时；先用 --rdap 试，RDAP 走 443 通常能通。
- WHOIS 返回的注册人信息绝大多数已被 GDPR 打码成 REDACTED FOR PRIVACY，查不到真人姓名是正常的，别以为是脚本坏了。
- IP 的 whois 要逐级查（IANA → RIR → 分配到的组织），只看第一跳会误以为整个网段都归 IANA。
- 返回文本是「键: 值」的自由格式，不同注册商字段名不统一，脚本只能提取常见字段，完整内容要看原文。

---

← 返回 [工具箱总览](../README.md)
