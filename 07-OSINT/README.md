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


← 返回 [工具箱总览](../README.md)
