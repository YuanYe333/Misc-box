# 五、流量分析

> 题目给你一个 `.pcap` / `.pcapng`，要你还原通信内容、提取文件、找出 flag。

## 第一件事：先摸底，别急着看包

> **命令里的 `tshark` 是简写。** 本工具箱**不改系统 PATH**，Wireshark 安装时
> 默认也不勾「加入 PATH」，所以直接敲 `tshark` 多数机器会报找不到命令。
> 用完整路径：
>
> ```powershell
> $tshark = 'C:\Program Files\Wireshark\tshark.exe'
> ```
>
> 下文所有示例都按 `tshark` 书写，请自行替换成 `& $tshark`。

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
cd D:\杂项工具\05-流量分析\nmap
.\nmap.exe -sV -p 1-1000 目标IP
.\nmap.exe -p- --min-rate 1000 目标IP
```

## ⚠️ 关于 Npcap

| 场景 | 需要 Npcap 吗 |
| --- | --- |
| 分析已有 `.pcap` 文件 | **不需要**（tshark 直接读文件） |
| 实时抓包 / nmap 的 SYN 扫描 / OS 指纹 | 需要 |

**Npcap 免费版不支持静默安装**（`/S` 会弹提示），必须手动跑安装程序点界面。
不装也不影响做题——CTF 流量题都是给现成的 pcap。

### 本机当前状态：已安装 Npcap 1.90

- 安装位置：`C:\Windows\System32\Npcap`（驱动路径由系统固定，不能选盘）
- 服务：`npcap`（Npcap Packet Driver，已运行，开机自启）
- 已装组件：`wpcap.dll`、`Packet.dll`、`NpcapHelper.exe`、`WlanHelper.exe`
- 未装组件：WinPcap 兼容模式、无线监听模式（不需要）

验证是否可用：

```powershell
# 列出可抓包接口，应看到 \Device\NPF_... 开头的网卡
& 'C:\Program Files\Wireshark\tshark.exe' -D

# 实测抓 5 个包（把 10 换成上一步看到的接口编号）
& 'C:\Program Files\Wireshark\tshark.exe' -i 10 -c 5
```

⚠️ 安装时若勾了「仅管理员可访问驱动」，理论上抓包需管理员权限。
**但本机实测普通权限下也能正常抓包**（上面的验证就是在未提权的会话里跑通的），
所以先直接试，报权限错误时再用「以管理员身份运行」。

⚠️ nmap 的 `-sS`（SYN 扫描）需要管理员；普通扫描 `-sT` 不需要。

## 常见陷阱

1. **大 pcap 直接全量打开会卡死**：先用 `-q -z io,phs` 摸底。
2. **`tshark` 不在 PATH**：用完整路径 `C:\Program Files\Wireshark\tshark.exe`。
3. **`follow,tcp,ascii,N` 的 N 是流序号**，不是包序号。
4. **HTTP 是分块传输时** `http.file_data` 可能为空，要用 `--export-objects`。
5. **USB 题要先确定设备类型**（键盘/鼠标/存储），用 `usb.src` 过滤。

## 下一步

导出的文件 → 按类型去 **隐写** / **压缩包与文件修复** / **取证**。

## 本分类工具一览

| 工具 | 版本 | 一句话说明 |
| --- | --- | --- |
| [Wireshark / tshark](#tshark) | 4.7.4 | 流量分析标准工具：图形界面看包 + tshark 命令行批量处理。 |
| [nmap](#nmap) | 7.992 | 端口扫描、服务与版本识别、OS 指纹、NSE 脚本引擎。 |
| [DNS 导出与隧道识别](#dnsdump) | 1.0 | DNS 查询/应答全量导出，识别并解码 DNS 隧道。 |
| [pcap 明文提取](#pcapcarve) | 1.0 | 解析 pcap/pcapng、重组 TCP、提取明文协议。 |
| [TCP 流重组导出](#tcpextract) | 1.0 | 按四元组拆分并重组 TCP 双向流。 |
| [USB HID 键盘鼠标还原](#usbhid) | 1.0 | 解码 USB HID 键盘/鼠标流量成按键序列与轨迹。 |

---

<a id="tshark"></a>

## Wireshark / tshark · Wireshark

**版本**：4.7.4  
**类型**：gui-cli  
**位置**：`C:\Program Files\Wireshark\tshark.exe`

> 流量分析标准工具：图形界面看包 + tshark 命令行批量处理。

### 什么时候用

拿到 .pcap/.pcapng，要还原协议、提取文件、找 flag。

### 怎么用

**概览（先看有什么协议）**

```
tshark -r 题目.pcap -q -z io,phs
```

**只列 HTTP 请求**

```
tshark -r 题目.pcap -Y http.request -T fields -e http.host -e http.request.uri
```

**导出 HTTP 对象**

```
tshark -r 题目.pcap --export-objects http,输出目录
```

**看 DNS 查询**

```
tshark -r 题目.pcap -Y dns -T fields -e dns.qry.name
```

**提取 TCP 流**

```
tshark -r 题目.pcap -q -z follow,tcp,ascii,0
```

**按流统计**

```
tshark -r 题目.pcap -q -z conv,tcp
```

**图形方式**

```
双击卡片「打开工具」→ Wireshark 图形界面 → 统计/追踪流
```

### 界面里怎么跑

命令行批量处理、导出对象、追踪流。

把文件拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.pcap`  `.pcapng`  `.cap`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 协议层次统计 | `-r {file} -q -z io,phs` |
| 导出 HTTP 对象 | `-r {file} --export-objects http,{outdir}/http` |
| 只看 HTTP 请求 | `-r {file} -Y http.request -T fields -e http.host -e http.request.uri` |
| TCP 对话统计 | `-r {file} -q -z conv,tcp` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-r` | 读取 pcap 文件 |
| `-Y` | 显示过滤器（Wireshark 语法） |
| `-T fields -e` | 只输出指定字段，便于脚本处理 |
| `--export-objects` | 导出协议对象（http/smb/tftp 等） |
| `-z` | 统计项（io,phs / conv,tcp / follow,tcp,ascii,N） |
| `-q` | 安静模式，只输出统计 |

### 踩坑提醒

- 分析 pcap 文件不需要 Npcap；实时抓包才需要
- Npcap 免费版不支持静默安装（/S 会弹提示），需手动点界面
- tshark 在 PATH 里可能没有，用完整路径 C:\Program Files\Wireshark\tshark.exe
- 大 pcap 先用 -q -z io,phs 摸底再细看，别一上来全量渲染

### 下一步

nmap

---

<a id="nmap"></a>

## nmap · Nmap

**版本**：7.992  
**类型**：cli  
**位置**：`05-流量分析/nmap/nmap.exe`

> 端口扫描、服务与版本识别、OS 指纹、NSE 脚本引擎。

### 什么时候用

流量题要还原目标服务、或授权渗透测试的信息收集阶段。

### 怎么用

**基础扫描**

```
.\nmap.exe 192.168.1.1
```

**常见端口 + 版本**

```
.\nmap.exe -sV -p 1-1000 192.168.1.1
```

**全端口快速**

```
.\nmap.exe -p- --min-rate 1000 192.168.1.1
```

**NSE 脚本**

```
.\nmap.exe -sV --script http-title,http-headers -p 80,443 目标
```

### 界面里怎么跑

端口扫描。只对自己有权限的目标用。

选中后在「输入内容」框里填数据，点「▶ 运行」。

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 服务识别（-sV） | `-sV {text}` |
| 快速扫描（-F） | `-F {text}` |
| 全端口（-p-） | `-p- {text}` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-sV` | 服务版本识别 |
| `-p` | 端口范围（-p- 为全端口） |
| `-O` | OS 指纹（需管理员） |
| `-sS` | SYN 半开扫描（需 Npcap + 管理员） |
| `--script` | NSE 脚本 |

### 踩坑提醒

- 未装 Npcap 时会警告并回退 connect() 模式，普通扫描仍可用，但 SYN/OS 指纹受限
- 本机是便携解包版，不需要安装、不写注册表
- 仅用于自有资产或授权目标

### 下一步

Wireshark / tshark

---


<a id="dnsdump"></a>

## DNS 导出与隧道识别 · dnsdump.py

**类型**：script  
**位置**：`05-流量分析/scripts/dnsdump.py`

> 导出 pcap 里的 DNS 查询/响应，按超长子域名、编码标签、高频、TXT 异常打分找隧道，并能把隧道数据拼回来自动解码。

### 什么时候用

DNS 隧道题：域名一长串、查询量巨大、TXT 记录可疑，需要批量导出、定位可疑项并把隐藏数据还原出来时。

### 怎么用

**一步到位：拼接+解码（最常用）**

```bat
python -X utf8 dnsdump.py 题目.pcap --decode
```

- 脚本按根域名和编码类型分组拼接，自动试 base32/base64/hex

**先看聚合再抓可疑**

```bat
python -X utf8 dnsdump.py 题目.pcap --stats
```

- python -X utf8 dnsdump.py 题目.pcap --tunnel

**导出 CSV**

```bat
python -X utf8 dnsdump.py 题目.pcap --csv -o dns.csv
```

### 界面里怎么跑

DNS 批量导出 + 隧道特征识别。

把文件拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.pcap`  `.pcapng`  `.cap`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 总览 | `{file}` |
| 只看 DNS 隧道特征 | `{file} --tunnel` |
| 尝试解码隧道数据 | `{file} --tunnel --decode` |
| 导出 CSV | `{file} --csv -o {outdir}/dns.csv` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--decode` | 把可疑标签按根域名+编码类型分组拼接，自动解码（找 flag 首选） |
| `--tunnel` | 只输出隧道嫌疑分达标的项 |
| `--threshold N` | 调整可疑阈值，默认 4.0，调低会更敏感 |
| `--stats` | 按根域名输出查询/响应/NXDOMAIN 聚合表 |
| `--csv` | 输出 CSV，便于丢进 Excel 或脚本二次处理 |
| `-o FILE` | 写入文件，已存在需 --force |

### 踩坑提醒

- 隧道分是启发式打分，会误报；分数高只代表「值得看一眼」，不是判决
- 同一域名下可能混有 base32 和 base64 两类数据，--decode 已按类型分开拼接，不要手动混拼
- 只认端口 53 的标准 DNS，mDNS(5353)/LLMNR/DoH/DoT 一个都不处理
- DNS over TCP 只拼接同一四元组的分段，跨连接的长报文可能解不全

---

<a id="pcapcarve"></a>

## pcap 明文提取 · pcapcarve.py

**类型**：script  
**位置**：`05-流量分析/scripts/pcapcarve.py`

> 自己解析 pcap/pcapng，按 TCP 流重组并提取 HTTP/FTP/Telnet/SMTP 明文内容。

### 什么时候用

拿到 .pcap/.pcapng 要捞 HTTP 响应体、FTP 传输、Telnet 明文，又不想开 Wireshark 时。

### 怎么用

**先列流再挑一条看**

```bat
python -X utf8 pcapcarve.py 题目.pcap --list
```

- python -X utf8 pcapcarve.py 题目.pcap --stream 3
- 需要存档时加 -o 结果.txt

**命令行**

```bat
python -X utf8 pcapcarve.py 题目.pcapng -o 全部内容.txt --force
```

### 界面里怎么跑

从 pcap 提取 HTTP/FTP/Telnet 明文内容。

把文件拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.pcap`  `.pcapng`  `.cap`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 列出可提取的流 | `{file} --list` |
| 提取全部明文到目录 | `{file} -o {outdir}/carved` |
| 跟随某条流（填流号到文本框） | `{file} --follow {text}` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--list` | 只列所有 TCP 流（编号、端点、协议、字节数） |
| `--stream N` | 只输出第 N 条流的内容 |
| `--follow N` | 按抓包顺序交错显示第 N 条流的双向数据 |
| `-o FILE` | 结果写入文件，已存在需 --force |
| `--limit N` | 单段最多显示多少字节，默认 200000，0 为不限 |

### 踩坑提醒

- IP 分片重叠时按「先到先得」合并，不做 Wireshark 那种启发式裁决，结果可能与 tshark 略有差异
- 流序号从 1 开始（按四元组首次出现顺序），与 tshark follow,tcp 的 0 基编号不同，别直接套用
- 只处理 TCP；纯 UDP 的题（DNS 除外）看不到内容，加密流（TLS）导出来也是密文
- HTTP 分块传输且抓包不完整时 chunked 解码会提前结束，响应体会比实际短

---

<a id="tcpextract"></a>

## TCP 流重组导出 · tcpextract.py

**类型**：script  
**位置**：`05-流量分析/scripts/tcpextract.py`

> 按四元组分流、处理乱序重传后双向重组，导出 stream_N_client/server.txt。

### 什么时候用

要把 pcap 里每条 TCP 会话分别落成文件、再按类型分拣或丢给其他工具分析时。

### 怎么用

**列流后批量导出**

```bat
python -X utf8 tcpextract.py 题目.pcap --list
```

- python -X utf8 tcpextract.py 题目.pcap --all -o 导出目录
- 目录里会得到 stream_1_client.txt / stream_1_server.txt …

**命令行**

```bat
python -X utf8 tcpextract.py 题目.pcap --stream 2 -o 导出
```

### 界面里怎么跑

按流重组 TCP 会话并导出。

把文件拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.pcap`  `.pcapng`  `.cap`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 列出所有 TCP 流 | `{file} --list` |
| 导出全部流到目录 | `{file} --all -o {outdir}/streams` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--list` | 列出所有流：客户端/服务端、端口、双向字节数 |
| `--stream N` | 只导出第 N 条流 |
| `--all` | 导出全部流到 -o 指定的目录 |
| `-o DIR` | 输出目录，不存在会自动创建 |
| `--limit N` | 单方向最多导出多少字节，默认 0 为不限 |

### 踩坑提醒

- 序号回绕只告警不真正处理：超过 4GB 的流会跨 2^32 边界，拼接可能错位，这种题请用 tshark follow,tcp,raw
- 抓包丢掉的字节会如实留 0x00 并统计空洞数，不会假装数据完整；空洞位置在 stderr 里报
- 客户端是「先发 SYN 的那一方」；只有单向流量（没抓到握手）时按地址排序取第一个，可能标反
- 导出的 .txt 是原始字节不做编码转换，遇到二进制内容请用十六进制查看器再看

---

<a id="usbhid"></a>

## USB HID 键盘鼠标还原 · usbhid.py

**类型**：script  
**位置**：`05-流量分析/scripts/usbhid.py`

> 解 usbmon/USBPcap 记录，从 HID 中断报告还原键盘输入（含 Shift/Ctrl）与鼠标轨迹图。

### 什么时候用

USB 流量题：给了抓 USB 总线的 pcap，要还原敲出的 flag 或鼠标画出的轨迹时。

### 怎么用

**先看设备分组**

```bat
python -X utf8 usbhid.py 题目.pcap --list
```

- python -X utf8 usbhid.py 题目.pcap --keyboard
- 鼠标题改 --mouse -o 轨迹.png

**命令行**

```bat
python -X utf8 usbhid.py 题目.pcap --all -o 轨迹.png
```

### 界面里怎么跑

USB HID 键盘/鼠标流量还原，CTF 高频。

把文件拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.pcap`  `.pcapng`  `.cap`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 列出 USB 设备 | `{file} --list` |
| 键盘流量还原 | `{file} --keyboard` |
| 键盘 + 鼠标 | `{file} --all` |
| 看原始 HID 数据 | `{file} --raw` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--keyboard` | 只还原键盘，输出含 <CR>/<0x01> 等可见化控制字符 |
| `--mouse` | 只还原鼠标轨迹，可用 -o 输出 PNG |
| `--all` | 键盘鼠标都处理（默认行为） |
| `--raw` | 额外打印每条 HID 原始报告十六进制，便于对照 |
| `--device N` | 只看第 N 组设备，先用 --list 查编号 |
| `-o FILE` | 鼠标轨迹图输出路径（PNG，纯 zlib 手写） |

### 踩坑提醒

- 抓包漏掉「松手」报告时，连打同一个字母（如 flag 里的 ll）只会出一个字符，这是数据缺失不是解码错
- 只解中断传输（transfer_type=1）的 HID 报告，控制传输里的 GET_REPORT/SET_REPORT 不处理
- 标准 8 字节 boot 报告才可靠；6 字节或 NKRO 位图报告会走兼容分支并给出警告，结果需人工核对
- 鼠标只还原相对位移，触摸板/数位板这类绝对坐标设备解不出来

---

← 返回 [工具箱总览](../README.md)
