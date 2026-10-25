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


← 返回 [工具箱总览](../README.md)
