# 三、隐写

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
.\exiftool.exe 图片.png              # 全部元数据
.\exiftool.exe -a -G1 图片.png       # 分组显示，不漏重复标签
.\exiftool.exe -b -Comment 图片.png  # 只取值，便于管道
```

flag 常见藏匿点：`Comment`、`Artist`、`ImageDescription`、`GPS*`、`UserComment`。

### 2. PNG 结构：pngcheck 套件

```powershell
.\pngcheck.exe 图片.png          # 基本校验
.\pngcheck.exe -v 图片.png       # 逐 chunk 结构
.\pngcheck.exe -t 图片.png       # 打印 tEXt 文本块 ← 藏 flag 必查
.\pngcheck.exe -7 图片.png       # 乱码时转义高位字符
.\pngcheck.exe -p 图片.png       # 调色板 / 透明度
.\pngcheck.exe -s 文件.bin       # 在任意文件里搜 PNG 签名
.\pngcheck.exe -x 文件.bin       # 搜索并提取
```

**⚠️ 关键认知**：pngcheck **只验 CRC**。如果题目改了长宽并重算了 CRC，
pngcheck 会报 `No errors detected`——完全查不出来。**所以必须配合 imgsize。**

### 3. 长宽篡改：imgsize.py

```powershell
# 拖拽：把图片拖到 _脚本\imgsize.bat 上
# 命令行：
$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe -X utf8 ^
  D:\杂项工具\_脚本\imgsize.py 题目.png
```

原理：用「实际像素数据量 ÷ 每像素字节数」反推真实高度，
与文件头声明的长宽对账。**PNG/BMP 严格，JPG 启发式**（JPG 没有像素长度字段）。

### 4. 位平面 / 通道：StegSolve

双击 `StegSolve\启动StegSolve.bat`（需要 Java）。

| 功能 | 用途 |
| --- | --- |
| `Red/Green/Blue plane` | 单通道查看，颜色通道可能各藏一部分 |
| `Bit planes 0-7` | 逐位平面，**低位平面（0-2）常藏 LSB 数据** |
| `Frame Browser` | 多帧 GIF 逐帧浏览 |
| `Stereogram Solver` | 立体图/随机点图解码 |

### 5. 附加数据 / 嵌套文件：binwalk + foremost

```powershell
.\binwalk\binwalk.bat 题目.png        # 看有没有嵌别的文件
.\binwalk\binwalk.bat -e 题目.png     # 自动提取
# binwalk 失败时用 foremost 兜底：
cd D:\杂项工具\foremost
.\foremost.exe -t png -i 题目.png -o 输出目录
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

## 本分类工具一览

| 工具 | 版本 | 一句话说明 |
| --- | --- | --- |
| [imgsize 长宽校验](#imgsize) | 1.0 | 通过像素数据量与声明长宽对账，反推被篡改的真实宽高（PNG/BMP 严格，JPG 启发式）。 |
| [pngcheck 套件](#pngcheck) | 3.0.3 | PNG 结构校验、chunk 拆分、IDAT 窗口修复；能在任意文件里搜索并提取 PNG。 |
| [StegSolve](#stegsolve) | 1.4 | 图片逐通道、逐位平面查看，Frame Browser 翻帧，Stereogram Solver 解立体图。 |
| [ExifTool](#exiftool) | 13.59 | 读/写图片、文档、音视频元数据：GPS、作者、注释、隐藏字段。 |
| [音频波形/频谱图](#audiospec) | 1.0 | 把 WAV 画成波形与频谱图，专看频谱藏字。 |
| [LSB 隐写提取/写入](#lsb) | 1.0 | LSB 最低位提取/嵌入，自动遍历通道与位序。 |
| [隐写总检](#stegodetect) | 1.0 | 隐写一键体检：尾部追加、异常 chunk、尺寸不符、内嵌文件。 |
| [ZIP 隐写检测](#zipstego) | 1.0 | ZIP 隐写检查：伪加密、注释载荷、尾部数据、隐藏条目。 |

---

<a id="imgsize"></a>

## imgsize 长宽校验 · imgsize.py

**版本**：1.0  
**类型**：script  
**位置**：`03-隐写/scripts/imgsize.py`

> 通过像素数据量与声明长宽对账，反推被篡改的真实宽高（PNG/BMP 严格，JPG 启发式）。

### 什么时候用

图片显示异常、下半截是噪点、比例被拉伸，或怀疑 IHDR/SOF 被改过。

### 怎么用

**拖拽（最省事）**

1. 把图片或文件夹拖到 _脚本/imgsize.bat 上松手

**命令行**

```
python -X utf8 D:\杂项工具\_脚本\imgsize.py 题目.png
```

**批量（递归）**

```
... imgsize.py D:\题目\ -r
```

### 界面里怎么跑

反推被篡改的真实宽高。pngcheck 漏检的情况它能抓到。

把文件（可多个）拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.png`  `.bmp`  `.gif`  `.jpg`  `.jpeg`

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-r` | 递归子目录 |
| `多路径` | 可一次传多个文件 |

### 踩坑提醒

- 必须加 -X utf8，否则中文路径乱码
- pngcheck 在 CRC 被重算后完全漏检，本脚本靠数据量对账仍能发现
- JPG 没有像素长度字段，只能靠底部中性灰填充带启发式判断

### 下一步

pngcheck 套件 → StegSolve → ExifTool

---

<a id="pngcheck"></a>

## pngcheck 套件 · pngcheck / pngsplit / png-fix-IDAT

**版本**：3.0.3  
**类型**：cli  
**位置**：`pngcheck/pngcheck.exe`

> PNG 结构校验、chunk 拆分、IDAT 窗口修复；能在任意文件里搜索并提取 PNG。

### 什么时候用

PNG 打不开、CRC 报错、怀疑 tEXt 藏 flag、或要从 bin 里捞图片。

### 怎么用

**基本校验**

```
.\pngcheck\pngcheck.exe 图片.png
```

**逐 chunk 结构**

```
.\pngcheck\pngcheck.exe -v 图片.png
```

**看 tEXt 文本块（藏 flag 必查）**

```
.\pngcheck\pngcheck.exe -t 图片.png
```

**乱码时转义高位字符**

```
.\pngcheck\pngcheck.exe -7 图片.png
```

**调色板/透明度**

```
.\pngcheck\pngcheck.exe -p 图片.png
```

**只报错**

```
.\pngcheck\pngcheck.exe -q 图片.png
```

**在任意文件里搜 PNG**

```
.\pngcheck\pngcheck.exe -s 文件.bin
```

**搜索并提取**

```
.\pngcheck\pngcheck.exe -x 文件.bin
```

**拆 chunk**

```
.\pngcheck\pngsplit.exe 图片.png
```

**修 IDAT 窗口**

```
.\pngcheck\png-fix-IDAT-windowsize.exe 图片.png
```

### 界面里怎么跑

PNG 结构校验。多文件可一起拖。

把文件（可多个）拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.png`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 校验（-v，看 chunk 明细） | `-v {file}` |
| 简洁校验（只报 OK/错误） | `{file}` |
| 打印 tEXt 文本块 | `-t {file}` |
| 只报错误 | `-q {file}` |
| 在文件里搜内嵌 PNG | `-s {file}` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-v / -vv` | 详细结构 / 解码并打印每行 filter |
| `-t` | 打印 tEXt 文本块 |
| `-7` | 打印 tEXt 并转义高位字符 |
| `-p` | 打印 PLTE 调色板与 tRNS |
| `-q` | 只输出错误 |
| `-s / -x` | 在任意文件中搜索 / 搜索并提取 |

### 踩坑提醒

- 只验 CRC：改完长宽并重算 CRC 就查不出来，高度改大时甚至报 No errors detected
- 怀疑尺寸时务必配合 imgsize.py
- 参数可组合：-q -7、-v -t

### 下一步

imgsize 长宽校验 → StegSolve

---

<a id="stegsolve"></a>

## StegSolve · StegSolve

**版本**：1.4  
**类型**：gui  
**位置**：`StegSolve/StegSolve-1.4.jar`

> 图片逐通道、逐位平面查看，Frame Browser 翻帧，Stereogram Solver 解立体图。

### 什么时候用

图片肉眼看不出问题，怀疑低位藏数据、多帧 GIF 藏图、或需要看某个颜色通道。

### 怎么用

**图形方式**

1. 双击 StegSolve/启动StegSolve.bat
2. File → Open 选图片
3. 底部箭头切换通道/位平面

**Frame Browser**

```
Analyse → Frame Browser（GIF 多帧逐帧看）
```

**Stereogram Solver**

```
Analyse → Stereogram Solver（立体图/随机点图）
```

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `Red/Green/Blue plane` | 单通道查看 |
| `Bit planes 0-7` | 逐位平面，低位平面常藏 LSB 数据 |
| `Frame Browser` | 多帧图片逐帧浏览 |
| `Stereogram Solver` | 解立体图 |

### 踩坑提醒

- 需要 Java，双击无反应先查 java -version
- 大图逐位平面切换较慢，耐心等

### 下一步

pngcheck 套件 → imgsize 长宽校验

---

<a id="exiftool"></a>

## ExifTool · ExifTool

**版本**：13.59  
**类型**：cli  
**位置**：`CTF-tools/exiftool/exiftool.exe`

> 读/写图片、文档、音视频元数据：GPS、作者、注释、隐藏字段。

### 什么时候用

拿到任何文件先看元数据，flag 常藏在 Comment/Artist/GPS 里。

### 怎么用

**全部元数据**

```
.\exiftool.exe 图片.png
```

**分组显示全部字段**

```
.\exiftool.exe -a -G1 图片.png
```

**只取值（便于管道）**

```
.\exiftool.exe -b -Comment 图片.png
```

**递归扫描目录**

```
.\exiftool.exe -r D:\题目\
```

### 界面里怎么跑

读元数据：GPS、作者、注释、隐藏字段。

把文件（可多个）拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 读全部元数据 | `{file}` |
| 只看 GPS | `-GPS:all -a -g {file}` |
| 含未知/隐藏字段 | `-a -u -g {file}` |
| 导出 JSON | `-j -a -g {file}` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-a` | 显示重复标签 |
| `-G1` | 按分组显示 |
| `-b` | 二进制/原始值输出 |
| `-r` | 递归目录 |

### 踩坑提醒

- exiftool 只读文件头，报告的是被篡改后的值，不能判断真假

### 下一步

imgsize 长宽校验

---


<a id="audiospec"></a>

## 音频波形/频谱图 · audiospec.py

**类型**：script  
**位置**：`03-隐写/scripts/audiospec.py`

> 把 WAV 画成波形图和频谱图，纯标准库自带 FFT，专门用来看频谱藏字。

### 什么时候用

题目给了音频文件（尤其 .wav），怀疑有频谱藏字或者要听/看静音段藏的摩斯码。

### 怎么用

**直接出两张图**

```bat
python -X utf8 audiospec.py 题目.wav
```

- 会生成 题目_wave.png（波形）和 题目_spec.png（频谱）
- 先看频谱图：如果有规则的笔画或方块，就是藏字

**高频区放大看**

```bat
python -X utf8 audiospec.py 题目.wav --spec --fmin 8000 --fmax 16000 --width 1600 --height 600
```

- 藏字常写在 8k-16k 这段人耳不敏感的区间，裁掉低频后笔画会清楚很多
- 还是看不清就把 --range-db 调小（比如 40），弱信号会更亮

**只看某一段**

```bat
python -X utf8 audiospec.py 题目.wav --spec --start 2.5 --end 4.0 -o 片段.png
```

**分开看左右声道**

```bat
python -X utf8 audiospec.py 题目.wav --spec --channel R -o 右声道.png
```

### 界面里怎么跑

频谱藏字题。默认出频谱图，产物在下方列表里。

把文件拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.wav`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 出频谱图（推荐） | `{file} --spec -o {outdir}/频谱.png` |
| 出波形图 | `{file} --wave -o {outdir}/波形.png` |
| 两张都出 | `{file} -o {outdir}/音频` |
| 高分辨率频谱 | `{file} --spec --width 1400 --height 700 -o {outdir}/频谱_大.png` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--spec` | 只出频谱图 |
| `--wave` | 只出波形图 |
| `--channel` | L/R/both，默认 both（双声道会叠加成一路） |
| `--start / --end` | 截取时间段（秒） |
| `--fmin / --fmax` | 只显示这一段频率（Hz），藏字常在高频 |
| `--n-fft` | STFT 窗长，默认 2048；调大频率分辨率高、时间分辨率低 |
| `--range-db` | 显示多少 dB 动态范围，默认 90；调小能突出弱信号 |
| `--gamma` | 亮度 gamma，默认 0.7；小于 1 提亮暗部 |
| `--width / --height` | 输出尺寸 |

### 踩坑提醒

- 只认 WAV。MP3/FLAC/OGG 会直接报「不是 WAV」，要先用 7zip 或音频工具转成 WAV，别指望脚本自动识别。
- --channel both 会把左右声道平均成一路。如果出题人把字分别藏在左右两个声道（或者左右藏的是不同内容），叠加后可能互相抵消成一团糊，这种题必须用 --channel L 和 --channel R 各看一次。
- 频率轴默认铺满 0 到采样率一半。藏字通常只占很窄的一条，全谱显示时会被压成几个像素高的细线，一定要配合 --fmin/--fmax 放大。
- 纯 Python 算 FFT，长音频慢。默认 hop 是窗长的 1/4，10 分钟的音频会产生上万帧，跑之前先用 --start/--end 截一段；脚本在帧数超过 6000 时会提示。

---

<a id="lsb"></a>

## LSB 隐写提取/写入 · lsb.py

**类型**：script  
**位置**：`03-隐写/scripts/lsb.py`

> PNG/BMP 最低位提取与写入，自动穷举通道/位平面/位序组合并打分排序，可出位平面图。

### 什么时候用

拿到一张图怀疑像素最低位藏了数据，或要把 payload 反向写进图片时。

### 怎么用

**不知道参数时先自动试**

```bat
python -X utf8 lsb.py 图.png
```

- 脚本会穷举 通道×位平面×位序×布局 并按「像不像明文」打分排序
- 看排第一的那条后面的「复现」命令，再精确提取

**精确提取到文件**

```bat
python -X utf8 lsb.py 图.png --channel R --bit 0 --count 200
```

- 确认读出来的东西对，再加 -o 落地：python -X utf8 lsb.py 图.png --channel R --bit 0 -o out.bin

**位平面可视化**

```bat
python -X utf8 lsb.py 图.png --plane 3 -o plane3.png
```

- 打开黑白图，白=该位为 1；有规则笔画就是藏了字

**命令行**

```bat
python -X utf8 lsb.py 图.png --embed -f payload.bin -o 藏了东西.png
```

### 界面里怎么跑

LSB 提取。不知道参数时先跑「自动穷举」。

把文件拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.png`  `.bmp`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 自动穷举通道/位平面/位序 | `{file}` |
| 只看 RGB 最低位 | `{file} --channel all --bit 0` |
| 看 Alpha 通道最低位 | `{file} --channel A --bit 0` |
| 出第 3 位平面图 | `{file} --plane 3 -o {outdir}/plane3.png` |
| 出第 0 位平面图 | `{file} --plane 0 -o {outdir}/plane0.png` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--channel` | R/G/B/A/all/rgba，all 只含 RGB（Stegsolve 习惯） |
| `--bit` | 位平面 0-7，0 是最低位 |
| `--bit-order` | lsb/msb，先读到的位放输出字节的低位还是高位 |
| `--layout` | row 逐像素RGB / bgr 逐像素BGR / planar 先整张R再G再B |
| `--count` | 提取多少字节，0=全部容量 |
| `--plane` | 输出第 N 位平面的黑白 PNG |
| `--embed` | 写入模式，配 -f 或 --payload-text |
| `--length-header` | 写入时加 4 字节长度头，自动模式能认出来 |

### 踩坑提醒

- --channel all 只含 RGB 不含 Alpha。这是 Stegsolve 的习惯，把 A 混进来会让正常题目直接读不出来；要读 Alpha 用 --channel A 或 rgba。
- PNG 只支持 8-bit 非隔行。16-bit PNG 的最低位语义和 8-bit 完全不同（一个像素 16 位），强行按 8-bit 读出来是噪声，脚本会直接报错而不是瞎猜。
- 调色板 PNG 会先展开成 RGBA 再取位。如果出题人是直接改调色板索引的 LSB，展开后就读不到了——这种题要先用别的方式还原索引。
- 自动模式只抽样前 1KB 打分。如果藏的数据在第 2KB 之后才开始，或者开头有段乱码，可能排不到第一，要看完整候选列表。

---

<a id="stegodetect"></a>

## 隐写总检 · stegodetect.py

**类型**：script  
**位置**：`03-隐写/scripts/stegodetect.py`

> 一键盘查 PNG/JPEG/BMP/ZIP 的尾部附加、异常块、尺寸不符、内嵌文件和明文 flag，按可信度排序。

### 什么时候用

拿到一个可疑文件但不知道该往哪个方向查，先跑这个把明显的隐写痕迹全列出来。

### 怎么用

**先全检一遍**

```bat
python -X utf8 stegodetect.py 题目.png
```

- 结果按 [高]/[中]/[低] 排序，先只看 [高] 那几条
- 如果报了「IEND 之后有附加数据」，用 --tail-dump 把那一段单独存出来再分析

**两图对比找改动点**

```bat
python -X utf8 stegodetect.py --diff 原图.png 改过.png -o 差异.png
```

- 差异图会把不同像素放大 32 倍并标红，改动区域一眼可见
- 输出里会写明最大通道差；差 1 通常就是 LSB 级改动

**整目录扫一遍**

```bat
python -X utf8 stegodetect.py 附件目录/ -r
```

**导出尾部数据**

```bat
python -X utf8 stegodetect.py 题目.png --tail-dump -o tail.bin
```

### 界面里怎么跑

隐写总检：文件尾附加数据、多图对比、异常块。可一次拖多张图。

把文件（可多个）拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 总检（可多选文件） | `{files}` |
| 总检 + 导出尾部数据 | `{files} --tail-dump` |
| 两张图对比 | `--diff {file} {text}` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `-r` | 递归子目录 |
| `--diff A B` | 两张同尺寸图做像素级对比，输出差异图 |
| `--tail-dump` | 把容器尾部（IEND/EOI 之后）的附加数据导出成文件 |
| `-o` | 输出文件（配合 --diff / --tail-dump） |
| `--no-amplify` | 差异图不放大，只按原始差值画 |
| `-v` | 详细输出，含更多数据预览 |

### 踩坑提醒

- 「没有发现明显异常」不等于没有隐写。本脚本查的是容器层面的痕迹（尾部数据、块异常、尺寸不符、内嵌文件），LSB 隐写、频域隐写这类内容级手法不会留下任何结构痕迹，必须再用 lsb.py 或 stegsolve 看。
- JPEG 天然存在多个 APP 段和 COM 段，数量多不代表有问题；脚本把 APP 段数量作为「低」优先级提示，别把它当成结论。
- PNG 声明的像素数据比实际少，可能是出题人改了 IHDR 宽度或高度（常见手法），也可能只是编码器优化。判据是差值大小和尾部是否紧接数据，脚本会给出具体字节数让你自己判断。
- 两图对比要求尺寸完全一致。尺寸不同时脚本直接报错，因为那本身就是线索（出题人裁过图），别急着去 resize。

---

<a id="zipstego"></a>

## ZIP 隐写检测 · zipstego.py

**类型**：script  
**位置**：`03-隐写/scripts/zipstego.py`

> 查 ZIP 伪加密、注释藏数据、EOCD 后附加数据、隐藏条目，并可一键修复伪加密。

### 什么时候用

ZIP 打开要密码但题目没给，或者怀疑 ZIP 里除了看得见的文件还藏了别的东西。

### 怎么用

**先体检**

```bat
python -X utf8 zipstego.py 题目.zip
```

- 看到「伪加密」就直接用 --clean 修；看到「注释里内嵌 ZIP」就用 --dump-comment 取出来
- 结果按 [高]/[中]/[低] 排序，[高] 是确定性的

**修复伪加密**

```bat
python -X utf8 zipstego.py 伪加密.zip --clean -o 修好了.zip
```

- 脚本只清标志位里的 bit0，字节数不变，CRC 和压缩数据都不动
- 修完用 7zip 直接打开，不需要密码

**导出注释**

```bat
python -X utf8 zipstego.py 题目.zip --dump-comment -o 注释.bin
```

**整目录扫**

```bat
python -X utf8 zipstego.py 附件目录/ -r
```

### 界面里怎么跑

ZIP 伪加密 / 注释藏数据 / CRC 痕迹检测。

把文件（可多个）拖进窗口，或点拖放区选文件，然后点「▶ 运行」。

接受：`.zip`

「运行方式」下拉里的预设：

| 运行方式 | 说明 |
| --- | --- |
| 检测 | `{files}` |
| 导出 ZIP 注释 | `{files} --dump-comment {outdir}/注释.bin` |

> 输出会实时刷在下方面板，跑出来的文件在 `_box\work\runs\<时间戳>_<工具id>\`，点「📂 输出目录」直接打开。

### 参数速查

| 参数 | 说明 |
| --- | --- |
| `--dump-comment` | 把 EOCD 注释导出成文件 |
| `--clean` | 修复伪加密，必须配 -o 指定输出文件名 |
| `-o` | 输出文件 |
| `-r` | 目录递归 |
| `-v` | 打印每个条目的 method/大小/加密状态 |
| `--force` | 允许覆盖已存在文件 |

### 踩坑提醒

- 伪加密的判定看「本地头 flags」和「中央目录 flags」是否一致。只改一处的题（本地头置位、中央目录没置位）最坑：7-Zip 看中央目录直接就能解，Windows 资源管理器却弹密码框，两边现象不一样，别以为是文件坏了。
- 真加密和伪加密都表现为「flags bit0 = 1」。脚本用「csize 是否比 usize 大至少 12 字节」来区分——真 ZipCrypto 会加 12 字节加密头。但如果出题人对存储方式（method=0）且内容恰好加密后长度不变做了特殊处理，这个判据会失准，此时脚本会明确说「无法确认」，不会硬改。
- --clean 只动「已确认是伪加密」的条目。真加密的条目一律保留，否则会把本来能用密码解开的包改成彻底打不开。修完一定要先用 7zip 打开验证。
- 注释长度字段是 16 位的，最大 65535。如果注释超长被截断，EOCD 的注释长度和实际剩余字节数会对不上，脚本会报「注释长度字段与实际不符」——这本身就是一条线索，别当成文件损坏。

---

← 返回 [工具箱总览](../README.md)
