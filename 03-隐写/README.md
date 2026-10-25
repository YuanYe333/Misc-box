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
C:\Users\<你>\AppData\Local\Python\pythoncore-3.14-64\python.exe -X utf8 ^
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

---

<a id="imgsize"></a>

## imgsize 长宽校验 · imgsize.py

**版本**：1.0  
**类型**：script  
**位置**：`_脚本/imgsize.py`

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


← 返回 [工具箱总览](../README.md)
