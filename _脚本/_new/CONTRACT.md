# 脚本编写契约（所有新脚本必须遵守）

本目录是「待集成」暂存区。你只写 `.py` 和 `.meta.json`，**不要**写 `.bat`、不要改 `tools.json`、不要改任何 README。

## 一、技术约束（硬性）

1. **只用标准库**。禁止 `pip install`、禁止 `requests`/`PIL`/`numpy`/`pycryptodome`/`zbar`/`opencv`。允许：`os sys io re json struct zlib gzip bz2 lzma base64 binascii hashlib hmac urllib.parse html string random itertools collections datetime argparse pathlib textwrap unicodedata codecs socket subprocess glob time math functools typing`。
2. **Python 3.9 兼容**。禁止 `match/case`、禁止 `X | Y` 类型注解、禁止 `list[int]` 形式的内置泛型下标注解（用 `typing.List` 或不写注解）。本机有 3.9（Perl 自带）和 3.14，必须都能跑。
3. **文件编码**：源文件存为 **UTF-8**（可以有中文注释/输出）。所有 `open()` 读写文本必须显式写 `encoding="utf-8"`。
4. **中文路径**：必须能处理。不要用 `os.path.exists(p)` 拼字符串以外的花招，直接 `pathlib.Path`。
5. **绝不破坏输入**：默认只读输入。只有显式给了 `-o/--output` 才写新文件；写文件前若目标已存在，除非带 `--force`，否则报错退出。禁止 `shutil.rmtree`、禁止删除用户文件。
6. **退出码**：正常结束 `return 0` / `sys.exit(0)`；参数错误或处理失败 `sys.exit(1)` 或 `2`。**不要**在成功路径抛未捕获异常。
7. **无参数运行**：打印中文用法摘要（做什么、怎么用、例子），退出码 `0`。带 `-h/--help` 也一样。
8. **输出**：结果打到 stdout。诊断/警告打到 stderr。不要用 `print` 拼超长单行；列表类结果每行一条。
9. **幂等/可重复**：同一输入跑两次结果一致，不产生垃圾文件。

## 二、代码风格

- 顶部 `# -*- coding: utf-8 -*-` + 模块 docstring（中文，说明：做什么 / 为什么需要 / 用法示例 / 已知限制）。
- `if __name__ == "__main__": sys.exit(main())`。
- `main()` 里自己解析参数（用 `argparse` 或手写都可以），**不要**在模块顶层做重活。
- 关键算法处写简短中文注释解释「为什么这么算」，不要注释废话。
- 不要打印 ASCII art 大横幅，简洁即可。

## 三、产出物

对每个脚本 `<name>.py`，在同目录再写一个 `<name>.meta.json`：

```json
{
  "id": "kebab-case-id",
  "category": "code|stego|archive|traffic|forensics|osint|env",
  "name": "中文显示名",
  "name_en": "script.py",
  "summary": "一句话说清它解决什么问题（会显示在 GUI 卡片上，控制在 60 字内）",
  "when": "什么时候该用它（一句话，说清触发场景）",
  "usage": [
    {"title": "标题", "steps": ["步骤1", "步骤2"]},
    {"title": "命令行", "code": "python -X utf8 xxx.py 参数"}
  ],
  "params": [{"flag": "-r", "desc": "递归子目录"}],
  "pitfalls": ["踩坑提醒1", "踩坑提醒2"],
  "next": ["相关工具id"]
}
```

`usage` 里两种形态二选一：有 `steps` 或 有 `code`，**不要两个都写**。
`pitfalls` 至少 2 条，要写真实的坑（不是「注意参数」这种废话）。
`next` 写 0-3 个已存在的工具 id，从这些里挑：`cyberchef nmap hashcat john 7zip exiftool perl volatility3 theharvester pngcheck foremost stegsolve archpr wireshark binwalk npcap imgsize setup python-runtime java-runtime tshark`。

### 再加一个 `run` 块（让脚本能在图形界面里直接跑）

`run` 块描述「界面里怎么调用这个脚本」，有了它用户就能**拖文件 → 点运行 → 看输出**：

```json
"run": {
  "kind": "python",
  "input": "files",
  "accept": [".png", ".bmp"],
  "multi": false,
  "argv": ["{file}", "-o", "{outdir}/out.png"],
  "intro": "一句话说清这个入口干什么。",
  "presets": [
    {"title": "默认处理", "argv": ["{file}", "-o", "{outdir}/out.png"]},
    {"title": "只看信息", "argv": ["{file}", "--info"]},
    {"title": "不需要文件的用法", "argv": ["--list"], "no_file": true}
  ]
}
```

要点：

1. **`argv` 必须和脚本真实的 `argparse` 参数对得上**。写完用 `-h` 核对一遍，别凭印象写。
2. **产物一律写到 `{outdir}`**，不要写到输入文件旁边。`{outdir}` 是本次运行的独立目录。
3. **`presets` 至少 2 条**，第一条是最常用/最推荐的。标题要让人一眼知道干什么。
4. `input` 选 `files`（拖文件）、`text`（填文本框）、`none`（都不需要）。
   用 `{text}` 的预设，脚本必须能从 stdin 或某个参数接收这段文本。
5. 不需要文件的预设加 `"no_file": true`，界面上就不会拦着你要文件。
6. `accept` 只写脚本**真的能处理**的扩展名，不要图省事写 `[]` 或写一堆用不上的。
7. 脚本要读自己目录下配置/数据的，加 `"cwd": "tool"`；默认是在运行目录里跑。

## 四、自测要求

你写完必须自己跑一遍验证，至少覆盖：
- 无参数运行 → 打印用法、退出码 0
- 正常路径 → 用你临时造的最小样例（自己生成，不要依赖真实题目文件）
- 异常路径 → 文件不存在 / 格式不对，给出清楚报错而不是 traceback
- 中文路径 → 造一个含中文的临时目录名试一次
- **`run` 块里每个 preset 的 `argv` 都实际跑一次**，确认参数没写错、产物真落在 `{outdir}` 里

临时文件放 `%TEMP%` 下自己的子目录，测完删掉。不要往 `D:\杂项工具` 里丢测试文件。

## 五、报告格式

完成后用 `send_message` 回：每个脚本一行（文件名 + 一句话 + 自测结论），以及你验证过的具体命令。
