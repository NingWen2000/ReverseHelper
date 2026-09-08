"""CLI-only localization, including safe stream handling for redirected Windows output."""

import sys

from .localization import Language, message


HELP = {
    "target": "EXE、DLL、SYS 或其他 PE 文件的路径",
    "help": "显示帮助并退出",
    "quick": "Quick（快速分析）模式：在有限预算内生成题目摘要（默认）",
    "deep": "Deep（深入静态分析）模式：使用相同分析器并提高预算",
    "only": "仅运行一个诊断模块：anomaly、strings、imports、antidebug、validation、crypto 或 targets",
    "report": "生成 Markdown、JSON 和独立 HTML 报告（默认目录：reports）",
    "json_path": "写入 JSON 报告；字段名、枚举和分析事实保持英文且与语言无关",
    "ghidra": "导出 Ghidra 注释 JSON；RH:* 分类保持英文，注释跟随界面语言",
    "html_path": "写入独立 HTML 报告",
    "markdown_path": "写入 Markdown 报告",
    "x64dbg_script": "将高/中优先级目标写入支持 ASLR 的 .txt 或 .x64dbg 脚本",
    "min_string_length": "提取字符串的最小长度（默认：4）",
    "max_strings": "保留的唯一字符串数量上限（默认：2000）",
    "quiet": "不显示终端分析表格",
    "verbose": "显示预算、覆盖范围及开发者诊断详情（部分为英文）",
    "version": "显示版本并退出",
    "lang": "界面语言：en 或 zh-CN（默认：en，不随系统语言改变）",
}

ERRORS = {
    "--min-string-length must be at least 3": "--min-string-length 必须至少为 3",
    "--max-strings must be positive": "--max-strings 必须为正数",
    "report options require Quick Analysis; omit --only": "报告选项要求使用 Quick/Deep 模式；请移除 --only",
    "--x64dbg-script requires default analysis or --only targets": "--x64dbg-script 要求默认分析模式或 --only targets",
    "--x64dbg-script output must end in .txt or .x64dbg": "--x64dbg-script 输出文件必须以 .txt 或 .x64dbg 结尾",
}


def localize_parser(parser):
    parser.description = "离线 CTF Quick 分析：查找值得关注的字符串、验证逻辑候选与建议起点。"
    parser.epilog = "示例：\n  reversehelper challenge.exe --lang zh-CN\n  reversehelper challenge.exe --lang zh-CN --deep\n  reversehelper challenge.exe --lang zh-CN --ghidra\n  reversehelper challenge.exe --lang zh-CN --report reports"
    for action in parser._actions:
        action.help = HELP.get(action.dest, action.help)
    for group in parser._action_groups:
        group.title = {"positional arguments": "位置参数", "options": "选项", "optional arguments": "可选参数"}.get(group.title, group.title)
    formatter_type = parser.formatter_class

    class Formatter(formatter_type):
        def add_usage(self, usage, actions, groups, prefix=None):
            super().add_usage(usage, actions, groups, prefix="用法：" if prefix is None else prefix)

    parser.formatter_class = Formatter

    def error(text):
        parser.print_usage(sys.stderr)
        translated = ERRORS.get(text, "参数无效。详情：" + text)
        parser.exit(2, "reversehelper：错误：" + translated + "\n")

    parser.error = error


def prepare_streams():
    # Change only this process's stream, never the console code page or system locale.
    # Native Python Windows console streams are already Unicode. Compatible encodings
    # (including GBK) are retained; pipes with ASCII/western encodings use UTF-8.
    for stream in (sys.stdout, sys.stderr):
        encoding = getattr(stream, "encoding", None)
        if encoding and hasattr(stream, "reconfigure"):
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
                continue
            try:
                "简体中文".encode(encoding)
            except (UnicodeEncodeError, LookupError):
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
            else:
                stream.reconfigure(errors="backslashreplace")


def analysis_error(error):
    text = str(error)
    if text.startswith("Input file does not exist"):
        key = "error.missing"
    elif text.startswith(("Could not read input file", "Input path")):
        key = "error.read"
    elif text.startswith(("Input is not a PE file", "Invalid or unsupported PE file")):
        key = "error.format"
    else:
        key = "error.analysis"
    return message(key, Language.ZH_CN)
