"""Language is a rendering choice, never an analysis input."""

from copy import deepcopy
import io
import json
import os
from pathlib import Path
import runpy
import string
import subprocess
import sys

import pytest
from rich.console import Console

from reversehelper import ReverseHelperAnalyzer, cli, reporting
from reversehelper.challenge_summary import summary_lines
from reversehelper.console import print_quick_analysis
from reversehelper.localization import Language, MESSAGES, display_enum
from reversehelper.localized_annotations import annotation_export
from p0_support import write_pe


GOLDEN = Path(__file__).parent / "golden" / "localization"


@pytest.fixture
def result():
    return json.loads((GOLDEN / "summary-input.json").read_text(encoding="utf-8"))


def test_lang_default_en(result):
    expected = (GOLDEN / "summary.en.txt").read_text(encoding="utf-8")
    assert "\n".join(summary_lines(result)) + "\n" == expected
    assert summary_lines(result) == summary_lines(result, lang="en")
    assert cli.build_parser().parse_args(["sample.exe"]).lang == "en"


def test_lang_zh_cn(result):
    assert "\n".join(summary_lines(result, lang="zh-CN")) + "\n" == (GOLDEN / "summary.zh-CN.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize("arguments", [["--lang", "zh-TW"], ["--lang=fr"], ["--lang", "zh-TW", "--help"]])
def test_invalid_lang(arguments, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 2
    assert "可用语言：en, zh-CN" in capsys.readouterr().err


@pytest.mark.parametrize("arguments", [["--help", "--lang", "zh-CN"], ["--lang=zh-CN", "--help"], ["--la", "zh-CN", "--help"]])
def test_help_zh_cn(arguments, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 0
    output = capsys.readouterr().out
    for text in ("用法", "Quick", "Deep", "--ghidra", "--json", "--lang", "界面语言", "写入"):
        assert text in output


def facts(value):
    # Time measurements differ between independent runs; no analysis fields are ignored.
    if isinstance(value, dict):
        return {key: facts(item) for key, item in value.items()
                if key not in {"analyzed_at_utc", "module_timings_ms"} and not key.endswith("elapsed_ms")}
    if isinstance(value, list):
        return [facts(item) for item in value]
    return value


@pytest.mark.parametrize("mode", [[], ["--deep"]])
def test_analysis_same_across_languages(tmp_path, mode):
    target = write_pe(tmp_path / "题目.exe", api="memcmp")
    outputs = []
    for language in ("en", "zh-CN"):
        path = tmp_path / (language + ".json")
        assert cli.main([str(target), *mode, "--lang", language, "--quiet", "--json", str(path)]) == 0
        outputs.append(json.loads(path.read_text(encoding="utf-8")))
    assert facts(outputs[0]) == facts(outputs[1])
    assert outputs[1]["schema_version"] == "1.5"
    assert outputs[1]["target_ranking"]["version"] == "2.2"


def test_json_schema_same(result, tmp_path):
    original = deepcopy(result)
    for language in Language:
        reporting.markdown_report(result, lang=language)
        reporting.html_report(result, lang=language)
        annotation_export(result, language)
    reporting.write_json(result, tmp_path / "result.json")
    assert json.loads((tmp_path / "result.json").read_text(encoding="utf-8")) == original == result


def test_summary_zh_cn(result):
    output = "\n".join(summary_lines(result, lang="zh-CN"))
    for text in ("建议从这里开始", "静态可见性：完全可见", "置信度：高", "验证逻辑", "静态", "算法候选", "控制流", "语义建议", "Wrong flag!", "FUN_401000"):
        assert text in output


@pytest.mark.parametrize("kind, expected", [("missing", "目标文件不存在"), ("invalid", "无效的 PE"), ("directory", "无法读取")])
def test_error_zh_cn(tmp_path, capsys, kind, expected):
    path = tmp_path / "目标.exe"
    if kind == "invalid":
        path.write_bytes(b"not a PE")
    elif kind == "directory":
        path.mkdir()
    assert cli.main([str(path), "--lang", "zh-CN"]) == 2
    output = capsys.readouterr().err
    assert expected in output and "Traceback" not in output


def test_warning_zh_cn(result):
    result["analysis_warnings"] = [{"module": "static-flow", "reason": "Interprocedural edge budget reached"}]
    result["truncated_modules"] = ["static-flow"]
    output = "\n".join(summary_lines(result, lang="zh-CN"))
    assert "警告" in output and "分析因预算限制被截断" in output


def test_ghidra_comment_zh_cn(result):
    exported = annotation_export(result, "zh-CN")
    start = next(item for item in exported["annotations"] if item["category"] == "RH:START")
    assert "建议从这里开始" in start["comment"] and "原因：" in start["comment"]
    importer = runpy.run_path(str(Path(__file__).parents[1] / "scripts/ImportReverseHelperFindings.py"))
    operations = importer["plan_import"](exported, exported["basic"]["file_name"], exported["hashes"]["sha256"], [(0, 0x10000)])
    assert any("建议从这里开始" in operation["comment"] for operation in operations)
    assert all(operation["rename"] is None for operation in operations)


def test_ghidra_category_stable(result):
    en = annotation_export(result, "en")
    zh = annotation_export(result, "zh-CN")
    for left, right in zip(en["annotations"], zh["annotations"], strict=True):
        assert {key: value for key, value in left.items() if key not in {"title", "comment"}} == {key: value for key, value in right.items() if key not in {"title", "comment"}}
    assert {key: value for key, value in en.items() if key != "annotations"} == {key: value for key, value in zh.items() if key != "annotations"}


def test_unicode_path(tmp_path):
    folder = tmp_path / "用户 测试" / "题目"
    folder.mkdir(parents=True)
    target = write_pe(folder / "逆向题.exe")
    output = folder / "报告"
    assert cli.main([str(target), "--lang", "zh-CN", "--report", str(output), "--ghidra", str(output / "annotations.json")]) == 0
    assert "目标文件：逆向题.exe" in (output / "逆向题_report.md").read_text(encoding="utf-8")
    html = (output / "逆向题_report.html").read_text(encoding="utf-8")
    assert '<html lang="zh-CN">' in html and "题目摘要" in html


@pytest.mark.parametrize("encoding", ["ascii", "cp1252", "gbk", "utf-8"])
def test_unicode_output(encoding):
    process = subprocess.run([sys.executable, "-m", "reversehelper", "--lang", "zh-CN", "--help"],
                             capture_output=True, env={**os.environ, "PYTHONIOENCODING": encoding})
    assert process.returncode == 0
    assert "界面语言" in process.stdout.decode("utf-8")
    assert b"UnicodeEncodeError" not in process.stderr


def test_sample_text_is_never_translated(result):
    result["interesting_strings"][0]["value"] = "START HERE HIGH <script>[red]建议"
    text = "\n".join(summary_lines(result, lang="zh-CN"))
    assert "START HERE HIGH <script>[red]建议" in text
    html = reporting.html_report(result, lang="zh-CN")
    assert "<script>" not in html and "&lt;script&gt;" in html
    stream = io.StringIO()
    print_quick_analysis(result, Console(file=stream, width=120), lang="zh-CN")
    assert "[red]建议" in stream.getvalue()


def test_symbol_names_are_not_enum_labels(result):
    from reversehelper.localization import prose
    result["challenge_summary"]["semantic_suggestions"] = [
        {"target": {"current_name": "KEY"}, "proposed_value": {"name": "INPUT"}, "confidence": "HIGH"},
        {"target": {"current_name": "buffer"}, "kind": "OBJECT_ROLE", "proposed_value": "INPUT", "confidence": "HIGH"},
    ]
    output = "\n".join(summary_lines(result, lang="zh-CN"))
    assert "KEY -> INPUT" in output and "buffer -> 输入" in output
    assert "检查 INPUT" in prose("Inspect INPUT and follow the next source-reachable use.", "zh-CN")


def test_resource_placeholders_match():
    def fields(template):
        return sorted(field for _, field, _, _ in string.Formatter().parse(template) if field is not None)
    for key, (en, zh) in MESSAGES.items():
        assert fields(en) == fields(zh), key


@pytest.mark.parametrize("language", ["en", "zh-CN"])
def test_rich_summary_golden(language):
    result = json.loads((GOLDEN / "rich-input.json").read_text(encoding="utf-8"))
    output = "\n".join(summary_lines(result, lang=language)) + "\n"
    assert output == (GOLDEN / ("rich." + language + ".txt")).read_text(encoding="utf-8")
    if language == "zh-CN":
        for text in ("建议优先查看这些位置", "静态数据流切片", "状态机", "XTEA", "已变换输入", "uint8_t*", "分析因预算限制被截断"):
            assert text in output


@pytest.mark.parametrize("format, renderer", [("md", reporting.markdown_report), ("html", reporting.html_report)])
def test_english_report_golden(result, format, renderer):
    assert renderer(result) == (GOLDEN / ("report." + format + ".en.txt")).read_text(encoding="utf-8")


@pytest.mark.parametrize("option, expected", [("--markdown", "无法写入报告"), ("--ghidra", "无法导出 Ghidra")])
def test_report_error_zh_cn(tmp_path, capsys, option, expected):
    target = write_pe(tmp_path / "sample.exe")
    blocked = tmp_path / "blocked"
    blocked.write_text("file, not directory", encoding="utf-8")
    assert cli.main([str(target), "--lang", "zh-CN", option, str(blocked / "result"), "--quiet"]) == 3
    output = capsys.readouterr().err
    assert expected in output and "Traceback" not in output


def test_packed_visibility_and_guidance(result):
    from reversehelper.localization import prose
    summary = result["challenge_summary"]
    summary["static_visibility"] = "limited"
    summary["packing"] = "Packed / obfuscated binary detected; static visibility is limited"
    summary["packing_guidance"] = ["Inspect the entry stub and identify the transition to the original entry point (OEP)."]
    summary["notice"] = "Scores rank review priority, not probability. Pre-unpack strings, validation and ranking have reduced reliability; re-run on an unpacked dump."
    rendered = "\n".join(summary_lines(result, lang="zh-CN"))
    assert "已加壳或运行时变换" in rendered and "不要完全信任" in rendered and "OEP" in rendered
    assert prose("unknown developer diagnostic", "zh-CN") == "unknown developer diagnostic"


def test_all_annotation_categories_preserve_machine_values(result):
    categories = ["RH:INPUT", "RH:VALIDATION", "RH:SLICE", "RH:FLOW_BREAK", "RH:ALGORITHM", "RH:CONTROL_FLOW", "RH:STATE_MACHINE", "RH:SUGGEST_TYPE"]
    for index, category in enumerate(categories):
        result["annotations"].append({"rva":0x1100+index, "category":category, "title":"XTEA" if category == "RH:ALGORITHM" else "STATE_MACHINE",
                                      "comment":"Suggested semantic: uint8_t*\nSuggested: Inspect the selector range check, then label each case target before reading case bodies.",
                                      "confidence":"medium", "evidence":["technical evidence"], "fact_status":"candidate"})
    exported = annotation_export(result, "zh-CN")
    for original, translated in zip(result["annotations"], exported["annotations"], strict=True):
        assert "置信度：" in translated["comment"]
        assert original["category"] == translated["category"] and original["rva"] == translated["rva"]


@pytest.mark.parametrize("value", ["HIGH", "CONFIRMED", "NORMAL", "FULLY_VISIBLE", "PARTIALLY_VISIBLE", "PACKED_OR_TRANSFORMED", "INPUT", "KEY", "STATE_MACHINE", "TRUNCATED", "UNAVAILABLE"])
def test_enum_display_only(value):
    assert display_enum(value, "en") == value
    assert display_enum(value, "zh-CN") != value
