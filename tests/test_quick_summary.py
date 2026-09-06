import io
import json

import pytest
from rich.console import Console

from reversehelper import ReverseHelperAnalyzer, cli
from reversehelper import quick_analysis, reporting, string_intelligence, target_ranker, validation_analyzer
from reversehelper.challenge_summary import build_summary, summary_lines
from reversehelper.console import print_quick_analysis
from p0_support import write_pe


@pytest.mark.parametrize("x64", [False, True])
def test_quick_summary(tmp_path, x64):
    path = write_pe(tmp_path / "crackme.exe", api="memcmp", x64=x64)
    result = ReverseHelperAnalyzer().analyze(path)
    assert result["analysis_mode"] == "quick"
    assert result["schema_version"] == "1.5"
    assert result["challenge_summary"]["start_here"]["rva"] == 0x1000
    assert result["reverse_targets"][0]["score"] >= 65
    assert result["validation_candidates"][0]["compare_length"] == 6
    assert result["compare_sites"] and result["decision_sites"]
    assert "code_caves" not in result
    assert "dynamic-advisor" in result["skipped_modules"]
    stream = io.StringIO()
    print_quick_analysis(result, Console(file=stream, width=120, color_system=None))
    text = stream.getvalue()
    assert "ReverseHelper Quick Analysis" in text
    assert text.index("START HERE") < text.index("Interesting Strings")
    assert "Validation Candidates" in text and "Top Reverse Targets" in text
    assert "Reason:" in text and "Wrong flag!" in text
    assert "Sections" not in text and "Entropy" not in text
    for document in (reporting.markdown_report(result), reporting.html_report(result)):
        assert "START HERE" in document
        assert "Independent evidence families" in document


@pytest.mark.parametrize("args", [[], ["--quick"]])
def test_default_and_explicit_quick_export_reports(tmp_path, capsys, args):
    path = write_pe(tmp_path / "crackme.exe")
    assert cli.main([str(path), *args, "--report", str(tmp_path / "reports")]) == 0
    output = capsys.readouterr().out
    assert "START HERE" in output
    assert "Sections" not in output
    report = json.loads((tmp_path / "reports/crackme_report.json").read_text(encoding="utf-8"))
    assert report["interesting_strings"] and report["reverse_targets"]


@pytest.mark.parametrize("module,attribute,warning,remaining", [
    (quick_analysis, "extract_strings", "strings", "validation_candidates"),
    (string_intelligence, "analyze_interesting_strings", "string-intelligence", "validation_candidates"),
    (validation_analyzer, "discover_validation", "validation", "interesting_strings"),
    (target_ranker, "rank_targets", "target-ranking", "validation_candidates"),
])
def test_optional_p0_module_failure_preserves_other_results(tmp_path, monkeypatch, module, attribute, warning, remaining):
    path = write_pe(tmp_path / "crackme.exe")

    def fail(*args, **kwargs):
        raise RuntimeError("injected P0 failure")

    monkeypatch.setattr(module, attribute, fail)
    result = ReverseHelperAnalyzer().analyze(path)
    assert any(w["module"] == warning and "injected" in w["reason"] for w in result["analysis_warnings"])
    assert result[remaining]
    assert "START HERE" in reporting.markdown_report(result)


def test_report_failure_does_not_block_other_formats(tmp_path, monkeypatch, capsys):
    path = write_pe(tmp_path / "crackme.exe")

    def fail(*args):
        raise RuntimeError("injected Markdown failure")

    monkeypatch.setattr(reporting, "markdown_report", fail)
    code = cli.main([str(path), "--report", str(tmp_path / "reports")])
    assert code == 3
    output = capsys.readouterr()
    assert "START HERE" in output.out and "injected Markdown failure" in output.err
    assert (tmp_path / "reports/crackme_report.html").exists()
    result = json.loads((tmp_path / "reports/crackme_report.json").read_text(encoding="utf-8"))
    assert any(w["module"] == "report.md" for w in result["analysis_warnings"])
    assert result["reverse_targets"]


def test_individual_report_failure_does_not_block_json(tmp_path, monkeypatch, capsys):
    path = write_pe(tmp_path / "crackme.exe")
    def fail(*args):
        raise ValueError("injected HTML failure")
    monkeypatch.setattr(cli, "write_html", fail)
    assert cli.main([str(path), "--html", str(tmp_path / "broken.html"), "--json", str(tmp_path / "ok.json")]) == 3
    assert (tmp_path / "ok.json").exists()
    assert "Warning" in capsys.readouterr().err


def test_quick_budget_is_reported_and_does_not_start_expensive_modules(tmp_path, monkeypatch):
    path = write_pe(tmp_path / "crackme.exe")
    monkeypatch.setattr(quick_analysis, "MAX_INSTRUCTIONS", 3)
    def forbidden(*args, **kwargs):
        raise AssertionError("legacy full analysis should not start")
    monkeypatch.setattr(ReverseHelperAnalyzer, "analyze_full", forbidden)
    result = ReverseHelperAnalyzer().analyze(path)
    assert result["disassembly"]["instruction_count"] <= 3
    assert result["analysis_limits"]["max_instructions"] == 3
    assert any(w["module"] == "disassembler" for w in result["analysis_warnings"])
    assert result["interesting_strings"]


def test_empty_candidate_summary_has_honest_fallback(tmp_path):
    path = write_pe(tmp_path / "empty.exe", code=b"\xc3")
    result = ReverseHelperAnalyzer().analyze(path)
    assert result["challenge_summary"]["start_here"] is None
    assert "No supported critical-function candidate" in reporting.markdown_report(result)


def test_low_confidence_close_scores_offer_multiple_starting_points():
    result = {
        "basic": {"is_64_bit": False, "architecture": "x86", "entry_point_rva": 0x1000},
        "packing": {"verdict": "no-obvious-indicators", "static_visibility": "normal"},
        "reverse_targets": [
            {"function": "FUN_A", "rva": 0x1010, "va": 0x401010, "score": 24, "confidence": "low",
             "reason": "weak A", "recommended_action": "inspect A", "type": "COMPARE"},
            {"function": "FUN_B", "rva": 0x1020, "va": 0x401020, "score": 22, "confidence": "low",
             "reason": "weak B", "recommended_action": "inspect B", "type": "INPUT"},
        ],
        "static_slices": [], "input_sources": [], "interesting_strings": [],
        "validation_candidates": [], "compare_sites": [], "analysis_warnings": [],
    }
    summary = build_summary(result)
    assert summary["start_here"] is None
    assert [item["label"] for item in summary["starting_points"]] == ["FUN_A", "FUN_B"]
    rendered = "\n".join(summary_lines({**result, "challenge_summary": summary}))
    assert "START WITH THESE" in rendered


def test_quick_output_escapes_sample_markup(tmp_path):
    result = ReverseHelperAnalyzer().analyze(write_pe(tmp_path / "crackme.exe"))
    result["interesting_strings"][0]["value"] = '<script>alert(1)</script> [red]`|'
    html = reporting.html_report(result)
    assert "<script>" not in html and "&lt;script&gt;" in html
    markdown = reporting.markdown_report(result)
    assert "<script>" not in markdown and "\\[red]" in markdown
    stream = io.StringIO()
    print_quick_analysis(result, Console(file=stream))
    assert "[red]" in stream.getvalue()


def test_console_render_failure_preserves_file_report(tmp_path, monkeypatch, capsys):
    path = write_pe(tmp_path / "crackme.exe")
    def fail(*args):
        raise RuntimeError("injected console failure")
    monkeypatch.setattr(cli, "print_quick_analysis", fail)
    assert cli.main([str(path), "--json", str(tmp_path / "report.json")]) == 3
    result = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert result["reverse_targets"]
    assert any(w["module"] == "report-console" for w in result["analysis_warnings"])
    assert "Warning" in capsys.readouterr().err
