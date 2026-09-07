import json
import runpy
import socket
from pathlib import Path

from reversehelper import ReverseHelperAnalyzer, cli
from reversehelper.analysis_budget import AnalysisBudget
from reversehelper.challenge_summary import summary_lines
from p0_support import write_pe


def test_deep_uses_same_schema_with_larger_explicit_budgets(tmp_path):
    path = write_pe(tmp_path / "challenge.exe", api="memcmp")
    quick = ReverseHelperAnalyzer().analyze_quick(path)
    deep = ReverseHelperAnalyzer().analyze_deep(path)

    assert quick["analysis_mode"] == "quick"
    assert deep["analysis_mode"] == "deep"
    assert deep["schema_version"] == quick["schema_version"]
    assert deep["analysis_limits"]["max_instructions"] > quick["analysis_limits"]["max_instructions"]
    assert deep["target_ranking"]["version"] == quick["target_ranking"]["version"] == "2.2"
    assert "deep_elapsed_ms" in deep and "quick_elapsed_ms" not in deep


def test_product_summary_and_annotation_contract(tmp_path):
    result = ReverseHelperAnalyzer().analyze(write_pe(tmp_path / "challenge.exe", api="memcmp"))
    rendered = "\n".join(summary_lines(result))

    assert "Target: challenge.exe" in rendered
    assert "Static visibility:" in rendered
    assert "Likely Validation" in rendered
    assert result["annotations"]
    assert {"rva", "category", "title", "comment", "confidence", "evidence", "fact_status"} <= result["annotations"][0].keys()
    assert set(result["result_status"]) == {"facts", "candidates", "suggestions", "unavailable", "truncated"}


def test_quick_workflow_does_not_require_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    path = write_pe(tmp_path / "offline.exe")
    output = tmp_path / "offline.json"
    assert cli.main([str(path), "--quiet", "--json", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["analysis_scope"].startswith("Static PE")


def test_deep_cli_and_default_ghidra_export(tmp_path, monkeypatch):
    path = write_pe(tmp_path / "deep.exe")
    monkeypatch.chdir(tmp_path)
    assert cli.main([str(path), "--deep", "--quiet", "--ghidra"]) == 0
    payload = json.loads((tmp_path / "reports" / "deep.reversehelper.json").read_text(encoding="utf-8"))
    assert payload["analysis_mode"] == "deep"
    assert payload["annotations"]


def test_ghidra_importer_consumes_unified_annotations():
    script = Path(__file__).parents[1] / "scripts" / "ImportReverseHelperFindings.py"
    api = runpy.run_path(str(script))
    payload = {
        "basic": {"file_name": "challenge.exe"},
        "hashes": {"sha256": "a" * 64},
        "annotations": [{"rva": 0x1200, "category": "RH:START", "title": "START HERE",
                         "comment": "Inspect this function.", "confidence": "high", "evidence": ["ranked first"]}],
    }
    operations = api["plan_import"](payload, "challenge.exe", "a" * 64, [(0x1000, 0x2000)])
    assert operations[0]["bookmark"] == "RH:START"
    assert operations[0]["rename"] is None


def test_budget_profiles_are_valid_and_ordered():
    quick, deep = AnalysisBudget.quick(), AnalysisBudget.deep()
    assert quick.mode == "quick" and deep.mode == "deep"
    for key, value in quick.to_dict().items():
        if key != "mode":
            assert value > 0 and deep.to_dict()[key] >= value
