import sys
from pathlib import Path

import pytest

import reversehelper.analyzer as analyzer_module
from reversehelper import ReverseHelperAnalyzer


pytestmark = pytest.mark.skipif(
    Path(sys.executable).read_bytes()[:2] != b"MZ",
    reason="integration target is not a Windows PE",
)


def test_default_analysis_adds_schema_1_2_fields_without_removing_legacy_results():
    result = ReverseHelperAnalyzer(maximum_strings=100).analyze(sys.executable)

    assert result["schema_version"] == "1.2"
    for key in (
        "basic",
        "sections",
        "imports",
        "exports",
        "strings",
        "entry_point_analysis",
        "code_caves",
        "crypto_constants",
        "packing",
        "risk",
    ):
        assert key in result
    for key in (
        "disassembly",
        "control_transfers",
        "findings",
        "reverse_targets",
        "analysis_path",
        "unresolved_questions",
        "analysis_warnings",
    ):
        assert key in result
    assert result["disassembly"]["instruction_count"] > 0
    assert all(target["finding_ids"] for target in result["reverse_targets"])


def test_optional_analyzer_failure_becomes_warning_and_other_modules_continue(monkeypatch):
    def fail_anti_debug(*args, **kwargs):
        raise RuntimeError("synthetic anti-debug failure")

    monkeypatch.setattr(analyzer_module.anti_debug_analyzer, "analyze_anti_debug", fail_anti_debug)

    result = ReverseHelperAnalyzer(maximum_strings=50).analyze(sys.executable)

    warning = next(item for item in result["analysis_warnings"] if item["module"] == "anti-debug")
    assert warning == {
        "module": "anti-debug",
        "error_type": "RuntimeError",
        "reason": "synthetic anti-debug failure",
    }
    assert "validation" in {finding["category"] for finding in result["findings"]}
    assert "risk" in result


@pytest.mark.parametrize("module", ["antidebug", "validation", "crypto", "targets"])
def test_new_single_module_modes_are_explicit(module):
    result = ReverseHelperAnalyzer(maximum_strings=50).analyze_module(sys.executable, module)

    assert result["schema_version"] == "1.2"
    assert result["analysis_mode"] == module
    assert result["analysis_modules"] == [module]
    assert "findings" in result
    assert "strings" not in result


def test_quick_mode_skips_instruction_pipeline():
    result = ReverseHelperAnalyzer(maximum_strings=50).analyze_quick(sys.executable)

    assert result["schema_version"] == "1.2"
    assert "disassembly" not in result
    assert "findings" not in result
    assert "reverse_targets" not in result


def test_resolved_import_call_is_not_reported_as_unresolved_control_flow():
    transfer = {
        "transfer_type": "call",
        "target_status": "unresolved",
        "pointer_address": None,
        "source_address": 0x401000,
        "source_rva": 0x1000,
        "file_offset": 0x200,
        "mnemonic": "call",
        "op_str": "eax",
    }

    findings = analyzer_module._control_flow_findings(
        [transfer],
        [{"name": ".text", "virtual_address": 0x1000, "raw_size": 0x100}],
        {0x401000},
    )

    assert findings == []
