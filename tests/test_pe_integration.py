import sys
from pathlib import Path

import pytest

from reversehelper import ReverseHelperAnalyzer


pytestmark = pytest.mark.skipif(
    Path(sys.executable).read_bytes()[:2] != b"MZ",
    reason="integration target is not a Windows PE",
)


def test_analyzes_python_executable_without_running_target():
    result = ReverseHelperAnalyzer(maximum_strings=250).analyze(sys.executable)
    assert result["basic"]["file_name"]
    assert result["basic"]["number_of_sections"] > 0
    assert len(result["hashes"]["sha256"]) == 64
    assert result["sections"]
    assert result["entry_point_analysis"]["file_offset"] == result["basic"]["entry_point_offset"]
    assert all("rva" in item and "va" in item and "section" in item for item in result["strings"]["items"])
    assert result["analysis_scope"].startswith("Static PE triage")


def test_quick_analysis_skips_expensive_modules():
    result = ReverseHelperAnalyzer(maximum_strings=250).analyze_quick(sys.executable)

    assert result["analysis_mode"] == "quick"
    assert result["analysis_modules"] == ["pe", "sections", "imports", "exports", "entry", "anomaly"]
    assert "entry_point_analysis" in result
    assert "packing" in result
    assert "risk" in result
    assert "strings" not in result
    assert "crypto_constants" not in result
    assert "code_caves" not in result


@pytest.mark.parametrize(
    ("module", "expected_key"),
    [("anomaly", "packing"), ("strings", "strings"), ("imports", "imports")],
)
def test_single_module_analysis(module, expected_key):
    result = ReverseHelperAnalyzer(maximum_strings=250).analyze_module(sys.executable, module)

    assert result["analysis_mode"] == module
    assert result["analysis_modules"] == [module]
    assert expected_key in result
