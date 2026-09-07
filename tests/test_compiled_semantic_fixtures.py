"""Optimized semantic fixtures are statically analyzed and never executed."""

from pathlib import Path
import subprocess

import pytest

from reversehelper.analyzer import ReverseHelperAnalyzer
from p0_support import find_mingw_gcc


SOURCE = Path(__file__).parent / "fixtures" / "phase3c_semantics.c"


@pytest.mark.parametrize("optimization", ["-O1", "-O2"])
def test_optimized_semantic_fixture_keeps_budgets_and_schema(tmp_path, optimization):
    compiler = find_mingw_gcc()
    if compiler is None:
        pytest.skip("MinGW GCC is not installed; the reproducible fixture source remains available")
    output = tmp_path / f"phase3c_{optimization[1:]}.exe"
    subprocess.run([compiler, optimization, str(SOURCE), "-o", str(output)], check=True,
                   capture_output=True, text=True, timeout=30)
    result = ReverseHelperAnalyzer().analyze_quick(output)
    assert "decompiler_suggestions" in result
    assert len(result["decompiler_suggestions"]) <= 20
    assert result["analysis_limits"]["max_expression_groups"] == 8
    assert not any(warning.get("module") == "decompiler-assistance"
                   and warning.get("error_type") == "ModuleFailure"
                   for warning in result["analysis_warnings"])
