"""Optimized Phase 3B fixtures are compiled for static analysis and never executed."""

from pathlib import Path
import shutil
import subprocess

import pytest

from reversehelper.analyzer import ReverseHelperAnalyzer


SOURCE = Path(__file__).parent / "fixtures" / "phase3b_control_flow.c"


@pytest.mark.parametrize("optimization", ["-O1", "-O2"])
def test_optimized_control_flow_fixture_is_bounded_and_explainable(tmp_path, optimization):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("MinGW GCC is not installed; the reproducible fixture source remains available")
    output = tmp_path / f"phase3b_{optimization[1:]}.exe"
    subprocess.run([compiler, optimization, str(SOURCE), "-o", str(output)], check=True,
                   capture_output=True, text=True, timeout=30)
    result = ReverseHelperAnalyzer().analyze_quick(output)
    assert "control_flow_findings" in result
    assert result["control_flow_analysis"]["blocks_analyzed"] > 0
    assert result["analysis_limits"]["max_cfg_edges"] == 12000
    assert not any(warning.get("module") == "control-flow-understanding"
                   and warning.get("error_type") == "ModuleFailure"
                   for warning in result["analysis_warnings"])
