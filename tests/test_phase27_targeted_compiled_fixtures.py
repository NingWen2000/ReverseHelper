"""Compile Phase 2.7B shapes at real optimization levels; generated PEs are never run."""

from pathlib import Path
import subprocess

import pytest

from reversehelper.analyzer import ReverseHelperAnalyzer
from p0_support import find_mingw_gcc


SOURCE = Path(__file__).parent / "fixtures" / "phase27_targeted_recovery.c"


@pytest.mark.parametrize("optimization", ["-O1", "-O2"])
def test_phase27_targeted_fixture_remains_statically_analyzable(tmp_path, optimization):
    compiler = find_mingw_gcc()
    if compiler is None:
        pytest.skip("MinGW GCC is not installed; the reproducible fixture source remains available")
    output = tmp_path / f"phase27_{optimization[1:]}.exe"
    subprocess.run([compiler, optimization, "-s", str(SOURCE), "-o", str(output)],
                   check=True, capture_output=True, text=True, timeout=30)
    result = ReverseHelperAnalyzer().analyze(output)
    assert result["basic"]["file_type"] == "EXE"
    assert result["disassembly"]["instruction_count"] > 0
    assert not any(warning.get("error_type") == "ModuleFailure"
                   for warning in result["analysis_warnings"])
