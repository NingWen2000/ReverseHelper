"""Real compiler fixtures for optimized flow shapes; generated PE files are never executed."""

from pathlib import Path
import subprocess

import pytest

from reversehelper.analyzer import ReverseHelperAnalyzer
from p0_support import find_mingw_gcc


SOURCE = Path(__file__).parent / "fixtures" / "phase26_optimized_flow.c"


@pytest.mark.parametrize("optimization", ["-O1", "-O2"])
def test_real_optimized_pe_fixture_is_statically_analyzable(tmp_path, optimization):
    compiler = find_mingw_gcc()
    if compiler is None:
        pytest.skip("MinGW GCC is not installed; the reproducible fixture source remains available")
    output = tmp_path / f"phase26_{optimization[1:]}.exe"
    subprocess.run(
        [compiler, optimization, "-s", str(SOURCE), "-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    result = ReverseHelperAnalyzer().analyze(output)

    assert result["basic"]["file_type"] == "EXE"
    assert result["disassembly"]["instruction_count"] > 0
    assert result["analysis_limits"]["max_instructions"] > 0
    assert not any(warning.get("error_type") == "ModuleFailure" for warning in result["analysis_warnings"])
