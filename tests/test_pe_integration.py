import sys
from pathlib import Path

import pytest

from reversehelper import ReverseHelperAnalyzer


@pytest.mark.skipif(Path(sys.executable).read_bytes()[:2] != b"MZ", reason="integration target is not a Windows PE")
def test_analyzes_python_executable_without_running_target():
    result = ReverseHelperAnalyzer(maximum_strings=250).analyze(sys.executable)
    assert result["basic"]["file_name"]
    assert result["basic"]["number_of_sections"] > 0
    assert len(result["hashes"]["sha256"]) == 64
    assert result["sections"]
    assert result["analysis_scope"].startswith("Static PE triage")
