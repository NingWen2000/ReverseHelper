import pytest

from reversehelper.analyzer import ReverseHelperAnalyzer
from p0_support import Code, write_pe


def flow_code(*, related=True, argv=False):
    c = Code(base=0x140000000, x64=True)
    if argv:
        c.emit("83 F9 02 48 8B 42 08 48 89 C1")
    else:
        c.emit("48 8D 4D C0 BA 20 00 00 00 45 31 C0")
        c.call(0x2008)  # fgets
        c.emit("48 8D 4D C0" if related else "48 8D 4D A0")
    c.pointer(0x3060, "d")
    c.emit("41 B8 06 00 00 00")
    c.call(0x2000)  # memcmp
    c.emit("85 C0")
    c.jump("75", "failure")
    c.pointer(0x3020)
    c.emit("C3")
    c.label("failure")
    c.pointer(0x3000)
    c.emit("C3")
    return c.finish()


@pytest.mark.parametrize("argv", [False, True], ids=["fgets", "argv_direct_compare"])
def test_quick_static_slice_reaches_memcmp(tmp_path, argv):
    path = write_pe(tmp_path / "flow.exe", api="memcmp", x64=True, code=flow_code(argv=argv))
    result = ReverseHelperAnalyzer().analyze(path)
    assert result["input_sources"]
    assert result["validation_candidates"][0]["input_flow_to_validation"] == "CONFIRMED"
    assert result["static_slices"]
    assert result["challenge_summary"]["static_slice"]["label"] == "Static Slice"
    assert "dataflow" in result["reverse_targets"][0]["evidence_sources"]
    assert "confirmed_static_slice" in {
        part["rule"] for part in result["reverse_targets"][0]["score_breakdown"]
    }


def test_quick_false_same_function_context_is_not_linked(tmp_path):
    path = write_pe(tmp_path / "unrelated.exe", api="memcmp", x64=True, code=flow_code(related=False))
    result = ReverseHelperAnalyzer().analyze(path)
    assert result["input_sources"] and result["validation_candidates"]
    assert result["validation_candidates"][0]["input_flow_to_validation"] == "NONE"
    assert result["static_slices"] == []
    assert "unlinked_input_comparison" in {
        part["rule"] for part in result["reverse_targets"][0]["score_breakdown"]
    }
    assert result["input_source_diagnostics"][0]["code"] == "ARGV_SOURCE_UNRESOLVED"
