import pytest

from reversehelper.findings import ReverseTarget
from reversehelper.x64dbg_exporter import generate_x64dbg_script, write_x64dbg_script


def _target(
    category: str,
    rva: int | None,
    *,
    priority: str = "high",
    finding_id: str = "finding",
) -> ReverseTarget:
    return ReverseTarget(
        category=category,
        rva=rva,
        va=0x401820,
        file_offset=0xC20,
        section=".text",
        priority=priority,
        reason="Static evidence identifies a useful reverse target.",
        recommended_action="Inspect this location.",
        finding_ids=(finding_id,),
    )


@pytest.mark.parametrize("architecture", ["x86", "x86-64"])
def test_script_uses_module_relative_rva_for_x86_and_x64(architecture):
    script = generate_x64dbg_script(
        [_target("validation", 0x1820)],
        "challenge.exe",
        architecture,
    )

    assert 'bp challenge.exe:$1820, "RH_HIGH_validation_1820"' in script
    assert 'cmt challenge.exe:$1820, "ReverseHelper high validation target"' in script
    assert "401820" not in script


def test_supported_target_categories_receive_breakpoint_suggestions():
    targets = [
        _target("validation", 0x1820, finding_id="validation"),
        _target("anti-debug", 0x1900, priority="medium", finding_id="anti"),
        _target("crypto", 0x1A00, priority="medium", finding_id="crypto"),
        _target("control-flow", 0x1B00, priority="high", finding_id="indirect-call"),
    ]

    script = generate_x64dbg_script(targets, "challenge.exe", "x86-64")

    assert {line.split(",", 1)[0] for line in script.splitlines() if line.startswith("bp ")} == {
        "bp challenge.exe:$1820",
        "bp challenge.exe:$1900",
        "bp challenge.exe:$1A00",
        "bp challenge.exe:$1B00",
    }


def test_target_without_rva_does_not_generate_breakpoint():
    script = generate_x64dbg_script(
        [_target("control-flow", None, finding_id="unresolved-without-location")],
        "challenge.exe",
        "x86",
    )

    assert not any(line.startswith("bp ") for line in script.splitlines())


def test_low_priority_target_is_not_exported_automatically():
    script = generate_x64dbg_script(
        [_target("input", 0x2000, priority="low")],
        "challenge.exe",
        "x86",
    )

    assert not any(line.startswith("bp ") for line in script.splitlines())


def test_unsafe_module_name_is_rejected():
    with pytest.raises(ValueError, match="unsafe"):
        generate_x64dbg_script([_target("validation", 0x1820)], "bad;run.exe", "x86")


def test_script_writer_uses_requested_txt_or_x64dbg_path(tmp_path):
    path = write_x64dbg_script(
        [_target("validation", 0x1820)],
        "challenge.exe",
        "x86-64",
        tmp_path / "breakpoints.x64dbg",
    )

    assert path.suffix == ".x64dbg"
    assert "challenge.exe:$1820" in path.read_text(encoding="utf-8")
