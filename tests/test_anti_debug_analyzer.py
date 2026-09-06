import pytest

from reversehelper.anti_debug_analyzer import ANTI_DEBUG_APIS, analyze_anti_debug
from reversehelper.disassembler import Disassembler


IMAGE_BASE_X86 = 0x400000
IMAGE_BASE_X64 = 0x140000000


def _decode(
    code: bytes,
    architecture: str = "x86",
    image_base: int = IMAGE_BASE_X86,
    start_rva: int = 0x1000,
):
    raw_address = 0x200
    data = b"\x00" * raw_address + code
    sections = [
        {
            "name": ".text",
            "virtual_address": start_rva,
            "virtual_size": len(code),
            "raw_address": raw_address,
            "raw_size": len(code),
        }
    ]
    instructions = Disassembler(architecture, image_base).disassemble_range(
        data, sections, start_rva, len(code)
    )
    return instructions, sections


def _imports(*names: str, image_base: int = IMAGE_BASE_X86):
    return [
        {
            "dll": "KERNEL32.dll",
            "functions": [
                {"name": name, "ordinal": None, "iat_address": image_base + 0x2000, "suspicious": False}
                for name in names
            ],
        }
    ]


def test_supported_api_imports_remain_low_confidence_without_calls():
    names = tuple(ANTI_DEBUG_APIS.values())

    findings = analyze_anti_debug([], _imports(*names), [], "x86", IMAGE_BASE_X86)

    assert {finding.title.rsplit(": ", 1)[-1] for finding in findings} == set(names)
    assert all(finding.confidence == "low" for finding in findings)
    assert all("does not prove" in finding.reason for finding in findings)


def test_isdebuggerpresent_result_reaches_test_and_jcc_without_fixed_window():
    code = bytes.fromhex("FF 15 00 20 40 00") + b"\x90" * 12 + bytes.fromhex("85 C0 75 02 90 C3")
    instructions, sections = _decode(code)

    findings = analyze_anti_debug(
        instructions,
        _imports("IsDebuggerPresent"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    branch = next(finding for finding in findings if "branch after IsDebuggerPresent" in finding.title)
    assert branch.confidence == "high"
    assert any("TEST eax, eax" in evidence for evidence in branch.evidence)
    assert any("JNE" in evidence for evidence in branch.evidence)


def test_eflags_overwrite_breaks_api_branch_association():
    code = bytes.fromhex("FF 15 00 20 40 00 85 C0 83 C1 01 75 02 C3")
    instructions, sections = _decode(code)

    findings = analyze_anti_debug(
        instructions,
        _imports("IsDebuggerPresent"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert not any("branch after IsDebuggerPresent" in finding.title for finding in findings)


def test_return_register_overwrite_breaks_api_branch_association():
    code = bytes.fromhex("FF 15 00 20 40 00 31 C0 85 C0 75 02 C3")
    instructions, sections = _decode(code)

    findings = analyze_anti_debug(
        instructions,
        _imports("IsDebuggerPresent"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert not any("branch after IsDebuggerPresent" in finding.title for finding in findings)


def test_non_flag_conditional_transfer_does_not_consume_test_result():
    code = bytes.fromhex("FF 15 00 20 40 00 85 C0 E3 02 C3")
    instructions, sections = _decode(code)

    findings = analyze_anti_debug(
        instructions,
        _imports("IsDebuggerPresent"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert not any("branch after IsDebuggerPresent" in finding.title for finding in findings)


def test_branch_context_does_not_cross_disjoint_regions():
    call_instructions, call_sections = _decode(bytes.fromhex("FF 15 00 20 40 00"))
    condition_instructions, condition_sections = _decode(
        bytes.fromhex("85 C0 75 02 C3"),
        start_rva=0x3000,
    )

    findings = analyze_anti_debug(
        call_instructions + condition_instructions,
        _imports("IsDebuggerPresent"),
        call_sections + condition_sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert not any("branch after IsDebuggerPresent" in finding.title for finding in findings)


def test_fs_peb_access_alone_is_not_high_confidence():
    instructions, sections = _decode(bytes.fromhex("64 A1 30 00 00 00 C3"))

    findings = analyze_anti_debug(instructions, [], sections, "x86", IMAGE_BASE_X86)

    peb = next(finding for finding in findings if finding.title == "Possible PEB access")
    assert peb.confidence == "low"
    assert not any(finding.confidence == "high" for finding in findings)


@pytest.mark.parametrize(
    ("architecture", "image_base", "code"),
    [
        ("x86", IMAGE_BASE_X86, "64 A1 30 00 00 00 0F B6 40 02 85 C0 75 02 C3"),
        ("x86-64", IMAGE_BASE_X64, "65 48 8B 04 25 60 00 00 00 0F B6 40 02 85 C0 75 02 C3"),
    ],
)
def test_peb_beingdebugged_value_controls_branch(architecture, image_base, code):
    instructions, sections = _decode(bytes.fromhex(code), architecture, image_base)

    findings = analyze_anti_debug(instructions, [], sections, architecture, image_base)

    field = next(finding for finding in findings if finding.title == "Possible PEB BeingDebugged access")
    branch = next(finding for finding in findings if "branch using PEB BeingDebugged" in finding.title)
    assert field.confidence == "medium"
    assert branch.confidence == "high"


def test_peb_ntglobalflag_candidate_can_form_branch_context():
    instructions, sections = _decode(bytes.fromhex("64 A1 30 00 00 00 8B 40 68 85 C0 75 02 C3"))

    findings = analyze_anti_debug(instructions, [], sections, "x86", IMAGE_BASE_X86)

    field = next(finding for finding in findings if finding.title == "Possible PEB NtGlobalFlag access")
    branch = next(finding for finding in findings if "branch using PEB NtGlobalFlag" in finding.title)
    assert field.confidence == "medium"
    assert branch.confidence == "high"


def test_trap_and_timing_instructions_stay_conservative():
    instructions, sections = _decode(bytes.fromhex("CC F1 0F 31 C3"))

    findings = analyze_anti_debug(instructions, [], sections, "x86", IMAGE_BASE_X86)

    by_title = {finding.title: finding for finding in findings}
    assert by_title["INT3 instruction candidate"].confidence == "low"
    assert by_title["ICEBP instruction candidate"].confidence == "medium"
    assert by_title["RDTSC timing candidate"].confidence == "low"


def test_consecutive_int3_padding_does_not_create_anti_debug_findings():
    instructions, sections = _decode(bytes.fromhex("CC CC CC C3"))

    findings = analyze_anti_debug(instructions, [], sections, "x86", IMAGE_BASE_X86)

    assert not any(finding.title == "INT3 instruction candidate" for finding in findings)


def test_unreferenced_int3_inside_linear_region_stays_suppressed():
    instructions, sections = _decode(bytes.fromhex("90 CC 90 C3"))

    findings = analyze_anti_debug(instructions, [], sections, "x86", IMAGE_BASE_X86)

    assert not any(finding.title == "INT3 instruction candidate" for finding in findings)
