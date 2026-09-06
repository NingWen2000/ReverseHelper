import pytest

from reversehelper.disassembler import Disassembler
from reversehelper.validation_analyzer import analyze_validation, find_input_candidates


IMAGE_BASE_X86 = 0x400000
IMAGE_BASE_X64 = 0x140000000


def _decode(
    code: bytes,
    architecture: str = "x86",
    image_base: int = IMAGE_BASE_X86,
    start_rva: int = 0x1000,
    raw_address: int = 0x200,
):
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
        data,
        sections,
        start_rva,
        len(code),
    )
    return instructions, sections


def _imports(*names: str, image_base: int = IMAGE_BASE_X86):
    return [
        {
            "dll": "msvcrt.dll",
            "functions": [
                {
                    "name": name,
                    "ordinal": None,
                    "iat_address": image_base + 0x2000,
                    "suspicious": False,
                }
                for name in names
            ],
        }
    ]


def _call_bytes(architecture: str) -> bytes:
    if architecture == "x86-64":
        # RIP + 0xFFA at RVA 0x1000 resolves to the IAT slot at RVA 0x2000.
        return bytes.fromhex("FF 15 FA 0F 00 00")
    return bytes.fromhex("FF 15 00 20 40 00")


def test_strcmp_test_and_jne_form_validation_site():
    code = _call_bytes("x86") + bytes.fromhex("85 C0 75 02 90 C3")
    instructions, sections = _decode(code)

    findings = analyze_validation(
        instructions,
        _imports("strcmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    finding = next(item for item in findings if item.title == "Possible Validation Site")
    assert finding.confidence == "high"
    assert finding.category == "validation"
    assert finding.rva == 0x1000
    assert finding.va == IMAGE_BASE_X86 + 0x1000
    assert finding.file_offset == 0x200
    assert finding.section == ".text"
    assert "Comparator: msvcrt.dll!strcmp" in finding.evidence
    assert any("Condition: TEST eax, eax" in item for item in finding.evidence)
    assert any("Branch: JNE" in item for item in finding.evidence)


def test_memcmp_cmp_zero_and_je_form_validation_site():
    code = _call_bytes("x86") + bytes.fromhex("83 F8 00 74 02 90 C3")
    instructions, sections = _decode(code)

    findings = analyze_validation(
        instructions,
        _imports("memcmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    finding = next(item for item in findings if item.title == "Possible Validation Site")
    assert finding.confidence == "high"
    assert any("Condition: CMP eax, 0" in item for item in finding.evidence)
    assert any("Branch: JE" in item for item in finding.evidence)


def test_comparator_import_only_stays_low_confidence():
    findings = analyze_validation([], _imports("strcmp"), [], "x86", IMAGE_BASE_X86)

    assert len(findings) == 1
    assert findings[0].title == "Imported Comparator API: strcmp"
    assert findings[0].confidence == "low"


def test_comparator_call_with_ignored_result_is_not_a_validation_site():
    instructions, sections = _decode(_call_bytes("x86") + bytes.fromhex("90 C3"))

    findings = analyze_validation(
        instructions,
        _imports("strcmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    call = next(item for item in findings if item.title == "Comparator Call Site: strcmp")
    assert call.confidence == "medium"
    assert not any(item.title == "Possible Validation Site" for item in findings)


def test_return_register_overwrite_breaks_validation_association():
    code = _call_bytes("x86") + bytes.fromhex("31 C0 85 C0 75 02 C3")
    instructions, sections = _decode(code)

    findings = analyze_validation(
        instructions,
        _imports("strcmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert not any(item.title == "Possible Validation Site" for item in findings)


def test_eflags_overwrite_breaks_validation_association():
    code = _call_bytes("x86") + bytes.fromhex("85 C0 83 C1 01 75 02 C3")
    instructions, sections = _decode(code)

    findings = analyze_validation(
        instructions,
        _imports("strcmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert not any(item.title == "Possible Validation Site" for item in findings)


@pytest.mark.parametrize(
    "barrier",
    [
        bytes.fromhex("E8 00 00 00 00"),
        bytes.fromhex("EB 00"),
        bytes.fromhex("C3"),
    ],
)
def test_control_transfer_breaks_validation_association(barrier):
    code = _call_bytes("x86") + barrier + bytes.fromhex("85 C0 75 02 C3")
    instructions, sections = _decode(code)

    findings = analyze_validation(
        instructions,
        _imports("strcmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert not any(item.title == "Possible Validation Site" for item in findings)


def test_nops_do_not_break_validation_association():
    code = _call_bytes("x86") + b"\x90" * 10 + bytes.fromhex("85 C0 75 02 C3")
    instructions, sections = _decode(code)

    findings = analyze_validation(
        instructions,
        _imports("strncmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert any(item.title == "Possible Validation Site" for item in findings)


def test_pe_header_comparator_branch_is_not_high_confidence_validation():
    code = (
        bytes.fromhex("3D 4D 5A 00 00 3D 50 45 00 00")
        + _call_bytes("x86")
        + bytes.fromhex("85 C0 75 02 C3")
    )
    instructions, sections = _decode(code)

    findings = analyze_validation(
        instructions,
        _imports("strncmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    finding = next(
        item for item in findings if item.title == "PE Structure Comparator Branch Candidate"
    )
    assert finding.confidence == "medium"
    assert "processing PE structures" in finding.reason


def test_disjoint_regions_do_not_form_validation_association():
    call_instructions, call_sections = _decode(_call_bytes("x86"))
    condition_instructions, condition_sections = _decode(
        bytes.fromhex("85 C0 75 02 C3"),
        start_rva=0x3000,
        raw_address=0x600,
    )

    findings = analyze_validation(
        call_instructions + condition_instructions,
        _imports("strcmp"),
        call_sections + condition_sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert not any(item.title == "Possible Validation Site" for item in findings)


@pytest.mark.parametrize(
    ("architecture", "image_base"),
    [("x86", IMAGE_BASE_X86), ("x86-64", IMAGE_BASE_X64)],
)
def test_validation_call_chain_supports_x86_and_x64(architecture, image_base):
    code = _call_bytes(architecture) + bytes.fromhex("85 C0 75 02 C3")
    instructions, sections = _decode(code, architecture, image_base)

    findings = analyze_validation(
        instructions,
        _imports("wcscmp", image_base=image_base),
        sections,
        architecture,
        image_base,
    )

    assert any(item.title == "Possible Validation Site" for item in findings)


def test_input_imports_stay_low_without_calls():
    findings = find_input_candidates(
        [],
        _imports("scanf", "fgets"),
        [],
        "x86",
        IMAGE_BASE_X86,
    )

    assert {item.title for item in findings} == {
        "Imported Input API: scanf",
        "Imported Input API: fgets",
    }
    assert all(item.confidence == "low" for item in findings)


@pytest.mark.parametrize(
    ("architecture", "image_base", "name"),
    [
        ("x86", IMAGE_BASE_X86, "scanf"),
        ("x86-64", IMAGE_BASE_X64, "ReadConsoleW"),
    ],
)
def test_actual_input_call_sites_support_x86_and_x64(architecture, image_base, name):
    instructions, sections = _decode(_call_bytes(architecture) + b"\xC3", architecture, image_base)

    findings = find_input_candidates(
        instructions,
        _imports(name, image_base=image_base),
        sections,
        architecture,
        image_base,
    )

    call = next(item for item in findings if item.title == f"Input Candidate: {name} call site")
    assert call.confidence == "medium"
    assert any("Actual input-related API call site" in item for item in call.evidence)
    assert call.rva == 0x1000
    assert call.va == image_base + 0x1000
    assert call.file_offset == 0x200
    if architecture == "x86-64":
        assert "RCX, RDX, R8, and R9" in call.recommended_action
    else:
        assert "RCX" not in call.recommended_action


def test_program_without_input_api_has_no_input_findings():
    instructions, sections = _decode(bytes.fromhex("31 C0 C3"))

    findings = find_input_candidates(
        instructions,
        _imports("strcmp"),
        sections,
        "x86",
        IMAGE_BASE_X86,
    )

    assert findings == []
