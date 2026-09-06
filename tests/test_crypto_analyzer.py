import pytest

from reversehelper.crypto_analyzer import AES_SBOX, find_crypto_candidates, find_crypto_constants
from reversehelper.disassembler import Disassembler


def test_detects_crypto_constants_and_offsets():
    data = b"prefix" + AES_SBOX + b"padding" + bytes.fromhex("b979379e")
    findings = find_crypto_constants(data)
    names = {(item["algorithm"], item["constant"]) for item in findings}
    assert ("AES", "S-box") in names
    assert ("TEA", "delta 0x9E3779B9 (LE)") in names
    aes = next(item for item in findings if item["constant"] == "S-box")
    assert aes["offsets"] == [6]


def test_no_false_match_on_empty_data():
    assert find_crypto_constants(b"") == []


def _decode(code: bytes, architecture: str = "x86"):
    image_base = 0x400000 if architecture == "x86" else 0x140000000
    raw_address = 0x200
    data = b"\x00" * raw_address + code
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": len(code),
            "raw_address": raw_address,
            "raw_size": len(code),
        }
    ]
    instructions = Disassembler(architecture, image_base).disassemble_range(
        data, sections, 0x1000, len(code)
    )
    return data, instructions, sections, image_base


def test_tea_constant_without_instruction_pattern_stays_low():
    code = bytes.fromhex("B8 B9 79 37 9E C3")
    data, instructions, sections, image_base = _decode(code)

    findings = find_crypto_candidates(data, instructions, sections, "x86", image_base)

    tea = next(finding for finding in findings if finding.title == "Possible TEA-family routine")
    assert tea.confidence == "low"
    assert tea.rva == 0x1000


def test_accidental_tea_delta_in_data_is_not_promoted():
    data = b"ordinary data" + bytes.fromhex("B9 79 37 9E") + b"not code"

    findings = find_crypto_candidates(data, [], [], "x86", 0x400000)

    assert len(findings) == 1
    assert findings[0].confidence == "low"
    assert "not sufficient" in findings[0].reason


@pytest.mark.parametrize("architecture", ["x86", "x86-64"])
def test_tea_constant_with_matching_round_pattern_is_high_confidence(architecture):
    code = bytes.fromhex(
        "B8 B9 79 37 9E "
        "C1 E1 04 "
        "C1 EA 05 "
        "31 D1 "
        "01 C8 "
        "83 E8 01 "
        "75 EC"
    )
    data, instructions, sections, image_base = _decode(code, architecture)

    findings = find_crypto_candidates(data, instructions, sections, architecture, image_base)

    tea = next(finding for finding in findings if finding.title == "Possible TEA-family routine")
    assert tea.confidence == "high"
    assert {"SHL 4", "SHR 5", "XOR", "ADD", "SUB", "backward conditional branch"}.issubset(
        tea.evidence
    )


def test_rc4_like_state_table_loop_is_a_medium_candidate():
    code = bytes.fromhex(
        "0F B6 04 0E "
        "01 C2 "
        "81 E2 FF 00 00 00 "
        "8A 1C 16 "
        "88 1C 0E "
        "88 04 16 "
        "41 "
        "81 F9 00 01 00 00 "
        "75 E2"
    )
    data, instructions, sections, image_base = _decode(code)

    findings = find_crypto_candidates(data, instructions, sections, "x86", image_base)

    rc4 = next(finding for finding in findings if "RC4-like" in finding.title)
    assert rc4.confidence == "medium"
    assert rc4.rva == 0x1000


def test_simple_indexed_loop_is_not_labeled_rc4():
    code = bytes.fromhex("0F B6 04 0E 01 C2 41 83 F9 10 75 F5")
    data, instructions, sections, image_base = _decode(code)

    findings = find_crypto_candidates(data, instructions, sections, "x86", image_base)

    assert not any("RC4-like" in finding.title for finding in findings)
