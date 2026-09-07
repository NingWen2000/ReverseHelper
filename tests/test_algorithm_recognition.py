from types import SimpleNamespace

from reversehelper.algorithm_recognition import recognize_algorithms
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.findings import Function


def _context(code: bytes):
    image_base = 0x400000
    raw_address = 0x200
    data = b"\x00" * raw_address + code
    sections = [{"name": ".text", "virtual_address": 0x1000, "virtual_size": len(code),
                 "raw_address": raw_address, "raw_size": len(code), "flags": ["CODE", "EXECUTE"]}]
    instructions = Disassembler("x86", image_base).disassemble_range(data, sections, 0x1000, len(code))
    records = list(iter_instruction_details(instructions, "x86"))
    function = Function(0x1000, image_base + 0x1000, "FUN_401000", raw_address, ".text",
                        "test", "high", tuple(ins.rva for ins, _ in records),
                        runtime_likelihood="USER_CODE")
    return SimpleNamespace(functions=[function], by_rva={ins.rva: pair for pair in records for ins in [pair[0]]},
                           sections=sections, image_base=image_base), data


def test_tea_magic_constant_alone_is_low():
    context, data = _context(bytes.fromhex("B8 B9 79 37 9E C3"))
    candidates, budget = recognize_algorithms(context, data)
    tea = next(item for item in candidates if item.algorithm == "TEA_FAMILY")
    assert tea.confidence == "LOW"
    assert [item.kind for item in tea.evidence] == ["MAGIC_CONSTANT"]
    assert not budget["truncated"]


def test_tea_family_requires_multiple_structural_evidence_types_for_high():
    context, data = _context(bytes.fromhex(
        "B8 B9 79 37 9E 83 F9 20 C1 E1 04 C1 EA 05 31 D1 31 C8 01 C8 29 D0 49 75 EA C3"
    ))
    candidates, _ = recognize_algorithms(context, data)
    tea = next(item for item in candidates if item.algorithm == "TEA")
    assert tea.confidence == "HIGH"
    assert {item.kind for item in tea.evidence} >= {"MAGIC_CONSTANT", "LOOP_STRUCTURE", "SHIFT_PATTERN", "ROUND_COUNT"}


def test_crc_constant_without_feedback_loop_is_low():
    context, data = _context(bytes.fromhex("B8 20 83 B8 ED C3"))
    candidates, _ = recognize_algorithms(context, data)
    crc = next(item for item in candidates if item.algorithm == "CRC32")
    assert crc.confidence == "LOW"


def test_repeated_indexed_xor_loop_is_classified_not_just_contains_xor():
    context, data = _context(bytes.fromhex("8A 04 0E 32 04 17 88 04 0E 41 83 F9 08 75 F0 C3"))
    candidates, _ = recognize_algorithms(context, data)
    xor = next(item for item in candidates if item.algorithm.endswith("XOR"))
    assert xor.algorithm in {"ROLLING_XOR", "REPEATING_KEY_XOR"}
    assert xor.confidence == "MEDIUM"


def test_budget_truncation_is_explicit():
    context, data = _context(bytes.fromhex("90 90 90 C3"))
    _, budget = recognize_algorithms(context, data, budgets={"max_algorithm_instructions": 1})
    assert budget["truncated"] is True
    assert budget["instructions_analyzed"] == 1


def test_rc4_ksa_requires_256_state_swap_loop():
    context, data = _context(bytes.fromhex(
        "0F B6 04 0E 01 C2 81 E2 FF 00 00 00 8A 1C 16 88 1C 0E 88 04 16 41 81 F9 00 01 00 00 75 E2 C3"
    ))
    candidates, _ = recognize_algorithms(context, data)
    assert any(item.algorithm == "RC4_KSA_CANDIDATE" and item.confidence == "MEDIUM" for item in candidates)


def test_ordinary_256_constant_or_xor_heavy_straight_line_is_not_promoted():
    context, data = _context(bytes.fromhex("B8 00 01 00 00 31 C0 31 D1 31 D2 C3"))
    candidates, _ = recognize_algorithms(context, data)
    assert not any(item.confidence in {"HIGH", "MEDIUM"} for item in candidates)


def test_known_lcg_constants_with_feedback_loop_are_recognized():
    context, data = _context(bytes.fromhex(
        "69 C0 0D 66 19 00 05 5F F3 6E 3C 89 C3 89 06 49 75 EB C3"
    ))
    candidates, _ = recognize_algorithms(context, data)
    assert any(item.algorithm == "LCG" for item in candidates)


def test_rotate_add_xor_loop_is_a_custom_transform_not_named_crypto():
    context, data = _context(bytes.fromhex("D1 C0 01 D0 31 D8 49 75 F7 C3"))
    candidates, _ = recognize_algorithms(context, data)
    custom = next(item for item in candidates if item.algorithm == "CUSTOM_WORD_TRANSFORM")
    assert custom.family == "CUSTOM"
