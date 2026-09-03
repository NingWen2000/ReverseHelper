import pytest

from reversehelper.control_flow_analyzer import analyze_control_transfers
from reversehelper.disassembler import Disassembler
from reversehelper.findings import Instruction


def _decode(code: bytes, architecture: str = "x86", image_base: int = 0x400000):
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
    return Disassembler(architecture, image_base).disassemble_range(data, sections, 0x1000, len(code))


@pytest.mark.parametrize(
    ("code", "transfer_type"),
    [
        (bytes.fromhex("E8 FB 00 00 00"), "call"),
        (bytes.fromhex("E9 FB 00 00 00"), "jmp"),
    ],
)
def test_resolves_direct_call_and_jump(code, transfer_type):
    transfers = analyze_control_transfers(_decode(code), "x86", 0x400000)

    assert transfers == [
        {
            "transfer_type": transfer_type,
            "mnemonic": transfer_type,
            "op_str": "0x401100",
            "source_address": 0x401000,
            "source_rva": 0x1000,
            "file_offset": 0x200,
            "direct": True,
            "target_status": "resolved",
            "target_address": 0x401100,
            "target_rva": 0x1100,
            "pointer_address": None,
            "pointer_rva": None,
        }
    ]


def test_marks_register_indirect_call_and_jump_unresolved():
    instructions = _decode(bytes.fromhex("FF D0 FF E0"))

    transfers = analyze_control_transfers(instructions, "x86", 0x400000)

    assert [item["transfer_type"] for item in transfers] == ["call", "jmp"]
    assert all(item["direct"] is False for item in transfers)
    assert all(item["target_status"] == "unresolved" for item in transfers)
    assert all(item["target_address"] is None for item in transfers)


def test_identifies_conditional_jump_and_return():
    instructions = _decode(bytes.fromhex("75 05 C3"))

    transfers = analyze_control_transfers(instructions, "x86", 0x400000)

    assert transfers[0]["transfer_type"] == "jcc"
    assert transfers[0]["mnemonic"] == "jne"
    assert transfers[0]["target_status"] == "resolved"
    assert transfers[0]["target_rva"] == 0x1007
    assert transfers[1]["transfer_type"] == "ret"
    assert transfers[1]["target_status"] == "not-applicable"
    assert transfers[1]["direct"] is None


def test_x64_rip_relative_call_and_jump_resolve_pointer_slot_not_target():
    image_base = 0x140000000
    instructions = _decode(
        bytes.fromhex("FF 15 34 12 00 00 FF 25 34 12 00 00"),
        architecture="x86-64",
        image_base=image_base,
    )

    transfers = analyze_control_transfers(instructions, "x86-64", image_base)

    assert [item["transfer_type"] for item in transfers] == ["call", "jmp"]
    assert [item["pointer_rva"] for item in transfers] == [0x223A, 0x2240]
    assert all(item["target_status"] == "unresolved" for item in transfers)
    assert all(item["target_address"] is None for item in transfers)


def test_invalid_instruction_is_ignored_without_aborting_other_regions():
    broken = Instruction(
        address=0x401000,
        rva=0x1000,
        file_offset=0x200,
        size=2,
        raw_bytes=bytes.fromhex("E8 00"),
        mnemonic="call",
        op_str="",
    )
    valid = _decode(bytes.fromhex("C3"))[0]

    transfers = analyze_control_transfers([broken, valid], "x86", 0x400000)

    assert len(transfers) == 1
    assert transfers[0]["transfer_type"] == "ret"
