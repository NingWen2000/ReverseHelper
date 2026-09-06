import pytest

from reversehelper.disassembler import Disassembler, DisassemblyError


def test_disassembles_x86_with_consistent_addresses():
    data = bytearray(0x500)
    data[0x410:0x414] = bytes.fromhex("55 8B EC C3")
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x200,
            "raw_address": 0x400,
            "raw_size": 0x40,
        }
    ]

    instructions = Disassembler("x86", 0x400000).disassemble_range(bytes(data), sections, 0x1010, 4)

    assert [insn.mnemonic for insn in instructions] == ["push", "mov", "ret"]
    assert instructions[0].to_dict() == {
        "address": 0x401010,
        "rva": 0x1010,
        "file_offset": 0x410,
        "size": 1,
        "bytes": "55",
        "mnemonic": "push",
        "op_str": "ebp",
    }
    assert instructions[-1].file_offset == 0x413


def test_disassembles_x64_in_64_bit_mode():
    data = b"\x00" * 0x200 + bytes.fromhex("48 89 D8 C3")
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 4,
            "raw_address": 0x200,
            "raw_size": 4,
        }
    ]

    instructions = Disassembler("x86-64", 0x140000000).disassemble_range(data, sections, 0x1000, 4)

    assert instructions[0].mnemonic == "mov"
    assert instructions[0].op_str == "rax, rbx"
    assert instructions[0].address == 0x140001000
    assert instructions[1].mnemonic == "ret"


def test_disassembly_stops_at_raw_section_boundary_not_virtual_tail():
    data = b"\x00" * 0x100 + bytes.fromhex("90 C3") + b"\x90" * 16
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x2000,
            "virtual_size": 0x200,
            "raw_address": 0x100,
            "raw_size": 2,
        }
    ]
    disassembler = Disassembler("x86", 0x400000)

    instructions = disassembler.disassemble_range(data, sections, 0x2000, 0x100)

    assert [insn.mnemonic for insn in instructions] == ["nop", "ret"]
    assert disassembler.disassemble_range(data, sections, 0x2002, 8) == []


def test_truncated_instruction_returns_decoded_prefix():
    data = b"\x00" * 0x80 + bytes.fromhex("90 E8 01 02")
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x100,
            "raw_address": 0x80,
            "raw_size": 4,
        }
    ]

    instructions = Disassembler("x86", 0x400000).disassemble_range(data, sections, 0x1000, 4)

    assert [insn.mnemonic for insn in instructions] == ["nop"]


def test_rejects_unsupported_architecture():
    with pytest.raises(DisassemblyError, match="Unsupported disassembly architecture"):
        Disassembler("ARM64", 0x140000000)
