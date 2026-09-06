import pytest

from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.instruction_context import find_import_calls


@pytest.mark.parametrize(
    ("architecture", "image_base", "code"),
    [
        (
            "x86",
            0x400000,
            bytes.fromhex("E8 05 00 00 00 C3 90 90 90 90 FF 25 00 20 40 00"),
        ),
        (
            "x86-64",
            0x140000000,
            bytes.fromhex("E8 05 00 00 00 C3 90 90 90 90 FF 25 F0 0F 00 00"),
        ),
    ],
)
def test_import_call_resolves_one_hop_jump_thunk(architecture, image_base, code):
    data = b"\0" * 0x200 + code
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": len(code),
            "raw_address": 0x200,
            "raw_size": len(code),
        }
    ]
    instructions = Disassembler(architecture, image_base).disassemble_range(
        data, sections, 0x1000, len(code)
    )
    imports = [
        {
            "dll": "msvcrt.dll",
            "functions": [
                {
                    "name": "strcmp",
                    "ordinal": None,
                    "iat_address": image_base + 0x2000,
                    "suspicious": False,
                }
            ],
        }
    ]

    calls = find_import_calls(
        instructions,
        imports,
        architecture,
        image_base,
        list(iter_instruction_details(instructions, architecture)),
    )

    assert len(calls) == 1
    assert calls[0][0]["source_rva"] == 0x1000
    assert calls[0][2]["name"] == "strcmp"


@pytest.mark.parametrize(
    ("architecture", "image_base", "code"),
    [
        ("x86", 0x400000, bytes.fromhex("8B 05 00 20 40 00 FF D0 C3")),
        ("x86-64", 0x140000000, bytes.fromhex("48 8B 05 F9 0F 00 00 FF D0 C3")),
    ],
)
def test_import_call_resolves_register_loaded_from_iat(architecture, image_base, code):
    data = b"\0" * 0x200 + code
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": len(code),
            "raw_address": 0x200,
            "raw_size": len(code),
        }
    ]
    instructions = Disassembler(architecture, image_base).disassemble_range(
        data, sections, 0x1000, len(code)
    )
    imports = [
        {
            "dll": "kernel32.dll",
            "functions": [
                {
                    "name": "IsDebuggerPresent",
                    "ordinal": None,
                    "iat_address": image_base + 0x2000,
                    "suspicious": False,
                }
            ],
        }
    ]

    calls = find_import_calls(
        instructions,
        imports,
        architecture,
        image_base,
        list(iter_instruction_details(instructions, architecture)),
    )

    assert len(calls) == 1
    assert calls[0][0]["source_rva"] in {0x1006, 0x1007}
    assert calls[0][2]["name"] == "IsDebuggerPresent"


def test_overwritten_import_register_is_not_resolved_as_api_call():
    code = bytes.fromhex("48 8B 05 F9 0F 00 00 31 C0 FF D0 C3")
    data = b"\0" * 0x200 + code
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": len(code),
            "raw_address": 0x200,
            "raw_size": len(code),
        }
    ]
    instructions = Disassembler("x86-64", 0x140000000).disassemble_range(
        data, sections, 0x1000, len(code)
    )
    imports = [
        {
            "dll": "kernel32.dll",
            "functions": [
                {
                    "name": "IsDebuggerPresent",
                    "ordinal": None,
                    "iat_address": 0x140002000,
                    "suspicious": False,
                }
            ],
        }
    ]

    calls = find_import_calls(
        instructions,
        imports,
        "x86-64",
        0x140000000,
        list(iter_instruction_details(instructions, "x86-64")),
    )

    assert calls == []
