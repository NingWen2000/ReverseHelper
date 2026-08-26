import pytest

from reversehelper.code_cave_analyzer import find_code_caves


def test_finds_padding_in_executable_section_with_mapped_addresses():
    data = b"A" * 0x80 + b"\x00" * 0x40 + b"B" * 0x40
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "raw_address": 0x40,
            "raw_size": 0xC0,
            "flags": ["READ", "EXECUTE"],
        }
    ]
    caves = find_code_caves(data, sections, 0x400000, minimum_size=0x20)
    assert caves == [
        {
            "section": ".text",
            "file_offset": 0x80,
            "rva": 0x1040,
            "va": 0x401040,
            "size": 0x40,
            "fill_byte": "00",
        }
    ]


def test_rejects_invalid_minimum_size():
    with pytest.raises(ValueError):
        find_code_caves(b"", [], 0x400000, minimum_size=0)
