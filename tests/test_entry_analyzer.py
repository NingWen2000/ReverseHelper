from reversehelper.entry_analyzer import analyze_entry_point


def test_recognizes_patchme_style_entry_stub():
    data = bytearray(0x500)
    data[0x100:0x107] = bytes.fromhex("60 E8 E3 00 00 00 C3")
    basic = {
        "architecture": "x86",
        "image_base": 0x400000,
        "entry_point_rva": 0x1000,
        "entry_point_offset": 0x100,
    }
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x400,
            "raw_size": 0x400,
            "flags": ["READ", "WRITE", "EXECUTE"],
        }
    ]

    result = analyze_entry_point(bytes(data), basic, sections)

    assert result["bytes_hex"].startswith("60 E8 E3 00 00 00 C3")
    assert result["pattern"] == "pushad-call-ret"
    assert result["control_transfer_target_rva"] == 0x10E9
    assert result["control_transfer_target_va"] == 0x4010E9
    assert result["review_priority"] == "high"
    assert {item["type"] for item in result["indicators"]} == {
        "writable-entry-section",
        "compact-entry-stub",
    }
