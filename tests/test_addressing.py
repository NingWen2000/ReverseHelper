from reversehelper.addressing import annotate_string_locations, file_offset_to_location


SECTIONS = [
    {
        "name": ".text",
        "virtual_address": 0x1000,
        "raw_address": 0x400,
        "raw_size": 0x400,
    }
]


def test_maps_header_section_and_overlay_offsets():
    header = file_offset_to_location(0x120, SECTIONS, 0x400000, 0x400)
    assert header == {"file_offset": 0x120, "rva": 0x120, "va": 0x400120, "section": "<headers>"}

    text = file_offset_to_location(0x408, SECTIONS, 0x400000, 0x400)
    assert text == {"file_offset": 0x408, "rva": 0x1008, "va": 0x401008, "section": ".text"}

    overlay = file_offset_to_location(0x900, SECTIONS, 0x400000, 0x400)
    assert overlay["rva"] is None
    assert overlay["va"] is None
    assert overlay["section"] is None


def test_annotates_extracted_strings_in_place():
    item = {"offset": 0x408, "value": "CrC", "encoding": "ASCII", "categories": []}
    strings = {"items": [item], "interesting": [item]}
    annotate_string_locations(strings, SECTIONS, 0x400000, 0x400)
    assert strings["interesting"][0]["rva"] == 0x1008
    assert strings["interesting"][0]["va"] == 0x401008
