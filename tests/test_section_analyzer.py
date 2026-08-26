from reversehelper.section_analyzer import calculate_entropy, decode_characteristics, rva_to_offset


def test_entropy_bounds_and_known_distribution():
    assert calculate_entropy(b"") == 0.0
    assert calculate_entropy(b"A" * 100) == 0.0
    assert calculate_entropy(bytes(range(256))) == 8.0


def test_decode_section_permissions():
    flags = decode_characteristics(0x20000000 | 0x40000000 | 0x80000000)
    assert {"EXECUTE", "READ", "WRITE"}.issubset(flags)


def test_rva_to_offset_fallback():
    class BrokenPE:
        class Section:
            VirtualAddress = 0x1000
            Misc_VirtualSize = 0x500
            SizeOfRawData = 0x400
            PointerToRawData = 0x200

        sections = [Section()]

        def get_offset_from_rva(self, _rva):
            raise ValueError("force fallback")

    assert rva_to_offset(BrokenPE(), 0x1123) == 0x323
    assert rva_to_offset(BrokenPE(), 0x3000) is None
