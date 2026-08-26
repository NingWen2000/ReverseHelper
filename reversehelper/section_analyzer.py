"""PE section analysis and address conversion helpers."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any


SECTION_FLAGS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x02000000: "DISCARDABLE",
    0x04000000: "NOT_CACHED",
    0x08000000: "NOT_PAGED",
    0x10000000: "SHARED",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}


def calculate_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    length = len(data)
    value = -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(data).values()
    )
    return 0.0 if value == 0 else value


def decode_characteristics(value: int) -> list[str]:
    return [name for flag, name in SECTION_FLAGS.items() if value & flag]


def rva_to_offset(pe: Any, rva: int) -> int | None:
    """Convert an RVA to a file offset using the containing section."""
    try:
        return int(pe.get_offset_from_rva(rva))
    except Exception:
        for section in pe.sections:
            start = int(section.VirtualAddress)
            span = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            if start <= rva < start + span:
                return rva - start + int(section.PointerToRawData)
    return None


def analyze_sections(pe: Any) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace") or "<unnamed>"
        characteristics = int(section.Characteristics)
        flags = decode_characteristics(characteristics)
        entropy = calculate_entropy(section.get_data())
        sections.append(
            {
                "name": name,
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_address": int(section.PointerToRawData),
                "raw_size": int(section.SizeOfRawData),
                "characteristics": characteristics,
                "permissions": "".join(
                    letter
                    for letter, flag in (("R", "READ"), ("W", "WRITE"), ("X", "EXECUTE"))
                    if flag in flags
                )
                or "-",
                "flags": flags,
                "entropy": round(entropy, 3),
                "high_entropy": entropy >= 7.2 and int(section.SizeOfRawData) >= 512,
                "rwx": all(flag in flags for flag in ("READ", "WRITE", "EXECUTE")),
            }
        )
    return sections


def find_entry_point_section(sections: list[dict[str, Any]], entry_point_rva: int) -> dict[str, Any] | None:
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= entry_point_rva < start + span:
            return section
    return None
