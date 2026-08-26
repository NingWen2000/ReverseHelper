"""Small, dependency-free checks around the PE entry point."""

from __future__ import annotations

from typing import Any

from .section_analyzer import find_entry_point_section


def _relative_target(start_rva: int, instruction_offset: int, displacement: bytes) -> int:
    relative = int.from_bytes(displacement, byteorder="little", signed=True)
    return start_rva + instruction_offset + 5 + relative


def analyze_entry_point(
    data: bytes,
    basic: dict[str, Any],
    sections: list[dict[str, Any]],
    window_size: int = 16,
) -> dict[str, Any]:
    """Describe entry bytes and recognize a few high-signal unpacking stubs."""
    offset = basic["entry_point_offset"]
    section = find_entry_point_section(sections, basic["entry_point_rva"])
    if offset is None or offset >= len(data):
        return {
            "file_offset": offset,
            "section": section["name"] if section else None,
            "bytes_hex": "",
            "pattern": None,
            "control_transfer_target_rva": None,
            "control_transfer_target_va": None,
            "indicators": [],
        }

    window = data[offset : offset + window_size]
    indicators: list[dict[str, str]] = []
    pattern = None
    target_rva = None

    writable_code = bool(section and "WRITE" in section["flags"] and "EXECUTE" in section["flags"])
    if writable_code:
        indicators.append(
            {
                "type": "writable-entry-section",
                "evidence": f"Entry point is inside writable executable section {section['name']}",
            }
        )

    # Common 32-bit protector stub: PUSHAD; CALL rel32; RET.  This does not
    # prove packing, but it gives the analyst a concrete call target to inspect.
    if (
        basic["architecture"] == "x86"
        and len(window) >= 7
        and window[0] == 0x60
        and window[1] == 0xE8
        and window[6] == 0xC3
    ):
        pattern = "pushad-call-ret"
        target_rva = _relative_target(basic["entry_point_rva"], 1, window[2:6])
        indicators.append(
            {
                "type": "compact-entry-stub",
                "evidence": "Entry bytes match PUSHAD; CALL rel32; RET",
            }
        )
    elif len(window) >= 5 and window[0] in {0xE8, 0xE9}:
        pattern = "relative-call" if window[0] == 0xE8 else "relative-jump"
        target_rva = _relative_target(basic["entry_point_rva"], 0, window[1:5])

    return {
        "file_offset": offset,
        "section": section["name"] if section else None,
        "bytes_hex": " ".join(f"{byte:02X}" for byte in window),
        "pattern": pattern,
        "control_transfer_target_rva": target_rva,
        "control_transfer_target_va": basic["image_base"] + target_rva if target_rva is not None else None,
        "indicators": indicators,
        "review_priority": "high" if writable_code and pattern else "normal",
    }
