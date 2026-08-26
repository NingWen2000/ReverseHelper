"""Locate simple padding runs that may be useful during manual patch planning."""

from __future__ import annotations

from typing import Any


def find_code_caves(
    data: bytes,
    sections: list[dict[str, Any]],
    image_base: int,
    minimum_size: int = 32,
    maximum_results: int = 50,
) -> list[dict[str, int | str]]:
    """Find 00/CC runs in executable sections without treating them as safe automatically."""
    if minimum_size < 1:
        raise ValueError("minimum code-cave size must be positive")

    caves: list[dict[str, int | str]] = []
    for section in sections:
        if "EXECUTE" not in section["flags"]:
            continue
        raw_start = int(section["raw_address"])
        raw_end = min(len(data), raw_start + int(section["raw_size"]))
        cursor = raw_start
        while cursor < raw_end:
            fill = data[cursor]
            if fill not in {0x00, 0xCC}:
                cursor += 1
                continue
            end = cursor + 1
            while end < raw_end and data[end] == fill:
                end += 1
            size = end - cursor
            if size >= minimum_size:
                rva = int(section["virtual_address"]) + cursor - raw_start
                caves.append(
                    {
                        "section": str(section["name"]),
                        "file_offset": cursor,
                        "rva": rva,
                        "va": image_base + rva,
                        "size": size,
                        "fill_byte": f"{fill:02X}",
                    }
                )
                if len(caves) >= maximum_results:
                    return caves
            cursor = end
    return caves
