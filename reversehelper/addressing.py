"""Translate file offsets into PE addresses used by reverse-engineering tools."""

from __future__ import annotations

from typing import Any


def file_offset_to_location(
    offset: int,
    sections: list[dict[str, Any]],
    image_base: int,
    size_of_headers: int,
) -> dict[str, int | str | None]:
    """Return the RVA, VA and section containing a raw file offset."""
    if offset < 0:
        raise ValueError("file offset cannot be negative")

    if offset < size_of_headers:
        rva: int | None = offset
        section_name: str | None = "<headers>"
    else:
        rva = None
        section_name = None
        for section in sections:
            raw_start = int(section["raw_address"])
            raw_size = int(section["raw_size"])
            if raw_start <= offset < raw_start + raw_size:
                rva = int(section["virtual_address"]) + offset - raw_start
                section_name = str(section["name"])
                break

    return {
        "file_offset": offset,
        "rva": rva,
        "va": image_base + rva if rva is not None else None,
        "section": section_name,
    }


def annotate_string_locations(
    strings: dict[str, Any],
    sections: list[dict[str, Any]],
    image_base: int,
    size_of_headers: int,
) -> None:
    """Add debugger-friendly address fields to extracted string records."""
    for item in strings["items"]:
        item.update(file_offset_to_location(item["offset"], sections, image_base, size_of_headers))
