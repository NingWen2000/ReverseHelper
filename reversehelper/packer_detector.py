"""Transparent packing and section-anomaly heuristics."""

from __future__ import annotations

from typing import Any

from .section_analyzer import find_entry_point_section


KNOWN_PACKER_SECTIONS = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".themida": "Themida",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    "pec1": "PECompact",
    "pec2": "PECompact",
}


def detect_packing(
    pe: Any,
    sections: list[dict[str, Any]],
    entry_point_rva: int,
    import_count: int,
    file_size: int,
) -> dict[str, Any]:
    indicators: list[dict[str, Any]] = []
    packers: set[str] = set()

    for section in sections:
        normalized = section["name"].strip().lower()
        if normalized in KNOWN_PACKER_SECTIONS:
            packer = KNOWN_PACKER_SECTIONS[normalized]
            packers.add(packer)
            indicators.append(
                {
                    "type": "known-packer-section",
                    "severity": "high",
                    "evidence": f"Section {section['name']} matches {packer}",
                    "weight": 3.0,
                }
            )
        if section["high_entropy"]:
            indicators.append(
                {
                    "type": "high-entropy",
                    "severity": "medium",
                    "evidence": f"Section {section['name']} entropy is {section['entropy']:.3f}",
                    "weight": 1.2,
                }
            )
        if section["rwx"]:
            indicators.append(
                {
                    "type": "rwx-section",
                    "severity": "high",
                    "evidence": f"Section {section['name']} is readable, writable and executable",
                    "weight": 2.0,
                }
            )
        if section["raw_size"] == 0 and section["virtual_size"] >= 4096:
            indicators.append(
                {
                    "type": "virtual-only-section",
                    "severity": "low",
                    "evidence": f"Section {section['name']} has virtual data but no raw data",
                    "weight": 0.5,
                }
            )

    ep_section = find_entry_point_section(sections, entry_point_rva)
    if ep_section is None:
        indicators.append(
            {
                "type": "entry-point-outside-sections",
                "severity": "high",
                "evidence": f"Entry point RVA 0x{entry_point_rva:X} is not inside a section",
                "weight": 2.5,
            }
        )
    else:
        if "EXECUTE" not in ep_section["flags"]:
            indicators.append(
                {
                    "type": "non-executable-entry-point",
                    "severity": "high",
                    "evidence": f"Entry point is inside non-executable section {ep_section['name']}",
                    "weight": 2.0,
                }
            )
        if ep_section["high_entropy"]:
            indicators.append(
                {
                    "type": "high-entropy-entry-point",
                    "severity": "medium",
                    "evidence": f"Entry point is inside high-entropy section {ep_section['name']}",
                    "weight": 1.0,
                }
            )

    high_entropy_count = sum(section["high_entropy"] for section in sections)
    if high_entropy_count and import_count <= 5:
        indicators.append(
            {
                "type": "few-imports-with-high-entropy",
                "severity": "medium",
                "evidence": f"Only {import_count} imports with {high_entropy_count} high-entropy section(s)",
                "weight": 1.0,
            }
        )

    overlay_offset = pe.get_overlay_data_start_offset()
    overlay_size = max(0, file_size - overlay_offset) if overlay_offset is not None else 0
    if overlay_size and file_size and overlay_size / file_size >= 0.25:
        indicators.append(
            {
                "type": "large-overlay",
                "severity": "low",
                "evidence": f"Overlay is {overlay_size} bytes ({overlay_size / file_size:.1%} of file)",
                "weight": 0.5,
            }
        )

    confidence_score = min(10.0, sum(item["weight"] for item in indicators))
    if packers:
        verdict = "likely-packed"
    elif confidence_score >= 4:
        verdict = "suspicious"
    elif indicators:
        verdict = "weak-indicators"
    else:
        verdict = "no-obvious-indicators"

    limited_visibility = verdict in {"likely-packed", "suspicious"}
    recommended_steps = [
        "Inspect the entry stub and identify the transition to the original entry point (OEP).",
        "Record the unpacked image layout and rebuild or verify imports after the OEP transition.",
        "Dump the unpacked image in an isolated debugger, then run ReverseHelper again on that dump.",
    ] if limited_visibility else []

    return {
        "verdict": verdict,
        "possible_packers": sorted(packers),
        "confidence_score": round(confidence_score, 1),
        "entry_point_section": ep_section["name"] if ep_section else None,
        "overlay_offset": overlay_offset,
        "overlay_size": overlay_size,
        "indicators": indicators,
        "static_visibility": "limited" if limited_visibility else "normal",
        "analysis_reliability": "reduced" if limited_visibility else "normal",
        "recommended_steps": recommended_steps,
        "disclaimer": "Heuristic result only; indicators are not proof that a file is packed or malicious.",
    }
