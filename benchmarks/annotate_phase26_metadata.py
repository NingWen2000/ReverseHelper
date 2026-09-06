"""Apply reviewed Phase 2.6 static-visibility and slice-ground-truth metadata."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks" / "manifest.json"
TAXONOMY = ROOT / "benchmarks" / "analysis" / "slice_failures.json"


def _visibility(entry):
    if entry.get("availability", "available") != "available":
        return "UNKNOWN"
    if entry["id"] == "reverse-engineering-ctfs-01":
        return "UNKNOWN"
    if entry.get("packed"):
        return "PACKED_OR_TRANSFORMED"
    if entry.get("obfuscated") or entry["id"] == "flareon2017-04":
        return "PARTIALLY_VISIBLE"
    return "FULLY_VISIBLE"


def main():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    taxonomy = json.loads(TAXONOMY.read_text(encoding="utf-8"))
    failures = defaultdict(list)
    for record in taxonomy["records"]:
        failures[record["challenge"]].append(record)

    for entry in manifest["challenges"]:
        entry["static_visibility"] = _visibility(entry)
        if entry.get("availability", "available") != "available":
            continue
        path = ROOT / entry["ground_truth"]
        document = json.loads(path.read_text(encoding="utf-8"))
        truth = document["ground_truth"]
        truth["review_status"] = entry["review_status"]
        notes = truth.setdefault("reviewer_notes", [])
        phase_note = (
            "Phase 2.6 metadata review checked critical_functions, validation_functions, "
            "input evidence and static visibility against the retained source citations."
        )
        review_note = (
            "No second independent human reviewer was available; SINGLE_REVIEW records "
            "remain SINGLE_REVIEW."
        )
        for note in (phase_note, review_note):
            if note not in notes:
                notes.append(note)
        truth["static_visibility"] = entry["static_visibility"]
        if failures[entry["id"]]:
            truth["input_sources_ground_truth"] = list(dict.fromkeys(
                item["input_source"] for item in failures[entry["id"]]
            ))
            truth["static_slice_ground_truth"] = [{
                "validation_sink_rva": int(item["validation_sink"].rsplit("0x", 1)[1], 16),
                "static_visibility": item["static_visibility"],
                "input_source": item["input_source"],
                "first_failed_edge": item["first_failed_edge"],
                "ground_truth_evidence": item["ground_truth_evidence"],
            } for item in failures[entry["id"]]]
        else:
            truth.setdefault("input_sources_ground_truth", [])
            truth.setdefault("static_slice_ground_truth", [])
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    manifest["schema_version"] = "reversehelper-public-ctf-manifest-3"
    manifest["dataset"] = "public-ctf-v0.3-phase-2.6"
    pending = sum(
        entry.get("availability", "available") != "available"
        for entry in manifest["challenges"]
    )
    manifest["limitations"] = [
        f"{pending} benchmark slots remain pending and are excluded from scored denominators.",
        "Ground truth remains single-review unless review_status says OFFICIAL_WP_CONFIRMED; no record is labeled double-review.",
        "Static visibility is reported separately while packed/transformed samples remain in Overall metrics.",
    ]
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
