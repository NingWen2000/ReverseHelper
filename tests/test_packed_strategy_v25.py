from reversehelper.challenge_summary import build_summary, summary_lines
from reversehelper.findings import Finding
from reversehelper.packer_detector import detect_packing
from reversehelper.target_ranker import rank_targets


class _PE:
    def get_overlay_data_start_offset(self):
        return None


def _finding(identifier, category, title, rva):
    return Finding(identifier, category, title, rva, 0x400000 + rva, rva, ".text", "low", "medium",
                   ("test",), "test evidence", "inspect")


def test_packer_detection_emits_bounded_post_unpack_workflow():
    sections = [{"name": "UPX0", "virtual_address": 0x1000, "virtual_size": 0x3000,
                 "raw_size": 0, "flags": ["READ", "WRITE", "EXECUTE"], "rwx": True,
                 "high_entropy": False, "entropy": 0.0},
                {"name": "UPX1", "virtual_address": 0x4000, "virtual_size": 0x2000,
                 "raw_size": 0x2000, "flags": ["READ", "EXECUTE"], "rwx": False,
                 "high_entropy": True, "entropy": 7.9}]
    result = detect_packing(_PE(), sections, 0x4000, 4, 0x5000)
    assert result["verdict"] == "likely-packed"
    assert result["static_visibility"] == "limited"
    assert len(result["recommended_steps"]) == 3
    assert any("OEP" in step for step in result["recommended_steps"])


def test_packed_surface_places_entry_guidance_before_validation_claims():
    findings = [_finding("packing-entry", "packing", "Packing entry", 0x1000),
                _finding("validation-branch", "validation", "Possible Validation Site", 0x2000)]
    targets = rank_targets(findings, image_base=0x400000, packed=True)
    assert targets[0].target_type == "PACKING"
    assert all(target.score <= 20 for target in targets if target.target_type != "PACKING")


def test_quick_summary_labels_limited_visibility_and_reanalysis_steps():
    result = {
        "basic": {"is_64_bit": True, "architecture": "x86-64", "image_base": 0x140000000,
                  "entry_point_rva": 0x5000},
        "packing": {"verdict": "likely-packed", "static_visibility": "limited",
                    "recommended_steps": ["Identify OEP.", "Rebuild imports.", "Re-run on unpacked dump."]},
        "reverse_targets": [{"function": "FUN_140005000", "rva": 0x5000, "va": 0x140005000,
                             "score": 30, "confidence": "medium", "reason": "packed entry",
                             "recommended_action": "inspect entry", "target_kind": "function",
                             "type": "PACKING"}],
        "static_slices": [], "input_sources": [], "interesting_strings": [],
        "validation_candidates": [], "analysis_warnings": [],
    }
    summary = build_summary(result)
    rendered = "\n".join(summary_lines({**result, "challenge_summary": summary}))
    assert "static visibility is limited" in rendered
    assert "Post-Unpack Guidance" in rendered
    assert "Re-run on unpacked dump" in rendered
