import json

from reversehelper.reporting import html_report, markdown_report, write_report_bundle


def sample_result():
    return {
        "basic": {
            "file_name": "demo.exe",
            "file_size": 1024,
            "file_type": "EXE",
            "architecture": "x86",
            "machine": 0x14C,
            "image_base": 0x400000,
            "entry_point_rva": 0x1000,
            "entry_point_va": 0x401000,
            "subsystem": "Windows Console",
            "compile_time_utc": None,
        },
        "hashes": {"sha256": "a" * 64},
        "analyzed_at_utc": "2026-01-01T00:00:00+00:00",
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x200,
                "raw_address": 0x400,
                "raw_size": 0x200,
                "permissions": "RX",
                "entropy": 5.5,
                "high_entropy": False,
                "rwx": False,
            }
        ],
        "imports": [],
        "suspicious_imports": [],
        "strings": {"interesting": [], "items": []},
        "packing": {"verdict": "no-obvious-indicators", "indicators": []},
        "crypto_constants": [],
        "risk": {"level": "LOW", "score": 0, "maximum": 10, "reasons": [], "disclaimer": "Triage only."},
    }


def test_markdown_and_html_are_standalone():
    result = sample_result()
    assert "# ReverseHelper Analysis Report" in markdown_report(result)
    rendered = html_report(result)
    assert "<!doctype html>" in rendered.lower()
    assert "demo.exe" in rendered


def test_markdown_includes_string_address_mapping():
    result = sample_result()
    item = {
        "offset": 0x408,
        "rva": 0x1008,
        "va": 0x401008,
        "section": ".text",
        "encoding": "ASCII",
        "categories": [],
        "value": "decoded text",
    }
    result["strings"]["items"] = [item]
    report = markdown_report(result)
    assert "| 0x408 | 0x1008 | 0x401008 | .text | ASCII | `decoded text` |" in report


def test_report_bundle_writes_all_formats(tmp_path):
    paths = write_report_bundle(sample_result(), tmp_path)
    assert {path.suffix for path in paths} == {".md", ".json", ".html"}
    payload = json.loads(next(path for path in paths if path.suffix == ".json").read_text(encoding="utf-8"))
    assert payload["basic"]["file_name"] == "demo.exe"


def test_reports_include_findings_targets_guidance_questions_and_warnings():
    result = sample_result()
    result.update(
        {
            "schema_version": "1.2",
            "findings": [
                {
                    "id": "validation-branch",
                    "category": "validation",
                    "title": "Possible Validation Site",
                    "rva": 0x1820,
                    "va": 0x401820,
                    "file_offset": 0xC20,
                    "section": ".text",
                    "severity": "low",
                    "confidence": "high",
                    "evidence": ["Comparator: memcmp", "Branch: JNE"],
                    "reason": "The comparator result controls a conditional branch.",
                    "recommended_action": "Inspect both branch targets.",
                }
            ],
            "reverse_targets": [
                {
                    "category": "validation",
                    "rva": 0x1820,
                    "va": 0x401820,
                    "file_offset": 0xC20,
                    "section": ".text",
                    "priority": "high",
                    "reason": "The comparator result controls a conditional branch.",
                    "recommended_action": "Inspect both branch targets.",
                    "finding_ids": ["validation-branch"],
                }
            ],
            "analysis_path": [
                {
                    "where": "RVA 0x1820 (preferred VA 0x401820)",
                    "rva": 0x1820,
                    "category": "validation",
                    "priority": "high",
                    "why": "The comparator result controls a conditional branch.",
                    "static_question": "What prepares the buffers?",
                    "dynamic_question": "What are the runtime buffers?",
                    "recommended_action": "Inspect the caller and break before memcmp.",
                    "finding_ids": ["validation-branch"],
                }
            ],
            "unresolved_questions": [
                {
                    "question": "What values are compared?",
                    "why_unresolved": "The buffers are runtime values.",
                    "related_rva": 0x1820,
                    "suggested_dynamic_observation": "Record both arguments before memcmp.",
                    "finding_ids": ["validation-branch"],
                }
            ],
            "analysis_warnings": [
                {"module": "anti-debug", "error_type": "RuntimeError", "reason": "module failed"}
            ],
            "debugger_export_notice": (
                "Breakpoints are suggested analysis targets, not guaranteed solution points."
            ),
        }
    )

    markdown = markdown_report(result)
    rendered_html = html_report(result)

    assert "## Findings" in markdown
    assert "## Recommended Reverse Targets" in markdown
    assert "**Static Question:** What prepares the buffers?" in markdown
    assert "**Dynamic Question:** What are the runtime buffers?" in markdown
    assert "## Unresolved Questions" in markdown
    assert "## Analysis Warnings" in markdown
    assert "validation-branch" in rendered_html
    assert "module failed" in rendered_html
