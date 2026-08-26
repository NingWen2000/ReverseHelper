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
        "strings": {"interesting": []},
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


def test_report_bundle_writes_all_formats(tmp_path):
    paths = write_report_bundle(sample_result(), tmp_path)
    assert {path.suffix for path in paths} == {".md", ".json", ".html"}
    payload = json.loads(next(path for path in paths if path.suffix == ".json").read_text(encoding="utf-8"))
    assert payload["basic"]["file_name"] == "demo.exe"
