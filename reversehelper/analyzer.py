"""High-level orchestration for a complete static analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import crypto_analyzer
from .addressing import annotate_string_locations
from .code_cave_analyzer import find_code_caves
from .entry_analyzer import analyze_entry_point
from .packer_detector import detect_packing
from .pe_parser import PEFormatError, PEParser
from .risk import calculate_risk
from .string_analyzer import extract_strings
from .version import __version__


class AnalysisError(RuntimeError):
    """User-facing analysis error."""


class ReverseHelperAnalyzer:
    def __init__(self, minimum_string_length: int = 4, maximum_strings: int = 2000):
        self.minimum_string_length = minimum_string_length
        self.maximum_strings = maximum_strings

    def analyze(self, path: str | Path) -> dict[str, Any]:
        try:
            parser = PEParser(path)
        except (OSError, PEFormatError, ValueError) as exc:
            raise AnalysisError(str(exc)) from exc

        try:
            result = parser.parse()
            strings = extract_strings(
                parser.data,
                minimum=self.minimum_string_length,
                maximum=self.maximum_strings,
            )
            annotate_string_locations(
                strings,
                result["sections"],
                result["basic"]["image_base"],
                result["basic"]["size_of_headers"],
            )
            entry_point = analyze_entry_point(parser.data, result["basic"], result["sections"])
            code_caves = find_code_caves(
                parser.data,
                result["sections"],
                result["basic"]["image_base"],
            )
            crypto = crypto_analyzer.find_crypto_constants(parser.data)
            packing = detect_packing(
                parser.pe,
                result["sections"],
                result["basic"]["entry_point_rva"],
                result["import_count"],
                result["basic"]["file_size"],
            )
            risk = calculate_risk(result["suspicious_imports"], strings, packing, result["parser_warnings"])
            result.update(
                {
                    "schema_version": "1.1",
                    "tool": {"name": "ReverseHelper", "version": __version__},
                    "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
                    "strings": strings,
                    "entry_point_analysis": entry_point,
                    "code_caves": code_caves,
                    "crypto_constants": crypto,
                    "packing": packing,
                    "risk": risk,
                    "analysis_scope": "Static PE triage; the target was read but never executed.",
                }
            )
            return result
        except AnalysisError:
            raise
        except Exception as exc:
            raise AnalysisError(f"Analysis failed: {exc}") from exc
        finally:
            parser.close()
