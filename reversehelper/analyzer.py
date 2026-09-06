"""High-level orchestration for a complete static analysis."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import anti_debug_analyzer, crypto_analyzer, validation_analyzer
from .addressing import annotate_string_locations
from .code_cave_analyzer import find_code_caves
from .control_flow_analyzer import analyze_control_transfers
from .disassembler import Disassembler, iter_instruction_details
from .dynamic_advisor import build_analysis_path, build_unresolved_questions
from .entry_analyzer import analyze_entry_point
from .findings import Finding, Instruction
from .instruction_context import find_import_calls, section_name
from .packer_detector import detect_packing
from .pe_parser import PEFormatError, PEParser
from .risk import calculate_risk
from .string_analyzer import extract_strings
from .target_ranker import rank_targets
from .version import __version__


SCHEMA_VERSION = "1.5"
DEBUGGER_NOTICE = "Breakpoints are suggested analysis targets, not guaranteed solution points."
INSTRUCTION_MODULES = {"antidebug", "validation", "crypto", "targets"}


class AnalysisError(RuntimeError):
    """User-facing analysis error."""


def _warning(module: str, error: Exception) -> dict[str, str]:
    reason = " ".join(str(error).split()) or "No error message was provided"
    return {
        "module": module,
        "error_type": type(error).__name__,
        "reason": reason[:240],
    }


def _optional(
    module: str,
    warnings: list[dict[str, str]],
    fallback: Any,
    callback: Callable[[], Any],
) -> Any:
    try:
        return callback()
    except Exception as error:
        warnings.append(_warning(module, error))
        return fallback


def _empty_strings(minimum: int) -> dict[str, Any]:
    return {
        "minimum_length": minimum,
        "count": 0,
        "interesting_count": 0,
        "category_counts": {},
        "truncated": False,
        "items": [],
        "interesting": [],
    }


def _empty_entry() -> dict[str, Any]:
    return {
        "file_offset": None,
        "section": None,
        "bytes_hex": "",
        "pattern": None,
        "control_transfer_target_rva": None,
        "control_transfer_target_va": None,
        "indicators": [],
    }


def _empty_packing() -> dict[str, Any]:
    return {
        "verdict": "analysis-unavailable",
        "possible_packers": [],
        "confidence_score": 0.0,
        "entry_point_section": None,
        "overlay_offset": None,
        "overlay_size": 0,
        "indicators": [],
        "static_visibility": "unknown",
        "analysis_reliability": "unknown",
        "recommended_steps": [],
        "disclaimer": "Packing analysis was unavailable; no conclusion was produced.",
    }


def _empty_risk() -> dict[str, Any]:
    return {
        "score": 0.0,
        "maximum": 10,
        "level": "LOW",
        "reasons": [],
        "disclaimer": "Risk calculation was unavailable; this value is not a safety conclusion.",
    }


def _disassemble_executable_sections(
    data: bytes,
    sections: list[dict[str, Any]],
    architecture: str,
    image_base: int,
) -> tuple[list[Instruction], list[dict[str, Any]]]:
    disassembler = Disassembler(architecture, image_base)
    instructions = []
    section_summaries = []
    for section in sections:
        if "EXECUTE" not in section["flags"] or int(section["raw_size"]) <= 0:
            continue
        decoded = disassembler.disassemble_range(
            data,
            sections,
            int(section["virtual_address"]),
            int(section["raw_size"]),
        )
        instructions.extend(decoded)
        section_summaries.append(
            {
                "name": section["name"],
                "rva": section["virtual_address"],
                "raw_size": section["raw_size"],
                "instruction_count": len(decoded),
            }
        )
    return instructions, section_summaries


def _control_flow_findings(
    transfers: list[dict[str, Any]],
    sections: list[dict[str, Any]],
    resolved_import_sources: set[int] | None = None,
) -> list[Finding]:
    findings = []
    resolved_import_sources = resolved_import_sources or set()
    for transfer in transfers:
        if transfer["transfer_type"] not in {"call", "jmp"}:
            continue
        if transfer["target_status"] != "unresolved":
            continue
        if int(transfer["source_address"]) in resolved_import_sources:
            continue
        # RIP-relative and absolute pointer slots are already useful static
        # locations. Reserve runtime-target findings for operands with no slot.
        if transfer["pointer_address"] is not None:
            continue
        rva = int(transfer["source_rva"])
        transfer_name = str(transfer["transfer_type"]).upper()
        evidence = [f"{str(transfer['mnemonic']).upper()} {transfer['op_str']} at RVA 0x{rva:X}"]
        evidence.append("Target comes from a register or memory operand")
        findings.append(
            Finding(
                id=f"control-flow-indirect-{transfer['transfer_type']}-{rva:08x}",
                category="control-flow",
                title=f"Indirect {transfer_name} target is unresolved",
                rva=rva,
                va=int(transfer["source_address"]),
                file_offset=int(transfer["file_offset"]),
                section=section_name(rva, sections),
                severity="info",
                confidence="high",
                evidence=tuple(evidence),
                reason="The instruction is an indirect control transfer whose final destination depends on runtime state.",
                recommended_action="Break before the transfer and record the register or memory operand value.",
            )
        )
    return findings


def _entry_findings(
    entry: dict[str, Any],
    basic: dict[str, Any],
) -> list[Finding]:
    if not entry.get("pattern") and not entry.get("indicators"):
        return []
    evidence = []
    if entry.get("pattern"):
        evidence.append(f"Entry pattern: {entry['pattern']}")
    evidence.extend(item["evidence"] for item in entry.get("indicators", []))
    return [
        Finding(
            id=f"entry-review-{int(basic['entry_point_rva']):08x}",
            category="entry",
            title="Entry-point review candidate",
            rva=int(basic["entry_point_rva"]),
            va=int(basic["entry_point_va"]),
            file_offset=entry.get("file_offset"),
            section=entry.get("section"),
            severity="info",
            confidence="medium",
            evidence=tuple(evidence),
            reason="Existing entry-point checks identified a concrete pattern or structural indicator.",
            recommended_action="Inspect the entry stub and its first control-transfer target before deeper analysis.",
        )
    ]


class ReverseHelperAnalyzer:
    def __init__(self, minimum_string_length: int = 4, maximum_strings: int = 2000):
        self.minimum_string_length = minimum_string_length
        self.maximum_strings = maximum_strings

    def analyze(self, path: str | Path) -> dict[str, Any]:
        """Default analysis is the bounded P0 Quick pipeline."""
        return self.analyze_quick(path)

    def analyze_full(self, path: str | Path) -> dict[str, Any]:
        """Legacy complete static report API, retained for existing consumers."""
        parser = self._open_parser(path)
        try:
            try:
                result = parser.parse()
            except Exception as error:
                raise AnalysisError(f"Analysis failed: {error}") from error

            warnings: list[dict[str, str]] = []

            def analyze_strings() -> dict[str, Any]:
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
                return strings

            strings = _optional(
                "strings",
                warnings,
                _empty_strings(self.minimum_string_length),
                analyze_strings,
            )
            entry_point = _optional(
                "entry",
                warnings,
                _empty_entry(),
                lambda: analyze_entry_point(parser.data, result["basic"], result["sections"]),
            )
            code_caves = _optional(
                "code-caves",
                warnings,
                [],
                lambda: find_code_caves(
                    parser.data,
                    result["sections"],
                    result["basic"]["image_base"],
                ),
            )
            crypto_constants = _optional(
                "crypto-constants",
                warnings,
                [],
                lambda: crypto_analyzer.find_crypto_constants(parser.data),
            )
            packing = _optional(
                "packing",
                warnings,
                _empty_packing(),
                lambda: detect_packing(
                    parser.pe,
                    result["sections"],
                    result["basic"]["entry_point_rva"],
                    result["import_count"],
                    result["basic"]["file_size"],
                ),
            )
            risk = _optional(
                "risk",
                warnings,
                _empty_risk(),
                lambda: calculate_risk(
                    result["suspicious_imports"],
                    strings,
                    packing,
                    result["parser_warnings"],
                ),
            )
            instruction_result = self._instruction_analysis(
                parser,
                result,
                {
                    "control-flow",
                    "anti-debug",
                    "crypto",
                    "validation",
                    "input",
                    "entry",
                    "targets",
                    "advisor",
                },
                entry_point,
            )
            warnings.extend(instruction_result.pop("analysis_warnings"))
            result.update(
                {
                    "schema_version": SCHEMA_VERSION,
                    "tool": {"name": "ReverseHelper", "version": __version__},
                    "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
                    "strings": strings,
                    "entry_point_analysis": entry_point,
                    "code_caves": code_caves,
                    "crypto_constants": crypto_constants,
                    "packing": packing,
                    "risk": risk,
                    **instruction_result,
                    "analysis_warnings": warnings,
                    "debugger_export_notice": DEBUGGER_NOTICE,
                    "analysis_scope": "Static PE triage; the target was read but never executed.",
                }
            )
            return result
        finally:
            parser.close()

    def analyze_quick(self, path: str | Path) -> dict[str, Any]:
        from .quick_analysis import analyze_quick
        return analyze_quick(self, path)

    def analyze_deep(self, path: str | Path) -> dict[str, Any]:
        """Run the same analyzers as Quick with larger explicit budgets."""
        from .analysis_budget import AnalysisBudget
        from .quick_analysis import analyze_quick
        return analyze_quick(self, path, AnalysisBudget.deep())

    def analyze_module(self, path: str | Path, module: str) -> dict[str, Any]:
        """Run one supported analysis module and its parsing prerequisites."""
        supported = {"anomaly", "imports", "strings", *INSTRUCTION_MODULES}
        if module not in supported:
            raise AnalysisError(f"Unsupported analysis module: {module}")
        return self._analyze_partial(path, module)

    def _open_parser(self, path: str | Path) -> PEParser:
        try:
            return PEParser(path)
        except (OSError, PEFormatError, ValueError) as error:
            raise AnalysisError(str(error)) from error

    def _analyze_partial(self, path: str | Path, mode: str) -> dict[str, Any]:
        parser = self._open_parser(path)
        try:
            try:
                result = parser.parse()
            except Exception as error:
                raise AnalysisError(f"Analysis failed: {error}") from error
            warnings: list[dict[str, str]] = []

            if mode == "strings":
                def analyze_strings() -> dict[str, Any]:
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
                    return strings

                result["strings"] = _optional(
                    "strings",
                    warnings,
                    _empty_strings(self.minimum_string_length),
                    analyze_strings,
                )
            elif mode == "imports":
                pass
            elif mode in INSTRUCTION_MODULES:
                requested = {
                    "antidebug": {"anti-debug"},
                    "validation": {"validation", "input"},
                    "crypto": {"crypto"},
                    "targets": {
                        "control-flow",
                        "anti-debug",
                        "crypto",
                        "validation",
                        "input",
                        "entry",
                        "targets",
                        "advisor",
                    },
                }[mode]
                entry_point = _optional(
                    "entry",
                    warnings,
                    _empty_entry(),
                    lambda: analyze_entry_point(parser.data, result["basic"], result["sections"]),
                )
                if mode == "crypto":
                    result["crypto_constants"] = _optional(
                        "crypto-constants",
                        warnings,
                        [],
                        lambda: crypto_analyzer.find_crypto_constants(parser.data),
                    )
                instruction_result = self._instruction_analysis(
                    parser,
                    result,
                    requested,
                    entry_point,
                )
                warnings.extend(instruction_result.pop("analysis_warnings"))
                result.update(instruction_result)
                if mode == "targets":
                    result["debugger_export_notice"] = DEBUGGER_NOTICE
            else:
                packing = _optional(
                    "packing",
                    warnings,
                    _empty_packing(),
                    lambda: detect_packing(
                        parser.pe,
                        result["sections"],
                        result["basic"]["entry_point_rva"],
                        result["import_count"],
                        result["basic"]["file_size"],
                    ),
                )
                result["packing"] = packing
                if mode == "quick":
                    result["entry_point_analysis"] = _optional(
                        "entry",
                        warnings,
                        _empty_entry(),
                        lambda: analyze_entry_point(parser.data, result["basic"], result["sections"]),
                    )
                    result["risk"] = _optional(
                        "risk",
                        warnings,
                        _empty_risk(),
                        lambda: calculate_risk(
                            result["suspicious_imports"],
                            {},
                            packing,
                            result["parser_warnings"],
                        ),
                    )

            modules = (
                ["pe", "sections", "imports", "exports", "entry", "anomaly"]
                if mode == "quick"
                else [mode]
            )
            result.update(
                {
                    "schema_version": SCHEMA_VERSION,
                    "tool": {"name": "ReverseHelper", "version": __version__},
                    "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
                    "analysis_mode": mode,
                    "analysis_modules": modules,
                    "analysis_warnings": warnings,
                    "analysis_scope": "Static PE triage; the target was read but never executed.",
                }
            )
            return result
        finally:
            parser.close()

    def _instruction_analysis(
        self,
        parser: PEParser,
        result: dict[str, Any],
        requested: set[str],
        entry_point: dict[str, Any],
    ) -> dict[str, Any]:
        warnings: list[dict[str, str]] = []
        basic = result["basic"]
        sections = result["sections"]
        architecture = basic["architecture"]
        image_base = int(basic["image_base"])
        instructions, section_summaries = _optional(
            "disassembler",
            warnings,
            ([], []),
            lambda: _disassemble_executable_sections(
                parser.data,
                sections,
                architecture,
                image_base,
            ),
        )
        details = (
            _optional(
                "instruction-details",
                warnings,
                [],
                lambda: list(iter_instruction_details(instructions, architecture)),
            )
            if instructions
            else []
        )
        findings: list[Finding] = []
        transfers = []
        import_calls = []

        if requested & {"anti-debug", "validation", "input"}:
            import_calls = _optional(
                "import-call-resolution",
                warnings,
                [],
                lambda: find_import_calls(
                    instructions,
                    result["imports"],
                    architecture,
                    image_base,
                    details,
                ),
            )

        if "control-flow" in requested:
            transfers = _optional(
                "control-flow",
                warnings,
                [],
                lambda: analyze_control_transfers(
                    instructions,
                    architecture,
                    image_base,
                    instruction_details=details,
                ),
            )
            findings.extend(
                _optional(
                    "control-flow-findings",
                    warnings,
                    [],
                    lambda: _control_flow_findings(
                        transfers,
                        sections,
                        {int(call[0]["source_address"]) for call in import_calls},
                    ),
                )
            )
        if "anti-debug" in requested:
            findings.extend(
                _optional(
                    "anti-debug",
                    warnings,
                    [],
                    lambda: anti_debug_analyzer.analyze_anti_debug(
                        instructions,
                        result["imports"],
                        sections,
                        architecture,
                        image_base,
                        instruction_details=details,
                        import_calls=import_calls,
                    ),
                )
            )
        if "crypto" in requested:
            findings.extend(
                _optional(
                    "crypto-candidates",
                    warnings,
                    [],
                    lambda: crypto_analyzer.find_crypto_candidates(
                        parser.data,
                        instructions,
                        sections,
                        architecture,
                        image_base,
                        int(basic["size_of_headers"]),
                        instruction_details=details,
                    ),
                )
            )
        if "validation" in requested:
            findings.extend(
                _optional(
                    "validation",
                    warnings,
                    [],
                    lambda: validation_analyzer.analyze_validation(
                        instructions,
                        result["imports"],
                        sections,
                        architecture,
                        image_base,
                        instruction_details=details,
                        import_calls=import_calls,
                    ),
                )
            )
        if "input" in requested:
            findings.extend(
                _optional(
                    "input",
                    warnings,
                    [],
                    lambda: validation_analyzer.find_input_candidates(
                        instructions,
                        result["imports"],
                        sections,
                        architecture,
                        image_base,
                        instruction_details=details,
                        import_calls=import_calls,
                    ),
                )
            )
        if "entry" in requested:
            findings.extend(_entry_findings(entry_point, basic))

        findings.sort(key=lambda item: (item.rva is None, item.rva or 0, item.category, item.id))
        targets = []
        if "targets" in requested:
            targets = _optional(
                "target-ranking",
                warnings,
                [],
                lambda: rank_targets(findings, image_base=image_base),
            )
        analysis_path = []
        unresolved_questions = []
        if "advisor" in requested:
            analysis_path = _optional(
                "dynamic-advisor",
                warnings,
                [],
                lambda: build_analysis_path(targets, findings),
            )
            unresolved_questions = _optional(
                "unresolved-questions",
                warnings,
                [],
                lambda: build_unresolved_questions(targets, findings),
            )

        return {
            "disassembly": {
                "instruction_count": len(instructions),
                "sections": section_summaries,
            },
            "control_transfers": transfers,
            "findings": [finding.to_dict() for finding in findings],
            "reverse_targets": [target.to_dict() for target in targets],
            "analysis_path": analysis_path,
            "unresolved_questions": unresolved_questions,
            "analysis_warnings": warnings,
        }
