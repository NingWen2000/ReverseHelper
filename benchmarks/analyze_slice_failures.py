"""Produce read-only diagnostics for public benchmark static-slice false negatives."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from run_benchmark import ROOT

from reversehelper.analyzer import ReverseHelperAnalyzer


def _contains(function, rva):
    start = int(function["start_rva"])
    end = function.get("end_rva_exclusive")
    return rva == start if end is None else start <= rva < int(end)


def collect(manifest_path: Path) -> list[dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    analyzer = ReverseHelperAnalyzer()
    diagnostics = []
    for entry in manifest["challenges"]:
        if entry.get("availability", "available") != "available":
            continue
        truth = json.loads((ROOT / entry["ground_truth"]).read_text(encoding="utf-8"))["ground_truth"]
        validation_truth = truth.get("validation_functions", [])
        if not validation_truth:
            continue
        path = ROOT / entry.get("sample_root", manifest["sample_root"]) / entry["path"]
        try:
            result = analyzer.analyze(path)
        except Exception as error:
            diagnostics.append({"challenge": entry["id"], "error": f"{type(error).__name__}: {error}"})
            continue
        slice_sinks = [
            int(item["validation_sink"]["function_rva"])
            for item in result.get("static_slices", [])
            if item.get("validation_sink") and item["validation_sink"].get("function_rva") is not None
        ]
        functions = {int(item["rva"]): item for item in result.get("functions", [])}
        candidates = result.get("validation_candidates", [])
        compare_sites = result.get("compare_sites", [])
        decision_sites = result.get("decision_sites", [])
        for expected in validation_truth:
            expected_rva = int(expected["start_rva"])
            if any(_contains(expected, sink) for sink in slice_sinks):
                continue
            owning_candidates = [item for item in candidates if item.get("function_rva") is not None
                                 and _contains(expected, int(item["function_rva"]))]
            owning_compares = [item for item in compare_sites if item.get("function_rva") is not None
                               and _contains(expected, int(item["function_rva"]))]
            owning_decisions = [item for item in decision_sites if item.get("function_rva") is not None
                                and _contains(expected, int(item["function_rva"]))]
            diagnostics.append({
                "challenge": entry["id"],
                "tier": entry["tier"],
                "expected_validation_rva": expected_rva,
                "packed": entry.get("packed"),
                "obfuscated": entry.get("obfuscated"),
                "techniques": entry.get("techniques", []),
                "input_sources": result.get("input_sources", []),
                "validation_candidates_at_truth": owning_candidates,
                "compare_sites_at_truth": owning_compares,
                "decision_sites_at_truth": owning_decisions,
                "validation_candidates": [{key: item.get(key) for key in (
                    "id", "function", "function_rva", "rva", "validation_type", "context_only",
                    "input_flow_to_validation", "decision_type", "runtime_noise",
                )} for item in candidates],
                "validation_candidate_count": len(candidates),
                "function_boundary_at_truth": functions.get(expected_rva),
                "trace_summaries": [{
                    "input_source_id": trace.get("input_source_id"),
                    "functions_visited": trace.get("functions_visited", []),
                    "edge_count": len(trace.get("edges", [])),
                    "call_argument_count": len(trace.get("call_arguments", [])),
                    "comparison_count": len(trace.get("comparisons", [])),
                    "warnings": trace.get("warnings", []),
                    "incomplete": trace.get("incomplete", False),
                    "call_arguments": trace.get("call_arguments", []),
                    "comparisons": trace.get("comparisons", []),
                    "returns": trace.get("returns", []),
                } for trace in result.get("data_flow", {}).get("traces", [])],
                "analysis_warnings": result.get("analysis_warnings", []),
                "static_flow_breaks": result.get("static_flow_breaks", []),
                "start_here": result.get("challenge_summary", {}).get("start_here"),
                "ground_truth_evidence": expected.get("evidence") or next((
                    item.get("evidence") for item in truth.get("critical_functions", [])
                    if int(item.get("start_rva", -1)) == expected_rva
                ), None),
                "ground_truth_sources": truth.get("sources", []),
            })
    return diagnostics


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=ROOT / "benchmarks" / "manifest.json")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "analysis" / "slice_diagnostics.json")
    args = parser.parse_args(argv)
    records = collect(args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"records": records}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(records)} slice FN diagnostics to {args.output}")


if __name__ == "__main__":
    main()
