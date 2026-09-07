"""Run the frozen public CTF Quick benchmark without executing any sample."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reversehelper.analyzer import ReverseHelperAnalyzer  # noqa: E402
from reversehelper.version import __version__  # noqa: E402


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "reversehelper").glob("*.py")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _contains(function: dict[str, Any], rva: int | None) -> bool:
    if rva is None:
        return False
    start = int(function["start_rva"])
    end = function.get("end_rva_exclusive")
    return rva == start if end is None else start <= rva < int(end)


def _first_matching_rank(targets: list[dict[str, Any]], truth: list[dict[str, Any]]) -> int | None:
    rank = 0
    seen: set[int] = set()
    for target in targets:
        if target.get("target_kind") != "function" or target.get("rva") is None:
            continue
        rva = int(target["rva"])
        if rva in seen:
            continue
        seen.add(rva)
        rank += 1
        if any(_contains(function, rva) for function in truth):
            return rank
    return None


def _normal(value: str) -> str:
    return " ".join(value.casefold().split())


def _matches_string(value: str, record: dict[str, Any]) -> bool:
    candidate = _normal(value)
    pattern = _normal(str(record["value"]))
    return candidate == pattern if record.get("match", "contains") == "exact" else pattern in candidate


def _algorithm_name_matches(predicted: str, expected: str) -> bool:
    predicted = predicted.upper()
    expected = expected.upper()
    if expected == "XOR":
        return predicted in {"SINGLE_XOR", "REPEATING_KEY_XOR", "ROLLING_XOR", "XOR_CHAIN"}
    return predicted == expected


def _control_flow_kind_matches(predicted: str, expected: str) -> bool:
    predicted, expected = predicted.upper(), expected.upper()
    aliases = {
        "INDIRECT_DISPATCH": {"INDIRECT_CALL_CLUSTER", "INDIRECT_JUMP", "JUMP_TABLE"},
        "SWITCH": {"SWITCH", "JUMP_TABLE"},
        "STATE_MACHINE": {"STATE_MACHINE"},
        "FLATTENING_LIKE": {"FLATTENING_LIKE"},
    }
    return predicted in aliases.get(expected, {expected})


def _semantic_target_matches(suggestion: dict[str, Any], truth: dict[str, Any]) -> bool:
    target = suggestion.get("target", {})
    if truth.get("function_rva") is not None:
        return _contains({"start_rva": truth["function_rva"],
                          "end_rva_exclusive": truth.get("end_rva_exclusive")},
                         target.get("rva") if target.get("kind") == "FUNCTION" else target.get("function_rva"))
    expected = truth.get("target", {})
    return expected.get("kind") == target.get("kind") and expected.get("rva") == target.get("rva")


def _suggested_role(suggestion: dict[str, Any]) -> str | None:
    value = suggestion.get("proposed_value")
    if isinstance(value, dict):
        return value.get("role") or value.get("suggested_role")
    if suggestion.get("kind") == "FUNCTION_RENAME":
        return str(value).removeprefix("possible_").removeprefix("likely_")
    return None


def _type_compatibility(actual: str | None, expected: str | None) -> str:
    if not actual or not expected:
        return "UNKNOWN"
    normal_actual = actual.replace(" ", "").lower()
    normal_expected = expected.replace(" ", "").lower()
    if normal_actual == normal_expected:
        return "EXACT"
    pointerish = lambda value: "*" in value or "[]" in value or "[" in value
    width = lambda value: next((item for item in ("8", "16", "32", "64") if item in value), None)
    if pointerish(normal_actual) == pointerish(normal_expected) and width(normal_actual) == width(normal_expected):
        return "COMPATIBLE"
    return "WRONG"


def evaluate_result(result: dict[str, Any], ground_truth: dict[str, Any]) -> dict[str, Any]:
    critical = ground_truth.get("critical_functions", [])
    targets = result.get("reverse_targets", [])
    rank = _first_matching_rank(targets, critical)
    start = (result.get("challenge_summary") or {}).get("start_here")
    start_rva = start.get("rva") if start else None

    validation_truth = ground_truth.get("validation_functions", [])
    predicted = {
        int(candidate.get("function_rva") if candidate.get("function_rva") is not None else candidate["rva"])
        for candidate in result.get("validation_candidates", [])
        if not candidate.get("context_only", False)
        and (candidate.get("function_rva") is not None or candidate.get("rva") is not None)
    }
    true_predicted = {rva for rva in predicted if any(_contains(function, rva) for function in validation_truth)}
    truth_hit = {
        int(function["start_rva"])
        for function in validation_truth
        if any(_contains(function, rva) for rva in predicted)
    }

    strings = result.get("interesting_strings", [])
    promoted = [item for item in strings if str(item.get("priority", "")).upper() in {"HIGH", "MEDIUM"}]
    relevant = ground_truth.get("relevant_strings", [])
    noise = ground_truth.get("irrelevant_strings", [])
    relevant_hits = [record["value"] for record in relevant if any(_matches_string(item.get("value", ""), record) for item in promoted)]
    noise_hits = [record["value"] for record in noise if any(_matches_string(item.get("value", ""), record) for item in promoted)]

    recovered_function_starts = {int(item["rva"]) for item in result.get("functions", [])}
    adjudicated_starts = {
        int(item["start_rva"])
        for item in critical + validation_truth
        if item.get("start_rva") is not None
    }
    recovered_starts = adjudicated_starts & recovered_function_starts
    slices = result.get("static_slices", [])
    slice_summary = result.get("static_slice_summary", {})
    boundary_distribution = {name: sum(
        str(item.get("boundary_confidence", "")).upper() == name
        for item in result.get("functions", [])
    ) for name in ("CONFIRMED", "LIKELY", "HEURISTIC")}
    slice_sinks_by_status: dict[str, set[int]] = {}
    for item in slices:
        sink = item.get("validation_sink") or {}
        if sink.get("function_rva") is None:
            continue
        slice_sinks_by_status.setdefault(str(item.get("status", "UNKNOWN")), set()).add(
            int(sink["function_rva"])
        )
    complete_slice_sinks = set().union(*(
        slice_sinks_by_status.get(name, set())
        for name in ("CONFIRMED_SLICE", "LIKELY_SLICE")
    ))
    actionable_slice_sinks = complete_slice_sinks | slice_sinks_by_status.get("PARTIAL_SLICE", set())
    flow_breaks = result.get("static_flow_breaks", [])
    flow_break_targets = {
        int(item["next_unresolved_target"]["function_rva"])
        for item in flow_breaks
        if item.get("next_unresolved_target")
        and item["next_unresolved_target"].get("function_rva") is not None
    }
    actionable_slice_sinks |= flow_break_targets
    slice_sinks = actionable_slice_sinks
    slice_truth_hits = {
        int(function["start_rva"])
        for function in validation_truth
        if any(_contains(function, rva) for rva in slice_sinks)
    }
    packing = result.get("packing") or {}
    packed = packing.get("verdict") == "likely-packed"
    visibility_limited = packed or packing.get("static_visibility") == "limited"
    algorithm_truth = ground_truth.get("algorithm_ground_truth", [])
    algorithm_predictions = [item for item in result.get("algorithm_candidates", [])
                             if item.get("confidence") in {"HIGH", "MEDIUM"}]
    matched_prediction_ids = set()
    matched_truth_indexes = set()
    for prediction in algorithm_predictions:
        for index, truth in enumerate(algorithm_truth):
            truth_function = {"start_rva": truth.get("function_rva"),
                              "end_rva_exclusive": truth.get("end_rva_exclusive")}
            if (_contains(truth_function, prediction.get("function_rva"))
                    and _algorithm_name_matches(prediction.get("algorithm", ""), truth.get("algorithm", ""))):
                matched_prediction_ids.add(prediction["id"])
                matched_truth_indexes.add(index)
                break
    on_slice_predictions = [item for item in algorithm_predictions
                            if item.get("slice_relation") != "OFF_SLICE"]
    on_slice_matches = {item["id"] for item in on_slice_predictions if item["id"] in matched_prediction_ids
                        and any(index in matched_truth_indexes
                                and algorithm_truth[index].get("slice_relation") == "ON_INPUT_VALIDATION_SLICE"
                                and _algorithm_name_matches(item.get("algorithm", ""), algorithm_truth[index].get("algorithm", ""))
                                for index in range(len(algorithm_truth)))}
    algorithm_names = sorted({str(item.get("algorithm", "")).upper() for item in algorithm_truth})
    per_algorithm = {}
    for name in algorithm_names:
        truth_indexes = {index for index, item in enumerate(algorithm_truth)
                         if str(item.get("algorithm", "")).upper() == name}
        predictions_for_name = [item for item in algorithm_predictions
                                if _algorithm_name_matches(item.get("algorithm", ""), name)]
        matched_for_name = {item["id"] for item in predictions_for_name if item["id"] in matched_prediction_ids}
        per_algorithm[name] = {"tp": len(matched_for_name),
                               "fp": len(predictions_for_name) - len(matched_for_name),
                               "fn": len(truth_indexes - matched_truth_indexes)}
    control_truth = ground_truth.get("control_flow_ground_truth", [])
    control_negative_truth = ground_truth.get("control_flow_negative_ground_truth", [])
    control_predictions = [item for item in result.get("control_flow_findings", [])
                           if item.get("confidence") in {"HIGH", "MEDIUM"}]
    matched_control_ids = set()
    matched_control_truth = set()
    dispatcher_correct = dispatcher_total = 0
    state_exact = state_same_base = state_wrong = state_unknown = 0
    for prediction in control_predictions:
        for index, truth in enumerate(control_truth):
            truth_function = {"start_rva": truth.get("function_rva"),
                              "end_rva_exclusive": truth.get("end_rva_exclusive")}
            if (_contains(truth_function, prediction.get("function_rva"))
                    and _control_flow_kind_matches(prediction.get("kind", ""), truth.get("kind", ""))):
                matched_control_ids.add(prediction["id"]); matched_control_truth.add(index)
                if truth.get("dispatcher_rva") is not None and prediction.get("dispatcher_block") is not None:
                    dispatcher_total += 1
                    dispatcher_correct += int(int(truth["dispatcher_rva"]) == int(prediction["dispatcher_block"]))
                expected_state = truth.get("state_variable")
                if expected_state:
                    actual_state = prediction.get("state_variable")
                    if actual_state is None:
                        state_unknown += 1
                    elif actual_state == expected_state:
                        state_exact += 1
                    elif actual_state.get("kind") == expected_state.get("kind"):
                        state_same_base += 1
                    else:
                        state_wrong += 1
                break
    on_slice_control = [item for item in control_predictions if item.get("slice_relation") != "OFF_SLICE"]
    on_slice_control_matches = {item["id"] for item in on_slice_control if item["id"] in matched_control_ids}
    false_control_ids = set()
    for prediction in control_predictions:
        for negative in control_negative_truth:
            negative_function = {"start_rva": negative.get("function_rva"),
                                 "end_rva_exclusive": negative.get("end_rva_exclusive")}
            if (_contains(negative_function, prediction.get("function_rva"))
                    and _control_flow_kind_matches(prediction.get("kind", ""), negative.get("kind", ""))):
                false_control_ids.add(prediction["id"])
                break
    control_names = sorted({str(item.get("kind", "")).upper() for item in control_truth})
    per_control = {}
    for name in control_names:
        truth_indexes = {index for index, item in enumerate(control_truth) if str(item.get("kind", "")).upper() == name}
        predictions_for_name = [item for item in control_predictions if _control_flow_kind_matches(item.get("kind", ""), name)]
        matched_for_name = {item["id"] for item in predictions_for_name if item["id"] in matched_control_ids}
        false_for_name = {item["id"] for item in predictions_for_name if item["id"] in false_control_ids}
        per_control[name] = {"tp": len(matched_for_name), "fp": len(false_for_name),
                             "fn": len(truth_indexes - matched_control_truth)}
    semantic_truth = ground_truth.get("decompiler_ground_truth", [])
    semantic_negative = ground_truth.get("decompiler_negative_ground_truth", [])
    semantic_predictions = [item for item in result.get("decompiler_suggestions", [])
                            if item.get("confidence") in {"HIGH", "MEDIUM"}]
    semantic_matches = set()
    semantic_truth_matches = set()
    rename_tp = role_tp = 0
    type_counts = {name: 0 for name in ("EXACT", "COMPATIBLE", "WRONG", "UNKNOWN")}
    for suggestion in semantic_predictions:
        role = _suggested_role(suggestion)
        for index, truth in enumerate(semantic_truth):
            if not _semantic_target_matches(suggestion, truth) or role != truth.get("role"):
                continue
            semantic_matches.add(suggestion["id"]); semantic_truth_matches.add(index); role_tp += 1
            if truth.get("kind") == "FUNCTION_ROLE":
                rename_tp += 1
            if truth.get("type"):
                proposed = suggestion.get("proposed_value")
                actual_type = proposed.get("type_hint") if isinstance(proposed, dict) else None
                type_counts[_type_compatibility(actual_type, truth.get("type"))] += 1
            break
    semantic_false = set()
    for suggestion in semantic_predictions:
        role = _suggested_role(suggestion)
        if any(_semantic_target_matches(suggestion, truth) and role == truth.get("role")
               for truth in semantic_negative):
            semantic_false.add(suggestion["id"])

    def _slice_score(sinks: set[int]) -> dict[str, Any]:
        true_sinks = {rva for rva in sinks if any(_contains(function, rva) for function in validation_truth)}
        hits = {
            int(function["start_rva"])
            for function in validation_truth
            if any(_contains(function, rva) for rva in sinks)
        }
        return {
            "predicted": len(sinks),
            "tp": len(true_sinks),
            "fp": len(sinks - true_sinks),
            "fn": len(validation_truth) - len(hits),
            "matched_truth_rvas": sorted(hits),
        }

    ordered = [{key: target.get(key) for key in ("rva", "va", "function", "type", "score", "confidence", "target_kind", "reason")}
               for target in targets[:20]]
    return {
        "status": "ok",
        "ordered_targets": ordered,
        "first_critical_function_rank": rank,
        "top_1_hit": rank is not None and rank <= 1,
        "top_3_hit": rank is not None and rank <= 3,
        "top_5_hit": rank is not None and rank <= 5,
        "ranking_eligible": bool(critical),
        "start_here_rva": start_rva,
        "start_here_hit": any(_contains(function, start_rva) for function in critical),
        "validation": {
            "tp": len(true_predicted),
            "fp": len(predicted - true_predicted),
            "fn": len(validation_truth) - len(truth_hit),
            "predicted_function_rvas": sorted(predicted),
            "matched_truth_rvas": sorted(truth_hit),
        },
        "strings": {
            "ground_truth_relevant": len(relevant),
            "relevant_hits": len(relevant_hits),
            "matched_relevant_values": relevant_hits,
            "known_noise_promotions": len(noise_hits),
            "matched_noise_values": noise_hits,
            "promoted_total": len(promoted),
            "unadjudicated_promotions": max(0, len(promoted) - len(noise_hits) - len(relevant_hits)),
        },
        "function_boundary": {
            "adjudicated_starts": len(adjudicated_starts),
            "recovered_starts": len(recovered_starts),
            "missed_start_rvas": sorted(adjudicated_starts - recovered_starts),
            "distribution": boundary_distribution,
        },
        "static_slice": {
            "predicted": len(slice_sinks),
            "tp": len({rva for rva in slice_sinks if any(_contains(function, rva) for function in validation_truth)}),
            "fp": len({rva for rva in slice_sinks if not any(_contains(function, rva) for function in validation_truth)}),
            "fn": len(validation_truth) - len(slice_truth_hits),
            "confirmed": int(slice_summary.get("confirmed", 0)),
            "likely": int(slice_summary.get("likely", 0)),
            "partial": int(slice_summary.get("partial", 0)),
            "unresolved": int(slice_summary.get("unresolved", 0)),
            "complete": _slice_score(complete_slice_sinks),
            "actionable": _slice_score(actionable_slice_sinks),
            "flow_breaks": len(flow_breaks),
            "flow_break_target_rvas": sorted(flow_break_targets),
        },
        "packed_predicted": packed,
        "limited_visibility_predicted": visibility_limited,
        "warnings": result.get("analysis_warnings", []),
        "quick_elapsed_ms": result.get("quick_elapsed_ms", result.get("analysis_elapsed_ms")),
        "analysis_elapsed_ms": result.get("analysis_elapsed_ms", result.get("quick_elapsed_ms")),
        "instruction_count": (result.get("disassembly") or {}).get("instruction_count"),
        "input_source_count": len(result.get("input_sources", [])),
        "static_slice_count": len(result.get("static_slices", [])),
        "static_flow_break_count": len(flow_breaks),
        "algorithms": {
            "adjudicated": bool(algorithm_truth),
            "tp": len(matched_prediction_ids),
            "fp": len(algorithm_predictions) - len(matched_prediction_ids),
            "fn": len(algorithm_truth) - len(matched_truth_indexes),
            "on_slice_tp": len(on_slice_matches),
            "on_slice_fp": len(on_slice_predictions) - len(on_slice_matches),
            "per_algorithm": per_algorithm,
            "predictions": [{key: item.get(key) for key in ("id", "algorithm", "function_rva", "confidence", "slice_relation")}
                            for item in algorithm_predictions],
        },
        "control_flow": {
            "adjudicated": bool(control_truth), "tp": len(matched_control_ids),
            "fp": len(false_control_ids),
            "fn": len(control_truth) - len(matched_control_truth),
            "on_slice_tp": len(on_slice_control_matches),
            "on_slice_fp": len({item["id"] for item in on_slice_control if item["id"] in false_control_ids}),
            "unadjudicated_predictions": len(control_predictions) - len(matched_control_ids) - len(false_control_ids),
            "dispatcher_correct": dispatcher_correct, "dispatcher_total": dispatcher_total,
            "state_exact": state_exact, "state_same_base": state_same_base,
            "state_wrong": state_wrong, "state_unknown": state_unknown,
            "per_kind": per_control,
            "predictions": [{key: item.get(key) for key in ("id", "kind", "function_rva", "confidence", "slice_relation", "dispatcher_block", "state_variable")}
                            for item in control_predictions],
        },
        "decompiler_assistance": {
            "adjudicated": bool(semantic_truth), "role_tp": role_tp,
            "role_fp": len(semantic_false), "role_fn": len(semantic_truth) - len(semantic_truth_matches),
            "rename_tp": rename_tp,
            "rename_fp": sum(item["id"] in semantic_false and item.get("kind") == "FUNCTION_RENAME"
                             for item in semantic_predictions),
            "type": type_counts,
            "unadjudicated_predictions": len(semantic_predictions) - len(semantic_matches) - len(semantic_false),
        },
        "flow_linked_validation_count": sum(
            not candidate.get("context_only", False)
            and candidate.get("input_flow_to_validation", "NONE") != "NONE"
            for candidate in result.get("validation_candidates", [])
        ),
    }


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    measured = [record for record in records if record.get("status") == "ok"]
    count = len(records)
    ranking_records = [record for record in records if record.get("ranking_eligible", True)]
    elapsed = [float(record["quick_elapsed_ms"]) for record in measured if record.get("quick_elapsed_ms") is not None]
    totals = {name: sum(int(record["validation"][name]) for record in measured) for name in ("tp", "fp", "fn")}
    precision_denominator = totals["tp"] + totals["fp"]
    recall_denominator = totals["tp"] + totals["fn"]
    relevant_total = sum(record["strings"]["ground_truth_relevant"] for record in measured)
    relevant_hits = sum(record["strings"]["relevant_hits"] for record in measured)
    noise_hits = sum(record["strings"]["known_noise_promotions"] for record in measured)
    slice_totals = {name: sum(int(record.get("static_slice", {}).get(name, 0)) for record in measured) for name in ("tp", "fp", "fn")}
    complete_slice_totals = {name: sum(int(record.get("static_slice", {}).get("complete", {}).get(name, 0)) for record in measured)
                             for name in ("tp", "fp", "fn")}
    actionable_slice_totals = {name: sum(int(record.get("static_slice", {}).get("actionable", {}).get(name, 0)) for record in measured)
                               for name in ("tp", "fp", "fn")}
    boundary_truth = sum(record.get("function_boundary", {}).get("adjudicated_starts", 0) for record in measured)
    boundary_hits = sum(record.get("function_boundary", {}).get("recovered_starts", 0) for record in measured)
    boundary_distribution = {name: sum(
        record.get("function_boundary", {}).get("distribution", {}).get(name, 0)
        for record in measured
    ) for name in ("CONFIRMED", "LIKELY", "HEURISTIC")}
    algorithm_records = [record for record in measured if record.get("algorithms", {}).get("adjudicated")]
    algorithm_totals = {name: sum(record["algorithms"].get(name, 0) for record in algorithm_records)
                        for name in ("tp", "fp", "fn", "on_slice_tp", "on_slice_fp")}
    algorithm_names = sorted({name for record in algorithm_records
                              for name in record["algorithms"].get("per_algorithm", {})})
    per_algorithm_totals = {name: {metric: sum(record["algorithms"].get("per_algorithm", {}).get(name, {}).get(metric, 0)
                                                    for record in algorithm_records)
                                    for metric in ("tp", "fp", "fn")}
                            for name in algorithm_names}
    control_records = [record for record in measured if record.get("control_flow", {}).get("adjudicated")]
    control_totals = {name: sum(record["control_flow"].get(name, 0) for record in control_records)
                      for name in ("tp", "fp", "fn", "on_slice_tp", "on_slice_fp", "dispatcher_correct",
                                   "dispatcher_total", "state_exact", "state_same_base", "state_wrong", "state_unknown")}
    control_names = sorted({name for record in control_records for name in record["control_flow"].get("per_kind", {})})
    per_control_totals = {name: {metric: sum(record["control_flow"].get("per_kind", {}).get(name, {}).get(metric, 0)
                                                  for record in control_records)
                                  for metric in ("tp", "fp", "fn")}
                          for name in control_names}
    semantic_records = [record for record in measured if record.get("decompiler_assistance", {}).get("adjudicated")]
    semantic_totals = {name: sum(record["decompiler_assistance"].get(name, 0) for record in semantic_records)
                       for name in ("role_tp", "role_fp", "role_fn", "rename_tp", "rename_fp")}
    semantic_types = {name: sum(record["decompiler_assistance"].get("type", {}).get(name, 0)
                                for record in semantic_records)
                      for name in ("EXACT", "COMPATIBLE", "WRONG", "UNKNOWN")}
    slice_precision_denominator = slice_totals["tp"] + slice_totals["fp"]
    slice_recall_denominator = slice_totals["tp"] + slice_totals["fn"]
    p90 = None
    if elapsed:
        ordered_elapsed = sorted(elapsed)
        p90 = ordered_elapsed[max(0, int((len(ordered_elapsed) - 1) * 0.9))]
    validation_precision = totals["tp"] / precision_denominator if precision_denominator else None
    validation_recall = totals["tp"] / recall_denominator if recall_denominator else None
    ranking_count = len(ranking_records)
    emitted_starts = [record for record in ranking_records if record.get("start_here_rva") is not None]
    packed_records = [record for record in measured if record.get("packed_expected")]
    visibility_records = [record for record in measured if record.get("static_visibility") != "UNKNOWN"]
    visibility_tp = sum(
        record.get("static_visibility") == "PACKED_OR_TRANSFORMED" and bool(record.get("limited_visibility_predicted"))
        for record in visibility_records
    )
    visibility_tn = sum(
        record.get("static_visibility") != "PACKED_OR_TRANSFORMED" and not bool(record.get("limited_visibility_predicted"))
        for record in visibility_records
    )
    visibility_fp = sum(
        record.get("static_visibility") != "PACKED_OR_TRANSFORMED" and bool(record.get("limited_visibility_predicted"))
        for record in visibility_records
    )
    visibility_fn = sum(
        record.get("static_visibility") == "PACKED_OR_TRANSFORMED" and not bool(record.get("limited_visibility_predicted"))
        for record in visibility_records
    )

    def _slice_aggregate(totals: dict[str, int]) -> dict[str, Any]:
        precision_denominator = totals["tp"] + totals["fp"]
        recall_denominator = totals["tp"] + totals["fn"]
        return {
            **totals,
            "precision": totals["tp"] / precision_denominator if precision_denominator else None,
            "recall": totals["tp"] / recall_denominator if recall_denominator else None,
        }
    return {
        "challenge_count": count,
        "completed_count": len(measured),
        "failed_count": count - len(measured),
        "ranking_eligible_count": ranking_count,
        "top_1_accuracy": sum(bool(r.get("top_1_hit")) for r in ranking_records) / ranking_count if ranking_count else None,
        "top_3_accuracy": sum(bool(r.get("top_3_hit")) for r in ranking_records) / ranking_count if ranking_count else None,
        "top_5_accuracy": sum(bool(r.get("top_5_hit")) for r in ranking_records) / ranking_count if ranking_count else None,
        "start_here_accuracy": sum(bool(r.get("start_here_hit")) for r in ranking_records) / ranking_count if ranking_count else None,
        "start_here_emitted_count": len(emitted_starts),
        "start_here_precision": sum(bool(r.get("start_here_hit")) for r in emitted_starts) / len(emitted_starts) if emitted_starts else None,
        "validation": {
            **totals,
            "precision": validation_precision,
            "recall": validation_recall,
            "f1": (2 * validation_precision * validation_recall / (validation_precision + validation_recall))
            if validation_precision is not None and validation_recall is not None and validation_precision + validation_recall else None,
        },
        "strings": {
            "relevant_total": relevant_total,
            "relevant_hits": relevant_hits,
            "relevant_recall": relevant_hits / relevant_total if relevant_total else None,
            "adjudicated_precision": relevant_hits / (relevant_hits + noise_hits) if relevant_hits + noise_hits else None,
            "known_noise_promotions": noise_hits,
            "unadjudicated_promotions": sum(r["strings"]["unadjudicated_promotions"] for r in measured),
        },
        "data_flow": {
            "input_sources": sum(record.get("input_source_count", 0) for record in measured),
            "static_slices": sum(record.get("static_slice_count", 0) for record in measured),
            "flow_linked_validations": sum(record.get("flow_linked_validation_count", 0) for record in measured),
            "static_flow_breaks": sum(record.get("static_flow_break_count", 0) for record in measured),
        },
        "function_boundary": {
            "adjudicated_starts": boundary_truth,
            "recovered_starts": boundary_hits,
            "start_recall": boundary_hits / boundary_truth if boundary_truth else None,
            "distribution": boundary_distribution,
        },
        "static_slice": {
            **slice_totals,
            **{name: sum(record.get("static_slice", {}).get(name, 0) for record in measured)
               for name in ("confirmed", "likely", "partial", "unresolved")},
            "precision": slice_totals["tp"] / slice_precision_denominator if slice_precision_denominator else None,
            "recall": slice_totals["tp"] / slice_recall_denominator if slice_recall_denominator else None,
            "complete": _slice_aggregate(complete_slice_totals),
            "actionable": _slice_aggregate(actionable_slice_totals),
        },
        "algorithms": {
            **algorithm_totals,
            "adjudicated_samples": len(algorithm_records),
            "precision": algorithm_totals["tp"] / (algorithm_totals["tp"] + algorithm_totals["fp"])
                         if algorithm_totals["tp"] + algorithm_totals["fp"] else None,
            "recall": algorithm_totals["tp"] / (algorithm_totals["tp"] + algorithm_totals["fn"])
                      if algorithm_totals["tp"] + algorithm_totals["fn"] else None,
            "on_slice_precision": algorithm_totals["on_slice_tp"] / (algorithm_totals["on_slice_tp"] + algorithm_totals["on_slice_fp"])
                                  if algorithm_totals["on_slice_tp"] + algorithm_totals["on_slice_fp"] else None,
            "per_algorithm": per_algorithm_totals,
        },
        "control_flow": {
            **control_totals, "adjudicated_samples": len(control_records),
            "precision": control_totals["tp"] / (control_totals["tp"] + control_totals["fp"])
                         if control_totals["tp"] + control_totals["fp"] else None,
            "recall": control_totals["tp"] / (control_totals["tp"] + control_totals["fn"])
                      if control_totals["tp"] + control_totals["fn"] else None,
            "on_slice_precision": control_totals["on_slice_tp"] / (control_totals["on_slice_tp"] + control_totals["on_slice_fp"])
                                  if control_totals["on_slice_tp"] + control_totals["on_slice_fp"] else None,
            "dispatcher_accuracy": control_totals["dispatcher_correct"] / control_totals["dispatcher_total"]
                                   if control_totals["dispatcher_total"] else None,
            "per_kind": per_control_totals,
        },
        "decompiler_assistance": {
            **semantic_totals, "adjudicated_samples": len(semantic_records), "type": semantic_types,
            "role_precision": semantic_totals["role_tp"] / (semantic_totals["role_tp"] + semantic_totals["role_fp"])
                              if semantic_totals["role_tp"] + semantic_totals["role_fp"] else None,
            "role_recall": semantic_totals["role_tp"] / (semantic_totals["role_tp"] + semantic_totals["role_fn"])
                           if semantic_totals["role_tp"] + semantic_totals["role_fn"] else None,
            "rename_precision": semantic_totals["rename_tp"] / (semantic_totals["rename_tp"] + semantic_totals["rename_fp"])
                                if semantic_totals["rename_tp"] + semantic_totals["rename_fp"] else None,
        },
        "packed_visibility": {
            "expected_packed": len(packed_records),
            "detected_packed": sum(bool(record.get("packed_predicted")) for record in packed_records),
            "recall": sum(bool(record.get("packed_predicted")) for record in packed_records) / len(packed_records)
            if packed_records else None,
            "tp": visibility_tp,
            "tn": visibility_tn,
            "fp": visibility_fp,
            "fn": visibility_fn,
            "accuracy": (visibility_tp + visibility_tn) / len(visibility_records) if visibility_records else None,
        },
        "median_quick_elapsed_ms": statistics.median(elapsed) if elapsed else None,
        "p90_quick_elapsed_ms": p90,
        "max_quick_elapsed_ms": max(elapsed) if elapsed else None,
        "median_analysis_elapsed_ms": statistics.median(elapsed) if elapsed else None,
        "p90_analysis_elapsed_ms": p90,
        "max_analysis_elapsed_ms": max(elapsed) if elapsed else None,
    }


def _failure_category(entry: dict[str, Any], outcome: dict[str, Any]) -> str | None:
    if outcome.get("status") != "ok":
        return outcome.get("failure_category", "PARSER_FAILURE")
    if outcome.get("top_5_hit"):
        return None
    if not outcome.get("ordered_targets"):
        return entry.get("failure_category_hint", "NO_STRING_SIGNAL")
    return entry.get("failure_category_hint", "OTHER")


def run(manifest_path: Path, output: Path, selected_ids: set[str] | None = None, mode: str = "quick") -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sample_root = ROOT / manifest["sample_root"]
    output.mkdir(parents=True, exist_ok=True)
    analyzer = ReverseHelperAnalyzer()
    records = []
    pending = []
    for entry in manifest["challenges"]:
        if selected_ids and entry["id"] not in selected_ids:
            continue
        if entry.get("availability", "available") != "available":
            pending.append({"challenge_id": entry["id"], "tier": entry.get("tier"),
                            "availability": entry.get("availability")})
            continue
        entry_root = ROOT / entry.get("sample_root", manifest["sample_root"])
        path = entry_root / entry["path"]
        ground_truth = json.loads((ROOT / entry["ground_truth"]).read_text(encoding="utf-8"))["ground_truth"]
        started = time.perf_counter()
        try:
            if not path.is_file():
                raise FileNotFoundError(path)
            actual_hash = _sha256(path)
            if actual_hash != entry["sha256"]:
                raise ValueError(f"SHA-256 mismatch: {actual_hash}")
            result = analyzer.analyze_deep(path) if mode == "deep" else analyzer.analyze(path)
            outcome = evaluate_result(result, ground_truth)
            outcome["wall_elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        except Exception as error:  # one challenge must not abort the benchmark
            outcome = {
                "status": "error",
                "failure_category": "MISSING_SAMPLE" if isinstance(error, FileNotFoundError) else "PARSER_FAILURE",
                "error_type": type(error).__name__,
                "error": str(error),
                "wall_elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        outcome.update({"challenge_id": entry["id"], "name": entry["name"], "split": entry["split"],
                        "tier": entry.get("tier"), "packed_expected": bool(entry.get("packed")),
                        "review_status": entry.get("review_status"),
                        "static_visibility": entry.get("static_visibility", "UNKNOWN")})
        outcome.setdefault("ranking_eligible", bool(ground_truth.get("critical_functions")))
        outcome["binary_size_bytes"] = entry["file_size_bytes"]
        outcome["failure_category"] = _failure_category(entry, outcome)
        records.append(outcome)
        (output / f"{entry['id']}.json").write_text(json.dumps(outcome, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    tier_metrics = {tier: aggregate([record for record in records if record.get("tier") == tier])
                    for tier in ("A", "B", "C")}
    visibility_metrics = {
        visibility: aggregate([record for record in records if record.get("static_visibility") == visibility])
        for visibility in ("FULLY_VISIBLE", "PARTIALLY_VISIBLE", "PACKED_OR_TRANSFORMED", "UNKNOWN")
    }
    static_visible_records = [record for record in records if record.get("static_visibility") in {
        "FULLY_VISIBLE", "PARTIALLY_VISIBLE"
    }]
    summary = {
        "schema_version": "reversehelper-public-ctf-results-3",
        "dataset": manifest["dataset"],
        "ground_truth_frozen_at": manifest["ground_truth_frozen_at"],
        "run_at_utc": datetime.now(timezone.utc).isoformat(),
        "tool": {"version": __version__, "source_hash": _source_hash()},
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "processor": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER")},
        "configuration": {"mode": mode, "network": "not used by runner", "sample_execution": False},
        "metrics": aggregate(records),
        "metrics_by_tier": tier_metrics,
        "metrics_by_static_visibility": visibility_metrics,
        "metrics_static_visible": aggregate(static_visible_records),
        "manifest_coverage": {
            "total_slots": len([entry for entry in manifest["challenges"] if not selected_ids or entry["id"] in selected_ids]),
            "available": len(records), "pending": len(pending), "pending_records": pending,
            "review_status": {
                status: sum(entry.get("review_status") == status for entry in manifest["challenges"]
                            if entry.get("availability", "available") == "available")
                for status in ("SINGLE_REVIEW", "DOUBLE_REVIEW", "OFFICIAL_WP_CONFIRMED")
            },
            "static_visibility": {
                visibility: sum(entry.get("static_visibility") == visibility for entry in manifest["challenges"]
                                if entry.get("availability", "available") == "available")
                for visibility in ("FULLY_VISIBLE", "PARTIALLY_VISIBLE", "PACKED_OR_TRANSFORMED", "UNKNOWN")
            },
        },
        "failure_categories": {category: sum(r.get("failure_category") == category for r in records)
                               for category in ("NO_STRING_SIGNAL", "FUNCTION_BOUNDARY_FAILURE", "INDIRECT_CALL",
                                                "INPUT_FLOW_MISSING", "OPTIMIZED_COMPARE", "STATIC_LINK_NOISE",
                                                "CRT_NOISE", "PACKED", "OBFUSCATED", "RANKING_WEIGHT_ERROR",
                                                "PARSER_FAILURE", "OTHER")},
        "records": [{"challenge_id": r["challenge_id"], "tier": r.get("tier"), "status": r["status"],
                     "static_visibility": r.get("static_visibility"),
                     "failure_category": r.get("failure_category"), "top_5_hit": r.get("top_5_hit")}
                    for r in records],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "benchmarks" / "manifest.json")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "results" / "latest")
    parser.add_argument("--id", action="append", dest="ids", help="run only this challenge id (repeatable)")
    parser.add_argument("--deep", action="store_true", help="use the larger Deep budget profile")
    args = parser.parse_args()
    summary = run(args.manifest, args.output, set(args.ids) if args.ids else None,
                  "deep" if args.deep else "quick")
    print(json.dumps(summary["metrics"], indent=2))
    return 0 if summary["metrics"]["failed_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
