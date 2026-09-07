"""Validate and summarize the hand-reviewed Phase 2.7A slice FN audit."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AUDIT = ROOT / "benchmarks" / "analysis" / "phase27_slice_failure_audit.json"

FAILURE_CATEGORIES = {
    "STATIC_NOT_VISIBLE", "INPUT_SOURCE_MISSED", "INPUT_WRAPPER_MISSED",
    "FUNCTION_BOUNDARY", "FUNCTION_CHUNK", "TAIL_CALL", "THUNK_CHAIN",
    "ARGUMENT_MAPPING", "X86_STACK_ARGUMENT", "X64_REGISTER_ARGUMENT",
    "REGISTER_SPILL_RESTORE", "REGISTER_REUSE", "VALUE_IDENTITY_LOSS",
    "STACK_ALIAS", "INDEXED_STACK", "GLOBAL_FLOW", "INDEXED_GLOBAL",
    "POINTER_OFFSET", "POINTER_ALIAS", "MULTI_LEVEL_POINTER", "HEAP_FLOW",
    "RETURN_FLOW", "DERIVED_RETURN", "INDIRECT_CALL", "FUNCTION_POINTER",
    "VTABLE_CALL", "OPTIMIZED_COMPARE", "STATIC_LINKED_COMPARE",
    "COMPARE_NOT_DETECTED", "DECISION_NOT_LINKED", "OUTCOME_NOT_LINKED",
    "PATH_MERGE", "PHI_LIKE", "INLINING", "OPTIMIZATION_ARTIFACT",
    "BUDGET_LIMIT", "GROUND_TRUTH_AMBIGUOUS", "OTHER",
}
TIERS = {"A", "B", "C"}
VISIBILITY = {"FULLY_VISIBLE", "PARTIALLY_VISIBLE", "PACKED_OR_TRANSFORMED", "UNKNOWN"}
REPAIRABILITY = {"HIGH", "MEDIUM", "LOW", "OUT_OF_SCOPE"}
COMPLEXITY = {"S", "M", "L", "XL"}
PRODUCT_VALUE = {"HIGH", "MEDIUM", "LOW"}
FLOW_BREAK_QUALITY = {"EXACT", "NEAR", "WRONG", "NONE"}
FUNNEL_STAGES = {"A", "B", "C", "D", "E", "F", "G"}


def load_audit(path: Path = DEFAULT_AUDIT) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_record(record: dict) -> None:
    required = {
        "challenge", "tier", "architecture", "static_visibility", "ground_truth",
        "reversehelper", "first_broken_edge", "primary_failure_category",
        "secondary_failure_categories", "repairability", "estimated_complexity",
        "expected_product_value", "failure_funnel_stage", "notes",
    }
    missing = required - record.keys()
    if missing:
        raise ValueError(f"missing audit fields: {sorted(missing)}")
    if record["tier"] not in TIERS:
        raise ValueError(f"unknown tier: {record['tier']}")
    if record["static_visibility"] not in VISIBILITY:
        raise ValueError(f"unknown static visibility: {record['static_visibility']}")
    categories = [record["primary_failure_category"], *record["secondary_failure_categories"]]
    unknown = set(categories) - FAILURE_CATEGORIES
    if unknown:
        raise ValueError(f"unknown failure category: {sorted(unknown)}")
    if record["repairability"] not in REPAIRABILITY:
        raise ValueError(f"unknown repairability: {record['repairability']}")
    if record["estimated_complexity"] not in COMPLEXITY:
        raise ValueError(f"unknown complexity: {record['estimated_complexity']}")
    if record["expected_product_value"] not in PRODUCT_VALUE:
        raise ValueError(f"unknown product value: {record['expected_product_value']}")
    if record["failure_funnel_stage"] not in FUNNEL_STAGES:
        raise ValueError(f"unknown funnel stage: {record['failure_funnel_stage']}")
    quality = record["reversehelper"].get("flow_break_quality")
    if quality not in FLOW_BREAK_QUALITY:
        raise ValueError(f"unknown flow-break quality: {quality}")


def aggregate(records: list[dict]) -> dict:
    for record in records:
        validate_record(record)
    primary = Counter(r["primary_failure_category"] for r in records)
    secondary = Counter(c for r in records for c in r["secondary_failure_categories"])
    tiers = Counter(r["tier"] for r in records)
    visibility = Counter(r["static_visibility"] for r in records)
    repairability = Counter(r["repairability"] for r in records)
    funnel = Counter(r["failure_funnel_stage"] for r in records)
    breaks = Counter(r["reversehelper"]["flow_break_quality"] for r in records)
    fixable = [r for r in records if r["static_visibility"] in {"FULLY_VISIBLE", "PARTIALLY_VISIBLE"}
               and r["repairability"] in {"HIGH", "MEDIUM"}]
    return {
        "slice_false_negatives": len(records),
        "audit_challenges": len({r["challenge"] for r in records}),
        "primary_failure_frequency": dict(primary.most_common()),
        "secondary_failure_frequency": dict(secondary.most_common()),
        "tier_distribution": dict(sorted(tiers.items())),
        "static_visibility_distribution": dict(visibility.most_common()),
        "repairability_distribution": dict(repairability.most_common()),
        "failure_funnel": dict(sorted(funnel.items())),
        "flow_break_accuracy": dict(sorted(breaks.items())),
        "fixable_static_visible_fn": len(fixable),
        "publication_threshold_only_blocks": sum(
            r["reversehelper"].get("publication_block_reason") == "THRESHOLD_ONLY" for r in records
        ),
    }


def main() -> None:
    audit = load_audit()
    print(json.dumps(aggregate(audit["records"]), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
