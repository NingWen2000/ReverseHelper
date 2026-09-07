from copy import deepcopy

import pytest

from benchmarks.analysis.phase27_audit import aggregate, load_audit, validate_record


def test_phase27_audit_schema_and_aggregation():
    records = load_audit()["records"]
    summary = aggregate(records)
    assert len(records) == 19
    assert summary["audit_challenges"] == 14
    assert summary["tier_distribution"] == {"A": 3, "B": 13, "C": 3}
    assert summary["fixable_static_visible_fn"] == 15
    assert summary["publication_threshold_only_blocks"] == 0


def test_phase27_audit_repairability_and_visibility_aggregation():
    summary = aggregate(load_audit()["records"])
    assert summary["repairability_distribution"] == {
        "HIGH": 11, "MEDIUM": 4, "LOW": 3, "OUT_OF_SCOPE": 1,
    }
    assert summary["static_visibility_distribution"] == {
        "FULLY_VISIBLE": 15, "PARTIALLY_VISIBLE": 3, "PACKED_OR_TRANSFORMED": 1,
    }


def test_phase27_audit_rejects_unknown_failure_category():
    record = deepcopy(load_audit()["records"][0])
    record["primary_failure_category"] = "DATA_FLOW_FAILED"
    with pytest.raises(ValueError, match="unknown failure category"):
        validate_record(record)


def test_phase27_audit_rejects_unknown_tier():
    record = deepcopy(load_audit()["records"][0])
    record["tier"] = "D"
    with pytest.raises(ValueError, match="unknown tier"):
        validate_record(record)
