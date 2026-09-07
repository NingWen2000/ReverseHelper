from benchmarks.run_benchmark import aggregate, evaluate_result


def test_benchmark_evaluation_uses_function_ranges_and_adjudicated_strings():
    result = {
        "reverse_targets": [
            {"rva": 0x1010, "target_kind": "function", "score": 80, "function": "FUN_401010",
             "va": 0x401010, "type": "VALIDATION", "confidence": "high", "reason": "evidence"}
        ],
        "challenge_summary": {"start_here": {"rva": 0x1010}},
        "validation_candidates": [{"rva": 0x1018, "function_rva": 0x1010}],
        "interesting_strings": [
            {"value": "Wrong flag!", "priority": "HIGH"},
            {"value": "CreateFile failed", "priority": "MEDIUM"},
        ],
        "quick_elapsed_ms": 12.5,
        "disassembly": {"instruction_count": 20},
    }
    truth = {
        "critical_functions": [{"start_rva": 0x1000, "end_rva_exclusive": 0x1100}],
        "validation_functions": [{"start_rva": 0x1000, "end_rva_exclusive": 0x1100}],
        "relevant_strings": [{"value": "wrong flag"}],
        "irrelevant_strings": [{"value": "createfile failed"}],
    }
    record = evaluate_result(result, truth)
    assert record["top_1_hit"] is True
    assert record["start_here_hit"] is True
    assert record["validation"] == {
        "tp": 1, "fp": 0, "fn": 0,
        "predicted_function_rvas": [0x1010], "matched_truth_rvas": [0x1000],
    }
    assert record["strings"]["relevant_hits"] == 1
    assert record["strings"]["known_noise_promotions"] == 1


def test_benchmark_aggregate_keeps_failed_challenges_in_accuracy_denominator():
    record = {
        "status": "ok", "top_1_hit": True, "top_3_hit": True, "top_5_hit": True,
        "start_here_hit": True, "quick_elapsed_ms": 10,
        "validation": {"tp": 1, "fp": 1, "fn": 1},
        "strings": {"ground_truth_relevant": 2, "relevant_hits": 1,
                    "known_noise_promotions": 1, "unadjudicated_promotions": 0},
    }
    metrics = aggregate([record, {"status": "error"}])
    assert metrics["top_1_accuracy"] == 0.5
    assert metrics["validation"]["precision"] == 0.5
    assert metrics["validation"]["recall"] == 0.5
    assert metrics["strings"]["relevant_recall"] == 0.5
