from reversehelper.risk import calculate_risk


def test_low_risk_for_no_indicators():
    result = calculate_risk([], {"category_counts": {}}, {"confidence_score": 0, "indicators": []}, [])
    assert result["score"] == 0
    assert result["level"] == "LOW"


def test_high_signal_inputs_increase_score():
    imports = [
        {"name": "WriteProcessMemory", "severity": "high"},
        {"name": "CreateRemoteThread", "severity": "high"},
    ]
    strings = {"category_counts": {"command": 4, "network": 2}}
    packing = {"confidence_score": 8, "indicators": [{"type": "rwx"}]}
    result = calculate_risk(imports, strings, packing, ["warning"])
    assert result["score"] >= 6
    assert result["level"] in {"HIGH", "CRITICAL"}
    assert result["reasons"]
