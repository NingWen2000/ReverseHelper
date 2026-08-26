"""Explainable triage score. This is not a malware verdict."""

from __future__ import annotations

from typing import Any


API_WEIGHTS = {"low": 0.2, "medium": 0.45, "high": 0.8}


def calculate_risk(
    suspicious_imports: list[dict[str, Any]],
    strings: dict[str, Any],
    packing: dict[str, Any],
    parser_warnings: list[str],
) -> dict[str, Any]:
    score = 0.0
    reasons: list[dict[str, Any]] = []

    if suspicious_imports:
        api_score = min(3.0, sum(API_WEIGHTS.get(item.get("severity", "low"), 0.2) for item in suspicious_imports))
        score += api_score
        names = ", ".join(item["name"] for item in suspicious_imports[:6])
        reasons.append({"source": "imports", "points": round(api_score, 1), "detail": names})

    packing_score = min(5.0, float(packing.get("confidence_score", 0)) * 0.65)
    if packing_score:
        score += packing_score
        reasons.append(
            {
                "source": "packing",
                "points": round(packing_score, 1),
                "detail": f"{len(packing['indicators'])} packing/anomaly indicator(s)",
            }
        )

    category_counts = strings.get("category_counts", {})
    high_signal = sum(category_counts.get(name, 0) for name in ("command", "credential", "debug", "network"))
    string_score = min(1.5, high_signal * 0.25)
    if string_score:
        score += string_score
        reasons.append(
            {
                "source": "strings",
                "points": round(string_score, 1),
                "detail": f"{high_signal} high-signal classified string(s)",
            }
        )

    warning_score = min(0.5, len(parser_warnings) * 0.1)
    if warning_score:
        score += warning_score
        reasons.append(
            {
                "source": "parser-warnings",
                "points": round(warning_score, 1),
                "detail": f"{len(parser_warnings)} structural warning(s)",
            }
        )

    rounded = round(min(10.0, score), 1)
    if rounded >= 8:
        level = "CRITICAL"
    elif rounded >= 6:
        level = "HIGH"
    elif rounded >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": rounded,
        "maximum": 10,
        "level": level,
        "reasons": reasons,
        "disclaimer": "Triage score only. A high score does not prove maliciousness; a low score does not prove safety.",
    }
