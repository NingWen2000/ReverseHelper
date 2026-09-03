"""Turn evidence findings into a short, actionable target list."""

from __future__ import annotations

from collections.abc import Iterable

from .findings import Finding, ReverseTarget


_CATEGORY_VALUE = {
    "validation": 3,
    "crypto": 3,
    "anti-debug": 2,
    "control-flow": 0,
    "entry": 1,
    "input": 1,
}
_CONFIDENCE_VALUE = {"low": 0, "medium": 2, "high": 4}
_PRIORITY_VALUE = {"low": 0, "medium": 1, "high": 2}
_MAX_CONTROL_FLOW_TARGETS = 4


def _finding_score(finding: Finding) -> int:
    score = (
        _CONFIDENCE_VALUE[finding.confidence]
        + _CATEGORY_VALUE.get(finding.category, 0)
        + 1
    )
    text = " ".join((finding.title, finding.reason, *finding.evidence)).lower()
    if "import" in finding.title.lower() and "call" not in finding.title.lower():
        score -= 3
    if "pe structure" in text:
        score -= 3
    if "possible validation site" in finding.title.lower():
        score += 3
    elif "branch" in finding.title.lower():
        score += 1
    elif finding.category == "crypto" and any(word in text for word in ("routine", "loop")):
        score += 1
    if (
        "unresolved" in text
        or "only available at runtime" in text
        or "target comes from a register" in text
    ):
        score += 1
    return score


def _same_region(group: list[Finding], finding: Finding, merge_distance: int) -> bool:
    for existing in group:
        if existing.rva == finding.rva:
            return True
        if (
            existing.section is not None
            and existing.section == finding.section
            and abs(int(existing.rva) - int(finding.rva)) <= merge_distance
        ):
            categories = {existing.category, finding.category}
            if len(categories) == 1 or categories <= {"validation", "input"}:
                return True
    return False


def _priority(score: int) -> str:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def rank_targets(
    findings: Iterable[Finding],
    *,
    image_base: int | None = None,
    merge_distance: int = 0x10,
) -> list[ReverseTarget]:
    if merge_distance < 0:
        raise ValueError("Merge distance cannot be negative")

    located = []
    for finding in findings:
        if finding.rva is None or finding.rva < 0:
            continue
        if finding.va is None and image_base is None:
            continue
        located.append(finding)

    groups: list[list[Finding]] = []
    for finding in sorted(located, key=lambda item: (item.rva, item.id)):
        group = next(
            (candidate for candidate in groups if _same_region(candidate, finding, merge_distance)),
            None,
        )
        if group is None:
            groups.append([finding])
        else:
            group.append(finding)

    targets = []
    for group in groups:
        primary = max(
            group,
            key=lambda item: (_finding_score(item), _CONFIDENCE_VALUE[item.confidence], item.id),
        )
        score = _finding_score(primary) + (1 if len(group) > 1 else 0)
        reason = primary.reason
        if len(group) > 1:
            categories = ", ".join(sorted({item.category for item in group}))
            reason += f" Corroborating findings in this local region were merged ({categories})."

        target_va = primary.va
        if target_va is None:
            target_va = int(image_base) + int(primary.rva)
        same_address = [item for item in group if item.rva == primary.rva]
        file_offset = primary.file_offset
        if file_offset is None:
            file_offset = next(
                (item.file_offset for item in same_address if item.file_offset is not None),
                None,
            )
        section = primary.section or next(
            (item.section for item in same_address if item.section is not None),
            None,
        )
        targets.append(
            ReverseTarget(
                category=primary.category,
                rva=primary.rva,
                va=target_va,
                file_offset=file_offset,
                section=section,
                priority=_priority(score),
                reason=reason,
                recommended_action=primary.recommended_action,
                finding_ids=tuple(sorted(item.id for item in group)),
            )
        )

    ranked = sorted(
        targets,
        key=lambda target: (-_PRIORITY_VALUE[target.priority], target.rva, target.category),
    )
    selected = []
    control_flow_count = 0
    for target in ranked:
        if target.category == "control-flow":
            if control_flow_count >= _MAX_CONTROL_FLOW_TARGETS:
                continue
            control_flow_count += 1
        selected.append(target)
    return selected
