from reversehelper.findings import Finding
from reversehelper.target_ranker import rank_targets


def _finding(
    finding_id: str,
    category: str,
    title: str,
    rva: int | None,
    *,
    confidence: str = "medium",
    severity: str = "info",
    section: str | None = ".text",
) -> Finding:
    return Finding(
        id=finding_id,
        category=category,
        title=title,
        rva=rva,
        va=None if rva is None else 0x400000 + rva,
        file_offset=None if rva is None else 0x200 + rva - 0x1000,
        section=section,
        severity=severity,
        confidence=confidence,
        evidence=(title,),
        reason=f"Evidence supports reviewing {title}, but does not establish runtime behavior.",
        recommended_action="Inspect the local code and verify unresolved values dynamically.",
    )


def test_high_confidence_validation_precedes_import_only_finding():
    validation = _finding(
        "validation-branch",
        "validation",
        "Possible Validation Site",
        0x1820,
        confidence="high",
        severity="low",
    )
    imported = _finding(
        "validation-import",
        "validation",
        "Imported Comparator API: strcmp",
        0x3000,
        confidence="low",
        section=".idata",
    )

    targets = rank_targets([imported, validation])

    assert targets[0].score > targets[1].score
    assert targets[0].score <= 30
    assert targets[0].target_type == "COMPARE"
    assert targets[0].finding_ids == ("validation-branch",)


def test_finding_confidence_does_not_imply_high_reverse_priority():
    finding = _finding(
        "validation-low-severity",
        "validation",
        "Possible Validation Site",
        0x1820,
        confidence="high",
        severity="low",
    )

    target = rank_targets([finding])[0]

    assert finding.severity == "low"
    assert target.priority == "low"
    assert target.score <= 30


def test_nearby_generic_indirect_calls_do_not_become_high_priority_by_count():
    findings = [
        _finding(
            f"indirect-{rva:x}",
            "control-flow",
            "Indirect CALL target unresolved",
            rva,
            confidence="high",
        )
        for rva in (0x1400, 0x1408)
    ]

    target = rank_targets(findings)[0]

    assert target.priority == "low"


def test_pe_structure_comparator_does_not_rank_as_high_validation_target():
    branch = Finding(
        id="pe-structure-branch",
        category="validation",
        title="PE Structure Comparator Branch Candidate",
        rva=0x2200,
        va=0x402200,
        file_offset=0x1200,
        section=".text",
        severity="low",
        confidence="medium",
        evidence=("Comparator: strncmp",),
        reason="Nearby MZ and PE checks suggest this site is processing PE structures.",
        recommended_action="Confirm the compared section name.",
    )
    call = _finding(
        "pe-structure-call",
        "validation",
        "Comparator Call Site: strncmp",
        0x2200,
    )

    target = rank_targets([branch, call])[0]

    assert target.priority == "low"


def test_ranked_list_caps_generic_control_flow_noise():
    findings = [
        _finding(
            f"indirect-{index}",
            "control-flow",
            "Indirect CALL target unresolved",
            0x3000 + index * 0x20,
            confidence="high",
        )
        for index in range(9)
    ]

    targets = rank_targets(findings)

    assert len(targets) == 4
    assert all(target.category == "control-flow" for target in targets)


def test_same_rva_findings_merge_and_keep_traceability():
    findings = [
        _finding("validation", "validation", "Possible Validation Site", 0x1820, confidence="high"),
        _finding("input", "input", "Input Candidate: fgets call site", 0x1820),
        _finding("anti", "anti-debug", "RDTSC timing candidate", 0x1820, confidence="low"),
    ]

    targets = rank_targets(findings)

    assert len(targets) == 1
    assert targets[0].target_type == "COMPARE"
    assert targets[0].score <= 40  # no established function ownership
    assert targets[0].finding_ids == ("anti", "input", "validation")
    assert set(targets[0].evidence_sources) == {"api", "comparison", "input"}


def test_nearby_input_and_validation_do_not_merge_without_function_evidence():
    findings = [
        _finding("input", "input", "Input Candidate: fgets call site", 0x1818),
        _finding("validation", "validation", "Possible Validation Site", 0x1820, confidence="high"),
    ]

    targets = rank_targets(findings)

    assert len(targets) == 2
    assert targets[0].rva == 0x1820
    assert targets[0].finding_ids == ("validation",)
    assert targets[1].finding_ids == ("input",)


def test_finding_without_static_location_does_not_create_target():
    finding = _finding("no-location", "control-flow", "Indirect CALL target unresolved", None)

    assert rank_targets([finding]) == []


def test_image_base_can_complete_missing_preferred_va():
    finding = _finding("entry", "entry", "Entry transfer", 0x1000)
    finding = Finding(
        id=finding.id,
        category=finding.category,
        title=finding.title,
        rva=finding.rva,
        va=None,
        file_offset=finding.file_offset,
        section=finding.section,
        severity=finding.severity,
        confidence=finding.confidence,
        evidence=finding.evidence,
        reason=finding.reason,
        recommended_action=finding.recommended_action,
    )

    target = rank_targets([finding], image_base=0x140000000)[0]

    assert target.va == 0x140001000
