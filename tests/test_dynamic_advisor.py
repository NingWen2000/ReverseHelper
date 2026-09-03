from reversehelper.dynamic_advisor import build_analysis_path, build_unresolved_questions
from reversehelper.findings import Finding, ReverseTarget


def _finding(finding_id: str, category: str, title: str, evidence=()) -> Finding:
    return Finding(
        id=finding_id,
        category=category,
        title=title,
        rva=0x1820,
        va=0x401820,
        file_offset=0xC20,
        section=".text",
        severity="low",
        confidence="high",
        evidence=tuple(evidence),
        reason="The available evidence identifies a candidate, not its runtime values.",
        recommended_action="Verify the candidate dynamically.",
    )


def _target(category: str, finding_id: str, reason: str = "Static evidence supports review.") -> ReverseTarget:
    return ReverseTarget(
        category=category,
        rva=0x1820,
        va=0x401820,
        file_offset=0xC20,
        section=".text",
        priority="high",
        reason=reason,
        recommended_action="Inspect this location.",
        finding_ids=(finding_id,),
    )


def test_validation_path_asks_for_runtime_buffers_without_guessing_branch_meaning():
    finding = _finding(
        "validation",
        "validation",
        "Possible Validation Site",
        ("Comparator: memcmp", "Condition: TEST eax, eax", "Branch: JNE 0x401850"),
    )

    item = build_analysis_path([_target("validation", finding.id)], [finding])[0]

    assert item["priority"] == "high"
    assert "prepares the comparator arguments" in item["static_question"]
    assert "actual comparison buffers" in item["dynamic_question"]
    assert "success" not in str(item).lower()
    assert "fail" not in str(item).lower()


def test_indirect_call_creates_runtime_operand_question():
    finding = _finding(
        "indirect-call",
        "control-flow",
        "Indirect CALL target is unresolved",
        ("CALL EAX at RVA 0x1820", "Target comes from a register"),
    )
    target = _target("control-flow", finding.id, "The indirect CALL target is only available at runtime.")

    path = build_analysis_path([target], [finding])[0]
    question = build_unresolved_questions([target], [finding])[0]

    assert "register or memory operand" in path["dynamic_question"]
    assert "indirect control transfer" in question["question"]
    assert "record the register or memory operand" in question["suggested_dynamic_observation"]


def test_crypto_candidate_generates_input_output_observation():
    finding = _finding("crypto", "crypto", "Possible TEA-family routine")
    target = _target("crypto", finding.id)

    path = build_analysis_path([target], [finding])[0]
    question = build_unresolved_questions([target], [finding])[0]

    assert "input, output, key, and state buffers" in path["dynamic_question"]
    assert "before and after execution" in question["suggested_dynamic_observation"]


def test_merged_target_keeps_separate_unresolved_questions_without_answers():
    validation = _finding("validation", "validation", "Possible Validation Site")
    input_finding = _finding("input", "input", "Input Candidate: fgets call site")
    target = ReverseTarget(
        category="validation",
        rva=0x1820,
        va=0x401820,
        file_offset=0xC20,
        section=".text",
        priority="high",
        reason="Related input and validation evidence occupies one local region.",
        recommended_action="Inspect both findings.",
        finding_ids=(validation.id, input_finding.id),
    )

    questions = build_unresolved_questions([target], [validation, input_finding])

    assert {item["question"] for item in questions} == {
        "What concrete values are compared at this validation candidate?",
        "Which buffer receives input, and where does that data flow next?",
    }
    assert all("answer" not in item for item in questions)


def test_import_only_target_does_not_pretend_the_iat_slot_is_a_call_site():
    finding = _finding("import", "validation", "Imported Comparator API: strcmp")
    target = _target("validation", finding.id)

    path = build_analysis_path([target], [finding])[0]
    question = build_unresolved_questions([target], [finding])[0]

    assert "references this imported API slot" in path["static_question"]
    assert "import table entry alone" in question["why_unresolved"]
    assert "comparison buffers" not in path["dynamic_question"]
