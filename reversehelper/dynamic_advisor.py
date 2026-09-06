"""Build static and dynamic questions from ranked reverse targets."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .findings import Finding, ReverseTarget


def _linked_findings(
    target: ReverseTarget,
    findings_by_id: dict[str, Finding],
) -> list[Finding]:
    return [
        findings_by_id[finding_id]
        for finding_id in target.finding_ids
        if finding_id in findings_by_id
    ]


def _is_indirect_target(target: ReverseTarget, findings: list[Finding]) -> bool:
    text = " ".join(
        [
            target.reason,
            *(finding.title for finding in findings),
            *(item for finding in findings for item in finding.evidence),
        ]
    ).lower()
    return "indirect" in text and ("unresolved" in text or "register" in text or "memory" in text)


def _import_only(findings: list[Finding]) -> bool:
    return bool(findings) and all(
        "import" in finding.title.lower() and "call" not in finding.title.lower()
        for finding in findings
    )


def build_analysis_path(
    targets: Iterable[ReverseTarget],
    findings: Iterable[Finding] = (),
) -> list[dict[str, Any]]:
    findings_by_id = {finding.id: finding for finding in findings}
    path = []

    for target in targets:
        linked = _linked_findings(target, findings_by_id)
        indirect = _is_indirect_target(target, linked)
        if _import_only(linked):
            static_question = "Which code references this imported API slot, if any?"
            dynamic_question = "Does execution reach a call through this import, and with what arguments?"
            action = "Find IAT references in Ghidra before deciding whether a runtime breakpoint is useful."
        elif target.category == "validation":
            static_question = "What code prepares the comparator arguments before this call?"
            dynamic_question = "What are the actual comparison buffers and return value at runtime?"
            action = "Inspect the caller in Ghidra and break at this call site in x64dbg to observe the arguments."
        elif target.category == "crypto":
            static_question = "Do the surrounding rounds, state updates, and callers support the suspected algorithm family?"
            dynamic_question = "What input, output, key, and state buffers are used when this candidate executes?"
            action = "Review callers in Ghidra, then break at the candidate in x64dbg and record buffer changes."
        elif target.category == "anti-debug":
            static_question = "Which value is tested, and what behavior is guarded by the resulting branch?"
            dynamic_question = "What anti-debug-related value is observed at runtime, and which branch is taken?"
            action = "Inspect both paths in Ghidra and observe the value immediately before the condition in x64dbg."
        elif indirect:
            static_question = "Which instruction sequence supplies the indirect control-transfer operand?"
            dynamic_question = "What address is held in the register or memory operand immediately before the transfer?"
            action = "Trace the operand definition in Ghidra and break at the indirect transfer in x64dbg."
        elif target.category == "input":
            static_question = "Where is the destination buffer used after the input call returns?"
            dynamic_question = "What bytes are read, and where are they stored at runtime?"
            action = "Inspect the caller in Ghidra and break at the input call to observe its arguments and result."
        else:
            static_question = "What local references and callers explain why this location matters?"
            dynamic_question = "Which runtime values or control-flow decisions remain unavailable statically?"
            action = target.recommended_action

        path.append(
            {
                "where": f"RVA 0x{target.rva:X} (preferred VA 0x{target.va:X})",
                "rva": target.rva,
                "category": target.category,
                "priority": target.priority,
                "why": target.reason,
                "static_question": static_question,
                "dynamic_question": dynamic_question,
                "recommended_action": action,
                "finding_ids": list(target.finding_ids),
            }
        )

    return path


def build_unresolved_questions(
    targets: Iterable[ReverseTarget],
    findings: Iterable[Finding] = (),
) -> list[dict[str, Any]]:
    findings_by_id = {finding.id: finding for finding in findings}
    questions = []
    seen: set[tuple[str, int]] = set()

    for target in targets:
        linked = _linked_findings(target, findings_by_id)
        categories = {target.category, *(finding.category for finding in linked)}

        if _import_only(linked):
            key = ("import-only", target.rva)
            if key not in seen:
                seen.add(key)
                questions.append(
                    {
                        "question": "Is this imported API reached by executable code?",
                        "why_unresolved": "An import table entry alone does not identify a call site or runtime purpose.",
                        "related_rva": target.rva,
                        "suggested_dynamic_observation": (
                            "Resolve static IAT references first, then observe a call only if one is found."
                        ),
                        "finding_ids": list(target.finding_ids),
                    }
                )
            continue

        if _is_indirect_target(target, linked):
            key = ("indirect-control-flow", target.rva)
            if key not in seen:
                seen.add(key)
                questions.append(
                    {
                        "question": "What address does the indirect control transfer resolve to at runtime?",
                        "why_unresolved": "The static instruction identifies an operand, not its runtime value.",
                        "related_rva": target.rva,
                        "suggested_dynamic_observation": (
                            "Break at the transfer and record the register or memory operand before it executes."
                        ),
                        "finding_ids": list(target.finding_ids),
                    }
                )

        templates = {
            "validation": (
                "What concrete values are compared at this validation candidate?",
                "The local return-value chain does not recover comparator arguments or runtime-generated buffers.",
                "Break before the comparator call and record each argument according to the target ABI.",
            ),
            "crypto": (
                "What are the input, output, key, and state buffers for this crypto candidate?",
                "Instruction and constant evidence does not establish runtime buffer roles.",
                "Observe candidate callers and compare relevant buffers before and after execution.",
            ),
            "anti-debug": (
                "What value does the anti-debug candidate produce at runtime?",
                "The static pattern cannot determine the environment-dependent API, PEB, or timing value.",
                "Record the value before its condition and note which branch executes.",
            ),
            "input": (
                "Which buffer receives input, and where does that data flow next?",
                "The call site alone does not establish the concrete source, destination contents, or later consumers.",
                "Observe call arguments, returned length or status, and the destination buffer after the call.",
            ),
        }
        for category in sorted(categories):
            template = templates.get(category)
            key = (category, target.rva)
            if template is None or key in seen:
                continue
            seen.add(key)
            questions.append(
                {
                    "question": template[0],
                    "why_unresolved": template[1],
                    "related_rva": target.rva,
                    "suggested_dynamic_observation": template[2],
                    "finding_ids": list(target.finding_ids),
                }
            )

    return questions
