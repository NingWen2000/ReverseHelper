"""Comparator and input call-site candidates."""

from __future__ import annotations

from typing import Any

from capstone import CS_GRP_CALL
from capstone.x86 import X86_OP_IMM

from .disassembler import iter_instruction_details
from .findings import Finding, Instruction
from .instruction_context import (
    find_condition_branch,
    find_import_calls,
    follows,
    import_location,
    section_name,
)


COMPARATOR_APIS = {
    "strcmp": "strcmp",
    "strncmp": "strncmp",
    "memcmp": "memcmp",
    "wcscmp": "wcscmp",
    "lstrcmpa": "lstrcmpA",
    "lstrcmpw": "lstrcmpW",
    "comparestringa": "CompareStringA",
    "comparestringw": "CompareStringW",
}

INPUT_APIS = {
    "scanf": "scanf",
    "fscanf": "fscanf",
    "sscanf": "sscanf",
    "gets": "gets",
    "fgets": "fgets",
    "readfile": "ReadFile",
    "readconsolea": "ReadConsoleA",
    "readconsolew": "ReadConsoleW",
    "getdlgitemtexta": "GetDlgItemTextA",
    "getdlgitemtextw": "GetDlgItemTextW",
    "getwindowtexta": "GetWindowTextA",
    "getwindowtextw": "GetWindowTextW",
}


def _call_arguments_action(architecture: str, noun: str) -> str:
    if architecture == "x86-64":
        return (
            f"Inspect {noun} arguments in RCX, RDX, R8, and R9 as applicable before the call, "
            "then follow the surrounding code."
        )
    return f"Inspect the caller's {noun} argument setup before the call and follow the surrounding code."


def _looks_like_pe_structure_comparison(
    records: list[tuple[Instruction, Any]],
    call_index: int,
) -> bool:
    function_entries = {
        int(decoded.operands[0].imm)
        for _, decoded in records
        if decoded.group(CS_GRP_CALL)
        and decoded.operands
        and decoded.operands[0].type == X86_OP_IMM
    }
    signatures = set()
    for index in range(call_index - 1, -1, -1):
        instruction, decoded = records[index]
        if not follows(instruction, records[index + 1][0]):
            break
        for operand in decoded.operands:
            if operand.type == X86_OP_IMM and int(operand.imm) in {0x5A4D, 0x4550}:
                signatures.add(int(operand.imm))
        if len(signatures) == 2:
            return True
        if instruction.address in function_entries:
            break
    return False


def analyze_validation(
    instructions: list[Instruction],
    imports: list[dict[str, Any]],
    sections: list[dict[str, Any]],
    architecture: str,
    image_base: int,
    *,
    instruction_details: list[tuple[Instruction, Any]] | None = None,
    import_calls: list[tuple[dict[str, Any], str, dict[str, Any]]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    for library in imports:
        dll = str(library.get("dll", "<unknown>"))
        for imported in library.get("functions", []):
            name = COMPARATOR_APIS.get(str(imported.get("name", "")).lower())
            if name is None:
                continue
            iat_address = int(imported["iat_address"])
            rva, file_offset, section = import_location(iat_address, image_base, sections)
            findings.append(
                Finding(
                    id=f"validation-import-{name.lower()}-{rva if rva is not None else 0:08x}",
                    category="validation",
                    title=f"Imported Comparator API: {name}",
                    rva=rva,
                    va=iat_address,
                    file_offset=file_offset,
                    section=section,
                    severity="info",
                    confidence="low",
                    evidence=(f"Imported {dll}!{name}",),
                    reason="A comparator import does not show whether it participates in input validation.",
                    recommended_action="Inspect references to the IAT slot and the arguments at each call site.",
                )
            )

    records = (
        list(instruction_details)
        if instruction_details is not None
        else list(iter_instruction_details(instructions, architecture))
    )
    record_index = {instruction.address: index for index, (instruction, _) in enumerate(records)}
    calls = (
        import_calls
        if import_calls is not None
        else find_import_calls(instructions, imports, architecture, image_base, records)
    )
    for transfer, dll, imported in calls:
        name = COMPARATOR_APIS.get(str(imported.get("name", "")).lower())
        if name is None:
            continue
        index = record_index.get(int(transfer["source_address"]))
        if index is None:
            continue
        call = records[index][0]
        findings.append(
            Finding(
                id=f"validation-call-{name.lower()}-{call.rva:08x}",
                category="validation",
                title=f"Comparator Call Site: {name}",
                rva=call.rva,
                va=call.address,
                file_offset=call.file_offset,
                section=section_name(call.rva, sections),
                severity="info",
                confidence="medium",
                evidence=(
                    f"{call.mnemonic.upper()} {call.op_str}",
                    f"Call resolves through {dll}!{name}",
                ),
                reason="The comparator is called here, but use of its return value has not yet been established.",
                recommended_action=_call_arguments_action(architecture, "comparator"),
            )
        )

        branch = find_condition_branch(records, index + 1, "a")
        if branch is None:
            continue
        condition_index, branch_index = branch
        condition = records[condition_index][0]
        jcc = records[branch_index][0]
        pe_structure_context = _looks_like_pe_structure_comparison(records, index)
        if architecture == "x86-64":
            action = (
                "Inspect comparator arguments in RCX, RDX, R8, and R9 as applicable before the call, "
                "then follow both branch targets."
            )
        else:
            action = "Inspect comparator arguments before the call and follow both branch targets."
        findings.append(
            Finding(
                id=f"validation-branch-{name.lower()}-{call.rva:08x}",
                category="validation",
                title=(
                    "PE Structure Comparator Branch Candidate"
                    if pe_structure_context
                    else "Possible Validation Site"
                ),
                rva=call.rva,
                va=call.address,
                file_offset=call.file_offset,
                section=section_name(call.rva, sections),
                severity="low",
                confidence="medium" if pe_structure_context else "high",
                evidence=(
                    f"Comparator: {dll}!{name}",
                    f"Call RVA: 0x{call.rva:X}",
                    f"Condition: {condition.mnemonic.upper()} {condition.op_str}",
                    f"Branch: {jcc.mnemonic.upper()} {jcc.op_str}",
                ),
                reason=(
                    "The comparator result controls a branch, but nearby MZ and PE signature checks "
                    "suggest this site is processing PE structures rather than user input."
                    if pe_structure_context
                    else "The comparator return register reaches a condition, and the resulting flags reach "
                    "a conditional branch without an intervening overwrite."
                ),
                recommended_action=action,
            )
        )

    return findings


def find_input_candidates(
    instructions: list[Instruction],
    imports: list[dict[str, Any]],
    sections: list[dict[str, Any]],
    architecture: str,
    image_base: int,
    *,
    instruction_details: list[tuple[Instruction, Any]] | None = None,
    import_calls: list[tuple[dict[str, Any], str, dict[str, Any]]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    for library in imports:
        dll = str(library.get("dll", "<unknown>"))
        for imported in library.get("functions", []):
            name = INPUT_APIS.get(str(imported.get("name", "")).lower())
            if name is None:
                continue
            iat_address = int(imported["iat_address"])
            rva, file_offset, section = import_location(iat_address, image_base, sections)
            findings.append(
                Finding(
                    id=f"input-import-{name.lower()}-{rva if rva is not None else 0:08x}",
                    category="input",
                    title=f"Imported Input API: {name}",
                    rva=rva,
                    va=iat_address,
                    file_offset=file_offset,
                    section=section,
                    severity="info",
                    confidence="low",
                    evidence=(f"Imported {dll}!{name}",),
                    reason="The import shows input capability, but no call site or input buffer is established.",
                    recommended_action="Inspect references to the IAT slot and the arguments at each call site.",
                )
            )

    records = (
        list(instruction_details)
        if instruction_details is not None
        else list(iter_instruction_details(instructions, architecture))
    )
    record_index = {instruction.address: index for index, (instruction, _) in enumerate(records)}
    calls = (
        import_calls
        if import_calls is not None
        else find_import_calls(instructions, imports, architecture, image_base, records)
    )
    for transfer, dll, imported in calls:
        name = INPUT_APIS.get(str(imported.get("name", "")).lower())
        if name is None:
            continue
        index = record_index.get(int(transfer["source_address"]))
        if index is None:
            continue
        call = records[index][0]
        findings.append(
            Finding(
                id=f"input-call-{name.lower()}-{call.rva:08x}",
                category="input",
                title=f"Input Candidate: {name} call site",
                rva=call.rva,
                va=call.address,
                file_offset=call.file_offset,
                section=section_name(call.rva, sections),
                severity="info",
                confidence="medium",
                evidence=(
                    f"{call.mnemonic.upper()} {call.op_str}",
                    f"Call resolves through {dll}!{name}",
                    f"Actual input-related API call site at RVA 0x{call.rva:X}",
                ),
                reason=(
                    "This call reaches an input-related API; the source, destination buffer, and any later "
                    "validation relationship remain unresolved."
                ),
                recommended_action=_call_arguments_action(architecture, "input"),
            )
        )

    return findings
