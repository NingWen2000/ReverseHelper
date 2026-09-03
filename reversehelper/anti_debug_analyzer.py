"""Evidence-based anti-debug candidates from imports and local instruction flow."""

from __future__ import annotations

from typing import Any

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .disassembler import iter_instruction_details
from .findings import Finding, Instruction
from .instruction_context import (
    find_condition_branch,
    find_import_calls,
    follows,
    import_location,
    register_access,
    register_family,
    section_name,
)


ANTI_DEBUG_APIS = {
    "isdebuggerpresent": "IsDebuggerPresent",
    "checkremotedebuggerpresent": "CheckRemoteDebuggerPresent",
    "ntqueryinformationprocess": "NtQueryInformationProcess",
    "zwqueryinformationprocess": "ZwQueryInformationProcess",
    "ntsetinformationthread": "NtSetInformationThread",
    "outputdebugstringa": "OutputDebugStringA",
    "outputdebugstringw": "OutputDebugStringW",
    "queryperformancecounter": "QueryPerformanceCounter",
    "gettickcount": "GetTickCount",
}

def analyze_anti_debug(
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
            name = ANTI_DEBUG_APIS.get(str(imported.get("name", "")).lower())
            if name is None:
                continue
            iat_address = int(imported["iat_address"])
            rva, file_offset, section = import_location(iat_address, image_base, sections)
            findings.append(
                Finding(
                    id=f"anti-debug-api-{name.lower()}-{rva if rva is not None else 0:08x}",
                    category="anti-debug",
                    title=f"Anti-debug-related API import: {name}",
                    rva=rva,
                    va=iat_address,
                    file_offset=file_offset,
                    section=section,
                    severity="info",
                    confidence="low",
                    evidence=(f"Imported {dll}!{name}",),
                    reason="An import shows capability only; it does not prove the API is called for anti-debugging.",
                    recommended_action="Inspect references to the IAT slot and the arguments at each call site.",
                )
            )

    records = (
        list(instruction_details)
        if instruction_details is not None
        else list(iter_instruction_details(instructions, architecture))
    )
    peb_location = ("fs", 0x30) if architecture == "x86" else ("gs", 0x60)
    nt_global_flag_offset = 0x68 if architecture == "x86" else 0xBC
    record_index = {instruction.address: index for index, (instruction, _) in enumerate(records)}
    calls = (
        import_calls
        if import_calls is not None
        else find_import_calls(
            instructions,
            imports,
            architecture,
            image_base,
            records,
        )
    )

    for transfer, dll, imported in calls:
        name = ANTI_DEBUG_APIS.get(str(imported.get("name", "")).lower())
        if name is None:
            continue
        source_address = int(transfer["source_address"])
        index = record_index.get(source_address)
        if index is None:
            continue
        source = records[index][0]
        confidence = "medium" if name in {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
            "NtSetInformationThread",
        } else "low"
        findings.append(
            Finding(
                id=f"anti-debug-call-{name.lower()}-{source.rva:08x}",
                category="anti-debug",
                title=f"Call to anti-debug-related API: {name}",
                rva=source.rva,
                va=source.address,
                file_offset=source.file_offset,
                section=section_name(source.rva, sections),
                severity="low",
                confidence=confidence,
                evidence=(f"{source.mnemonic.upper()} {source.op_str}", f"Call resolves through {dll}!{name}"),
                reason="The API is reached by this call site, but its purpose still depends on arguments and surrounding logic.",
                recommended_action="Inspect call arguments and the code that consumes the API result.",
            )
        )

        if name != "IsDebuggerPresent":
            continue
        branch = find_condition_branch(records, index + 1, "a")
        if branch is None:
            continue
        condition_index, branch_index = branch
        condition = records[condition_index][0]
        jcc = records[branch_index][0]
        findings.append(
            Finding(
                id=f"anti-debug-branch-isdebuggerpresent-{source.rva:08x}",
                category="anti-debug",
                title="Possible anti-debug branch after IsDebuggerPresent",
                rva=source.rva,
                va=source.address,
                file_offset=source.file_offset,
                section=section_name(source.rva, sections),
                severity="medium",
                confidence="high",
                evidence=(
                    f"CALL {dll}!IsDebuggerPresent at RVA 0x{source.rva:X}",
                    f"{condition.mnemonic.upper()} {condition.op_str}",
                    f"{jcc.mnemonic.upper()} {jcc.op_str}",
                ),
                reason="The API return register reaches a condition, and its flags reach the conditional branch without being overwritten.",
                recommended_action="Inspect both branch targets and verify the runtime return value before the condition.",
            )
        )

    direct_targets = {
        int(decoded.operands[0].imm)
        for _, decoded in records
        if (decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_JUMP))
        and decoded.operands
        and decoded.operands[0].type == X86_OP_IMM
    }
    for index, (instruction, decoded) in enumerate(records):
        section = section_name(instruction.rva, sections)
        text = f"{instruction.mnemonic.upper()} {instruction.op_str}".rstrip()
        adjacent_int3 = any(
            0 <= neighbor < len(records)
            and follows(records[min(index, neighbor)][0], records[max(index, neighbor)][0])
            and records[neighbor][1].mnemonic == "int3"
            for neighbor in (index - 1, index + 1)
        )
        referenced_int3 = (
            index == 0
            or not follows(records[index - 1][0], instruction)
            or instruction.address in direct_targets
        )

        if decoded.mnemonic == "int3" and not adjacent_int3 and referenced_int3:
            findings.append(
                Finding(
                    id=f"anti-debug-int3-{instruction.rva:08x}",
                    category="anti-debug",
                    title="INT3 instruction candidate",
                    rva=instruction.rva,
                    va=instruction.address,
                    file_offset=instruction.file_offset,
                    section=section,
                    severity="low",
                    confidence="low",
                    evidence=(text,),
                    reason="INT3 may be an anti-debug trap, a deliberate breakpoint, or ordinary padding.",
                    recommended_action="Check whether normal control flow reaches this instruction.",
                )
            )
        elif decoded.mnemonic in {"int1", "icebp"} or instruction.raw_bytes == b"\xF1":
            findings.append(
                Finding(
                    id=f"anti-debug-icebp-{instruction.rva:08x}",
                    category="anti-debug",
                    title="ICEBP instruction candidate",
                    rva=instruction.rva,
                    va=instruction.address,
                    file_offset=instruction.file_offset,
                    section=section,
                    severity="low",
                    confidence="medium",
                    evidence=(text,),
                    reason="ICEBP can trigger debugger-specific exception behavior, but reachability is not known.",
                    recommended_action="Trace exception handling and confirm whether this instruction executes.",
                )
            )
        elif decoded.mnemonic == "rdtsc":
            findings.append(
                Finding(
                    id=f"anti-debug-rdtsc-{instruction.rva:08x}",
                    category="anti-debug",
                    title="RDTSC timing candidate",
                    rva=instruction.rva,
                    va=instruction.address,
                    file_offset=instruction.file_offset,
                    section=section,
                    severity="info",
                    confidence="low",
                    evidence=(text,),
                    reason="RDTSC provides timing data, but a single read does not establish a timing check.",
                    recommended_action="Look for a second timestamp read and a comparison of the elapsed value.",
                )
            )

        peb_register = None
        for operand in decoded.operands:
            if operand.type != X86_OP_MEM:
                continue
            segment = decoded.reg_name(operand.mem.segment)
            if (segment, int(operand.mem.disp)) != peb_location:
                continue
            if decoded.operands and decoded.operands[0].type == X86_OP_REG:
                peb_register = register_family(decoded.reg_name(decoded.operands[0].reg))
            findings.append(
                Finding(
                    id=f"anti-debug-peb-access-{instruction.rva:08x}",
                    category="anti-debug",
                    title="Possible PEB access",
                    rva=instruction.rva,
                    va=instruction.address,
                    file_offset=instruction.file_offset,
                    section=section,
                    severity="info",
                    confidence="low",
                    evidence=(text,),
                    reason=f"The instruction accesses {segment}:[0x{operand.mem.disp:X}], a common PEB location, but the use is not yet known.",
                    recommended_action="Track the loaded PEB pointer and inspect which fields are read from it.",
                )
            )
            break

        if peb_register is None:
            continue

        for field_index in range(index + 1, len(records)):
            if not follows(records[field_index - 1][0], records[field_index][0]):
                break
            field_instruction, field_decoded = records[field_index]
            if field_decoded.group(CS_GRP_CALL) or field_decoded.group(CS_GRP_JUMP) or field_decoded.group(CS_GRP_RET):
                break

            field_name = None
            for operand in field_decoded.operands:
                if operand.type != X86_OP_MEM:
                    continue
                base = register_family(field_decoded.reg_name(operand.mem.base))
                displacement = int(operand.mem.disp)
                if base == peb_register and displacement == 2:
                    field_name = "BeingDebugged"
                    break
                if base == peb_register and displacement == nt_global_flag_offset:
                    field_name = "NtGlobalFlag"
                    break

            _, field_writes = register_access(field_decoded)
            if field_name is None:
                if peb_register in field_writes:
                    break
                continue

            field_text = f"{field_instruction.mnemonic.upper()} {field_instruction.op_str}".rstrip()
            findings.append(
                Finding(
                    id=f"anti-debug-{field_name.lower()}-{field_instruction.rva:08x}",
                    category="anti-debug",
                    title=f"Possible PEB {field_name} access",
                    rva=field_instruction.rva,
                    va=field_instruction.address,
                    file_offset=field_instruction.file_offset,
                    section=section_name(field_instruction.rva, sections),
                    severity="low",
                    confidence="medium",
                    evidence=(text, field_text),
                    reason=f"A PEB pointer is followed by a read at a documented {field_name} candidate offset.",
                    recommended_action=f"Verify the loaded {field_name} value and all code paths that consume it.",
                )
            )

            branch = None
            if field_decoded.mnemonic in {"test", "cmp"}:
                for branch_index in range(field_index + 1, len(records)):
                    if not follows(records[branch_index - 1][0], records[branch_index][0]):
                        break
                    _, candidate = records[branch_index]
                    candidate_reads, candidate_writes = register_access(candidate)
                    if candidate.group(CS_GRP_JUMP):
                        if candidate.mnemonic != "jmp" and "flags" in candidate_reads:
                            branch = (field_index, branch_index)
                        break
                    if candidate.group(CS_GRP_CALL) or candidate.group(CS_GRP_RET) or "flags" in candidate_writes:
                        break
            elif field_decoded.operands and field_decoded.operands[0].type == X86_OP_REG:
                value_register = register_family(field_decoded.reg_name(field_decoded.operands[0].reg))
                branch = find_condition_branch(records, field_index + 1, value_register)

            if branch is not None:
                condition_index, branch_index = branch
                condition = records[condition_index][0]
                jcc = records[branch_index][0]
                findings.append(
                    Finding(
                        id=f"anti-debug-branch-{field_name.lower()}-{field_instruction.rva:08x}",
                        category="anti-debug",
                        title=f"Possible anti-debug branch using PEB {field_name}",
                        rva=field_instruction.rva,
                        va=field_instruction.address,
                        file_offset=field_instruction.file_offset,
                        section=section_name(field_instruction.rva, sections),
                        severity="medium",
                        confidence="high",
                        evidence=(text, field_text, f"{condition.mnemonic.upper()} {condition.op_str}", f"{jcc.mnemonic.upper()} {jcc.op_str}"),
                        reason=f"The {field_name} candidate reaches a condition whose flags directly control a branch.",
                        recommended_action="Inspect both branch targets and confirm the field value in a debugger.",
                    )
                )
            break

    return findings
