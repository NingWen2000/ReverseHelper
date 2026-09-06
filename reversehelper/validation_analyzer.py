"""Comparator and input call-site candidates."""

from __future__ import annotations

from typing import Any

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .disassembler import iter_instruction_details
from .findings import CompareSite, DecisionSite, Finding, Instruction, ValidationCandidate
from .function_index import direct_address
from .instruction_context import (
    find_condition_branch,
    find_import_calls,
    follows,
    import_location,
    section_name,
    register_access,
    register_family,
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


def split_compare_decision_sites(candidates):
    """Expose the compare → decision layers without upgrading them to validation."""
    compare_sites = []
    decision_sites = []
    for candidate in candidates:
        operands = []
        if candidate.input_source is not None:
            operands.append({"role": "input", "value": candidate.input_source})
        if candidate.compare_target is not None:
            operands.append({"role": "target", "value": candidate.compare_target})
        compare_id = f"compare-{candidate.id}"
        compare_sites.append(CompareSite(
            compare_id, candidate.function, candidate.function_rva, candidate.address, candidate.rva,
            candidate.validation_type, tuple(operands), candidate.compare_length,
            candidate.confidence, candidate.evidence, candidate.runtime_noise,
            candidate.compare_origin, candidate.comparator_function, candidate.thunk_chain,
        ))
        if candidate.decision_type is None and candidate.branch_rva is None:
            continue
        decision_rva = candidate.branch_rva if candidate.branch_rva is not None else candidate.rva
        decision_address = candidate.address + (decision_rva - candidate.rva)
        decision_sites.append(DecisionSite(
            f"decision-{candidate.id}", compare_id, candidate.function, candidate.function_rva,
            decision_address, decision_rva, candidate.decision_type or "CONDITIONAL_BRANCH",
            candidate.branch_polarity, candidate.success_branch, candidate.failure_branch,
            candidate.confidence, candidate.evidence,
        ))
    return compare_sites, decision_sites

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
    "__isoc99_scanf": "scanf",
    "scanf_s": "scanf_s",
    "gets_s": "gets_s",
    "getcommandlinea": "GetCommandLineA",
    "getcommandlinew": "GetCommandLineW",
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


# P0 discovery uses these local observations as candidates, not recovered data flow.
CHECKSUM_APIS = {"crc32", "adler32", "rtlcomputecrc32"}
HASH_OUTPUT_APIS = {"bcryptfinishhash", "cryptgethashparam"}
LENGTH_APIS = {"strlen", "wcslen", "lstrlenA".lower(), "lstrlenW".lower()}


def _register_constant(records, end, family):
    for i in range(end - 1, max(-1, end - 25), -1):
        ins, dec = records[i]
        if i + 1 < len(records) and not follows(ins, records[i + 1][0]):
            return None
        if dec.group(CS_GRP_CALL) or dec.group(CS_GRP_JUMP) or dec.group(CS_GRP_RET):
            return None
        _, writes = register_access(dec)
        if family not in writes:
            continue
        if len(dec.operands) < 2 or dec.operands[0].type != X86_OP_REG:
            return None
        dest, source = dec.operands[:2]
        if register_family(dec.reg_name(dest.reg)) != family:
            return None
        if dec.mnemonic in {"mov", "movabs"} and source.type == X86_OP_REG:
            family = register_family(dec.reg_name(source.reg))
            continue
        if dec.mnemonic in {"mov", "movabs"} and source.type == X86_OP_IMM:
            # Partial-register writes do not establish pointer arguments.
            return int(source.imm) if dest.size >= 4 else None
        if dec.mnemonic == "lea" and source.type == X86_OP_MEM:
            return direct_address(dec, source)
        return None
    return None


def _arguments(records, call_index, architecture, count):
    if architecture == "x86-64":
        return [_register_constant(records, call_index, family) for family in ("c", "d", "r8", "r9")[:count]]
    values = []
    for i in range(call_index - 1, max(-1, call_index - 25), -1):
        ins, dec = records[i]
        if not follows(ins, records[i + 1][0]) or dec.group(CS_GRP_CALL) or dec.group(CS_GRP_JUMP) or dec.group(CS_GRP_RET):
            break
        if dec.mnemonic == "push" and dec.operands:
            operand = dec.operands[0]
            values.append(int(operand.imm) if operand.type == X86_OP_IMM else
                          _register_constant(records, i, register_family(dec.reg_name(operand.reg)))
                          if operand.type == X86_OP_REG else None)
            if len(values) == count:
                break
        elif "sp" in register_access(dec)[1]:
            break
    return values + [None] * (count - len(values))


def _trace_successor(context, start, function, limit=32):
    """One bounded straight-line path with direct jumps; stops at another decision."""
    visited = set()
    rva = start
    while len(visited) < limit and rva not in visited and context.owner(rva) is function:
        pair = context.by_rva.get(rva)
        if pair is None:
            break
        ins, dec = pair
        visited.add(rva)
        if dec.group(CS_GRP_RET):
            break
        if dec.group(CS_GRP_JUMP):
            if dec.mnemonic != "jmp" or not dec.operands or dec.operands[0].type != X86_OP_IMM:
                break
            rva = int(dec.operands[0].imm) - context.image_base
            continue
        following = context.by_rva.get(rva + ins.size)
        if not following or not follows(ins, following[0]):
            break
        rva += ins.size
    return visited


def _outcome_branches(context, branch_rva, strings_by_xref):
    fn = context.owner(branch_rva)
    if fn is None:
        return None, None
    ins, dec = context.by_rva[branch_rva]
    if not dec.operands or dec.operands[0].type != X86_OP_IMM:
        return None, None
    successors = (int(dec.operands[0].imm) - context.image_base, ins.rva + ins.size)
    paths = [_trace_successor(context, start, fn) for start in successors]
    # Strings in a shared suffix do not distinguish the branch arms.
    shared = paths[0] & paths[1]
    output = {}
    for start, path in zip(successors, paths):
        related = {item["id"]: item for rva in path - shared for item in strings_by_xref.get(rva, []) if item.get("outcome")}
        outcomes = {item["outcome"] for item in related.values()}
        if len(outcomes) == 1:
            outcome = next(iter(outcomes))
            record = {"branch_rva": branch_rva, "successor_rva": start, "string_ids": sorted(related),
                      "basis": "Exclusive successor path references outcome-related text; actual outcome remains a candidate"}
            output.setdefault(outcome, []).append(record)
    return tuple(output[key][0] if len(output.get(key, [])) == 1 else None for key in ("SUCCESS", "FAILURE"))


def _branch_after_compare(records, index):
    for j in range(index + 1, min(len(records), index + 9)):
        ins, dec = records[j]
        if not follows(records[j - 1][0], ins):
            break
        reads, writes = register_access(dec)
        if dec.group(CS_GRP_JUMP):
            return j if dec.mnemonic != "jmp" and "flags" in reads else None
        if "flags" in writes or dec.group(CS_GRP_CALL) or dec.group(CS_GRP_RET):
            break
    return None


def _branch_polarity(mnemonic):
    name = mnemonic.casefold()
    if name in {"je", "jz", "sete", "setz", "cmove", "cmovz"}:
        return "zero/equal condition selects the taken or assigned outcome"
    if name in {"jne", "jnz", "setne", "setnz", "cmovne", "cmovnz"}:
        return "nonzero/not-equal condition selects the taken or assigned outcome"
    if name.startswith(("j", "set", "cmov")):
        return f"{name} condition controls the selected outcome; semantic polarity is not normalized"
    return None


def _result_decision(records, index, register="a"):
    """Find a bounded branch, SETcc, or CMOVcc consuming a compare result."""
    condition_seen = False
    for j in range(index + 1, min(len(records), index + 13)):
        ins, dec = records[j]
        if not follows(records[j - 1][0], ins):
            break
        reads, writes = register_access(dec)
        if not condition_seen:
            if dec.mnemonic in {"test", "cmp"} and register in reads:
                condition_seen = True
                continue
            if dec.mnemonic in {"mov", "movzx", "movsx"} and register in reads and register in writes:
                continue
            if dec.group(CS_GRP_CALL) or dec.group(CS_GRP_JUMP) or dec.group(CS_GRP_RET) or register in writes:
                break
            continue
        if dec.group(CS_GRP_JUMP):
            return (j, "conditional_branch", _branch_polarity(dec.mnemonic)) if dec.mnemonic != "jmp" else None
        if dec.mnemonic.startswith("set"):
            return j, "setcc", _branch_polarity(dec.mnemonic)
        if dec.mnemonic.startswith("cmov"):
            return j, "cmovcc", _branch_polarity(dec.mnemonic)
        if "flags" in writes or dec.group(CS_GRP_CALL) or dec.group(CS_GRP_RET):
            break
    return None


def _byte_load(records, index, operand, *, allow_wide=False):
    if operand.type == X86_OP_MEM:
        return operand if operand.size == 1 else None
    if operand.type != X86_OP_REG:
        return None
    family = register_family(records[index][1].reg_name(operand.reg))
    for i in range(index - 1, max(-1, index - 9), -1):
        ins, dec = records[i]
        if not follows(ins, records[i + 1][0]) or dec.group(CS_GRP_CALL) or dec.group(CS_GRP_JUMP):
            break
        if family in register_access(dec)[1]:
            if dec.mnemonic in {"mov", "movzx", "movsx"} and len(dec.operands) == 2:
                source = dec.operands[1]
                if source.type == X86_OP_MEM and (source.size == 1 or allow_wide):
                    return source
            break
    return None


def discover_validation(context, import_calls, interesting_strings, architecture, data=b"", *, input_sources=(),
                        limited_static_visibility=False, function_summaries=()):
    """Conservative comparison candidates with explicit unknown arguments/outcomes."""
    calls = {int(transfer["source_rva"]): str(imported["name"]).lower() for transfer, _, imported in import_calls}
    by_function = {}
    for rva, name in calls.items():
        fn = context.owner(rva)
        if fn:
            by_function.setdefault(fn.rva, []).append((rva, name))
    strings_by_xref = {}
    for item in interesting_strings:
        for xref in item["xrefs"]:
            strings_by_xref.setdefault(xref["rva"], []).append(item)
    candidates = []

    def runtime_function(fn):
        if fn is None or fn.source != "COFF symbol table":
            return False
        name = fn.name.casefold().lstrip("_")
        prefixes = ("mingw", "pei386", "gnu_exception", "register_frame", "deregister_frame",
                    "fpreset", "alloca", "chkstk", "security_check", "tls", "crt")
        exact = {"strlen", "memcmp", "strcmp", "strncmp", "wcscmp", "maincrtstartup", "winmaincrtstartup"}
        return name.startswith(prefixes) or name in exact

    sources_by_function = {}
    for source in input_sources:
        if source.function_rva is not None:
            sources_by_function.setdefault(source.function_rva, []).append(source)

    def create(rva, kind, branch_rva=None, loop=False, target=None, length=None, extra=(), decision_type=None,
               branch_polarity=None, compare_origin=None, comparator_function=None, thunk_chain=(),
               reported_function_rva=None):
        ins, _ = context.by_rva[rva]
        owner = context.owner(rva)
        fn = (next((item for item in context.functions if item.rva == reported_function_rva), None)
              if reported_function_rva is not None else owner)
        same_calls = by_function.get(owner.rva, []) if owner else []
        inputs = [(r, name) for r, name in same_calls if r < rva and name in INPUT_APIS]
        input_source = None
        if inputs:
            input_rva, api = max(inputs)
            input_source = {"api": api, "call_rva": input_rva, "relation": "earlier address in same function; buffer linkage unproven"}
        structured_inputs = [source for source in sources_by_function.get(owner.rva if owner else None, ())
                             if source.callsite_rva <= rva]
        if structured_inputs:
            source = max(structured_inputs, key=lambda item: item.callsite_rva)
            input_source = {"api": source.source_type, "call_rva": source.callsite_rva,
                            "input_source_id": source.id,
                            "relation": "structured input source in same function; exact buffer linkage pending flow analysis"}
        length_check = None
        for length_rva, api in same_calls:
            if api not in LENGTH_APIS or not 0 < rva - length_rva <= 256:
                continue
            records = context.local_records(length_rva, after=16)
            if not records:
                continue
            pair = find_condition_branch(records, 1, "a")
            if pair:
                condition, branch = records[pair[0]], records[pair[1]]
                immediates = [int(op.imm) for op in condition[1].operands if op.type == X86_OP_IMM]
                if immediates and condition[1].mnemonic == "cmp":
                    length_check = {"api": api, "call_rva": length_rva, "branch_rva": branch[0].rva,
                                    "length": immediates[0], "relation": "same-function length check; same buffer unproven"}
        success, failure = _outcome_branches(context, branch_rva, strings_by_xref) if branch_rva is not None else (None, None)
        evidence = [f"{kind} at RVA 0x{rva:X}", *extra]
        if branch_rva is not None:
            evidence.append(f"Comparison flags reach conditional branch at RVA 0x{branch_rva:X}")
        if input_source:
            evidence.append(f"Same function contains input API {input_source['api']} at RVA 0x{input_source['call_rva']:X}; input buffer linkage unproven")
        if length_check:
            evidence.append(f"Nearby {length_check['api']} result checked against {length_check['length']}; same buffer unproven")
        if success or failure:
            evidence.append("Bounded branch successors reference outcome-related text; this is not proof of flag validation")
        comparison_cluster = sum(name in COMPARATOR_APIS or name in CHECKSUM_APIS for _, name in same_calls) >= 2
        if comparison_cluster:
            evidence.append("Multiple comparator/checksum calls occur in the same bounded function")
        hash_context = kind in COMPARATOR_APIS and any(
            name in HASH_OUTPUT_APIS and 0 < rva - call_rva <= 256 for call_rva, name in same_calls)
        if hash_context:
            kind = "HASH_COMPARISON_CANDIDATE"
            evidence.append("Hash output API in same function; compared buffer linkage unproven")
        elif length_check:
            kind = "LENGTH_AND_COMPARISON"
        confidence = "medium" if branch_rva is not None else "low"
        if input_source and success and failure:
            confidence = "high"
        if fn and fn.confidence == "low" and confidence == "high":
            confidence = "medium"
            evidence.append("Heuristic-only function boundary caps validation confidence at MEDIUM")
        noise = runtime_function(fn)
        strong_byte_loop = bool(loop and kind == "BYTE_COMPARE_LOOP")
        actionable = bool((branch_rva is not None or decision_type) and (
            strong_byte_loop or sum((bool(input_source), bool(success or failure), bool(target),
                                     comparison_cluster, bool(hash_context and comparison_cluster))) >= 2))
        if noise:
            actionable = False
            confidence = "low"
            evidence.append("Compiler/CRT symbol context; retained as non-actionable comparison evidence")
        if limited_static_visibility:
            actionable = False
            confidence = "low"
            evidence.append("Packed/obfuscated surface: validation role is deferred until post-unpack re-analysis")
        unknown = []
        for field, value in (("input_source", input_source), ("compare_target", target),
                             ("compare_length", length), ("success_branch", success),
                             ("failure_branch", failure)):
            if value is None:
                unknown.append(field)
        candidates.append(ValidationCandidate(f"V-{rva:08X}", fn.name if fn else None, fn.rva if fn else None,
            ins.address, rva, kind.upper(), input_source, target, length, success, failure,
            confidence if fn else "low", tuple(evidence), branch_rva, loop, length_check,
            not actionable, "NONE", decision_type or ("conditional_branch" if branch_rva is not None else None),
            branch_polarity, noise, tuple(unknown), compare_origin, comparator_function, tuple(thunk_chain)))

    comparator_decision_cache = {}

    def comparator_caller_decision(fn):
        if fn.rva in comparator_decision_cache:
            return comparator_decision_cache[fn.rva]
        targets = {fn.rva: ()}
        for possible in context.functions:
            if possible.is_thunk and possible.thunk_target_rva == fn.rva:
                targets[possible.rva] = (possible.rva,)
        for caller_rva, target_rva in context.calls:
            if target_rva not in targets:
                continue
            caller_records = context.local_records(caller_rva, before=0, after=16)
            caller_index = next((i for i, (item, _) in enumerate(caller_records) if item.rva == caller_rva), None)
            decision = _result_decision(caller_records, caller_index, "a") if caller_index is not None else None
            if decision:
                branch_rva = (caller_records[decision[0]][0].rva
                              if decision[1] == "conditional_branch" else None)
                result = branch_rva, "return_value_" + decision[1], decision[2], targets[target_rva]
                comparator_decision_cache[fn.rva] = result
                return result
        comparator_decision_cache[fn.rva] = None
        return None

    comparator_shape_cache = {}

    def comparator_return_shape(records):
        cache_key = records[0][0].rva if records else -1
        if cache_key in comparator_shape_cache:
            return comparator_shape_cache[cache_key]
        zero_return = False
        nonzero_return = False
        for index, (_, decoded) in enumerate(records):
            if not decoded.group(CS_GRP_RET):
                continue
            for _, prior in records[max(0, index - 3):index]:
                if (prior.mnemonic == "xor" and len(prior.operands) == 2
                        and all(op.type == X86_OP_REG and register_family(prior.reg_name(op.reg)) == "a"
                                for op in prior.operands)):
                    zero_return = True
                if (prior.mnemonic in {"or", "mov", "sbb"} and any(
                        op.type == X86_OP_IMM and int(op.imm) != 0 for op in prior.operands)):
                    nonzero_return = True
        result = zero_return and nonzero_return
        comparator_shape_cache[cache_key] = result
        return result

    for rva, name in sorted(calls.items()):
        if name not in COMPARATOR_APIS and name not in CHECKSUM_APIS:
            continue
        records = context.local_records(rva, before=24, after=24)
        index = next(i for i, (ins, _) in enumerate(records) if ins.rva == rva)
        decision = _result_decision(records, index, "a")
        branch_rva = records[decision[0]][0].rva if decision and decision[1] == "conditional_branch" else None
        decision_type = decision[1] if decision else None
        polarity = decision[2] if decision else None
        propagated_from = None
        if decision is None and context.owner(rva) is not None:
            callee = context.owner(rva)
            for caller_rva, target_rva in context.calls:
                if target_rva != callee.rva:
                    continue
                caller_records = context.local_records(caller_rva, before=0, after=16)
                caller_index = next((i for i, (item, _) in enumerate(caller_records) if item.rva == caller_rva), None)
                caller_decision = _result_decision(caller_records, caller_index, "a") if caller_index is not None else None
                if caller_decision:
                    decision = caller_decision
                    decision_type = "return_value_" + caller_decision[1]
                    polarity = caller_decision[2]
                    branch_rva = (caller_records[caller_decision[0]][0].rva
                                  if caller_decision[1] == "conditional_branch" else None)
                    propagated_from = caller_rva
                    break
        target = None
        length = None
        extra = []
        if name in COMPARATOR_APIS:
            args = _arguments(records, index, architecture, 3 if name in {"memcmp", "strncmp"} else 2)
            if name in {"memcmp", "strncmp"}:
                length = args[2] if args[2] is not None and 0 <= args[2] <= 0x100000 else None
            if args[1] is not None:
                target_rva, offset, section = import_location(args[1], context.image_base, context.sections)
                if offset is not None and 0 <= offset < len(data):
                    target = {"address": args[1], "rva": target_rva, "file_offset": offset,
                              "basis": "Constant second comparator argument; operand role unproven",
                              "bytes_hex": data[offset:offset + min(length if length is not None else 16, 32)].hex(" ")}
        elif decision:
            for _, condition in records[index + 1:index + 8]:
                immediates = [int(op.imm) for op in condition.operands if op.type == X86_OP_IMM]
                if condition.mnemonic == "cmp" and immediates:
                    target = {"value": immediates[0], "basis": "Scalar checksum return compared with immediate"}
                    break
        if name in CHECKSUM_APIS and target is None:
            continue
        if _looks_like_pe_structure_comparison(records, index):
            extra.append("PE structure context: nearby MZ and PE signatures; likely non-user comparison")
        if propagated_from is not None:
            extra.append(f"Comparator return value is consumed by caller at RVA 0x{propagated_from:X}")
        create(rva, name if name in COMPARATOR_APIS else "CHECKSUM_COMPARISON", branch_rva,
               target=target, length=length, extra=extra, decision_type=decision_type,
               branch_polarity=polarity)

    # Byte/custom compare loops require a back edge, byte operands, iterator progress
    # and a conditional comparison. A NUL terminator scan alone is not validation.
    seen_compares = set()
    for fn in context.functions:
        records = context.function_records[fn.rva]
        positions = {ins.rva: i for i, (ins, _) in enumerate(records)}
        for end, (back_ins, back) in enumerate(records):
            bounded_loop = back.group(CS_GRP_JUMP) or back.mnemonic.startswith("loop")
            if not bounded_loop or not back.operands or back.operands[0].type != X86_OP_IMM:
                continue
            start = positions.get(int(back.operands[0].imm) - context.image_base)
            if start is None or not 0 < end - start <= 64:
                continue
            body = records[start:end + 1]
            if any(not follows(body[i - 1][0], body[i][0]) for i in range(1, len(body))):
                continue
            if any(dec.group(CS_GRP_CALL) for _, dec in body):
                continue
            caller_decision = comparator_caller_decision(fn) if comparator_return_shape(records) else None
            progress = set()
            for _, dec in body:
                if dec.mnemonic in {"inc", "dec"} or (dec.mnemonic in {"add", "sub"}
                        and len(dec.operands) == 2 and dec.operands[1].type == X86_OP_IMM and dec.operands[1].imm != 0):
                    progress.update(register_access(dec)[1])
            for i in range(start, end):
                ins, dec = records[i]
                if dec.mnemonic != "cmp" or len(dec.operands) != 2 or ins.rva in seen_compares:
                    continue
                left, right = dec.operands
                memory = [_byte_load(records, i, operand, allow_wide=bool(caller_decision))
                          for operand in (left, right)]
                loaded = [operand for operand in memory if operand is not None]
                immediate = [int(op.imm) for op in (left, right) if op.type == X86_OP_IMM]
                if not loaded or (len(loaded) < 2 and (not immediate or immediate[0] == 0)):
                    continue
                if len(loaded) == 2:
                    addresses = [(op.mem.segment, op.mem.base, op.mem.index, op.mem.scale, op.mem.disp) for op in loaded]
                    if addresses[0] == addresses[1]:
                        continue
                address_regs = {register_family(dec.reg_name(reg)) for op in loaded for reg in (op.mem.base, op.mem.index) if reg}
                if not progress & address_regs:
                    continue
                branch = _branch_after_compare(records, i)
                if branch is None:
                    continue
                seen_compares.add(ins.rva)
                decision_rva = caller_decision[0] if caller_decision else records[branch][0].rva
                decision_type = caller_decision[1] if caller_decision else "conditional_branch"
                polarity = caller_decision[2] if caller_decision else _branch_polarity(records[branch][1].mnemonic)
                create(ins.rva, "STATIC_LINKED_COMPARATOR" if caller_decision else
                       "BYTE_COMPARE_LOOP" if len(loaded) == 2 else "CUSTOM_COMPARE_LOOP",
                       decision_rva, True,
                       extra=(f"Byte comparison with iterator progress and back edge RVA 0x{back_ins.rva:X}",
                              *(("Comparator return value controls a caller decision",) if caller_decision else ())),
                       decision_type=decision_type, branch_polarity=polarity,
                       compare_origin="STATIC_LINKED_COMPARATOR" if caller_decision else None,
                       comparator_function=fn.rva if caller_decision else None,
                       thunk_chain=caller_decision[3] if caller_decision else ())

            mnemonics = {decoded.mnemonic for _, decoded in body}
            implicit_streams = (any(name.startswith("lods") for name in mnemonics)
                                and any(name.startswith("scas") for name in mnemonics))
            if not implicit_streams:
                continue
            caller_decision = comparator_caller_decision(fn)
            compare_record = next(((item, decoded) for item, decoded in body
                                   if decoded.mnemonic.startswith("scas")), None)
            if caller_decision is None or compare_record is None:
                continue
            compare_ins, _ = compare_record
            if compare_ins.rva in seen_compares:
                continue
            seen_compares.add(compare_ins.rva)
            create(compare_ins.rva, "STATIC_LINKED_COMPARATOR", caller_decision[0], True,
                   extra=("Two implicit byte streams use LODS/SCAS inside a bounded loop",
                          f"Comparator return value controls a caller decision; back edge RVA 0x{back_ins.rva:X}"),
                   decision_type=caller_decision[1], branch_polarity=caller_decision[2],
                   compare_origin="STATIC_LINKED_COMPARATOR", comparator_function=fn.rva,
                   thunk_chain=caller_decision[3])

    # Optimized validators often inline byte-to-immediate decisions instead of
    # calling a comparator. Require byte width plus contextual corroboration.
    for fn in context.functions:
        if runtime_function(fn):
            continue
        records = context.function_records[fn.rva]
        for index, (ins, dec) in enumerate(records):
            if ins.rva in seen_compares or dec.mnemonic != "cmp" or len(dec.operands) != 2:
                continue
            memory = [operand for operand in dec.operands if operand.type == X86_OP_MEM and operand.size == 1]
            immediates = [int(operand.imm) for operand in dec.operands if operand.type == X86_OP_IMM]
            if not memory or not immediates:
                continue
            branch = _branch_after_compare(records, index)
            if branch is None:
                continue
            branch_rva = records[branch][0].rva
            success, failure = _outcome_branches(context, branch_rva, strings_by_xref)
            if not (success or failure):
                continue
            create(ins.rva, "INLINED_BYTE_COMPARE", branch_rva,
                   target={"value": immediates[0] & 0xFF, "basis": "inline byte immediate"},
                   extra=("Byte-wide inline comparison with contextual input/outcome evidence",),
                   decision_type="conditional_branch", branch_polarity=_branch_polarity(records[branch][1].mnemonic))

    # A bounded callee summary can establish a compare-like decision even when
    # the implementation is reached through a local function pointer.  Require
    # the scalar return to be consumed immediately by branch/setcc/cmovcc.
    summaries = {summary.function_rva: summary for summary in function_summaries}
    for callsite_rva, target_rva in context.calls:
        summary = summaries.get(target_rva)
        if summary is None or not any(item.kind == "RETURNS_SCALAR_RESULT" for item in summary.returns):
            continue
        caller_records = context.local_records(callsite_rva, before=0, after=16)
        call_index = next((i for i, (item, _) in enumerate(caller_records)
                           if item.rva == callsite_rva), None)
        decision = _result_decision(caller_records, call_index, "a") if call_index is not None else None
        if decision is None:
            continue
        decision_rva = (caller_records[decision[0]][0].rva
                        if decision[1] == "conditional_branch" else None)
        if any(candidate.rva == callsite_rva for candidate in candidates):
            continue
        create(
            callsite_rva, "RETURN_SEMANTICS", decision_rva,
            extra=(f"callee RVA 0x{target_rva:X} returns an argument-related scalar result",
                   "callee summary is bounded and cached"),
            decision_type="return_value_" + decision[1], branch_polarity=decision[2],
            compare_origin="RETURN_SEMANTICS", comparator_function=target_rva,
            reported_function_rva=target_rva,
        )

    return sorted(candidates, key=lambda candidate: candidate.rva)


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
