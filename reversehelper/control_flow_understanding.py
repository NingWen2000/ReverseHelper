"""Bounded explanations for CTF-relevant control-flow structures."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from struct import unpack_from
from typing import Any, Literal

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, X86_REG_RIP

from .instruction_context import register_family


ControlFlowConfidence = Literal["HIGH", "MEDIUM", "LOW"]
SliceRelation = Literal["ON_CONFIRMED_SLICE", "ON_LIKELY_SLICE", "ON_PARTIAL_SLICE", "OFF_SLICE"]


@dataclass(frozen=True, slots=True)
class ControlFlowEvidence:
    kind: str
    value: Any
    block_rvas: tuple[int, ...] = ()

    def to_dict(self):
        result = asdict(self)
        result["block_rvas"] = list(self.block_rvas)
        return result


@dataclass(frozen=True, slots=True)
class ControlFlowFinding:
    id: str
    function: str
    function_rva: int
    kind: str
    confidence: ControlFlowConfidence
    entry_block: int
    related_blocks: tuple[int, ...]
    dispatcher_block: int | None
    state_variable: dict[str, Any] | None
    jump_table: dict[str, Any] | None
    evidence: tuple[ControlFlowEvidence, ...]
    structural_features: tuple[str, ...]
    slice_relation: SliceRelation
    suggested_action: str
    state_updates: tuple[dict[str, Any], ...] = ()

    def to_dict(self):
        return {
            "id": self.id, "function": self.function, "function_rva": self.function_rva,
            "kind": self.kind, "confidence": self.confidence, "entry_block": self.entry_block,
            "related_blocks": list(self.related_blocks), "dispatcher_block": self.dispatcher_block,
            "state_variable": self.state_variable, "jump_table": self.jump_table,
            "evidence": [item.to_dict() for item in self.evidence],
            "structural_features": list(self.structural_features), "slice_relation": self.slice_relation,
            "suggested_action": self.suggested_action, "state_updates": list(self.state_updates),
        }


@dataclass(slots=True)
class _Block:
    start: int
    rvas: list[int]
    successors: set[int]


DEFAULT_BUDGETS = {
    "max_cfg_functions": 96,
    "max_cfg_blocks": 4096,
    "max_cfg_edges": 12000,
    "max_indirect_targets": 64,
}


def _slice_relation(function_rva, slices):
    order = {"OFF_SLICE": 0, "ON_PARTIAL_SLICE": 1, "ON_LIKELY_SLICE": 2, "ON_CONFIRMED_SLICE": 3}
    mapping = {"PARTIAL_SLICE": "ON_PARTIAL_SLICE", "LIKELY_SLICE": "ON_LIKELY_SLICE",
               "CONFIRMED_SLICE": "ON_CONFIRMED_SLICE"}
    result = "OFF_SLICE"
    for item in slices:
        record = item.to_dict() if hasattr(item, "to_dict") else item
        functions = {node.get("function_rva") for node in record.get("nodes", [])}
        functions.update(transform.get("function_rva") for transform in record.get("transforms", []))
        functions.add((record.get("validation_sink") or {}).get("function_rva"))
        if function_rva in functions:
            candidate = mapping.get(record.get("status"), "ON_PARTIAL_SLICE")
            if order[candidate] > order[result]:
                result = candidate
    return result


def _location(decoded, operand):
    if operand.type == X86_OP_REG:
        return {"kind": "REGISTER", "name": register_family(decoded.reg_name(operand.reg))}
    if operand.type != X86_OP_MEM:
        return None
    base = register_family(decoded.reg_name(operand.mem.base)) if operand.mem.base != X86_REG_INVALID else None
    index = register_family(decoded.reg_name(operand.mem.index)) if operand.mem.index != X86_REG_INVALID else None
    if base in {"bp", "sp"} and index is None:
        return {"kind": "STACK", "base": base, "offset": int(operand.mem.disp)}
    if base is None and index is None:
        return {"kind": "GLOBAL", "address": int(operand.mem.disp)}
    return {"kind": "MEMORY", "base": base, "index": index, "scale": int(operand.mem.scale),
            "offset": int(operand.mem.disp)}


def _location_key(location):
    return tuple(sorted(location.items())) if location else None


def _blocks(context, fn):
    records = [context.by_rva[rva] for rva in fn.instruction_rvas if rva in context.by_rva]
    members = {ins.rva for ins, _ in records}
    leaders = {fn.rva}
    for ins, decoded in records:
        if decoded.group(CS_GRP_JUMP) and decoded.operands and decoded.operands[0].type == X86_OP_IMM:
            target = int(decoded.operands[0].imm) - context.image_base
            if target in members:
                leaders.add(target)
            if decoded.mnemonic != "jmp" and ins.rva + ins.size in members:
                leaders.add(ins.rva + ins.size)
        elif (decoded.group(CS_GRP_RET) or decoded.group(CS_GRP_JUMP)) and ins.rva + ins.size in members:
            leaders.add(ins.rva + ins.size)
    blocks = {}
    current = None
    for ins, decoded in records:
        if ins.rva in leaders or current is None:
            current = _Block(ins.rva, [], set())
            blocks[ins.rva] = current
        current.rvas.append(ins.rva)
        if decoded.group(CS_GRP_JUMP) or decoded.group(CS_GRP_RET):
            current = None
    starts = set(blocks)
    for block in blocks.values():
        ins, decoded = context.by_rva[block.rvas[-1]]
        if decoded.group(CS_GRP_RET):
            continue
        if decoded.group(CS_GRP_JUMP):
            if decoded.operands and decoded.operands[0].type == X86_OP_IMM:
                target = int(decoded.operands[0].imm) - context.image_base
                if target in starts:
                    block.successors.add(target)
            if decoded.mnemonic != "jmp" and ins.rva + ins.size in starts:
                block.successors.add(ins.rva + ins.size)
        elif ins.rva + ins.size in starts:
            block.successors.add(ins.rva + ins.size)
    return records, blocks


def _offset_for_rva(rva, sections):
    for section in sections:
        start = int(section["virtual_address"])
        if start <= rva < start + int(section["raw_size"]):
            return int(section["raw_address"]) + rva - start
    return None


def _jump_table(context, data, decoded, blocks, maximum):
    if not decoded.operands or decoded.operands[0].type != X86_OP_MEM:
        return None
    operand = decoded.operands[0]
    if operand.mem.index == X86_REG_INVALID or int(operand.mem.scale) not in {4, 8}:
        return None
    if operand.mem.base == X86_REG_RIP:
        address = int(decoded.address + decoded.size + operand.mem.disp)
    elif operand.mem.base == X86_REG_INVALID:
        address = int(operand.mem.disp)
    else:
        return None
    table_rva = address - context.image_base
    offset = _offset_for_rva(table_rva, context.sections)
    if offset is None:
        return None
    width = int(operand.mem.scale)
    targets = []
    encoding = None
    for index in range(maximum):
        item_offset = offset + index * width
        if item_offset + width > len(data):
            break
        raw = unpack_from("<I" if width == 4 else "<Q", data, item_offset)[0]
        choices = ((raw - context.image_base, "ABSOLUTE_VA"), (raw, "RVA"))
        if width == 4:
            signed = raw if raw < 0x80000000 else raw - 0x100000000
            choices += ((table_rva + signed, "RELATIVE_OFFSET"),)
        selected = next(((rva, kind) for rva, kind in choices if rva in context.by_rva), None)
        if selected is None:
            break
        targets.append(selected[0]); encoding = encoding or selected[1]
    if len(set(targets)) < 3:
        return None
    return {"rva": table_rva, "address": address, "entry_size": width, "encoding": encoding,
            "case_count": len(targets), "case_targets": list(dict.fromkeys(targets))}


def _selector(records, index):
    for _, decoded in reversed(records[max(0, index - 8):index]):
        if decoded.mnemonic not in {"cmp", "test", "and"}:
            continue
        for operand in decoded.operands:
            location = _location(decoded, operand)
            if location and location.get("kind") in {"REGISTER", "STACK", "GLOBAL"}:
                return location
    return None


def analyze_control_flow(context, data: bytes, slices=(), algorithm_candidates=(), *, budgets=None):
    limits = {**DEFAULT_BUDGETS, **(budgets or {})}
    priority = {item.function_rva for item in algorithm_candidates}
    for item in slices:
        record = item.to_dict() if hasattr(item, "to_dict") else item
        priority.update(node.get("function_rva") for node in record.get("nodes", []))
        priority.add((record.get("validation_sink") or {}).get("function_rva"))
    def has_indirect_transfer(fn):
        return any(
            (decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_JUMP))
            and decoded.operands and decoded.operands[0].type != X86_OP_IMM
            for rva in fn.instruction_rvas if rva in context.by_rva
            for _, decoded in [context.by_rva[rva]]
        )

    functions = sorted(context.functions, key=lambda fn: (fn.rva not in priority,
                       not has_indirect_transfer(fn), fn.runtime_likelihood == "RUNTIME_LIKELY",
                       -len(fn.instruction_rvas), fn.rva))
    findings = []
    total_blocks = total_edges = indirect_targets = 0
    truncated = False
    analyzed = 0
    for fn in functions:
        if analyzed >= limits["max_cfg_functions"]:
            truncated = True; break
        records, blocks = _blocks(context, fn)
        if total_blocks + len(blocks) > limits["max_cfg_blocks"]:
            truncated = True; break
        analyzed += 1; total_blocks += len(blocks)
        predecessors = defaultdict(set)
        for block in blocks.values():
            for successor in block.successors:
                predecessors[successor].add(block.start)
        total_edges += sum(len(block.successors) for block in blocks.values())
        relation = _slice_relation(fn.rva, slices)
        switch_findings = []
        indirect_calls = []
        for index, (ins, decoded) in enumerate(records):
            if decoded.mnemonic == "jmp" and decoded.operands and decoded.operands[0].type != X86_OP_IMM:
                table = _jump_table(context, data, decoded, blocks,
                                    min(limits["max_indirect_targets"] - indirect_targets, 64))
                selector = _selector(records, index)
                if table:
                    indirect_targets += table["case_count"]
                    owner_block = next(block for block in blocks.values() if ins.rva in block.rvas)
                    owner_block.successors.update(table["case_targets"])
                    for target in table["case_targets"]:
                        predecessors[target].add(owner_block.start)
                    bound = any(dec.mnemonic == "cmp" for _, dec in records[max(0, index - 8):index])
                    evidence = (ControlFlowEvidence("COMPUTED_BRANCH", decoded.op_str, (owner_block.start,)),
                                ControlFlowEvidence("EXECUTABLE_TARGETS", table["case_count"], tuple(table["case_targets"])),
                                ControlFlowEvidence("RANGE_CHECK", bound, (owner_block.start,)))
                    switch_findings.append(ControlFlowFinding(
                        f"control-flow-{fn.rva:08X}-jump-table-{ins.rva:08X}", fn.name, fn.rva,
                        "SWITCH" if bound else "JUMP_TABLE", "HIGH" if bound and table["case_count"] >= 4 else "MEDIUM",
                        fn.rva, tuple(table["case_targets"]), None, selector, table, evidence,
                        ("COMPUTED_BRANCH", "PLAUSIBLE_CASE_TARGETS") + (("BOUNDED_SELECTOR",) if bound else ()),
                        relation, "Inspect the selector range check, then label each case target before reading case bodies.",
                    ))
                else:
                    block = next(block for block in blocks.values() if ins.rva in block.rvas)
                    findings.append(ControlFlowFinding(
                        f"control-flow-{fn.rva:08X}-indirect-jump-{ins.rva:08X}", fn.name, fn.rva,
                        "INDIRECT_JUMP", "LOW", fn.rva, (block.start,), None, _selector(records, index), None,
                        (ControlFlowEvidence("COMPUTED_BRANCH", decoded.op_str, (block.start,)),),
                        ("UNRESOLVED_TARGET",), relation,
                        "Trace the operand definition and classify it as a table, callback, or unknown target.",
                    ))
            elif decoded.group(CS_GRP_CALL) and decoded.operands and decoded.operands[0].type != X86_OP_IMM:
                indexed = (decoded.operands[0].type == X86_OP_MEM and
                           decoded.operands[0].mem.index != X86_REG_INVALID)
                source_indexed = sum(
                    operand.type == X86_OP_MEM and operand.mem.index != X86_REG_INVALID
                    for _, previous in records[max(0, index - 8):index]
                    for operand in previous.operands
                )
                table_register = False
                if decoded.operands[0].type == X86_OP_REG:
                    called = register_family(decoded.reg_name(decoded.operands[0].reg))
                    for _, previous in reversed(records[max(0, index - 8):index]):
                        if previous.mnemonic != "mov" or len(previous.operands) < 2:
                            continue
                        destination, source = previous.operands[:2]
                        if (destination.type == X86_OP_REG
                                and register_family(previous.reg_name(destination.reg)) == called):
                            table_register = source.type == X86_OP_MEM and source.mem.index != X86_REG_INVALID
                            break
                state_source = None
                prior = records[max(0, index - 12):index]
                for prior_index, (_, previous) in enumerate(prior):
                    if previous.mnemonic not in {"mov", "movzx", "movsx"} or len(previous.operands) < 2:
                        continue
                    destination, source = previous.operands[:2]
                    if destination.type != X86_OP_REG or source.type != X86_OP_MEM:
                        continue
                    if source.mem.base != X86_REG_INVALID or source.mem.index != X86_REG_INVALID:
                        continue
                    family = register_family(previous.reg_name(destination.reg))
                    if any(operand.type == X86_OP_MEM
                           and operand.mem.index != X86_REG_INVALID
                           and register_family(later.reg_name(operand.mem.index)) == family
                           for _, later in prior[prior_index + 1:]
                           for operand in later.operands):
                        state_source = {"kind": "GLOBAL", "rva": int(source.mem.disp) - context.image_base,
                                        "width": max(8, int(getattr(source, "size", 1)) * 8)}
                        break
                indirect_calls.append((ins.rva, decoded.op_str, indexed or table_register, source_indexed, state_source))
        findings.extend(switch_findings)
        strong_table_call = any(item[2] and item[3] for item in indirect_calls)
        if len(indirect_calls) >= 3 or strong_table_call:
            indexed = sum(item[2] for item in indirect_calls)
            state_source = next((item[4] for item in indirect_calls if item[4]), None)
            findings.append(ControlFlowFinding(
                f"control-flow-{fn.rva:08X}-indirect-call-cluster", fn.name, fn.rva,
                "INDIRECT_CALL_CLUSTER", "MEDIUM" if indexed >= 2 or strong_table_call else "LOW", fn.rva,
                tuple(item[0] for item in indirect_calls), fn.rva if strong_table_call else None, state_source, None,
                (ControlFlowEvidence("INDIRECT_CALL_COUNT", len(indirect_calls), tuple(item[0] for item in indirect_calls)),
                 ControlFlowEvidence("INDEXED_CALL_COUNT", indexed),
                 ControlFlowEvidence("INDEXED_SELECTOR_SOURCE", strong_table_call),
                 ControlFlowEvidence("STATE_SOURCE", state_source or "unknown")),
                ("FUNCTION_TABLE_LIKE",) if indexed >= 2 or strong_table_call else ("UNKNOWN_INDIRECT_CALLS",), relation,
                "Inspect the call operand origins as a possible function table; keep each target unresolved unless uniquely proven.",
            ))

        # Structural hint only: repeated constant-heavy predicates are not proof
        # of opacity without symbolic or dynamic reasoning.
        predicate_constants = []
        predicate_blocks = []
        for block in blocks.values():
            if not block.rvas:
                continue
            _, tail = context.by_rva[block.rvas[-1]]
            if not tail.group(CS_GRP_JUMP) or tail.mnemonic == "jmp":
                continue
            for rva in block.rvas[:-1]:
                _, decoded = context.by_rva[rva]
                if decoded.mnemonic not in {"cmp", "test"}:
                    continue
                values = [int(op.imm) for op in decoded.operands if op.type == X86_OP_IMM]
                if values:
                    predicate_constants.extend(values); predicate_blocks.append(block.start)
        repeated = [value for value, count in Counter(predicate_constants).items() if count >= 3]
        if repeated and len(set(predicate_blocks)) >= 3:
            findings.append(ControlFlowFinding(
                f"control-flow-{fn.rva:08X}-opaque-like", fn.name, fn.rva,
                "OPAQUE_LIKE_CANDIDATE", "LOW", fn.rva, tuple(sorted(set(predicate_blocks))),
                None, None, None,
                (ControlFlowEvidence("REPEATED_PREDICATE_CONSTANT", repeated, tuple(predicate_blocks)),
                 ControlFlowEvidence("CONDITIONAL_BLOCK_COUNT", len(set(predicate_blocks)))),
                ("REPEATED_CONSTANT_HEAVY_CONDITION",), relation,
                "Review both successors manually; this is only an opaque-like pattern and does not prove either edge unreachable.",
            ))

        # A state-machine dispatcher is a switch-like block repeatedly revisited by case blocks.
        for switch in switch_findings:
            jump_block = next((block for block in blocks.values()
                               if any(rva in block.rvas for rva in switch.evidence[0].block_rvas)), None)
            dispatch_predecessors = list(predecessors.get(jump_block.start, ())) if jump_block else []
            dispatcher = (blocks.get(dispatch_predecessors[0])
                          if len(dispatch_predecessors) == 1 else jump_block)
            if dispatcher is None or switch.state_variable is None:
                continue
            state_key = _location_key(switch.state_variable)
            updates = []
            for block in blocks.values():
                for rva in block.rvas:
                    _, decoded = context.by_rva[rva]
                    if decoded.mnemonic not in {"mov", "lea", "xor", "add", "sub"} or not decoded.operands:
                        continue
                    if _location_key(_location(decoded, decoded.operands[0])) != state_key:
                        continue
                    value = int(decoded.operands[1].imm) if len(decoded.operands) > 1 and decoded.operands[1].type == X86_OP_IMM else "computed"
                    updates.append({"block_rva": block.start, "instruction_rva": rva, "value": value})
            returns = {block.start for block in blocks.values() if dispatcher.start in block.successors}
            if len(updates) < 2 or len(returns) < 2:
                continue
            dispatch_targets = set(switch.jump_table["case_targets"] if switch.jump_table else dispatcher.successors)
            evidence = (ControlFlowEvidence("DISPATCH_TARGETS", len(dispatch_targets), tuple(dispatch_targets)),
                        ControlFlowEvidence("BACK_TO_DISPATCH", len(returns), tuple(returns)),
                        ControlFlowEvidence("STATE_WRITES", len(updates), tuple(item["block_rva"] for item in updates)))
            confidence = "HIGH" if len(dispatch_targets) >= 4 and len(updates) >= 3 and len(returns) >= 3 else "MEDIUM"
            findings.append(ControlFlowFinding(
                f"control-flow-{fn.rva:08X}-state-machine-{dispatcher.start:08X}", fn.name, fn.rva,
                "STATE_MACHINE", confidence, fn.rva, tuple(sorted(dispatch_targets | returns)),
                dispatcher.start, switch.state_variable, switch.jump_table, evidence,
                ("CENTRAL_DISPATCH", "STATE_UPDATES", "REPEATED_REVISIT"), relation,
                "Track state assignments first, then group case blocks by the state values that reach the dispatcher.",
                tuple(updates),
            ))
            ratio = len(returns) / max(1, len(blocks))
            if len(dispatch_targets) >= 4 and len(updates) >= 3 and len(returns) >= 3 and ratio >= 0.25:
                flatten_confidence = "MEDIUM" if fn.runtime_likelihood != "RUNTIME_LIKELY" else "LOW"
                findings.append(ControlFlowFinding(
                    f"control-flow-{fn.rva:08X}-flattening-like-{dispatcher.start:08X}", fn.name, fn.rva,
                    "FLATTENING_LIKE", flatten_confidence, fn.rva,
                    tuple(sorted(dispatch_targets | returns)), dispatcher.start, switch.state_variable,
                    switch.jump_table, evidence + (ControlFlowEvidence("BACK_TO_DISPATCH_RATIO", round(ratio, 3)),),
                    ("CENTRAL_DISPATCH", "STATE_UPDATES", "ABNORMAL_REENTRY"), relation,
                    "Treat this as flattening-like, not proven flattening; map state writes and dispatcher cases without rewriting the CFG.",
                    tuple(updates),
                ))
        if total_edges > limits["max_cfg_edges"] or indirect_targets >= limits["max_indirect_targets"]:
            truncated = True; break

    # Runtime and weak function boundaries remain available in JSON but cannot become strong claims.
    runtime = {fn.rva: fn for fn in functions}
    normalized = []
    for finding in findings:
        fn = runtime.get(finding.function_rva)
        confidence = finding.confidence
        if fn and (fn.runtime_likelihood == "RUNTIME_LIKELY" or fn.confidence == "low") and confidence == "HIGH":
            confidence = "MEDIUM"
        if fn and fn.runtime_likelihood == "RUNTIME_LIKELY" and finding.kind == "FLATTENING_LIKE":
            confidence = "LOW"
        if confidence != finding.confidence:
            finding = ControlFlowFinding(**{**finding.to_dict(), "confidence": confidence,
                "related_blocks": finding.related_blocks, "evidence": finding.evidence,
                "structural_features": finding.structural_features, "state_updates": finding.state_updates})
        normalized.append(finding)
    normalized.sort(key=lambda item: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[item.confidence],
                                      item.slice_relation == "OFF_SLICE", item.function_rva, item.kind))
    return normalized, {**limits, "functions_analyzed": analyzed, "blocks_analyzed": total_blocks,
                        "edges_analyzed": total_edges, "indirect_targets": indirect_targets,
                        "truncated": truncated}
