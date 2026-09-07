"""Shared direct references and bounded local function membership, without data flow."""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from dataclasses import replace
from typing import Any

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_INVALID, X86_REG_RIP

from .findings import Function, FunctionChunk
from .instruction_context import follows, register_family, section_name
from .indirect_resolver import resolve_indirect_call


_PROGRAM_ENTRY_NAMES = {"main", "wmain", "winmain", "wwinmain", "dllmain"}
_RUNTIME_NAME_PARTS = (
    "mingw", "gcc_register_frame", "gcc_deregister_frame", "pei386_runtime_relocator",
    "chkstk", "security_cookie", "security_check_cookie", "crtstartup", "tmaincrtstartup",
    "maincrtstartup", "cxxframehandler", "except_handler", "tls_callback",
)
_RUNTIME_EXACT_NAMES = {
    "__main", "___main", "memcmp", "strcmp", "strncmp", "strlen", "wcslen",
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
}


def _classify_runtime(function):
    if function.is_thunk:
        return "THUNK", ("one-instruction forwarding jump",)
    raw_name = function.name.casefold()
    normalized = raw_name.lstrip("_")
    if raw_name in _RUNTIME_EXACT_NAMES or normalized in _RUNTIME_EXACT_NAMES:
        return "RUNTIME_LIKELY", (f"known compiler/runtime symbol {function.name}",)
    if normalized in _PROGRAM_ENTRY_NAMES:
        return "USER_CODE", (f"program-level symbol {function.name}",)
    if any(part in normalized for part in _RUNTIME_NAME_PARTS):
        return "RUNTIME_LIKELY", (f"compiler/runtime symbol pattern {function.name}",)
    if function.source == "COFF symbol table" and normalized:
        return "USER_CODE", (f"retained non-runtime COFF symbol {function.name}",)
    return "UNKNOWN", ("no decisive runtime or user-code evidence",)


def direct_address(decoded: Any, operand: Any) -> int | None:
    """Address of the referenced storage, not the value loaded from it."""
    if operand.type == X86_OP_IMM:
        return int(operand.imm)
    if operand.type == X86_OP_MEM and operand.mem.segment == X86_REG_INVALID:
        if operand.mem.index != X86_REG_INVALID:
            return None
        if operand.mem.base == X86_REG_RIP:
            return int(decoded.address + decoded.size + operand.mem.disp)
        if operand.mem.base == X86_REG_INVALID:
            return int(operand.mem.disp)
    return None


def _function_chunks(function, by_rva, shared_rvas=()):
    groups = []
    current = []
    for rva in sorted(function.instruction_rvas):
        if current and current[-1] + by_rva[current[-1]][0].size != rva:
            groups.append(current)
            current = []
        current.append(rva)
    if current:
        groups.append(current)
    chunks = []
    for group in groups:
        start = group[0]
        end = group[-1] + by_rva[group[-1]][0].size
        relation = "PRIMARY" if function.rva in group else "COLD"
        incoming = []
        for source_rva in function.instruction_rvas:
            _, decoded = by_rva[source_rva]
            if not decoded.group(CS_GRP_JUMP) or not decoded.operands or decoded.operands[0].type != X86_OP_IMM:
                continue
            if int(decoded.operands[0].imm) - function.address + function.rva == start:
                incoming.append(decoded.mnemonic)
        if relation != "PRIMARY" and "jmp" in incoming:
            relation = "TAIL"
        chunks.append(FunctionChunk(
            start, end, relation,
            "CONFIRMED" if relation == "PRIMARY" and function.confidence == "high" else "LIKELY",
            (f"{relation.lower()} code range recovered from bounded control-flow membership",),
        ))
    shared = sorted(set(shared_rvas))
    if shared:
        start = shared[0]
        previous = shared[0]
        for rva in [*shared[1:], None]:
            if rva is not None and previous + by_rva[previous][0].size == rva:
                previous = rva
                continue
            chunks.append(FunctionChunk(
                start, previous + by_rva[previous][0].size, "SHARED_EPILOGUE", "POSSIBLE",
                ("multiple function candidates reach this tail; ownership remains ambiguous",),
            ))
            if rva is not None:
                start = previous = rva
    return tuple(chunks)


class FunctionIndex:
    def __init__(self, records, sections, image_base, entry_rva=None, exports=(), runtime_functions=(), *,
                 symbols=(), limit=4096):
        if limit < 1:
            raise ValueError("Function instruction limit must be positive")
        self.records = sorted(records, key=lambda pair: pair[0].rva)
        self.by_rva = {ins.rva: (ins, dec) for ins, dec in self.records}
        self.positions = {ins.rva: i for i, (ins, _) in enumerate(self.records)}
        self.image_base = image_base
        self.sections = sections
        self.functions: list[Function] = []
        self.owners: dict[int, Function] = {}
        self.calls: list[tuple[int, int]] = []
        self.resolved_indirect_calls: dict[int, dict[str, Any]] = {}
        self.truncated = False
        self.ambiguous_rvas: tuple[int, ...] = ()
        seeds: dict[int, tuple[str, int | None, str, str, tuple[str, ...]]] = {}
        ranges = sorted((int(start), int(end)) for start, end in runtime_functions if int(start) < int(end))
        range_starts = [start for start, _ in ranges]

        def add_seed(rva, source, *, end=None, name=None, confidence="medium", reasons=()):
            if rva is None:
                return
            rva = int(rva)
            if rva not in self.by_rva:
                return
            i = bisect_right(range_starts, rva) - 1
            if i >= 0 and ranges[i][0] < rva < ranges[i][1]:
                return
            existing = seeds.get(rva)
            proposed = (source, end, name or f"FUN_{image_base + rva:X}", confidence,
                        tuple(reasons) or (f"function lead: {source}",))
            priority = {"low": 0, "medium": 1, "high": 2}
            if existing is None or priority[confidence] > priority[existing[3]]:
                seeds[rva] = proposed

        for start, end in ranges:
            if start in self.by_rva:
                add_seed(start, "PE exception directory", end=end, confidence="high",
                         reasons=(f"runtime function range 0x{start:X}-0x{end:X}",))
        add_seed(entry_rva, "PE entry point")
        for exported in exports:
            add_seed(exported.get("address_rva"), "PE export")
        for symbol in symbols:
            add_seed(symbol.get("rva"), "COFF symbol table", name=symbol.get("name"), confidence="high",
                     reasons=(f"retained COFF function symbol {symbol.get('name') or '<unnamed>'}",))

        def inside_strong_preamble(index, rva):
            for lead, (_, _, _, confidence, _) in seeds.items():
                if confidence != "high" or not 0 < rva - lead <= 32:
                    continue
                lead_index = self.positions.get(lead)
                if lead_index is None or lead_index >= index:
                    continue
                between = self.records[lead_index:index]
                if all(not dec.group(CS_GRP_RET) and not (dec.group(CS_GRP_JUMP) and dec.mnemonic == "jmp")
                       for _, dec in between):
                    return True
            return False

        for i, (ins, dec) in enumerate(self.records):
            if dec.group(CS_GRP_CALL) and dec.operands and dec.operands[0].type == X86_OP_IMM:
                target = int(dec.operands[0].imm) - image_base
                # CALL next-instruction is commonly position discovery, not a function.
                if target != ins.rva + ins.size:
                    add_seed(target, "direct CALL target")
                    self.calls.append((ins.rva, target))
            elif dec.group(CS_GRP_CALL) and dec.operands:
                resolution = resolve_indirect_call(self.records, i, image_base)
                if resolution.target_address is not None:
                    target = int(resolution.target_address) - image_base
                    if target in self.by_rva:
                        add_seed(target, "resolved indirect CALL target", confidence="medium",
                                 reasons=resolution.evidence)
                        self.calls.append((ins.rva, target))
                        self.resolved_indirect_calls[ins.rva] = {
                            "target_rva": target,
                            "confidence": resolution.confidence,
                            "evidence": list(resolution.evidence),
                        }
            if i + 1 < len(self.records) and dec.mnemonic == "push" and dec.op_str in {"ebp", "rbp"}:
                next_ins, next_dec = self.records[i + 1]
                if follows(ins, next_ins) and next_dec.mnemonic == "mov" and next_dec.op_str in {"ebp, esp", "rbp, rsp"}:
                    if not inside_strong_preamble(i, ins.rva):
                        add_seed(ins.rva, "frame prologue heuristic", confidence="low")
            # Split after a return only when the next bytes look like a conventional or
            # stack-allocation prologue. This catches adjacent non-frame-pointer code
            # without treating every byte after RET as a function.
            if dec.group(CS_GRP_RET) and i + 1 < len(self.records):
                next_ins, next_dec = self.records[i + 1]
                following_dec = self.records[i + 2][1] if i + 2 < len(self.records) and follows(next_ins, self.records[i + 2][0]) else None
                stack_prologue = (
                    (next_dec.mnemonic == "sub" and next_dec.op_str.startswith(("rsp,", "esp,")))
                    or (next_dec.mnemonic == "push" and following_dec is not None and
                        following_dec.mnemonic in {"mov", "sub"})
                    or next_dec.mnemonic in {"endbr32", "endbr64"}
                )
                if stack_prologue:
                    add_seed(next_ins.rva, "post-return prologue", confidence="low",
                             reasons=(f"prologue-like instruction follows return at RVA 0x{ins.rva:X}",))

        # A one-instruction direct jump at a known lead is a thunk. Its destination is
        # also a useful boundary lead when it remains inside executable decoded code.
        for start in tuple(seeds):
            ins, dec = self.by_rva[start]
            if dec.mnemonic == "jmp" and dec.operands and dec.operands[0].type == X86_OP_IMM:
                target = int(dec.operands[0].imm) - image_base
                add_seed(target, "thunk target", confidence="medium",
                         reasons=(f"direct thunk from RVA 0x{start:X}",))

        memberships: dict[int, set[int]] = {}
        claims: dict[int, int] = {}
        ambiguous: set[int] = set()
        shared_by_start: dict[int, set[int]] = defaultdict(set)
        seed_items = sorted(seeds.items(), key=lambda item: (-{"high": 2, "medium": 1, "low": 0}[item[1][3]], item[0]))
        for start, (source, end, name, confidence, reasons) in seed_items:
            pending = [start]
            seen: set[int] = set()
            while pending and len(seen) < limit:
                rva = pending.pop()
                if rva in seen or rva not in self.by_rva or rva in ambiguous:
                    continue
                if rva != start and rva in seeds:
                    continue
                if end is not None and not start <= rva < end:
                    continue
                if rva < start or section_name(rva, sections) != section_name(start, sections):
                    continue
                if rva in claims and claims[rva] != start:
                    ambiguous.add(rva)
                    # Shared tails have uncertain ownership; remove their known suffix too.
                    old = claims[rva]
                    shared_by_start[start].add(rva)
                    shared_by_start[old].add(rva)
                    for tail in tuple(memberships.get(old, ())):
                        if tail >= rva:
                            ambiguous.add(tail)
                            shared_by_start[start].add(tail)
                            shared_by_start[old].add(tail)
                    continue
                ins, dec = self.by_rva[rva]
                if dec.mnemonic in {"int3", "ud2", "hlt"}:
                    continue
                seen.add(rva)
                claims[rva] = start
                if dec.group(CS_GRP_RET):
                    continue
                if dec.group(CS_GRP_JUMP):
                    if dec.operands and dec.operands[0].type == X86_OP_IMM:
                        pending.append(int(dec.operands[0].imm) - image_base)
                    if dec.mnemonic == "jmp":
                        continue
                following = self.by_rva.get(rva + ins.size)
                if following and follows(ins, following[0]):
                    pending.append(rva + ins.size)
            memberships[start] = seen
            truncated = bool(pending)
            self.truncated |= truncated
            ins = self.by_rva[start][0]
            end_rva = max((r + self.by_rva[r][0].size for r in seen), default=None)
            first_dec = self.by_rva[start][1]
            thunk_target = None
            if first_dec.mnemonic == "jmp" and first_dec.operands and first_dec.operands[0].type == X86_OP_IMM:
                thunk_target = int(first_dec.operands[0].imm) - image_base
            self.functions.append(Function(start, ins.address, name, ins.file_offset,
                                           section_name(start, sections), source, confidence,
                                           tuple(sorted(seen)), truncated, end_rva, reasons,
                                           thunk_target is not None, thunk_target))
        self.functions = [replace(fn, instruction_rvas=tuple(r for r in fn.instruction_rvas if r not in ambiguous))
                          for fn in self.functions if fn.instruction_rvas]
        self.functions = [fn for fn in self.functions if fn.instruction_rvas]
        # Reconcile only two bounded entry/body layouts: a non-control prefix
        # immediately before a heuristic prologue, and a tiny PE-entry stub whose
        # first CALL transfers to a prologue body before returning a constant.
        entry_body_relations: dict[int, tuple[int, str, tuple[str, ...]]] = {}
        entry_function = next((fn for fn in self.functions
                               if entry_rva is not None and fn.rva == int(entry_rva)
                               and fn.source == "PE entry point"), None)
        if entry_function is not None:
            body = None
            relation_evidence = ()
            ordered_entry = sorted(entry_function.instruction_rvas)
            if len(ordered_entry) <= 2:
                last_rva = ordered_entry[-1]
                adjacent_rva = last_rva + self.by_rva[last_rva][0].size
                candidate = next((fn for fn in self.functions if fn.rva == adjacent_rva
                                  and fn.source == "frame prologue heuristic"), None)
                if candidate is not None and all(
                        not self.by_rva[rva][1].group(CS_GRP_CALL)
                        and not self.by_rva[rva][1].group(CS_GRP_JUMP)
                        and not self.by_rva[rva][1].group(CS_GRP_RET)
                        for rva in ordered_entry):
                    body = candidate
                    relation_evidence = (
                        f"PE entry prefix falls through to prologue body RVA 0x{candidate.rva:X}",
                        "bounded entry/body reconciliation: non-control prefix",
                    )
            if body is None and 1 <= len(ordered_entry) <= 4:
                first_dec = self.by_rva[ordered_entry[0]][1]
                direct_target = (int(first_dec.operands[0].imm) - image_base
                                 if first_dec.group(CS_GRP_CALL) and first_dec.operands
                                 and first_dec.operands[0].type == X86_OP_IMM else None)
                candidate = next((fn for fn in self.functions if fn.rva == direct_target
                                  and fn.source == "direct CALL target"), None)
                tail_mnemonics = {self.by_rva[rva][1].mnemonic for rva in ordered_entry[1:]}
                candidate_records = (sorted(candidate.instruction_rvas)[:2] if candidate is not None else [])
                has_frame_prologue = (
                    len(candidate_records) == 2
                    and self.by_rva[candidate_records[0]][1].mnemonic == "push"
                    and self.by_rva[candidate_records[0]][1].op_str in {"ebp", "rbp"}
                    and self.by_rva[candidate_records[1]][1].mnemonic == "mov"
                    and self.by_rva[candidate_records[1]][1].op_str in {"ebp, esp", "rbp, rsp"}
                )
                if (candidate is not None and has_frame_prologue
                        and any(self.by_rva[rva][1].group(CS_GRP_RET) for rva in ordered_entry)):
                    allowed_tail = all(name in {"xor", "mov", "ret", "retf", "nop"} for name in tail_mnemonics)
                    if allowed_tail:
                        body = candidate
                        relation_evidence = (
                            f"tiny PE entry stub transfers to prologue body RVA 0x{candidate.rva:X}",
                            "bounded entry/body reconciliation: call-body-return stub",
                        )
            if body is not None:
                merged = replace(
                    entry_function,
                    confidence="medium",
                    instruction_rvas=tuple(sorted(set(entry_function.instruction_rvas) | set(body.instruction_rvas))),
                    end_rva_exclusive=max(filter(None, (entry_function.end_rva_exclusive, body.end_rva_exclusive))),
                    boundary_reasons=(*entry_function.boundary_reasons, *relation_evidence),
                )
                self.functions = [merged if fn is entry_function else fn for fn in self.functions if fn is not body]
                entry_body_relations[merged.rva] = (body.rva, "LIKELY", relation_evidence)
                self.calls = [(source, target) for source, target in self.calls
                              if not (source in entry_function.instruction_rvas and target == body.rva)]
        # The same fallthrough-prefix layout can occur at a direct-call target,
        # not only at the PE header entry (for example a one-byte register setup
        # immediately before the conventional body prologue).
        functions_by_rva = {fn.rva: fn for fn in self.functions}
        for prefix in tuple(self.functions):
            if prefix.rva in entry_body_relations or len(prefix.instruction_rvas) != 1:
                continue
            ordered_prefix = sorted(prefix.instruction_rvas)
            prefix_decoded = self.by_rva[ordered_prefix[0]][1]
            return_register_pop = (
                prefix_decoded.mnemonic == "pop" and prefix_decoded.operands
                and prefix_decoded.operands[0].type != X86_OP_MEM
                and register_family(prefix_decoded.reg_name(prefix_decoded.operands[0].reg)) == "a"
            )
            if not return_register_pop:
                continue
            last_rva = ordered_prefix[-1]
            adjacent_rva = last_rva + self.by_rva[last_rva][0].size
            body = functions_by_rva.get(adjacent_rva)
            if body is not None and body.source != "frame prologue heuristic":
                body = None
            if body is None or any(
                    self.by_rva[rva][1].group(CS_GRP_CALL)
                    or self.by_rva[rva][1].group(CS_GRP_JUMP)
                    or self.by_rva[rva][1].group(CS_GRP_RET)
                    for rva in ordered_prefix):
                continue
            evidence = (
                f"function prefix falls through to prologue body RVA 0x{body.rva:X}",
                "bounded entry/body reconciliation: non-control prefix",
            )
            merged = replace(
                prefix, confidence="medium",
                instruction_rvas=tuple(sorted(set(prefix.instruction_rvas) | set(body.instruction_rvas))),
                end_rva_exclusive=max(filter(None, (prefix.end_rva_exclusive, body.end_rva_exclusive))),
                boundary_reasons=(*prefix.boundary_reasons, *evidence),
            )
            self.functions = [merged if fn is prefix else fn for fn in self.functions if fn is not body]
            functions_by_rva[prefix.rva] = merged
            functions_by_rva.pop(body.rva, None)
            entry_body_relations[merged.rva] = (body.rva, "LIKELY", evidence)
        enriched = []
        for fn in self.functions:
            tails = []
            for rva in fn.instruction_rvas:
                ins, dec = self.by_rva[rva]
                if dec.mnemonic == "jmp" and dec.operands and dec.operands[0].type == X86_OP_IMM:
                    target = int(dec.operands[0].imm) - image_base
                    if target in seeds and target != fn.rva:
                        tails.append(target)
            owned_end = max((rva + self.by_rva[rva][0].size for rva in fn.instruction_rvas), default=None)
            chunks = _function_chunks(fn, self.by_rva, shared_by_start.get(fn.rva, ()))
            if fn.rva in entry_body_relations:
                body_rva, relation_confidence, relation_evidence = entry_body_relations[fn.rva]
                chunks = (
                    FunctionChunk(fn.rva, body_rva, "ENTRY_STUB", relation_confidence, relation_evidence),
                    FunctionChunk(body_rva, owned_end, "BODY", relation_confidence, relation_evidence),
                )
            enriched.append(replace(fn, end_rva_exclusive=owned_end,
                                    tail_call_targets=tuple(sorted(set(tails))),
                                    shared_tail_rvas=tuple(sorted(shared_by_start.get(fn.rva, ()))),
                                    chunks=chunks))
        classified = []
        for fn in enriched:
            likelihood, evidence = _classify_runtime(fn)
            classified.append(replace(fn, runtime_likelihood=likelihood, runtime_evidence=evidence))
        self.functions = classified
        self.ambiguous_rvas = tuple(sorted(ambiguous))
        self.owners = {rva: fn for fn in self.functions for rva in fn.instruction_rvas}
        self.function_records = {
            fn.rva: [self.by_rva[r] for r in sorted(set(fn.instruction_rvas) | set(fn.shared_tail_rvas))]
            for fn in self.functions
        }
        self.references: dict[int, list[int]] = defaultdict(list)
        for ins, dec in self.records:
            if dec.group(CS_GRP_CALL) or dec.group(CS_GRP_JUMP):
                continue
            seen_addresses = set()
            for operand in dec.operands:
                # Arithmetic immediates are not pointer references.
                if operand.type == X86_OP_IMM and dec.mnemonic not in {"push", "mov", "movabs"}:
                    continue
                address = direct_address(dec, operand)
                if address is not None and address not in seen_addresses:
                    self.references[address].append(ins.rva)
                    seen_addresses.add(address)

    def owner(self, rva):
        return self.owners.get(rva)

    def local_records(self, rva, before=0, after=32):
        position = self.positions.get(rva)
        if position is None:
            return []
        fn = self.owner(rva)
        result = []
        for ins, dec in self.records[max(0, position - before):position + after + 1]:
            if self.owner(ins.rva) is fn:
                result.append((ins, dec))
        return result
