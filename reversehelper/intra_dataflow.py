"""Bounded path-insensitive flow inside functions seeded by identified input."""

from __future__ import annotations

from typing import Any

from capstone import CS_GRP_CALL
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, X86_REG_RIP

from .dataflow_model import (
    ArgumentLocation, DataFlowEdge, GlobalLocation, ImmediateLocation, IntraFlowResult,
    MemoryLocation, RegisterLocation, ReturnValueLocation, StackLocation, UnknownLocation,
)
from .instruction_context import register_access, register_family
from .value_identity import TrackedValue, identity_for_source


X64_ARGUMENTS = ("c", "d", "r8", "r9")
TRANSFORMS = {"xor": "XOR", "add": "ADD", "sub": "SUB", "rol": "ROL", "ror": "ROR", "bswap": "BYTE_SWAP"}


def _memory_key(decoded, operand):
    mem = operand.mem
    base = register_family(decoded.reg_name(mem.base)) if mem.base != X86_REG_INVALID else None
    index = register_family(decoded.reg_name(mem.index)) if mem.index != X86_REG_INVALID else None
    return base, index, int(mem.scale), int(mem.disp)


def _base_location(decoded, operand, function_rva, image_base, definition_rva=None):
    if operand.type == X86_OP_REG:
        return RegisterLocation(register_family(decoded.reg_name(operand.reg)), function_rva, definition_rva)
    if operand.type == X86_OP_IMM:
        value = int(operand.imm)
        return GlobalLocation(value - image_base, value) if value >= image_base else ImmediateLocation(value)
    if operand.type != X86_OP_MEM:
        return UnknownLocation("unsupported operand")
    base, index, scale, offset = _memory_key(decoded, operand)
    if base in {"bp", "sp"} and index is None:
        raw_base = decoded.reg_name(operand.mem.base).lower() if operand.mem.base != X86_REG_INVALID else ""
        if raw_base in {"ebp", "bp"} and base == "bp" and offset >= 8 and offset % 4 == 0:
            return ArgumentLocation(function_rva, (offset - 8) // 4)
        return StackLocation(function_rva, offset, base, definition_rva)
    if base == "rip" and index is None:
        address = decoded.address + decoded.size + offset
        return GlobalLocation(address - image_base, address)
    if offset >= image_base and base not in {"bp", "sp", "rip"}:
        return GlobalLocation(offset - image_base, offset)
    return MemoryLocation(base, index, scale, offset, function_rva)


def _normalize_stack(location, stack_delta):
    if isinstance(location, StackLocation) and location.base == "sp":
        return StackLocation(location.function_rva, location.offset + stack_delta,
                             location.base, location.definition_rva)
    if isinstance(location, MemoryLocation) and location.base == "sp":
        return MemoryLocation(location.base, location.index, location.scale,
                              location.offset + stack_delta, location.function_rva)
    return location


def _loc_key(location):
    if isinstance(location, StackLocation):
        return ("stack", location.base, location.offset)
    if isinstance(location, GlobalLocation):
        return ("global", location.rva)
    if isinstance(location, MemoryLocation):
        if location.base in {"bp", "sp"}:
            return ("stack", location.base, location.offset)
        if location.base is None and location.offset >= 0:
            return ("absolute", location.offset)
        return ("memory", location.base, location.index, location.scale, location.offset)
    if isinstance(location, ArgumentLocation):
        return ("argument", location.index)
    return None


def _resolve(decoded, operand, function_rva, image_base, registers, memory, stack_delta=0):
    if operand.type == X86_OP_REG:
        family = register_family(decoded.reg_name(operand.reg))
        return registers.get(family)
    location = _normalize_stack(_base_location(decoded, operand, function_rva, image_base), stack_delta)
    key = _loc_key(location)
    if key in memory:
        return memory[key]
    if operand.type == X86_OP_MEM:
        base, index, scale, offset = _memory_key(decoded, operand)
        base_value = registers.get(base) if base else None
        index_value = registers.get(index) if index else None
        anchor = base_value or index_value
        if anchor is not None:
            symbolic_index = index if base_value is not None else base
            identity = anchor.identity.derived(
                f"memory alias at RVA 0x{decoded.address - image_base:X}",
                offset=offset, index=symbolic_index, scale=scale,
                possible=base_value is None,
            )
            return TrackedValue(location, identity)
    return None


def _defined(decoded, operand, function_rva, image_base, instruction_rva, stack_delta=0):
    return _normalize_stack(
        _base_location(decoded, operand, function_rva, image_base, instruction_rva), stack_delta,
    )


def _append_edge(edges, source, destination, instruction, edge_type, confidence, evidence, max_edges,
                 identity_budget=None):
    if len(edges) >= max_edges:
        return False
    source_location = source.location if isinstance(source, TrackedValue) else source
    destination_location = destination.location if isinstance(destination, TrackedValue) else destination
    identity = destination.identity if isinstance(destination, TrackedValue) else (
        source.identity if isinstance(source, TrackedValue) else None
    )
    if identity is not None and identity_budget is not None:
        if identity.id not in identity_budget["ids"] and len(identity_budget["ids"]) >= identity_budget["max_values"]:
            identity_budget["exceeded"].add("max values")
            return False
        if identity.alias_confidence != "EXACT_ALIAS" and identity_budget["aliases"] >= identity_budget["max_aliases"]:
            identity_budget["exceeded"].add("max aliases")
            return False
        if identity.version > identity_budget["max_versions"]:
            identity_budget["exceeded"].add("max versions")
            return False
        identity_budget["ids"].add(identity.id)
        identity_budget["aliases"] += int(identity.alias_confidence != "EXACT_ALIAS")
    edges.append(DataFlowEdge(source_location, destination_location, instruction.address, instruction.rva,
                              edge_type, confidence, evidence, identity))
    return True


def _call_target(decoded, image_base, context):
    if decoded.group(CS_GRP_CALL) and decoded.operands and decoded.operands[0].type == X86_OP_IMM:
        return int(decoded.operands[0].imm) - image_base, "CONFIRMED", "direct"
    resolved = context.resolved_indirect_calls.get(decoded.address - image_base)
    if resolved is not None:
        return int(resolved["target_rva"]), "LIKELY", "resolved-indirect"
    return None, None, "unresolved"


def analyze_intra_function(context, input_sources, architecture: str, *, max_instructions=12000, max_edges=4000,
                           max_values=256, max_aliases=1024, max_versions=64, max_flow_states=512):
    """Track only source-reachable values; obvious register/stack writes kill old state."""
    by_function: dict[int, list[Any]] = {}
    for source in input_sources:
        if source.function_rva is not None:
            by_function.setdefault(source.function_rva, []).append(source)
    edges = []
    call_arguments = []
    comparisons = []
    transforms = []
    returns = []
    mutations = []
    output_parameters = []
    warnings = []
    processed = 0
    incomplete = False
    identity_budget = {"ids": set(), "aliases": 0, "exceeded": set(),
                       "max_values": max_values, "max_aliases": max_aliases,
                       "max_versions": max_versions}

    for function_rva, sources in sorted(by_function.items()):
        function = next((fn for fn in context.functions if fn.rva == function_rva), None)
        if function is None:
            continue
        records = sorted(context.function_records.get(function_rva, []), key=lambda pair: pair[0].rva)
        activate: dict[int, list[Any]] = {}
        for source in sources:
            activate.setdefault(source.callsite_rva, []).append(source)
        registers = {}
        memory = {}
        pending_pushes = []
        stack_delta = 0
        argument_aliases = ({family: index for index, family in enumerate(X64_ARGUMENTS)}
                            if architecture == "x86-64" else {})
        source_arguments = {
            (source.value_identity or identity_for_source(source)).id: source.destination.index
            for source in sources if isinstance(source.destination, ArgumentLocation)
        }

        def x86_call_arguments():
            stored = {
                key[2] // 4: value
                for key, value in memory.items()
                if len(key) == 3 and key[:2] == ("stack", "sp") and key[2] >= 0 and key[2] % 4 == 0
            }
            if stored:
                return [(index, stored[index]) for index in sorted(stored) if index < 12]
            return list(enumerate(reversed(pending_pushes[-12:])))
        for source in sources:
            identity = source.value_identity or identity_for_source(source)
            tracked_source = TrackedValue(source.destination, identity)
            if isinstance(source.destination, ArgumentLocation) and source.callsite_rva == function_rva:
                index = source.destination.index
                if architecture == "x86-64" and index < len(X64_ARGUMENTS):
                    registers[X64_ARGUMENTS[index]] = tracked_source
                elif architecture == "x86":
                    memory[("argument", index)] = tracked_source
            elif source.callsite_rva == function_rva and not isinstance(
                    source.destination, (ReturnValueLocation, RegisterLocation)):
                key = _loc_key(source.destination)
                if key is not None:
                    memory[key] = tracked_source
        for instruction, decoded in records:
            if len(registers) + len(memory) > max_flow_states:
                incomplete = True
                warnings.append("BUDGET_LIMIT: max flow states reached")
                break
            processed += 1
            if processed > max_instructions:
                incomplete = True
                warnings.append("Static flow instruction budget reached")
                break

            # Calls consume the current argument state before their return clobbers RAX/EAX.
            target, call_confidence, call_kind = _call_target(decoded, context.image_base, context)
            if decoded.group(CS_GRP_CALL):
                indirect_result = None
                if target is not None:
                    if architecture == "x86-64":
                        for index, family in enumerate(X64_ARGUMENTS):
                            source_location = registers.get(family)
                            if source_location is None:
                                continue
                            destination = ArgumentLocation(target, index)
                            if not _append_edge(edges, source_location, destination, instruction, "ARGUMENT", call_confidence,
                                                f"{family.upper()} supplies {call_kind} call argument {index}", max_edges, identity_budget):
                                incomplete = True
                                break
                            call_arguments.append({"caller_function_rva": function_rva, "callsite_rva": instruction.rva,
                                                   "callee_rva": target, "argument_index": index,
                                                   "source": source_location.to_dict(), "confidence": call_confidence,
                                                   "resolution": call_kind,
                                                   "value_identity": source_location.identity.to_dict()})
                    else:
                        # Values are captured when PUSH executes so later register writes
                        # cannot retroactively change an earlier argument.
                        for index, source_location in x86_call_arguments():
                            if source_location is None:
                                continue
                            destination = ArgumentLocation(target, index)
                            _append_edge(edges, source_location, destination, instruction, "ARGUMENT", "LIKELY",
                                         f"x86 PUSH supplies {call_kind} call argument {index}", max_edges, identity_budget)
                            call_arguments.append({"caller_function_rva": function_rva, "callsite_rva": instruction.rva,
                                                   "callee_rva": target, "argument_index": index,
                                                   "source": source_location.to_dict(), "confidence": "LIKELY",
                                                   "resolution": call_kind,
                                                   "value_identity": source_location.identity.to_dict()})
                elif architecture == "x86-64":
                    # Imported/indirect calls are sinks only. Never propagate through an unknown target.
                    for index, family in enumerate(X64_ARGUMENTS):
                        source_location = registers.get(family)
                        if source_location is None:
                            continue
                        destination = UnknownLocation(f"indirect-call@RVA_0x{instruction.rva:X}.arg{index}")
                        _append_edge(edges, source_location, destination, instruction, "ARGUMENT", "CONFIRMED",
                                     f"{family.upper()} supplies indirect/import call argument {index}", max_edges, identity_budget)
                        call_arguments.append({"caller_function_rva": function_rva, "callsite_rva": instruction.rva,
                                               "callee_rva": None, "argument_index": index,
                                               "source": source_location.to_dict(), "confidence": "CONFIRMED",
                                               "value_identity": source_location.identity.to_dict()})
                        operand = decoded.operands[0] if decoded.operands else None
                        local_indirect = bool(
                            operand is not None and operand.type in {X86_OP_REG, X86_OP_MEM}
                            and not (operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP)
                        )
                        if local_indirect and indirect_result is None:
                            indirect_result = source_location
                else:
                    for index, source_location in x86_call_arguments():
                        if source_location is None:
                            continue
                        destination = UnknownLocation(f"indirect-call@RVA_0x{instruction.rva:X}.arg{index}")
                        _append_edge(edges, source_location, destination, instruction, "ARGUMENT", "LIKELY",
                                     f"x86 PUSH supplies indirect/import call argument {index}", max_edges, identity_budget)
                        call_arguments.append({"caller_function_rva": function_rva, "callsite_rva": instruction.rva,
                                               "callee_rva": None, "argument_index": index,
                                               "source": source_location.to_dict(), "confidence": "LIKELY",
                                               "value_identity": source_location.identity.to_dict()})
                registers.pop("a", None)
                if indirect_result is not None:
                    destination = ReturnValueLocation(function_rva, instruction.rva, "a")
                    identity = indirect_result.identity.derived(
                        f"local indirect-call scalar result at RVA 0x{instruction.rva:X}",
                        transformed=True,
                    )
                    returned = TrackedValue(destination, identity)
                    _append_edge(edges, indirect_result, returned, instruction, "RETURN", "LIKELY",
                                 "source-reachable argument enters a local indirect checker and produces a scalar result",
                                 max_edges, identity_budget)
                    registers["a"] = returned
                pending_pushes.clear()
                if architecture == "x86":
                    for key in tuple(memory):
                        if len(key) == 3 and key[:2] == ("stack", "sp") and key[2] >= 0:
                            memory.pop(key, None)

            operands = list(decoded.operands)
            mnemonic = decoded.mnemonic.lower()
            if architecture == "x86" and mnemonic == "push" and operands:
                pending_pushes.append(_resolve(decoded, operands[0], function_rva, context.image_base,
                                               registers, memory, stack_delta))
            if mnemonic.startswith("ret") and registers.get("a") is not None:
                returns.append({"function_rva": function_rva, "instruction_rva": instruction.rva,
                                "source": registers["a"].to_dict(), "confidence": "CONFIRMED",
                                "value_identity": registers["a"].identity.to_dict()})
            if mnemonic in {"cmp", "test"}:
                tainted = []
                tainted_values = []
                for operand in operands[:2]:
                    source_location = _resolve(decoded, operand, function_rva, context.image_base,
                                               registers, memory, stack_delta)
                    if source_location is not None:
                        sink = UnknownLocation(f"compare@RVA_0x{instruction.rva:X}")
                        _append_edge(edges, source_location, sink, instruction, "COMPARE", "CONFIRMED",
                                     f"tainted operand reaches {mnemonic.upper()}", max_edges, identity_budget)
                        tainted.append(source_location.to_dict())
                        tainted_values.append(source_location)
                input_flow = "NONE"
                if tainted_values:
                    input_flow = min(
                        (value.identity.confidence for value in tainted_values),
                        key={"POSSIBLE": 0, "LIKELY": 1, "CONFIRMED": 2}.get,
                    )
                comparisons.append({"function_rva": function_rva, "instruction_rva": instruction.rva,
                                    "mnemonic": mnemonic, "tainted_operands": tainted,
                                    "input_flow": input_flow,
                                    "value_identities": [value.identity.to_dict() for value in tainted_values]})

            handled_write = False
            if operands and operands[0].type == X86_OP_REG:
                destination_family = register_family(decoded.reg_name(operands[0].reg))
                if mnemonic in {"mov", "movzx", "movsx", "lea"} and len(operands) >= 2:
                    source_location = _resolve(decoded, operands[1], function_rva, context.image_base,
                                               registers, memory, stack_delta)
                    # LEA of a tainted stack/global object carries its address to the argument register.
                    if mnemonic == "lea" and source_location is None:
                        raw = _normalize_stack(
                            _base_location(decoded, operands[1], function_rva, context.image_base), stack_delta,
                        )
                        source_location = memory.get(_loc_key(raw))
                    table_lookup = False
                    if source_location is None and mnemonic in {"mov", "movzx", "movsx"} and operands[1].type == X86_OP_MEM:
                        base, index, _, _ = _memory_key(decoded, operands[1])
                        source_location = registers.get(index) if index else None
                        if source_location is not None:
                            table_lookup = True
                    if source_location is not None:
                        destination = RegisterLocation(destination_family, function_rva, instruction.rva)
                        edge_type = "TRANSFORM" if table_lookup else "ADDRESS" if mnemonic == "lea" else "LOAD" if operands[1].type == X86_OP_MEM else "COPY"
                        confidence = "POSSIBLE" if table_lookup or isinstance(source_location.location, MemoryLocation) else "CONFIRMED"
                        copied = TrackedValue(destination, source_location.identity.copied(
                            f"{mnemonic.upper()} at RVA 0x{instruction.rva:X}"
                        ))
                        _append_edge(edges, source_location, copied, instruction, edge_type, confidence,
                                     "indexed memory load is a possible TABLE_LOOKUP" if table_lookup else f"{mnemonic.upper()} propagates a source-reachable value", max_edges, identity_budget)
                        registers[destination_family] = copied
                        if table_lookup:
                            transforms.append({"function_rva": function_rva, "instruction_rva": instruction.rva,
                                               "type": "TABLE_LOOKUP", "confidence": "POSSIBLE"})
                    else:
                        registers.pop(destination_family, None)
                    handled_write = True
                    source_alias = None
                    if operands[1].type == X86_OP_REG:
                        source_alias = argument_aliases.get(register_family(decoded.reg_name(operands[1].reg)))
                    elif operands[1].type == X86_OP_MEM:
                        raw_source = _normalize_stack(
                            _base_location(decoded, operands[1], function_rva, context.image_base), stack_delta,
                        )
                        key = _loc_key(raw_source)
                        if key and len(key) == 3 and key[:2] == ("stack", "sp"):
                            source_alias = memory.get(("argument-alias", key[2]))
                        elif isinstance(raw_source, ArgumentLocation):
                            source_alias = raw_source.index
                    if source_alias is None:
                        argument_aliases.pop(destination_family, None)
                    else:
                        argument_aliases[destination_family] = source_alias
                elif mnemonic in TRANSFORMS:
                    old = registers.get(destination_family)
                    right = _resolve(decoded, operands[1], function_rva, context.image_base,
                                     registers, memory, stack_delta) if len(operands) > 1 else None
                    zero_idiom = (
                        mnemonic == "xor" and len(operands) >= 2
                        and operands[1].type == X86_OP_REG
                        and register_family(decoded.reg_name(operands[1].reg)) == destination_family
                    )
                    if zero_idiom:
                        registers.pop(destination_family, None)
                    elif old is not None or right is not None:
                        origin_value = old or right
                        destination = RegisterLocation(destination_family, function_rva, instruction.rva)
                        pointer_delta = 0
                        if len(operands) > 1 and operands[1].type == X86_OP_IMM and mnemonic in {"add", "sub"}:
                            pointer_delta = int(operands[1].imm) * (1 if mnemonic == "add" else -1)
                        transform_evidence = f"{TRANSFORMS[mnemonic]} at RVA 0x{instruction.rva:X}"
                        if mnemonic in {"add", "sub"}:
                            next_identity = origin_value.identity.derived(
                                transform_evidence, offset=pointer_delta,
                                possible=len(operands) > 1 and operands[1].type == X86_OP_REG,
                                transformed=True,
                            )
                        else:
                            next_identity = origin_value.identity.transformed(transform_evidence)
                        transformed = TrackedValue(destination, next_identity)
                        _append_edge(edges, origin_value, transformed, instruction, "TRANSFORM", "CONFIRMED",
                                     f"{TRANSFORMS[mnemonic]} transforms a source-reachable register", max_edges, identity_budget)
                        registers[destination_family] = transformed
                        transforms.append({"function_rva": function_rva, "instruction_rva": instruction.rva,
                                           "type": TRANSFORMS[mnemonic], "confidence": "CONFIRMED"})
                    handled_write = True

            if operands and operands[0].type == X86_OP_MEM and mnemonic in {"mov", "movzx", "movsx"} and len(operands) >= 2:
                raw_destination = _defined(decoded, operands[0], function_rva, context.image_base,
                                           instruction.rva, stack_delta)
                key = _loc_key(raw_destination)
                source_location = _resolve(decoded, operands[1], function_rva, context.image_base,
                                           registers, memory, stack_delta)
                base = (register_family(decoded.reg_name(operands[0].mem.base))
                        if operands[0].mem.base != X86_REG_INVALID else None)
                destination_argument = argument_aliases.get(base)
                if key is not None:
                    if source_location is not None:
                        stored = TrackedValue(raw_destination, source_location.identity.copied(
                            f"spill/store at RVA 0x{instruction.rva:X}"
                        ))
                        _append_edge(edges, source_location, stored, instruction, "STORE", "CONFIRMED",
                                     "store propagates a source-reachable value", max_edges, identity_budget)
                        memory[key] = stored
                        source_argument = source_arguments.get(source_location.identity.id)
                        if destination_argument is not None and source_argument is not None:
                            output_parameters.append({
                                "function_rva": function_rva,
                                "instruction_rva": instruction.rva,
                                "source_argument": source_argument,
                                "destination_argument": destination_argument,
                                "confidence": "LIKELY",
                                "value_identity": stored.identity.to_dict(),
                            })
                    else:
                        base_value = registers.get(base) if base else None
                        if destination_argument is not None and base_value is not None:
                            changed = TrackedValue(raw_destination, base_value.identity.transformed(
                                f"direct write through argument {destination_argument} at RVA 0x{instruction.rva:X}"
                            ))
                            _append_edge(edges, base_value, changed, instruction, "STORE", "LIKELY",
                                         "direct store mutates a source-reachable argument object",
                                         max_edges, identity_budget)
                            memory[key] = changed
                            mutations.append({"function_rva": function_rva,
                                              "instruction_rva": instruction.rva,
                                              "argument_index": destination_argument,
                                              "confidence": "LIKELY",
                                              "value_identity": changed.identity.to_dict()})
                        else:
                            memory.pop(key, None)  # obvious stack/global overwrite kill
                if (architecture == "x86-64" and isinstance(raw_destination, StackLocation)
                        and operands[1].type == X86_OP_REG):
                    alias = argument_aliases.get(register_family(decoded.reg_name(operands[1].reg)))
                    alias_key = ("argument-alias", raw_destination.offset)
                    if alias is None:
                        memory.pop(alias_key, None)
                    else:
                        memory[alias_key] = alias

            if operands and operands[0].type == X86_OP_MEM and mnemonic in TRANSFORMS:
                raw_destination = _defined(decoded, operands[0], function_rva, context.image_base,
                                           instruction.rva, stack_delta)
                key = _loc_key(raw_destination)
                old = memory.get(key)
                base = (register_family(decoded.reg_name(operands[0].mem.base))
                        if operands[0].mem.base != X86_REG_INVALID else None)
                destination_argument = argument_aliases.get(base)
                if old is None and base is not None:
                    old = registers.get(base)
                if key is not None and old is not None:
                    transform_evidence = f"{TRANSFORMS[mnemonic]} memory transform at RVA 0x{instruction.rva:X}"
                    if mnemonic in {"add", "sub"}:
                        next_identity = old.identity.derived(
                            transform_evidence,
                            index=raw_destination.index if isinstance(raw_destination, MemoryLocation) else None,
                            scale=raw_destination.scale if isinstance(raw_destination, MemoryLocation) else 1,
                            transformed=True,
                        )
                    else:
                        next_identity = old.identity.transformed(transform_evidence)
                    transformed = TrackedValue(raw_destination, next_identity)
                    _append_edge(edges, old, transformed, instruction, "TRANSFORM", "LIKELY",
                                 f"{TRANSFORMS[mnemonic]} transforms source-reachable memory", max_edges, identity_budget)
                    memory[key] = transformed
                    transforms.append({"function_rva": function_rva, "instruction_rva": instruction.rva,
                                       "type": TRANSFORMS[mnemonic], "confidence": "LIKELY"})
                    if destination_argument is not None:
                        mutations.append({"function_rva": function_rva,
                                          "instruction_rva": instruction.rva,
                                          "argument_index": destination_argument,
                                          "confidence": "LIKELY",
                                          "value_identity": transformed.identity.to_dict()})

            # Any unsupported write kills the previous register version.
            if not handled_write:
                _, written = register_access(decoded)
                for family in written:
                    if family != "flags":
                        registers.pop(family, None)
                        argument_aliases.pop(family, None)

            for source in activate.get(instruction.rva, []):
                destination = source.destination
                if isinstance(destination, ReturnValueLocation):
                    seeded = RegisterLocation(destination.register, function_rva, instruction.rva)
                    registers[destination.register] = TrackedValue(seeded, source.value_identity or identity_for_source(source))
                elif isinstance(destination, RegisterLocation):
                    seeded = RegisterLocation(destination.name, function_rva, instruction.rva)
                    registers[destination.name] = TrackedValue(seeded, source.value_identity or identity_for_source(source))
                else:
                    memory[_loc_key(destination)] = TrackedValue(destination, source.value_identity or identity_for_source(source))
            if architecture == "x86-64":
                if mnemonic == "push":
                    stack_delta -= 8
                elif mnemonic == "pop":
                    stack_delta += 8
                elif mnemonic in {"sub", "add"} and len(operands) >= 2:
                    left, amount = operands[:2]
                    if (left.type == X86_OP_REG and register_family(decoded.reg_name(left.reg)) == "sp"
                            and amount.type == X86_OP_IMM):
                        stack_delta += (-1 if mnemonic == "sub" else 1) * int(amount.imm)
        if incomplete:
            break
    if len(edges) >= max_edges:
        incomplete = True
        warnings.append("Static flow edge budget reached")
    if identity_budget["exceeded"]:
        incomplete = True
        warnings.extend(f"BUDGET_LIMIT: {name} reached" for name in sorted(identity_budget["exceeded"]))
    budgets = {"max_values": max_values, "max_aliases": max_aliases,
               "max_versions": max_versions, "max_flow_states": max_flow_states}
    return IntraFlowResult(tuple(edges), tuple(call_arguments), tuple(comparisons), tuple(transforms), tuple(returns),
                           tuple(dict.fromkeys(warnings)), incomplete, budgets,
                           tuple(_unique_event(mutations)), tuple(_unique_event(output_parameters)))


def _unique_event(items):
    unique = {}
    for item in items:
        key = tuple(sorted((name, repr(value)) for name, value in item.items()))
        unique[key] = item
    return unique.values()
