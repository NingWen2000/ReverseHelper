"""Recover structured Windows PE input sources and their immediate destinations."""

from __future__ import annotations

import re
from typing import Any

from capstone import CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, X86_REG_RIP

from .dataflow_model import (
    ArgumentLocation, GlobalLocation, ImmediateLocation, InputSource, MemoryLocation,
    RegisterLocation, ReturnValueLocation, StackLocation, UnknownLocation, ValueLocation,
)
from .instruction_context import follows, register_access, register_family
from .value_identity import ValueIdentity


INPUT_SIGNATURES = {
    "scanf": (1, None), "scanf_s": (1, None), "__isoc99_scanf": (1, None),
    "gets": (0, None), "gets_s": (0, 1), "fgets": (0, 1),
    "readfile": (1, 2), "readconsolea": (1, 2), "readconsolew": (1, 2),
    "read": (1, 2), "recv": (1, 2), "recvfrom": (1, 2),
    "getdlgitemtexta": (2, 3), "getdlgitemtextw": (2, 3),
    "getwindowtexta": (1, 2), "getwindowtextw": (1, 2),
}
RETURN_INPUTS = {"getcommandlinea", "getcommandlinew"}
X64_ARGUMENTS = ("c", "d", "r8", "r9")


def _memory_location(decoded, operand, function_rva: int, image_base: int) -> ValueLocation:
    mem = operand.mem
    base = register_family(decoded.reg_name(mem.base)) if mem.base != X86_REG_INVALID else None
    index = register_family(decoded.reg_name(mem.index)) if mem.index != X86_REG_INVALID else None
    if base in {"bp", "sp"} and index is None:
        raw_base = decoded.reg_name(mem.base).lower() if mem.base != X86_REG_INVALID else ""
        if raw_base in {"ebp", "bp"} and base == "bp" and int(mem.disp) >= 8 and int(mem.disp) % 4 == 0:
            return ArgumentLocation(function_rva, (int(mem.disp) - 8) // 4)
        return StackLocation(function_rva, int(mem.disp), base)
    if base == "rip" and index is None:
        address = int(decoded.address + decoded.size + mem.disp)
        return GlobalLocation(address - image_base, address)
    if base is None and index is None and int(mem.disp) >= image_base:
        return GlobalLocation(int(mem.disp) - image_base, int(mem.disp))
    return MemoryLocation(base, index, int(mem.scale), int(mem.disp), function_rva)


def _operand_location(decoded, operand, function_rva: int, image_base: int) -> ValueLocation:
    if operand.type == X86_OP_REG:
        return RegisterLocation(register_family(decoded.reg_name(operand.reg)))
    if operand.type == X86_OP_MEM:
        return _memory_location(decoded, operand, function_rva, image_base)
    if operand.type == X86_OP_IMM:
        value = int(operand.imm)
        return GlobalLocation(value - image_base, value) if value >= image_base else ImmediateLocation(value)
    return UnknownLocation("unsupported operand")


def _backward_register(records, call_index: int, family: str, function_rva: int, image_base: int,
                       *, maximum: int = 32) -> ValueLocation:
    wanted = family
    steps = 0
    for index in range(call_index - 1, -1, -1):
        instruction, decoded = records[index]
        if not follows(instruction, records[index + 1][0]):
            break
        if decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_JUMP):
            break
        _, written = register_access(decoded)
        if wanted not in written:
            continue
        steps += 1
        if steps > maximum or len(decoded.operands) < 2 or decoded.mnemonic not in {"mov", "movzx", "movsx", "lea"}:
            return UnknownLocation(f"{wanted} overwritten by unsupported instruction")
        destination, source = decoded.operands[:2]
        if destination.type != X86_OP_REG:
            return UnknownLocation(f"{wanted} write is not a register assignment")
        location = _operand_location(decoded, source, function_rva, image_base)
        if isinstance(location, RegisterLocation):
            wanted = location.name
            continue
        return location
    argument_map = {"c": 0, "d": 1, "r8": 2, "r9": 3}
    if wanted in argument_map:
        return ArgumentLocation(function_rva, argument_map[wanted])
    return UnknownLocation(f"value of register {wanted} is unresolved")


def _x86_arguments(records, call_index: int, function_rva: int, image_base: int, maximum: int = 12):
    pushed_arguments = []
    stack_arguments = {}
    for index in range(call_index - 1, max(-1, call_index - maximum - 1), -1):
        instruction, decoded = records[index]
        if not follows(instruction, records[index + 1][0]):
            break
        if decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_JUMP):
            break
        if decoded.mnemonic == "push" and decoded.operands:
            location = _operand_location(decoded, decoded.operands[0], function_rva, image_base)
            if isinstance(location, RegisterLocation):
                location = _backward_register(records, index, location.name, function_rva, image_base)
            pushed_arguments.append(location)
            continue
        if decoded.mnemonic != "mov" or len(decoded.operands) < 2 or decoded.operands[0].type != X86_OP_MEM:
            continue
        destination, source = decoded.operands[:2]
        base = register_family(decoded.reg_name(destination.mem.base)) if destination.mem.base != X86_REG_INVALID else None
        if base != "sp" or destination.mem.index != X86_REG_INVALID:
            continue
        displacement = int(destination.mem.disp)
        if displacement < 0 or displacement % 4:
            continue
        argument_index = displacement // 4
        if argument_index in stack_arguments:
            continue
        location = _operand_location(decoded, source, function_rva, image_base)
        if isinstance(location, RegisterLocation):
            location = _backward_register(records, index, location.name, function_rva, image_base)
        stack_arguments[argument_index] = location
    if stack_arguments:
        return [stack_arguments.get(index, UnknownLocation(f"x86 argument {index} unresolved"))
                for index in range(max(stack_arguments) + 1)]
    return pushed_arguments


def _argument(records, call_index, index, architecture, function_rva, image_base):
    if architecture == "x86-64":
        if index >= len(X64_ARGUMENTS):
            return UnknownLocation(f"stack argument {index} is outside Quick support")
        return _backward_register(records, call_index, X64_ARGUMENTS[index], function_rva, image_base)
    arguments = _x86_arguments(records, call_index, function_rva, image_base)
    return arguments[index] if index < len(arguments) else UnknownLocation(f"x86 argument {index} unresolved")


def recover_call_argument(context, callsite_rva: int, argument_index: int, architecture: str) -> ValueLocation:
    """Recover one direct-call argument without asserting that it is source-reachable."""
    function = context.owner(callsite_rva)
    if function is None:
        return UnknownLocation("callsite has no function owner")
    records = context.function_records.get(function.rva, [])
    call_index = next((i for i, (ins, _) in enumerate(records) if ins.rva == callsite_rva), None)
    if call_index is None:
        return UnknownLocation("callsite is outside the bounded function records")
    return _argument(records, call_index, argument_index, architecture, function.rva, context.image_base)


def _immediate_value(location: ValueLocation) -> int | None:
    return location.value if isinstance(location, ImmediateLocation) else None


def _scanf_size_hint(records, call_index, architecture, function_rva, image_base, strings):
    fmt = _argument(records, call_index, 0, architecture, function_rva, image_base)
    if not isinstance(fmt, GlobalLocation):
        return None
    match = next((item for item in strings if item.get("rva") == fmt.rva), None)
    if not match:
        return None
    width = re.search(r"%(?:\*)?(\d+)s", str(match.get("value", "")))
    return int(width.group(1)) if width else None


def _source_identity(source_id: str, source_type: str, index: int | None,
                     confidence: str, evidence: tuple[str, ...]) -> ValueIdentity:
    label = "*" if index is None else str(index)
    return ValueIdentity(
        id=f"value-{source_id}", origin=source_id,
        base_object={"kind": "ARGV", "object": f"ArgvObject#{label}", "index": index},
        index=None if index is not None else "*", confidence=confidence,
        provenance=(f"{source_type} recovered from program argument vector", *evidence),
        alias_confidence="EXACT_ALIAS" if index is not None else "POSSIBLE_ALIAS",
    )


def _argument_register_aliases(records, architecture: str, argument_index: int) -> set[str]:
    """Bounded aliases of an incoming register argument, stopping at ambiguous writes."""
    if architecture != "x86-64" or argument_index >= len(X64_ARGUMENTS):
        return set()
    aliases = {X64_ARGUMENTS[argument_index]}
    for _, decoded in records[:64]:
        if decoded.group(CS_GRP_CALL):
            break
        if decoded.mnemonic in {"mov", "lea"} and len(decoded.operands) >= 2:
            destination, source = decoded.operands[:2]
            if destination.type == X86_OP_REG and source.type == X86_OP_REG:
                destination_family = register_family(decoded.reg_name(destination.reg))
                source_family = register_family(decoded.reg_name(source.reg))
                if source_family in aliases:
                    aliases.add(destination_family)
                    continue
        _, written = register_access(decoded)
        aliases.difference_update(written)
    return aliases


def _argc_evidence(records, function_rva: int, architecture: str, image_base: int) -> bool:
    for _, decoded in records:
        if decoded.mnemonic != "cmp" or len(decoded.operands) < 2:
            continue
        first = decoded.operands[0]
        second = decoded.operands[1]
        if second.type != X86_OP_IMM or not 0 <= int(second.imm) <= 0x1000:
            continue
        if architecture == "x86-64" and first.type == X86_OP_REG:
            if register_family(decoded.reg_name(first.reg)) == "c":
                return True
        elif architecture == "x86" and first.type == X86_OP_MEM:
            location = _memory_location(decoded, first, function_rva, image_base)
            if isinstance(location, ArgumentLocation) and location.index == 0:
                return True
    return False


def _constant_before(records, end: int, family: str, *, maximum: int = 8) -> int | None:
    """Evaluate the tiny constant chains compilers use for argv subscripts."""
    value = None
    for index in range(max(0, end - maximum), end):
        _, decoded = records[index]
        if decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_JUMP):
            value = None
            continue
        if family not in register_access(decoded)[1] or not decoded.operands:
            continue
        destination = decoded.operands[0]
        if destination.type != X86_OP_REG or register_family(decoded.reg_name(destination.reg)) != family:
            continue
        if len(decoded.operands) >= 2 and decoded.mnemonic in {"mov", "movabs"} and decoded.operands[1].type == X86_OP_IMM:
            value = int(decoded.operands[1].imm)
        elif (decoded.mnemonic == "imul" and len(decoded.operands) == 3
              and decoded.operands[1].type == X86_OP_REG and decoded.operands[2].type == X86_OP_IMM):
            source_family = register_family(decoded.reg_name(decoded.operands[1].reg))
            source_value = _constant_before(records, index, source_family, maximum=maximum)
            value = source_value * int(decoded.operands[2].imm) if source_value is not None else None
        elif len(decoded.operands) >= 2 and value is not None and decoded.operands[1].type == X86_OP_IMM:
            immediate = int(decoded.operands[1].imm)
            if decoded.mnemonic == "add":
                value += immediate
            elif decoded.mnemonic == "sub":
                value -= immediate
            elif decoded.mnemonic in {"shl", "sal"}:
                value <<= immediate
            elif decoded.mnemonic == "imul":
                value *= immediate
            else:
                value = None
        else:
            value = None
    return value


def _x64_stack_state(records):
    """Return canonical entry-RSP slots holding argc/argv plus per-record RSP deltas."""
    delta = 0
    deltas = []
    argc_slots = set()
    argv_slots = set()
    for _, decoded in records:
        deltas.append(delta)
        if decoded.mnemonic == "mov" and len(decoded.operands) >= 2 and decoded.operands[0].type == X86_OP_MEM:
            destination, source = decoded.operands[:2]
            base = register_family(decoded.reg_name(destination.mem.base)) if destination.mem.base != X86_REG_INVALID else None
            if base == "sp" and destination.mem.index == X86_REG_INVALID and source.type == X86_OP_REG:
                slot = delta + int(destination.mem.disp)
                family = register_family(decoded.reg_name(source.reg))
                if family == "c":
                    argc_slots.add(slot)
                elif family == "d":
                    argv_slots.add(slot)
        if decoded.mnemonic == "push":
            delta -= 8
        elif decoded.mnemonic == "pop":
            delta += 8
        elif decoded.mnemonic in {"sub", "add"} and len(decoded.operands) >= 2:
            destination, amount = decoded.operands[:2]
            if (destination.type == X86_OP_REG and register_family(decoded.reg_name(destination.reg)) == "sp"
                    and amount.type == X86_OP_IMM):
                delta += (-1 if decoded.mnemonic == "sub" else 1) * int(amount.imm)
    return argc_slots, argv_slots, deltas


def _argv_sources(context, architecture: str, *, allow_unnamed=True) -> list[InputSource]:
    found = []
    for function in context.functions:
        normalized_name = function.name.casefold().lstrip("_")
        if not allow_unnamed and normalized_name not in {"main", "wmain"}:
            continue
        function_found = []
        records = context.function_records.get(function.rva, [])
        argc_seen = (_argc_evidence(records, function.rva, architecture, context.image_base)
                     if architecture == "x86-64" else False)
        argc_slots, argv_slots, stack_deltas = _x64_stack_state(records) if architecture == "x86-64" else (set(), set(), [0] * len(records))
        if architecture == "x86-64" and argc_slots:
            for position, (_, decoded) in enumerate(records):
                if decoded.mnemonic != "cmp" or len(decoded.operands) < 2 or decoded.operands[1].type != X86_OP_IMM:
                    continue
                operand = decoded.operands[0]
                if operand.type != X86_OP_MEM or operand.mem.base == X86_REG_INVALID:
                    continue
                if (register_family(decoded.reg_name(operand.mem.base)) == "sp"
                        and stack_deltas[position] + int(operand.mem.disp) in argc_slots):
                    argc_seen = True
        argv_registers = {"d"} if architecture == "x86-64" else set()
        for position, (instruction, decoded) in enumerate(records):
            if architecture == "x86" and decoded.mnemonic == "cmp" and len(decoded.operands) >= 2:
                location = (_memory_location(decoded, decoded.operands[0], function.rva, context.image_base)
                            if decoded.operands[0].type == X86_OP_MEM else None)
                if (isinstance(location, ArgumentLocation) and location.index == 0
                        and decoded.operands[1].type == X86_OP_IMM
                        and 0 <= int(decoded.operands[1].imm) <= 0x1000):
                    argc_seen = True
            if decoded.mnemonic != "mov" or len(decoded.operands) < 2 or decoded.operands[0].type != X86_OP_REG:
                continue
            destination = register_family(decoded.reg_name(decoded.operands[0].reg))
            source = decoded.operands[1]
            if architecture == "x86" and source.type == X86_OP_MEM:
                loc = _memory_location(decoded, source, function.rva, context.image_base)
                if isinstance(loc, ArgumentLocation) and loc.index == 1:
                    argv_registers.add(destination)
                    continue
            if source.type == X86_OP_REG and register_family(decoded.reg_name(source.reg)) in argv_registers:
                argv_registers.add(destination)
                continue
            if source.type != X86_OP_MEM:
                continue
            base = register_family(decoded.reg_name(source.mem.base)) if source.mem.base != X86_REG_INVALID else None
            if (architecture == "x86-64" and base == "sp" and source.mem.index == X86_REG_INVALID
                    and stack_deltas[position] + int(source.mem.disp) in argv_slots):
                argv_registers.add(destination)
                continue
            pointer_size = 8 if architecture == "x86-64" else 4
            if not argc_seen or base not in argv_registers or source.mem.disp < 0:
                continue
            scaled_index = source.mem.index != X86_REG_INVALID
            byte_offset = int(source.mem.disp)
            if scaled_index:
                index_family = register_family(decoded.reg_name(source.mem.index))
                constant = _constant_before(records, position, index_family)
                if constant is not None:
                    byte_offset += constant * int(source.mem.scale)
                    scaled_index = False
            index = byte_offset // pointer_size if not scaled_index and byte_offset % pointer_size == 0 else None
            source_type = f"argv[{index}]" if index is not None else "argv[*]"
            confidence = "CONFIRMED" if index is not None else "LIKELY"
            evidence = ("argc is checked in the same function",
                        f"load from argv pointer offset {byte_offset if index is not None else source.mem.disp}",
                        "argv index is dynamic" if index is None else f"argv index {index} is statically recovered")
            source_id = f"input-argv-{function.rva:08X}-{instruction.rva:08X}"
            function_found.append(InputSource(
                source_id, function.name, function.rva,
                instruction.address, instruction.rva, source_type, RegisterLocation(destination), None,
                confidence, evidence, _source_identity(source_id, source_type, index, confidence, evidence),
            ))
        if architecture != "x86-64":
            found.extend(function_found)
        else:
            credible_main_frame = bool(argc_slots and argv_slots)
            if (normalized_name in {"main", "wmain"} or credible_main_frame
                    or function.source == "PE entry point"):
                found.extend(function_found)
    # Keep later reloads: an intervening string instruction or call can kill the
    # first register definition.  All reloads still name one canonical object.
    canonical = {}
    result = []
    for source in found:
        key = (source.function_rva, source.source_type)
        identity = canonical.setdefault(key, source.value_identity)
        result.append(InputSource(
            source.id, source.function, source.function_rva, source.callsite,
            source.callsite_rva, source.source_type, source.destination,
            source.size_hint, source.confidence, source.evidence, identity,
        ))
    return result


def _export_argument_sources(context, architecture: str) -> list[InputSource]:
    """Seed only exported parameters with pointer-like use on a compare/transform path."""
    found = []
    for function in context.functions:
        if function.source != "PE export" or function.is_thunk:
            continue
        records = context.function_records.get(function.rva, [])
        has_decision = any(
            decoded.mnemonic == "cmp" or (decoded.group(CS_GRP_JUMP) and decoded.mnemonic != "jmp")
            for _, decoded in records
        )
        has_transform = any(decoded.mnemonic in {"xor", "add", "sub", "rol", "ror", "imul", "and", "or"}
                            for _, decoded in records)
        if not (has_decision or has_transform):
            continue
        consumed: dict[int, list[str]] = {}
        if architecture == "x86-64":
            for argument_index, family in enumerate(X64_ARGUMENTS):
                aliases = _argument_register_aliases(records, architecture, argument_index)
                for position, (instruction, decoded) in enumerate(records[:128]):
                    for operand in decoded.operands:
                        if operand.type != X86_OP_MEM:
                            continue
                        base = register_family(decoded.reg_name(operand.mem.base)) if operand.mem.base != X86_REG_INVALID else None
                        direct_semantic_use = decoded.mnemonic in {"cmp", "test", "xor", "add", "sub", "and", "or"}
                        loaded_then_used = False
                        if (decoded.mnemonic in {"mov", "movzx", "movsx"} and decoded.operands[0].type == X86_OP_REG
                                and base in aliases):
                            loaded_family = register_family(decoded.reg_name(decoded.operands[0].reg))
                            loaded_then_used = any(
                                loaded_family in register_access(next_decoded)[0]
                                and next_decoded.mnemonic in {"cmp", "test", "xor", "add", "sub", "and", "or"}
                                for _, next_decoded in records[position + 1:position + 9]
                            )
                        if base in aliases and (direct_semantic_use or loaded_then_used):
                            consumed.setdefault(argument_index, []).append(
                                f"argument {argument_index} is dereferenced at RVA 0x{instruction.rva:X}")
        else:
            aliases: dict[str, int] = {}
            for instruction, decoded in records[:128]:
                if decoded.mnemonic in {"mov", "lea"} and len(decoded.operands) >= 2 and decoded.operands[0].type == X86_OP_REG:
                    destination = register_family(decoded.reg_name(decoded.operands[0].reg))
                    source = decoded.operands[1]
                    if source.type == X86_OP_MEM:
                        location = _memory_location(decoded, source, function.rva, context.image_base)
                        if isinstance(location, ArgumentLocation):
                            aliases[destination] = location.index
                            continue
                    if source.type == X86_OP_REG:
                        source_family = register_family(decoded.reg_name(source.reg))
                        if source_family in aliases:
                            aliases[destination] = aliases[source_family]
                            continue
                semantic = decoded.mnemonic in {"cmp", "test", "xor", "add", "sub", "and", "or", "imul"}
                if semantic:
                    for operand in decoded.operands:
                        if operand.type == X86_OP_MEM:
                            location = _memory_location(decoded, operand, function.rva, context.image_base)
                            if isinstance(location, ArgumentLocation):
                                consumed.setdefault(location.index, []).append(
                                    f"argument {location.index} reaches {decoded.mnemonic} at RVA 0x{instruction.rva:X}")
                        elif operand.type == X86_OP_REG:
                            family = register_family(decoded.reg_name(operand.reg))
                            if family in aliases:
                                index = aliases[family]
                                consumed.setdefault(index, []).append(
                                    f"argument {index} reaches {decoded.mnemonic} at RVA 0x{instruction.rva:X}")
                _, written = register_access(decoded)
                for family in written:
                    if not (decoded.mnemonic in {"mov", "lea"} and decoded.operands
                            and decoded.operands[0].type == X86_OP_REG
                            and register_family(decoded.reg_name(decoded.operands[0].reg)) == family):
                        aliases.pop(family, None)
        for index, uses in sorted(consumed.items()):
            confidence = "CONFIRMED" if has_decision and has_transform else "LIKELY"
            source_id = f"input-export-{function.rva:08X}-arg{index}"
            evidence = (f"PE export {function.name} consumes argument {index} as a pointer",
                        *(uses[:2]),
                        "same exported function contains validation/transform structure")
            identity = ValueIdentity(
                id=f"value-{source_id}", origin=source_id,
                base_object={"kind": "EXPORTED_ARGUMENT", "object": f"ExportArgObject#{function.rva:X}:{index}",
                             "function_rva": function.rva, "index": index},
                confidence=confidence, provenance=evidence,
            )
            found.append(InputSource(
                source_id, function.name, function.rva, function.address, function.rva,
                "EXPORTED_ARGUMENT", ArgumentLocation(function.rva, index), None,
                confidence, evidence, identity,
            ))
    return found


def discover_input_sources(context, import_calls, architecture: str, strings=(), *,
                           include_export_arguments=True, allow_unnamed_argv=True) -> list[InputSource]:
    """Return sources with destinations. Unknown destinations remain explicit and low confidence."""
    sources = []
    for transfer, dll, imported in import_calls:
        name = str(imported.get("name", "")).lower()
        if name not in INPUT_SIGNATURES and name not in RETURN_INPUTS:
            continue
        callsite_rva = int(transfer["source_rva"])
        function = context.owner(callsite_rva)
        if function is None:
            continue
        records = context.function_records.get(function.rva, [])
        call_index = next((i for i, (ins, _) in enumerate(records) if ins.rva == callsite_rva), None)
        if call_index is None:
            continue
        if name in RETURN_INPUTS:
            register = "a"
            destination = ReturnValueLocation(function.rva, callsite_rva, register)
            size_hint = None
            confidence = "CONFIRMED"
            evidence = (f"CALL {dll}!{imported['name']} returns the command-line pointer in RAX/EAX",)
        else:
            destination_index, size_index = INPUT_SIGNATURES[name]
            destination = _argument(records, call_index, destination_index, architecture, function.rva, context.image_base)
            size_location = _argument(records, call_index, size_index, architecture, function.rva, context.image_base) if size_index is not None else None
            size_hint = _immediate_value(size_location) if size_location is not None else None
            if name in {"scanf", "scanf_s", "__isoc99_scanf"}:
                size_hint = _scanf_size_hint(records, call_index, architecture, function.rva, context.image_base, strings)
            confidence = "POSSIBLE" if isinstance(destination, UnknownLocation) else "CONFIRMED"
            evidence = (f"CALL {dll}!{imported['name']} at RVA 0x{callsite_rva:X}",
                        f"documented destination argument {destination_index} recovered as {destination.kind}")
        sources.append(InputSource(
            f"input-{name}-{callsite_rva:08X}", function.name, function.rva,
            context.image_base + callsite_rva, callsite_rva, imported["name"], destination,
            size_hint, confidence, evidence,
        ))
    sources.extend(_argv_sources(context, architecture, allow_unnamed=allow_unnamed_argv))
    if include_export_arguments:
        sources.extend(_export_argument_sources(context, architecture))
    unique = {source.id: source for source in sources}
    return sorted(unique.values(), key=lambda source: (source.callsite_rva, source.id))
