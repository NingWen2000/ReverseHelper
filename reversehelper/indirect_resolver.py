"""Conservative single-target recovery for simple indirect call patterns."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, X86_REG_RIP

from .instruction_context import follows, register_access, register_family


@dataclass(frozen=True, slots=True)
class IndirectCallResolution:
    callsite_rva: int
    target_address: int | None
    storage_address: int | None
    confidence: str
    evidence: tuple[str, ...]
    unresolved_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "callsite_rva": self.callsite_rva,
            "target_address": self.target_address,
            "storage_address": self.storage_address,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "unresolved_reason": self.unresolved_reason,
        }


def _memory_key(decoded, operand):
    base = register_family(decoded.reg_name(operand.mem.base)) if operand.mem.base != X86_REG_INVALID else None
    index = register_family(decoded.reg_name(operand.mem.index)) if operand.mem.index != X86_REG_INVALID else None
    return base, index, int(operand.mem.scale), int(operand.mem.disp)


def _storage_address(decoded, operand):
    if operand.mem.index != X86_REG_INVALID:
        return None
    if operand.mem.base == X86_REG_RIP:
        return int(decoded.address + decoded.size + operand.mem.disp)
    if operand.mem.base == X86_REG_INVALID:
        return int(operand.mem.disp)
    return None


def _ambiguous_entry(records, definition_index: int, call_index: int, maximum: int) -> bool:
    definition_address = records[definition_index][0].address
    call_address = records[call_index][0].address
    for index in range(definition_index - 1, max(-1, definition_index - maximum - 1), -1):
        _, decoded = records[index]
        if decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_RET):
            break
        if not decoded.group(CS_GRP_JUMP) or decoded.mnemonic == "jmp" or not decoded.operands:
            continue
        if decoded.operands[0].type == X86_OP_IMM:
            target = int(decoded.operands[0].imm)
            if definition_address <= target <= call_address:
                return True
    return False


def resolve_indirect_call(records, call_index: int, image_base: int, *, max_steps: int = 48) -> IndirectCallResolution:
    """Resolve register calls through copies and one stack spill; stop at control-flow ambiguity."""
    instruction, call = records[call_index]
    if not call.group(CS_GRP_CALL) or not call.operands or call.operands[0].type != X86_OP_REG:
        return IndirectCallResolution(instruction.rva, None, None, "NONE", (), "call operand is not a register")
    wanted_register = register_family(call.reg_name(call.operands[0].reg))
    wanted_stack = None
    evidence = [f"indirect CALL uses {wanted_register} at RVA 0x{instruction.rva:X}"]
    steps = 0
    for index in range(call_index - 1, -1, -1):
        previous, decoded = records[index]
        if not follows(previous, records[index + 1][0]):
            break
        if decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_JUMP) or decoded.group(CS_GRP_RET):
            return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                          "control-flow boundary makes the assignment ambiguous")
        steps += 1
        if steps > max_steps:
            return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                          "indirect resolution budget reached")

        operands = list(decoded.operands)
        if wanted_stack is not None:
            if decoded.mnemonic != "mov" or len(operands) < 2 or operands[0].type != X86_OP_MEM:
                continue
            if _memory_key(decoded, operands[0]) != wanted_stack:
                continue
            source = operands[1]
            evidence.append(f"stack spill restored from RVA 0x{previous.rva:X}")
            wanted_stack = None
            if source.type == X86_OP_REG:
                wanted_register = register_family(decoded.reg_name(source.reg))
                continue
            if source.type == X86_OP_IMM:
                return IndirectCallResolution(instruction.rva, int(source.imm), None, "LIKELY", tuple(evidence))
            return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                          "stack assignment source is unsupported")

        _, written = register_access(decoded)
        if wanted_register not in written:
            continue
        if decoded.mnemonic not in {"mov", "movabs", "lea"} or len(operands) < 2 or operands[0].type != X86_OP_REG:
            return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                          f"{wanted_register} is overwritten by an unsupported instruction")
        source = operands[1]
        if source.type == X86_OP_REG:
            wanted_register = register_family(decoded.reg_name(source.reg))
            evidence.append(f"register copy at RVA 0x{previous.rva:X}")
            continue
        if source.type == X86_OP_IMM:
            if _ambiguous_entry(records, index, call_index, max_steps):
                return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                              "multiple control-flow paths can reach the call target assignment")
            evidence.append(f"single constant target assignment at RVA 0x{previous.rva:X}")
            return IndirectCallResolution(instruction.rva, int(source.imm), None, "LIKELY", tuple(evidence))
        if source.type == X86_OP_MEM:
            key = _memory_key(decoded, source)
            if key[0] in {"bp", "sp"} and key[1] is None:
                wanted_stack = key
                evidence.append(f"register restored from stack at RVA 0x{previous.rva:X}")
                continue
            address = _storage_address(decoded, source)
            if address is None:
                return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                              "memory target is not a constant storage slot")
            evidence.append(f"constant storage slot 0x{address:X} loaded at RVA 0x{previous.rva:X}")
            if decoded.mnemonic == "lea":
                if _ambiguous_entry(records, index, call_index, max_steps):
                    return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                                  "multiple control-flow paths can reach the call target assignment")
                return IndirectCallResolution(instruction.rva, address, None, "LIKELY", tuple(evidence))
            if _ambiguous_entry(records, index, call_index, max_steps):
                return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                              "multiple control-flow paths can reach the call target assignment")
            return IndirectCallResolution(instruction.rva, None, address, "LIKELY", tuple(evidence))
    return IndirectCallResolution(instruction.rva, None, None, "NONE", tuple(evidence),
                                  "no unique static assignment found")
