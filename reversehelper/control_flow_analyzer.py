"""Classify x86/x64 control transfers without building a full CFG."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_INVALID, X86_REG_RIP

from .disassembler import iter_instruction_details
from .findings import Instruction


def _preferred_rva(address: int | None, image_base: int) -> int | None:
    if address is None or address < image_base:
        return None
    return address - image_base


def analyze_control_transfers(
    instructions: Iterable[Instruction],
    architecture: str,
    image_base: int,
    *,
    instruction_details: Iterable[tuple[Instruction, Any]] | None = None,
) -> list[dict[str, Any]]:
    transfers: list[dict[str, Any]] = []
    details = (
        instruction_details
        if instruction_details is not None
        else iter_instruction_details(instructions, architecture)
    )

    for instruction, decoded in details:
        if decoded.group(CS_GRP_CALL):
            transfer_type = "call"
        elif decoded.group(CS_GRP_JUMP):
            transfer_type = "jmp" if decoded.mnemonic == "jmp" else "jcc"
        elif decoded.group(CS_GRP_RET):
            transfer_type = "ret"
        else:
            continue

        direct: bool | None = None
        target_status = "not-applicable"
        target_address = None
        pointer_address = None

        if transfer_type != "ret" and decoded.operands:
            operand = decoded.operands[0]
            if operand.type == X86_OP_IMM:
                direct = True
                target_status = "resolved"
                target_address = int(operand.imm)
            else:
                direct = False
                target_status = "unresolved"
                if operand.type == X86_OP_MEM:
                    if operand.mem.base == X86_REG_RIP:
                        pointer_address = int(decoded.address + decoded.size + operand.mem.disp)
                    elif operand.mem.base == X86_REG_INVALID and operand.mem.index == X86_REG_INVALID:
                        pointer_address = int(operand.mem.disp)

        transfers.append(
            {
                "transfer_type": transfer_type,
                "mnemonic": decoded.mnemonic,
                "op_str": decoded.op_str,
                "source_address": instruction.address,
                "source_rva": instruction.rva,
                "file_offset": instruction.file_offset,
                "direct": direct,
                "target_status": target_status,
                "target_address": target_address,
                "target_rva": _preferred_rva(target_address, image_base),
                "pointer_address": pointer_address,
                "pointer_rva": _preferred_rva(pointer_address, image_base),
            }
        )

    return transfers
