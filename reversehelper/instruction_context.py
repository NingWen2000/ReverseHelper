"""Small shared checks for local instruction context."""

from __future__ import annotations

from typing import Any

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, X86_REG_RIP

from .control_flow_analyzer import analyze_control_transfers
from .findings import Instruction


_LEGACY_REGISTER_FAMILIES = {
    "al": "a",
    "ah": "a",
    "ax": "a",
    "eax": "a",
    "rax": "a",
    "bl": "b",
    "bh": "b",
    "bx": "b",
    "ebx": "b",
    "rbx": "b",
    "cl": "c",
    "ch": "c",
    "cx": "c",
    "ecx": "c",
    "rcx": "c",
    "dl": "d",
    "dh": "d",
    "dx": "d",
    "edx": "d",
    "rdx": "d",
    "sil": "si",
    "si": "si",
    "esi": "si",
    "rsi": "si",
    "dil": "di",
    "di": "di",
    "edi": "di",
    "rdi": "di",
    "bpl": "bp",
    "bp": "bp",
    "ebp": "bp",
    "rbp": "bp",
    "spl": "sp",
    "sp": "sp",
    "esp": "sp",
    "rsp": "sp",
    "eflags": "flags",
    "rflags": "flags",
}


def register_family(name: str | None) -> str:
    if not name:
        return ""
    family = _LEGACY_REGISTER_FAMILIES.get(name)
    if family:
        return family
    if name.startswith("r"):
        core = name[1:]
        if core.isdigit():
            return name
        if core[:-1].isdigit() and core[-1:] in {"b", "w", "d"}:
            return "r" + core[:-1]
    return name


def register_access(decoded: Any) -> tuple[set[str], set[str]]:
    read, written = decoded.regs_access()
    return (
        {register_family(decoded.reg_name(reg)) for reg in read},
        {register_family(decoded.reg_name(reg)) for reg in written},
    )


def follows(previous: Instruction, current: Instruction) -> bool:
    return (
        current.address == previous.address + previous.size
        and current.file_offset == previous.file_offset + previous.size
    )


def find_condition_branch(
    records: list[tuple[Instruction, Any]],
    start: int,
    register: str,
) -> tuple[int, int] | None:
    for index in range(start, len(records)):
        if index > 0 and not follows(records[index - 1][0], records[index][0]):
            return None
        _, decoded = records[index]
        read, written = register_access(decoded)
        if decoded.mnemonic in {"test", "cmp"} and register in read:
            for branch_index in range(index + 1, len(records)):
                if not follows(records[branch_index - 1][0], records[branch_index][0]):
                    return None
                _, candidate = records[branch_index]
                candidate_reads, candidate_writes = register_access(candidate)
                if candidate.group(CS_GRP_JUMP):
                    if candidate.mnemonic != "jmp" and "flags" in candidate_reads:
                        return index, branch_index
                    return None
                if (
                    candidate.group(CS_GRP_CALL)
                    or candidate.group(CS_GRP_RET)
                    or "flags" in candidate_writes
                ):
                    return None
            return None
        if decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_JUMP) or decoded.group(CS_GRP_RET):
            return None
        if register in written:
            return None
    return None


def section_name(rva: int, sections: list[dict[str, Any]]) -> str | None:
    for section in sections:
        start = int(section["virtual_address"])
        if start <= rva < start + int(section["raw_size"]):
            return str(section["name"])
    return None


def import_location(
    address: int,
    image_base: int,
    sections: list[dict[str, Any]],
) -> tuple[int | None, int | None, str | None]:
    if address < image_base:
        return None, None, None
    rva = address - image_base
    for section in sections:
        start = int(section["virtual_address"])
        raw_size = int(section["raw_size"])
        if start <= rva < start + raw_size:
            return rva, int(section["raw_address"]) + rva - start, str(section["name"])
    return rva, None, None


def find_import_calls(
    instructions: list[Instruction],
    imports: list[dict[str, Any]],
    architecture: str,
    image_base: int,
    records: list[tuple[Instruction, Any]],
) -> list[tuple[dict[str, Any], str, dict[str, Any]]]:
    import_slots: dict[int, tuple[str, dict[str, Any]]] = {}
    for library in imports:
        dll = str(library.get("dll", "<unknown>"))
        for imported in library.get("functions", []):
            import_slots[int(imported["iat_address"])] = (dll, imported)

    transfers = analyze_control_transfers(
        instructions,
        architecture,
        image_base,
        instruction_details=records,
    )

    # MinGW commonly emits a local JMP thunk for each imported function. Resolve
    # that single hop so the reported location remains the caller, not the IAT.
    import_thunks: dict[int, tuple[str, dict[str, Any]]] = {}
    for transfer in transfers:
        if transfer["transfer_type"] != "jmp":
            continue
        slot = (
            transfer["pointer_address"]
            if transfer["pointer_address"] is not None
            else transfer["target_address"]
        )
        imported = import_slots.get(slot)
        if imported is not None:
            import_thunks[transfer["source_address"]] = imported

    detail_indexes = {
        instruction.address: index
        for index, (instruction, _) in enumerate(records)
    }
    calls = []
    for transfer in transfers:
        if transfer["transfer_type"] != "call":
            continue
        slot = (
            transfer["pointer_address"]
            if transfer["pointer_address"] is not None
            else transfer["target_address"]
        )
        imported = import_slots.get(slot) or import_thunks.get(slot)
        if imported is None and not transfer["direct"]:
            record_index = detail_indexes.get(transfer["source_address"])
            if record_index is not None:
                from .indirect_resolver import resolve_indirect_call
                resolution = resolve_indirect_call(records, record_index, image_base)
                imported = import_slots.get(int(resolution.storage_address)) if resolution.storage_address is not None else None
        if imported is not None:
            calls.append((transfer, imported[0], imported[1]))
    return calls
