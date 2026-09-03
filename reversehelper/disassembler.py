"""Bounded x86/x64 disassembly over PE section raw bytes."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsError, CsInsn

from .findings import Instruction


class DisassemblyError(ValueError):
    pass


def create_capstone(architecture: str, *, detail: bool = False) -> Cs:
    modes = {"x86": CS_MODE_32, "x86-64": CS_MODE_64}
    try:
        mode = modes[architecture]
    except KeyError as exc:
        raise DisassemblyError(f"Unsupported disassembly architecture: {architecture}") from exc

    engine = Cs(CS_ARCH_X86, mode)
    engine.detail = detail
    return engine


def iter_instruction_details(
    instructions: Iterable[Instruction],
    architecture: str,
) -> Iterator[tuple[Instruction, CsInsn]]:
    engine = create_capstone(architecture, detail=True)
    for instruction in instructions:
        try:
            decoded = next(engine.disasm(instruction.raw_bytes, instruction.address, count=1), None)
        except CsError:
            continue
        if decoded is not None and int(decoded.size) == instruction.size:
            yield instruction, decoded


class Disassembler:
    def __init__(self, architecture: str, image_base: int):
        self.architecture = architecture
        self.image_base = image_base
        self._engine = create_capstone(architecture)

    def disassemble_range(
        self,
        data: bytes,
        sections: list[dict[str, Any]],
        start_rva: int,
        size: int,
    ) -> list[Instruction]:
        if start_rva < 0:
            raise DisassemblyError("Start RVA cannot be negative")
        if size <= 0:
            return []

        section = None
        for candidate in sections:
            section_rva = int(candidate["virtual_address"])
            raw_size = int(candidate["raw_size"])
            if section_rva <= start_rva < section_rva + raw_size:
                section = candidate
                break
        if section is None:
            return []

        section_rva = int(section["virtual_address"])
        raw_start = int(section["raw_address"])
        raw_size = int(section["raw_size"])
        section_offset = start_rva - section_rva
        file_offset = raw_start + section_offset
        available = min(size, raw_size - section_offset, len(data) - file_offset)
        if raw_start < 0 or file_offset < 0 or available <= 0:
            return []

        code = data[file_offset : file_offset + available]
        start_address = self.image_base + start_rva
        instructions: list[Instruction] = []
        try:
            for decoded in self._engine.disasm(code, start_address):
                delta = int(decoded.address) - start_address
                instructions.append(
                    Instruction(
                        address=int(decoded.address),
                        rva=start_rva + delta,
                        file_offset=file_offset + delta,
                        size=int(decoded.size),
                        raw_bytes=bytes(decoded.bytes),
                        mnemonic=decoded.mnemonic,
                        op_str=decoded.op_str,
                    )
                )
        except CsError:
            # A broken instruction ends this region, but earlier instructions remain useful.
            pass
        return instructions
