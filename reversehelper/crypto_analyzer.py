"""Known-constant matching for common cryptographic primitives."""

from __future__ import annotations

from typing import Any

from capstone import CS_AC_READ, CS_AC_WRITE, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_INVALID

from .addressing import file_offset_to_location
from .disassembler import iter_instruction_details
from .findings import Finding, Instruction


AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

SIGNATURES: tuple[dict[str, Any], ...] = (
    {"algorithm": "AES", "constant": "S-box", "pattern": AES_SBOX, "confidence": "high"},
    {"algorithm": "AES", "constant": "Rcon", "pattern": bytes.fromhex("01020408102040801b36"), "confidence": "medium"},
    {"algorithm": "TEA", "constant": "delta 0x9E3779B9 (LE)", "pattern": bytes.fromhex("b979379e"), "confidence": "medium"},
    {"algorithm": "TEA", "constant": "delta 0x9E3779B9 (BE)", "pattern": bytes.fromhex("9e3779b9"), "confidence": "medium"},
    {"algorithm": "MD5", "constant": "initialization vector", "pattern": bytes.fromhex("0123456789abcdeffedcba9876543210"), "confidence": "high"},
    {"algorithm": "CRC32", "constant": "polynomial 0xEDB88320 (LE)", "pattern": bytes.fromhex("2083b8ed"), "confidence": "medium"},
    {"algorithm": "CRC32", "constant": "polynomial 0xEDB88320 (BE)", "pattern": bytes.fromhex("edb88320"), "confidence": "medium"},
)


def _find_offsets(data: bytes, pattern: bytes, limit: int = 8) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        offset = data.find(pattern, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    return offsets


def find_crypto_constants(data: bytes) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for signature in SIGNATURES:
        offsets = _find_offsets(data, signature["pattern"])
        if offsets:
            findings.append(
                {
                    "algorithm": signature["algorithm"],
                    "constant": signature["constant"],
                    "confidence": signature["confidence"],
                    "offsets": offsets,
                    "match_count": len(offsets),
                }
            )
    return findings


def _immediate_values(decoded: Any) -> set[int]:
    return {int(operand.imm) for operand in decoded.operands if operand.type == X86_OP_IMM}


def _section_name(rva: int, sections: list[dict[str, Any]]) -> str | None:
    for section in sections:
        start = int(section["virtual_address"])
        if start <= rva < start + int(section["raw_size"]):
            return str(section["name"])
    return None


def _follows(previous: Instruction, current: Instruction) -> bool:
    return (
        current.address == previous.address + previous.size
        and current.file_offset == previous.file_offset + previous.size
    )


def _nearby_records(
    records: list[tuple[Instruction, Any]],
    source_index: int,
    maximum_distance: int = 0x100,
) -> list[tuple[Instruction, Any]]:
    start = source_index
    while start > 0:
        previous = records[start - 1][0]
        current = records[start][0]
        if not _follows(previous, current):
            break
        if records[source_index][0].file_offset - previous.file_offset > maximum_distance:
            break
        start -= 1

    end = source_index + 1
    while end < len(records):
        previous = records[end - 1][0]
        current = records[end][0]
        if not _follows(previous, current) or current.file_offset - records[source_index][0].file_offset > maximum_distance:
            break
        end += 1
    return records[start:end]


def find_crypto_candidates(
    data: bytes,
    instructions: list[Instruction],
    sections: list[dict[str, Any]],
    architecture: str,
    image_base: int,
    size_of_headers: int = 0,
    *,
    instruction_details: list[tuple[Instruction, Any]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    records = (
        list(instruction_details)
        if instruction_details is not None
        else list(iter_instruction_details(instructions, architecture))
    )

    for constant in find_crypto_constants(data):
        if constant["algorithm"] != "TEA":
            continue
        for offset in constant["offsets"]:
            source_index = next(
                (
                    index
                    for index, (instruction, _) in enumerate(records)
                    if instruction.file_offset <= offset < instruction.file_offset + instruction.size
                ),
                None,
            )
            source = records[source_index][0] if source_index is not None else None
            location = file_offset_to_location(offset, sections, image_base, size_of_headers)
            source_offset = source.file_offset if source else offset
            source_rva = source.rva if source else location["rva"]
            source_va = source.address if source else location["va"]
            section = _section_name(source.rva, sections) if source else location["section"]

            signals: set[str] = set()
            if source_index is not None:
                for instruction, decoded in _nearby_records(records, source_index):
                    if section is not None and _section_name(instruction.rva, sections) != section:
                        continue
                    immediates = _immediate_values(decoded)
                    if decoded.mnemonic in {"shl", "sal"} and 4 in immediates:
                        signals.add("SHL 4")
                    elif decoded.mnemonic == "shr" and 5 in immediates:
                        signals.add("SHR 5")
                    elif decoded.mnemonic == "xor":
                        signals.add("XOR")
                    elif decoded.mnemonic == "add":
                        signals.add("ADD")
                    elif decoded.mnemonic == "sub":
                        signals.add("SUB")

                    if decoded.group(CS_GRP_JUMP) and decoded.mnemonic != "jmp" and decoded.operands:
                        operand = decoded.operands[0]
                        if operand.type == X86_OP_IMM and int(operand.imm) < int(decoded.address):
                            signals.add("backward conditional branch")

            strong_pattern = {
                "SHL 4",
                "SHR 5",
                "XOR",
                "backward conditional branch",
            }.issubset(signals) and bool({"ADD", "SUB"} & signals)
            confidence = "high" if strong_pattern else "medium" if len(signals) >= 3 else "low"
            evidence = [f"TEA delta 0x9E3779B9 at file offset 0x{offset:X}"]
            evidence.extend(
                signal
                for signal in ("SHL 4", "SHR 5", "XOR", "ADD", "SUB", "backward conditional branch")
                if signal in signals
            )
            reason = (
                "The delta constant appears with characteristic shifts, XOR, arithmetic, and a backward branch; "
                "this supports a TEA-family routine but does not distinguish TEA, XTEA, and XXTEA."
                if confidence == "high"
                else "The delta constant is not sufficient to distinguish TEA, XTEA, XXTEA, or unrelated data."
            )
            findings.append(
                Finding(
                    id=f"crypto-tea-family-{offset:08x}",
                    category="crypto",
                    title="Possible TEA-family routine",
                    rva=int(source_rva) if source_rva is not None else None,
                    va=int(source_va) if source_va is not None else None,
                    file_offset=source_offset,
                    section=str(section) if section is not None else None,
                    severity="info",
                    confidence=confidence,
                    evidence=tuple(evidence),
                    reason=reason,
                    recommended_action="Inspect the containing routine for round count, key words, and input/output state.",
                )
            )

    address_index = {instruction.address: index for index, (instruction, _) in enumerate(records)}
    seen_rc4_loops: set[int] = set()
    for branch_index, (_, branch) in enumerate(records):
        if not branch.group(CS_GRP_JUMP) or branch.mnemonic == "jmp" or not branch.operands:
            continue
        operand = branch.operands[0]
        if operand.type != X86_OP_IMM or int(operand.imm) >= int(branch.address):
            continue
        start_index = address_index.get(int(operand.imm))
        if start_index is None or start_index in seen_rc4_loops or branch_index - start_index > 64:
            continue

        memory_reads = 0
        memory_writes = 0
        indexed_accesses = 0
        has_add = False
        has_modulo_marker = False
        body = records[start_index : branch_index + 1]
        if any(not _follows(body[index - 1][0], body[index][0]) for index in range(1, len(body))):
            continue
        for _, decoded in body:
            immediates = _immediate_values(decoded)
            has_add = has_add or decoded.mnemonic == "add"
            if decoded.mnemonic == "and" and 0xFF in immediates:
                has_modulo_marker = True
            if decoded.mnemonic == "cmp" and 0x100 in immediates:
                has_modulo_marker = True
            for item in decoded.operands:
                if item.type != X86_OP_MEM:
                    continue
                if item.mem.index != X86_REG_INVALID:
                    indexed_accesses += 1
                if item.access & CS_AC_READ:
                    memory_reads += 1
                if item.access & CS_AC_WRITE:
                    memory_writes += 1

        if not (
            indexed_accesses >= 4
            and memory_reads >= 2
            and memory_writes >= 2
            and has_add
            and has_modulo_marker
        ):
            continue

        seen_rc4_loops.add(start_index)
        source = body[0][0]
        findings.append(
            Finding(
                id=f"crypto-rc4-like-{source.rva:08x}",
                category="crypto",
                title="Possible RC4-like byte permutation loop",
                rva=source.rva,
                va=source.address,
                file_offset=source.file_offset,
                section=_section_name(source.rva, sections),
                severity="info",
                confidence="medium",
                evidence=(
                    f"{indexed_accesses} indexed memory accesses in a backward loop",
                    f"{memory_reads} memory reads and {memory_writes} memory writes",
                    "8-bit modulo marker and ADD operation",
                ),
                reason="The loop resembles an RC4 state-table permutation, but no universal RC4 constant exists to confirm it.",
                recommended_action="Inspect table initialization, key indexing, swap operations, and callers before labeling the algorithm.",
            )
        )

    return findings
