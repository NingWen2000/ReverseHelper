"""Bounded, conservative recognition of common CTF static transforms."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal

from capstone import CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_INVALID


AlgorithmConfidence = Literal["HIGH", "MEDIUM", "LOW"]
SliceRelation = Literal[
    "ON_CONFIRMED_SLICE", "ON_LIKELY_SLICE", "ON_PARTIAL_SLICE", "OFF_SLICE"
]


@dataclass(frozen=True, slots=True)
class AlgorithmEvidence:
    kind: str
    value: Any
    instruction_rvas: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["instruction_rvas"] = list(self.instruction_rvas)
        return result


@dataclass(frozen=True, slots=True)
class AlgorithmCandidate:
    id: str
    function: str
    function_rva: int
    algorithm: str
    family: str
    confidence: AlgorithmConfidence
    evidence: tuple[AlgorithmEvidence, ...]
    constants: tuple[int, ...]
    structural_features: tuple[str, ...]
    data_objects: tuple[dict[str, Any], ...]
    slice_relation: SliceRelation

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "function": self.function, "function_rva": self.function_rva,
            "algorithm": self.algorithm, "family": self.family, "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
            "constants": list(self.constants), "structural_features": list(self.structural_features),
            "data_objects": [dict(item) for item in self.data_objects],
            "slice_relation": self.slice_relation,
        }


DEFAULT_BUDGETS = {
    "max_algorithm_functions": 96,
    "max_algorithm_instructions": 24000,
    "max_table_candidates": 32,
}


def _slice_relation(function_rva: int, slices, evidence=()) -> SliceRelation:
    relation = "OFF_SLICE"
    order = {"OFF_SLICE": 0, "ON_PARTIAL_SLICE": 1, "ON_LIKELY_SLICE": 2, "ON_CONFIRMED_SLICE": 3}
    mapping = {
        "PARTIAL_SLICE": "ON_PARTIAL_SLICE",
        "LIKELY_SLICE": "ON_LIKELY_SLICE",
        "CONFIRMED_SLICE": "ON_CONFIRMED_SLICE",
    }
    for item in slices:
        data = item.to_dict() if hasattr(item, "to_dict") else item
        transforms = data.get("transforms", [])
        function_rvas = {node.get("function_rva") for node in data.get("nodes", [])}
        function_rvas.update(transform.get("function_rva") for transform in transforms)
        sink = data.get("validation_sink") or {}
        function_rvas.add(sink.get("function_rva"))
        if function_rva not in function_rvas:
            continue
        transform_rvas = {transform.get("instruction_rva") for transform in transforms
                          if transform.get("instruction_rva") is not None}
        evidence_rvas = {rva for item in evidence if item.kind in {"OP_SEQUENCE", "KEY_ACCESS_PATTERN", "STATE_ARRAY"}
                         for rva in item.instruction_rvas}
        # Function membership alone is too coarse when an inlined controller also
        # contains unrelated checksum/anti-patch logic.
        if transform_rvas and not any(abs(rva - transform_rva) <= 16
                                      for rva in evidence_rvas for transform_rva in transform_rvas):
            continue
        candidate = mapping.get(data.get("status"), "ON_PARTIAL_SLICE")
        if order[candidate] > order[relation]:
            relation = candidate
    return relation  # type: ignore[return-value]


def _ev(kind: str, value: Any, rvas=()) -> AlgorithmEvidence:
    return AlgorithmEvidence(kind, value, tuple(sorted(set(int(rva) for rva in rvas))))


def _candidate(fn, algorithm, family, confidence, evidence, constants=(), features=(), data_objects=(), slices=()):
    return AlgorithmCandidate(
        f"algorithm-{fn.rva:08X}-{algorithm.lower()}", fn.name, fn.rva, algorithm, family,
        confidence, tuple(evidence), tuple(sorted(set(constants))), tuple(features),
        tuple(data_objects), _slice_relation(fn.rva, slices, evidence),
    )


def recognize_algorithms(context, data: bytes, slices=(), *, budgets=None):
    """Recognize algorithms in prioritized bounded functions without executing target code."""
    limits = {**DEFAULT_BUDGETS, **(budgets or {})}
    slice_functions = set()
    for item in slices:
        record = item.to_dict() if hasattr(item, "to_dict") else item
        slice_functions.update(node.get("function_rva") for node in record.get("nodes", []))
        slice_functions.update(node.get("function_rva") for node in record.get("transforms", []))
        slice_functions.add((record.get("validation_sink") or {}).get("function_rva"))
    functions = sorted(
        context.functions,
        key=lambda fn: (fn.rva not in slice_functions, fn.runtime_likelihood == "RUNTIME_LIKELY", -len(fn.instruction_rvas), fn.rva),
    )[:limits["max_algorithm_functions"]]
    candidates = []
    instruction_count = 0
    table_count = 0
    truncated = len(context.functions) > len(functions)
    standard_b64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alphabet_offsets = []
    start = 0
    while len(alphabet_offsets) < limits["max_table_candidates"]:
        offset = data.find(standard_b64, start)
        if offset < 0:
            break
        alphabet_offsets.append(offset)
        start = offset + 1

    for fn in functions:
        if instruction_count >= limits["max_algorithm_instructions"]:
            truncated = True
            break
        records = [context.by_rva[rva] for rva in fn.instruction_rvas if rva in context.by_rva]
        remaining = limits["max_algorithm_instructions"] - instruction_count
        if len(records) > remaining:
            records = records[:remaining]
            truncated = True
        instruction_count += len(records)
        if not records or fn.is_thunk:
            continue
        mnemonics = Counter(decoded.mnemonic for _, decoded in records)
        immediates: dict[int, list[int]] = {}
        back_edges = []
        indexed_mem = []
        direct_mem = []
        for ins, decoded in records:
            for operand in decoded.operands:
                if operand.type == X86_OP_IMM:
                    immediates.setdefault(int(operand.imm) & 0xFFFFFFFF, []).append(ins.rva)
                elif operand.type == X86_OP_MEM:
                    if operand.mem.index != X86_REG_INVALID:
                        indexed_mem.append(ins.rva)
                    elif operand.mem.base == X86_REG_INVALID and operand.mem.disp:
                        direct_mem.append((int(operand.mem.disp), ins.rva))
            if decoded.group(CS_GRP_JUMP) and decoded.mnemonic != "jmp" and decoded.operands:
                operand = decoded.operands[0]
                if operand.type == X86_OP_IMM and int(operand.imm) < int(decoded.address):
                    back_edges.append(ins.rva)
        loop = bool(back_edges)
        shifts4 = immediates.get(4, [])
        shifts5 = immediates.get(5, [])
        delta_rvas = immediates.get(0x9E3779B9, []) + immediates.get(0x61C88647, [])
        rounds = immediates.get(32, []) + immediates.get(0x20, [])
        xor_count = mnemonics["xor"]
        arithmetic = mnemonics["add"] + mnemonics["sub"]

        if delta_rvas:
            evidence = [_ev("MAGIC_CONSTANT", "0x9E3779B9/negated delta", delta_rvas)]
            features = []
            if loop:
                evidence.append(_ev("LOOP_STRUCTURE", "backward conditional branch", back_edges)); features.append("ROUND_LOOP")
            if shifts4 and shifts5 and xor_count >= 2 and arithmetic >= 2:
                evidence.append(_ev("SHIFT_PATTERN", "<<4 and >>5", shifts4 + shifts5))
                evidence.append(_ev("OP_SEQUENCE", "shift/add/xor state mixing")); features.append("TEA_MIX")
            if rounds:
                evidence.append(_ev("ROUND_COUNT", 32, rounds)); features.append("32_ROUNDS")
            key_index = mnemonics["and"] >= 1 and len(indexed_mem) >= 2
            if key_index:
                evidence.append(_ev("KEY_ACCESS_PATTERN", "sum-dependent indexed word access", indexed_mem)); features.append("INDEXED_KEY")
            variable_words = len(indexed_mem) >= 4 and mnemonics["cmp"] >= 2
            if variable_words:
                algorithm = "POSSIBLE_XXTEA"
            elif key_index:
                algorithm = "XTEA"
            elif "TEA_MIX" in features and "32_ROUNDS" in features:
                algorithm = "TEA"
            else:
                algorithm = "TEA_FAMILY"
            independent = len({item.kind for item in evidence})
            confidence = "HIGH" if independent >= 4 and algorithm in {"TEA", "XTEA"} else "MEDIUM" if independent >= 3 else "LOW"
            candidates.append(_candidate(fn, algorithm, "CRYPTO", confidence, evidence,
                                         (0x9E3779B9,), features, slices=slices))

        has_256 = bool(immediates.get(0x100) or immediates.get(0xFF))
        swap_like = len(indexed_mem) >= 4 and mnemonics["mov"] >= 3
        if loop and has_256 and swap_like and arithmetic:
            evidence = [_ev("STATE_ARRAY", "256-byte indexed state", indexed_mem),
                        _ev("TABLE_SIZE", 256, immediates.get(0x100, []) + immediates.get(0xFF, [])),
                        _ev("LOOP_STRUCTURE", "byte permutation loop", back_edges),
                        _ev("OP_SEQUENCE", "indexed read/write swap with modular index")]
            full = xor_count >= 1 and len(back_edges) >= 2
            algorithm = "RC4" if full else "RC4_KSA_CANDIDATE"
            candidates.append(_candidate(fn, algorithm, "CRYPTO", "HIGH" if full else "MEDIUM", evidence,
                                         (256,), ("KSA", "PRGA") if full else ("KSA",), slices=slices))

        if loop and xor_count:
            memory_xor = any(decoded.mnemonic == "xor" and any(op.type == X86_OP_MEM for op in decoded.operands)
                             for _, decoded in records)
            if memory_xor or indexed_mem:
                modulo = bool(mnemonics["and"] or mnemonics["div"] or mnemonics["idiv"])
                feedback = xor_count >= 2 and mnemonics["mov"] >= 2
                algorithm = "XOR_CHAIN" if feedback else "REPEATING_KEY_XOR" if modulo and len(indexed_mem) >= 2 else "ROLLING_XOR" if len(indexed_mem) >= 2 else "SINGLE_XOR"
                xor_rvas = [ins.rva for ins, decoded in records if decoded.mnemonic == "xor"]
                evidence = [_ev("LOOP_STRUCTURE", "byte/word iteration", back_edges),
                            _ev("OP_SEQUENCE", f"repeated XOR ({xor_count} XOR instructions)", xor_rvas)]
                if modulo:
                    evidence.append(_ev("KEY_ACCESS_PATTERN", "periodic/indexed key access", indexed_mem))
                candidates.append(_candidate(fn, algorithm, "TRANSFORM", "MEDIUM", evidence,
                                             features=("BUFFER_LOOP",), slices=slices))

        crc_rvas = immediates.get(0xEDB88320, []) + immediates.get(0x04C11DB7, [])
        if crc_rvas:
            evidence = [_ev("MAGIC_CONSTANT", "CRC32 polynomial", crc_rvas)]
            structural = loop and xor_count and (mnemonics["shr"] or mnemonics["shl"])
            if structural:
                evidence += [_ev("LOOP_STRUCTURE", "byte/bit iteration", back_edges),
                             _ev("OP_SEQUENCE", "shift/XOR feedback")]
            candidates.append(_candidate(fn, "CRC32", "CHECKSUM", "MEDIUM" if structural else "LOW",
                                         evidence, (0xEDB88320,), slices=slices))

        # Table transforms require indexed input and indexed output/table activity in a loop.
        if (loop and len(indexed_mem) >= 4 and direct_mem and not crc_rvas
                and table_count < limits["max_table_candidates"] and not has_256):
            table_count += 1
            candidates.append(_candidate(fn, "TABLE_TRANSFORM", "TRANSFORM", "MEDIUM",
                (_ev("LOOP_STRUCTURE", "indexed buffer loop", back_edges),
                 _ev("STATE_ARRAY", "input-index-table-output accesses", indexed_mem)),
                features=("TABLE_LOOKUP",), slices=slices))

        multiply = mnemonics["imul"] + mnemonics["mul"]
        lcg_multipliers = {1103515245, 1664525, 214013, 22695477, 134775813}
        lcg_increments = {12345, 1013904223, 2531011, 1}
        multiplier_rvas = [rva for value in lcg_multipliers for rva in immediates.get(value, [])]
        increment_rvas = [rva for value in lcg_increments for rva in immediates.get(value, [])]
        if loop and multiply and multiplier_rvas and increment_rvas and mnemonics["mov"] >= 2:
            candidates.append(_candidate(fn, "LCG", "TRANSFORM", "MEDIUM",
                (_ev("LOOP_STRUCTURE", "state feedback loop", back_edges),
                 _ev("OP_SEQUENCE", "state = state * A + C"),
                 _ev("MAGIC_CONSTANT", "known LCG multiplier/increment", multiplier_rvas + increment_rvas)),
                features=("STATE_FEEDBACK",), slices=slices))

        rotates = mnemonics["rol"] + mnemonics["ror"]
        if loop and rotates and xor_count and arithmetic and not delta_rvas:
            candidates.append(_candidate(fn, "CUSTOM_WORD_TRANSFORM", "CUSTOM", "MEDIUM",
                (_ev("LOOP_STRUCTURE", "repeated transform loop", back_edges),
                 _ev("OP_SEQUENCE", "rotate/add-or-sub/xor")), features=("ROTATE", "ARITHMETIC", "XOR"), slices=slices))

        # An alphabet is only useful when the same function also has 6-bit/4:3 structure.
        six_bit = bool(immediates.get(6) or immediates.get(0x3F))
        grouping = bool(immediates.get(3) and immediates.get(4))
        referenced_alphabet = []
        for offset in alphabet_offsets:
            location = next((section for section in context.sections
                             if section["raw_address"] <= offset < section["raw_address"] + section["raw_size"]), None)
            if location is None:
                continue
            alphabet_rva = int(location["virtual_address"]) + offset - int(location["raw_address"])
            alphabet_va = context.image_base + alphabet_rva
            if any(address == alphabet_va for address, _ in direct_mem):
                referenced_alphabet.append((alphabet_rva, offset))
        if referenced_alphabet and loop and six_bit and grouping:
            objects = tuple({"rva": rva, "file_offset": offset, "size": 64,
                             "semantic": "BASE64_ALPHABET", "evidence": ["referenced by 6-bit grouping loop"]}
                            for rva, offset in referenced_alphabet)
            candidates.append(_candidate(fn, "STANDARD_BASE64", "ENCODING", "HIGH",
                (_ev("TABLE_SIZE", 64), _ev("LOOP_STRUCTURE", "4:3 grouping loop", back_edges),
                 _ev("OP_SEQUENCE", "6-bit indexed alphabet mapping")), (64, 6, 3, 4),
                ("PADDING_OPTIONAL",), objects, slices))
        elif loop and six_bit and grouping:
            custom_objects = []
            for address, _ in direct_mem[:limits["max_table_candidates"]]:
                rva = address - context.image_base
                section = next((item for item in context.sections
                                if item["virtual_address"] <= rva < item["virtual_address"] + item["raw_size"]), None)
                if section is None:
                    continue
                offset = int(section["raw_address"]) + rva - int(section["virtual_address"])
                alphabet = data[offset:offset + 64]
                if len(alphabet) == 64 and len(set(alphabet)) == 64 and all(0x21 <= byte <= 0x7E for byte in alphabet):
                    custom_objects.append({"rva": rva, "file_offset": offset, "size": 64,
                                           "semantic": "BASE64_ALPHABET",
                                           "evidence": ["64 unique printable symbols referenced by a 6-bit grouping loop"]})
            if custom_objects:
                candidates.append(_candidate(fn, "CUSTOM_BASE64_ALPHABET", "ENCODING", "MEDIUM",
                    (_ev("TABLE_SIZE", 64), _ev("LOOP_STRUCTURE", "4:3 grouping loop", back_edges),
                     _ev("OP_SEQUENCE", "6-bit indexed custom alphabet mapping")), (64, 6, 3, 4),
                    ("CUSTOM_ALPHABET",), tuple(custom_objects), slices))

    # Runtime implementations remain visible but cannot make a high-confidence product claim.
    by_rva = {fn.rva: fn for fn in functions}
    normalized = []
    for candidate in candidates:
        fn = by_rva[candidate.function_rva]
        if fn.runtime_likelihood == "RUNTIME_LIKELY" and candidate.confidence != "LOW":
            candidate = replace(candidate, confidence="LOW")
        normalized.append(candidate)
    normalized.sort(key=lambda item: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[item.confidence],
                                      item.slice_relation == "OFF_SLICE", item.function_rva, item.algorithm))
    return normalized, {
        **limits, "functions_analyzed": len(functions), "instructions_analyzed": instruction_count,
        "table_candidates": table_count, "truncated": truncated,
    }
