"""Conservative semantic suggestions derived from existing Quick evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from capstone import CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_INVALID

from .instruction_context import register_family


SuggestionConfidence = Literal["HIGH", "MEDIUM", "LOW"]
SuggestionSafety = Literal["SAFE_TO_APPLY", "REVIEW_RECOMMENDED", "COMMENT_ONLY"]


@dataclass(frozen=True, slots=True)
class SuggestionEvidence:
    kind: str
    value: Any
    source_id: str | None = None

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DecompilerSuggestion:
    id: str
    kind: str
    target: dict[str, Any]
    proposed_value: Any
    confidence: SuggestionConfidence
    evidence: tuple[SuggestionEvidence, ...]
    source_modules: tuple[str, ...]
    scope: str
    safety: SuggestionSafety
    reverse_value: int = 0

    def to_dict(self):
        return {
            "id": self.id, "kind": self.kind, "target": dict(self.target),
            "proposed_value": self.proposed_value, "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
            "source_modules": list(self.source_modules), "scope": self.scope,
            "safety": self.safety, "reverse_value": self.reverse_value,
        }


DEFAULT_BUDGETS = {"max_semantic_suggestions": 20, "max_objects_per_function": 8,
                   "max_expression_groups": 8}
_GENERATED_PREFIXES = ("FUN_", "SUB_", "sub_")


def _ev(kind, value, source_id=None):
    return SuggestionEvidence(kind, value, source_id)


def _generated_name(function):
    return function.name.startswith(_GENERATED_PREFIXES)


def _function_suggestion(fn, role, confidence, evidence, modules, reverse_value=0):
    prefix = "" if confidence == "HIGH" else "possible_"
    return DecompilerSuggestion(
        f"semantic-function-{fn.rva:08X}-{role}", "FUNCTION_RENAME",
        {"kind": "FUNCTION", "rva": fn.rva, "current_name": fn.name}, prefix + role,
        confidence, tuple(evidence), tuple(modules), "FUNCTION", "REVIEW_RECOMMENDED", reverse_value,
    )


def _object_key(target):
    return tuple(sorted((key, repr(value)) for key, value in target.items() if key != "current_name"))


def generate_suggestions(context, input_sources, slices, validation_candidates, algorithms,
                         control_flow_findings, flow_result=None, *, budgets=None):
    limits = {**DEFAULT_BUDGETS, **(budgets or {})}
    suggestions = []
    by_rva = {fn.rva: fn for fn in context.functions}
    slice_functions = set()
    for item in slices:
        record = item.to_dict() if hasattr(item, "to_dict") else item
        slice_functions.update(node.get("function_rva") for node in record.get("nodes", []))
        slice_functions.update(transform.get("function_rva") for transform in record.get("transforms", []))
        slice_functions.add((record.get("validation_sink") or {}).get("function_rva"))

    # Function roles use only existing evidence and preserve trusted/user names.
    roles = {}
    def add_role(rva, role, confidence, evidence, module, value):
        if rva is None or rva not in by_rva:
            return
        current = roles.get(rva)
        rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        proposal = (role, confidence, list(evidence), {module}, value)
        if current is not None and {current[0], role} == {"input_reader", "algorithm_transform"}:
            roles[rva] = ("input_transform", "HIGH" if "HIGH" in {current[1], confidence} else "MEDIUM",
                          current[2] + list(evidence), current[3] | {module}, max(value, current[4]) + 5)
            return
        if current is None or rank[confidence] > rank[current[1]] or value > current[4]:
            roles[rva] = proposal
        elif current[0] == role:
            current[2].extend(evidence); current[3].add(module)

    for source in input_sources:
        add_role(source.function_rva, "input_reader", "HIGH" if source.confidence == "CONFIRMED" else "MEDIUM",
                 [_ev("INPUT_PROVENANCE", source.source_type, source.id)], "input_sources", 80)
    for candidate in validation_candidates:
        if candidate.context_only or candidate.function_rva is None:
            continue
        confidence = "HIGH" if candidate.input_flow_to_validation in {"CONFIRMED", "LIKELY"} else "MEDIUM"
        add_role(candidate.function_rva, "validation_check", confidence,
                 [_ev("VALIDATION_OPERAND", candidate.validation_type, candidate.id)], "validation", 95)
    for algorithm in algorithms:
        if algorithm.confidence == "LOW":
            continue
        role = ("checksum_calc" if algorithm.family == "CHECKSUM" else
                "decode_transform" if algorithm.family == "ENCODING" else
                "table_lookup" if algorithm.algorithm == "TABLE_TRANSFORM" else "algorithm_transform")
        confidence = "HIGH" if algorithm.confidence == "HIGH" and algorithm.slice_relation != "OFF_SLICE" else "MEDIUM"
        add_role(algorithm.function_rva, role, confidence,
                 [_ev("ALGORITHM_RELATION", algorithm.algorithm, algorithm.id),
                  _ev("ON_STATIC_SLICE", algorithm.slice_relation, algorithm.id)],
                 "algorithm_recognition", 90 if algorithm.slice_relation != "OFF_SLICE" else 65)
    for finding in control_flow_findings:
        if finding.confidence == "LOW" or finding.dispatcher_block is None:
            continue
        add_role(finding.function_rva, "state_dispatcher", "HIGH" if finding.confidence == "HIGH" else "MEDIUM",
                 [_ev("DISPATCHER_BLOCK", finding.dispatcher_block, finding.id)],
                 "control_flow_understanding", 94 if finding.slice_relation != "OFF_SLICE" else 86)
    for rva, (role, confidence, evidence, modules, value) in roles.items():
        fn = by_rva[rva]
        if fn.runtime_likelihood == "RUNTIME_LIKELY":
            continue
        if _generated_name(fn):
            suggestions.append(_function_suggestion(fn, role, confidence, evidence, modules, value))
        else:
            suggestions.append(DecompilerSuggestion(
                f"semantic-preserve-{rva:08X}", "COMMENT", {"kind": "FUNCTION", "rva": rva,
                 "current_name": fn.name}, {"status": "existing symbol preserved", "suggested_role": role},
                confidence, tuple(evidence) + (_ev("EXISTING_SYMBOL", fn.name),), tuple(modules),
                "FUNCTION", "COMMENT_ONLY", value))

    # Input destinations become one merged role/type suggestion, not separate rename spam.
    for source in input_sources:
        destination = source.destination.to_dict()
        target = {**destination, "function_rva": source.function_rva}
        wide = source.source_type.startswith("WIDE_") or "WCHAR" in source.source_type
        pointer_input = source.source_type.startswith("argv[") or destination.get("kind") != "REGISTER"
        type_name = ("wchar_t *" if wide else "uint8_t *") if pointer_input else "uint8_t-like"
        name = "input_buf" if pointer_input else "input_value"
        suggestions.append(DecompilerSuggestion(
            f"semantic-input-object-{source.id}", "OBJECT_ROLE", target,
            {"name": name, "role": "INPUT", "type_hint": type_name, "pointer": pointer_input},
            "HIGH" if source.confidence == "CONFIRMED" else "MEDIUM",
            (_ev("INPUT_PROVENANCE", source.source_type, source.id),
             _ev("LOAD_WIDTH", 8 if not wide else 16, source.id)),
            ("input_sources", "value_identity"), "LOCAL_OBJECT", "REVIEW_RECOMMENDED", 92))

    # Dispatcher state is a high-value variable/global suggestion.
    for finding in control_flow_findings:
        state = finding.state_variable
        if (not state or finding.confidence == "LOW"
                or finding.kind not in {"STATE_MACHINE", "INDIRECT_CALL_CLUSTER"}):
            continue
        target = {**state, "function_rva": finding.function_rva}
        kind = "GLOBAL_RENAME" if state.get("kind") == "GLOBAL" else "VARIABLE_RENAME"
        suggestions.append(DecompilerSuggestion(
            f"semantic-state-{finding.id}", kind, target,
            {"name": "state", "role": "DISPATCH_STATE",
             "type_hint": f"uint{state['width']}_t" if state.get("width") in {8, 16, 32, 64} else "uint32_t-like"},
            "HIGH" if finding.confidence == "HIGH" else "MEDIUM",
            (_ev("STATE_VARIABLE", state, finding.id), _ev("STATE_UPDATE_COUNT", len(finding.state_updates), finding.id)),
            ("control_flow_understanding",), "GLOBAL" if kind == "GLOBAL_RENAME" else "LOCAL_OBJECT",
            "REVIEW_RECOMMENDED", 90))

    # Algorithm data objects carry conservative array roles and extents.
    for algorithm in algorithms:
        for obj in algorithm.data_objects:
            semantic = obj.get("semantic", "LOOKUP_TABLE")
            role = "POSSIBLE_KEY" if "KEY" in semantic else "LOOKUP_TABLE"
            width = 32 if obj.get("size") in {8, 16} and algorithm.algorithm in {"TEA", "XTEA"} else 8
            count = obj.get("size") * 8 // width if obj.get("size") else None
            suggestions.append(DecompilerSuggestion(
                f"semantic-data-{algorithm.id}-{obj.get('rva', 0):08X}", "OBJECT_ROLE",
                {"kind": "GLOBAL", "rva": obj.get("rva"), "file_offset": obj.get("file_offset")},
                {"name": "possible_key" if role == "POSSIBLE_KEY" else "lookup_table",
                 "role": role, "type_hint": f"uint{width}_t[{count}]" if count else f"uint{width}_t[]",
                 "readonly": True, "extent": obj.get("size")},
                "HIGH" if algorithm.confidence == "HIGH" else "MEDIUM",
                (_ev("ALGORITHM_KEY_RELATION", algorithm.algorithm, algorithm.id),
                 _ev("READONLY_GLOBAL", obj.get("size"), algorithm.id)),
                ("algorithm_recognition",), "GLOBAL", "REVIEW_RECOMMENDED", 82))

    # Existing instruction details provide bounded pointer/array and struct-like comments.
    relevant = [by_rva[rva] for rva in slice_functions | set(roles) if rva in by_rva]
    expression_count = 0
    for fn in relevant:
        records = [context.by_rva[rva] for rva in fn.instruction_rvas if rva in context.by_rva]
        arrays = {}
        fields = {}
        for ins, decoded in records:
            for operand in decoded.operands:
                if operand.type != X86_OP_MEM:
                    continue
                base = register_family(decoded.reg_name(operand.mem.base)) if operand.mem.base != X86_REG_INVALID else None
                index = register_family(decoded.reg_name(operand.mem.index)) if operand.mem.index != X86_REG_INVALID else None
                width = max(8, int(getattr(operand, "size", 1)) * 8)
                if base and index:
                    arrays.setdefault((base, index, int(operand.mem.scale), width), []).append(ins.rva)
                elif base and operand.mem.disp and base not in {"bp", "sp"}:
                    fields.setdefault(base, {}).setdefault((int(operand.mem.disp), width), []).append(ins.rva)
        for (base, index, scale, width), rvas in list(arrays.items())[:limits["max_objects_per_function"]]:
            if len(rvas) < 2 or scale not in {1, 2, 4, 8}:
                continue
            suggestions.append(DecompilerSuggestion(
                f"semantic-array-{fn.rva:08X}-{rvas[0]:08X}", "ARRAY_HINT",
                {"kind": "MEMORY_PATTERN", "function_rva": fn.rva, "base": base, "index": index},
                {"semantic_form": f"{base}_array[{index}]", "element_width": width,
                 "index_expression": f"{index} * {scale}", "observed_bounds": None,
                 "access": "read/write unknown"}, "MEDIUM",
                (_ev("ARRAY_INDEX_PATTERN", {"scale": scale, "access_count": len(rvas)}),
                 _ev("LOAD_WIDTH", width)), ("instruction_context",), "FUNCTION", "COMMENT_ONLY", 55))
        for base, offsets in fields.items():
            if len(offsets) < 3:
                continue
            suggestions.append(DecompilerSuggestion(
                f"semantic-struct-{fn.rva:08X}-{base}", "OBJECT_ROLE",
                {"kind": "REGISTER_BASE", "function_rva": fn.rva, "base": base},
                {"role": "STRUCT_LIKE_OBJECT", "fields": [
                    {"offset": offset, "width": width} for offset, width in sorted(offsets)]},
                "MEDIUM", (_ev("FIXED_OFFSET_FIELDS", len(offsets)),),
                ("instruction_context",), "FUNCTION", "COMMENT_ONLY", 45))
        if expression_count < limits["max_expression_groups"]:
            for index in range(len(records) - 3):
                window = records[index:index + 4]
                mnemonics = [decoded.mnemonic for _, decoded in window]
                if mnemonics[0] not in {"shl", "sal"} or mnemonics[1] != "shr" or mnemonics[2] != "xor" or mnemonics[3] not in {"add", "sub"}:
                    continue
                if any(decoded.group(CS_GRP_CALL) or decoded.group(CS_GRP_JUMP) for _, decoded in window):
                    continue
                rvas = [ins.rva for ins, _ in window]
                suggestions.append(DecompilerSuggestion(
                    f"semantic-expression-{fn.rva:08X}-{rvas[0]:08X}", "TEMPORARY_GROUP",
                    {"kind": "INSTRUCTION_GROUP", "function_rva": fn.rva, "instruction_rvas": rvas},
                    {"semantic_group": "shift/xor/arithmetic update",
                     "expression_hint": "((x << shift_left) ^ (y >> shift_right)) +/- z",
                     "width": "32-bit-like", "arithmetic": "unsigned wraparound preserved"},
                    "MEDIUM", (_ev("SHORT_DEF_USE_REGION", rvas), _ev("WIDTH_SEMANTICS", "32-bit wraparound")),
                    ("algorithm_recognition", "instruction_context"), "EXPRESSION", "COMMENT_ONLY", 50))
                expression_count += 1
                break

    # Deduplicate exact targets/kinds, preserving the strongest, most useful suggestion.
    rank = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    deduplicated = {}
    for suggestion in suggestions:
        key = (suggestion.kind, _object_key(suggestion.target))
        previous = deduplicated.get(key)
        if previous is None or (rank[suggestion.confidence], suggestion.reverse_value, len(suggestion.evidence)) > (
                rank[previous.confidence], previous.reverse_value, len(previous.evidence)):
            deduplicated[key] = suggestion
    ordered = sorted(deduplicated.values(), key=lambda item: (
        -rank[item.confidence], -item.reverse_value, -len(item.evidence), item.id))
    truncated = len(ordered) > limits["max_semantic_suggestions"]
    return ordered[:limits["max_semantic_suggestions"]], {
        **limits, "generated": len(suggestions), "deduplicated": len(ordered),
        "expression_groups": expression_count, "truncated": truncated,
    }
