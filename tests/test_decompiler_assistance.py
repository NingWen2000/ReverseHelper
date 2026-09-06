from types import SimpleNamespace

from reversehelper.algorithm_recognition import AlgorithmCandidate, AlgorithmEvidence
from reversehelper.control_flow_understanding import ControlFlowFinding, ControlFlowEvidence
from reversehelper.dataflow_model import InputSource, RegisterLocation
from reversehelper.decompiler_assistance import generate_suggestions
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.findings import Function


def _context(code=bytes.fromhex("90 C3"), *, name="FUN_401000", source="test"):
    base, raw = 0x400000, 0x200
    data = b"\0" * raw + code
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": raw,
                 "raw_size": len(code), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler("x86", base).disassemble_range(data, sections, 0x1000, len(code), skip_invalid=True)
    records = list(iter_instruction_details(instructions, "x86"))
    fn = Function(0x1000, base + 0x1000, name, raw, ".text", source, "high",
                  tuple(ins.rva for ins, _ in records), runtime_likelihood="USER_CODE")
    return SimpleNamespace(functions=[fn], by_rva={ins.rva: (ins, dec) for ins, dec in records},
                           sections=sections, image_base=base), fn


def _source(fn):
    return InputSource("input-1", fn.name, fn.rva, fn.address, fn.rva, "argv[1]",
                       RegisterLocation("a", fn.rva), None, "CONFIRMED", ("argv provenance",))


def _algorithm(fn, *, data_objects=()):
    return AlgorithmCandidate("algorithm-1", fn.name, fn.rva, "XTEA", "CRYPTO", "HIGH",
                              (AlgorithmEvidence("OP_SEQUENCE", "shift/add/xor", (0x1000,)),),
                              (0x9E3779B9,), ("TEA_MIX",), tuple(data_objects), "ON_LIKELY_SLICE")


def test_input_and_algorithm_evidence_produce_small_conservative_roles():
    context, fn = _context()
    suggestions, budget = generate_suggestions(context, [_source(fn)], [], [], [_algorithm(fn)], [])
    rename = next(item for item in suggestions if item.kind == "FUNCTION_RENAME")
    obj = next(item for item in suggestions if item.kind == "OBJECT_ROLE")
    assert rename.proposed_value == "input_transform"
    assert rename.safety == "REVIEW_RECOMMENDED"
    assert obj.proposed_value["role"] == "INPUT"
    assert obj.proposed_value["type_hint"] == "uint8_t *"
    assert budget["generated"] <= 20


def test_existing_trusted_symbol_is_preserved():
    context, fn = _context(name="decrypt_block", source="COFF symbol table")
    suggestions, _ = generate_suggestions(context, [_source(fn)], [], [], [], [])
    preserve = next(item for item in suggestions if item.kind == "COMMENT")
    assert preserve.proposed_value["status"] == "existing symbol preserved"
    assert not any(item.kind == "FUNCTION_RENAME" for item in suggestions)


def test_dispatcher_state_becomes_state_role_without_business_guess():
    context, fn = _context()
    control = ControlFlowFinding(
        "cf-1", fn.name, fn.rva, "STATE_MACHINE", "HIGH", fn.rva, (fn.rva,), fn.rva,
        {"kind": "STACK", "base": "bp", "offset": -0x24}, None,
        (ControlFlowEvidence("STATE_WRITES", 4),), ("STATE_UPDATES",), "ON_LIKELY_SLICE",
        "Track state writes.", ({"block_rva": fn.rva, "value": 1},),
    )
    suggestions, _ = generate_suggestions(context, [], [], [], [], [control])
    state = next(item for item in suggestions if item.kind == "VARIABLE_RENAME")
    assert state.proposed_value["name"] == "state"
    assert state.proposed_value["role"] == "DISPATCH_STATE"
    assert state.confidence == "HIGH"


def test_algorithm_data_object_gets_bounded_array_extent_not_context_type():
    context, fn = _context()
    obj = {"rva": 0x2000, "file_offset": 0x600, "size": 16, "semantic": "POSSIBLE_KEY"}
    suggestions, _ = generate_suggestions(context, [], [], [], [_algorithm(fn, data_objects=(obj,))], [])
    key = next(item for item in suggestions if item.target.get("rva") == 0x2000)
    assert key.proposed_value["role"] == "POSSIBLE_KEY"
    assert key.proposed_value["type_hint"] == "uint32_t[4]"
    assert "Context" not in str(key.proposed_value)


def test_indexed_access_generates_comment_only_array_semantics():
    context, fn = _context(bytes.fromhex("8B 04 8A 89 04 8A C3"))
    suggestions, _ = generate_suggestions(context, [_source(fn)], [], [], [], [])
    array = next(item for item in suggestions if item.kind == "ARRAY_HINT")
    assert array.proposed_value["element_width"] == 32
    assert array.proposed_value["observed_bounds"] is None
    assert array.safety == "COMMENT_ONLY"


def test_short_shift_xor_add_group_preserves_wraparound_width():
    context, fn = _context(bytes.fromhex("C1 E0 04 C1 EA 05 31 D0 01 D8 C3"))
    suggestions, _ = generate_suggestions(context, [_source(fn)], [], [], [], [])
    group = next(item for item in suggestions if item.kind == "TEMPORARY_GROUP")
    assert group.proposed_value["width"] == "32-bit-like"
    assert "wraparound" in group.proposed_value["arithmetic"]


def test_three_fixed_offsets_produce_comment_only_struct_like_hint():
    context, fn = _context(bytes.fromhex("8B 48 04 8B 50 08 8B 58 10 C3"))
    suggestions, _ = generate_suggestions(context, [_source(fn)], [], [], [], [])
    structure = next(item for item in suggestions
                     if isinstance(item.proposed_value, dict)
                     and item.proposed_value.get("role") == "STRUCT_LIKE_OBJECT")
    assert [field["offset"] for field in structure.proposed_value["fields"]] == [4, 8, 16]
    assert structure.safety == "COMMENT_ONLY"


def test_scalar_arithmetic_is_not_misreported_as_pointer_or_array():
    context, fn = _context(bytes.fromhex("8D 40 04 83 C0 07 C3"))
    suggestions, _ = generate_suggestions(context, [_source(fn)], [], [], [], [])
    assert not any(item.kind == "ARRAY_HINT" for item in suggestions)
    assert not any(isinstance(item.proposed_value, dict)
                   and item.proposed_value.get("role") == "STRUCT_LIKE_OBJECT"
                   for item in suggestions)


def test_side_effect_breaks_temporary_group_and_budget_is_explicit():
    context, fn = _context(bytes.fromhex("C1 E0 04 E8 00 00 00 00 C1 EA 05 31 D0 01 D8 C3"))
    suggestions, budget = generate_suggestions(context, [_source(fn)], [], [], [], [],
                                               budgets={"max_semantic_suggestions": 1})
    assert not any(item.kind == "TEMPORARY_GROUP" for item in suggestions)
    assert len(suggestions) == 1
    assert budget["truncated"] is True
