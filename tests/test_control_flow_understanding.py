import struct
from types import SimpleNamespace

from reversehelper.control_flow_understanding import analyze_control_flow
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.findings import Function
from tests.p0_support import Code


def _context(code, table_targets=(), *, x64=False, runtime="USER_CODE"):
    base = 0 if x64 else 0x400000
    architecture = "x86-64" if x64 else "x86"
    data = bytearray(0x800)
    data[0x200:0x200 + len(code)] = code
    width = 8 if x64 else 4
    for index, target in enumerate(table_targets):
        struct.pack_into("<Q" if x64 else "<I", data, 0x600 + index * width, base + target)
    sections = [
        {"name": ".text", "virtual_address": 0x1000, "raw_address": 0x200,
         "raw_size": len(code), "flags": ["EXECUTE", "READ"]},
        {"name": ".rdata", "virtual_address": 0x2000, "raw_address": 0x600,
         "raw_size": 0x200, "flags": ["READ"]},
    ]
    instructions = Disassembler(architecture, base).disassemble_range(bytes(data), sections, 0x1000, len(code), skip_invalid=True)
    records = list(iter_instruction_details(instructions, architecture))
    function = Function(0x1000, base + 0x1000, "FUN_SWITCH", 0x200, ".text", "test", "high",
                        tuple(ins.rva for ins, _ in records), runtime_likelihood=runtime)
    context = SimpleNamespace(functions=[function], by_rva={ins.rva: (ins, dec) for ins, dec in records},
                              image_base=base, sections=sections)
    return context, bytes(data)


def _state_switch():
    c = Code()
    c.label("dispatcher")
    c.emit("83 F8 03")
    c.jump("77", "default")
    c.emit("FF 24 85 00 20 40 00")
    c.label("case0"); c.emit("B8 01 00 00 00"); c.jump("EB", "dispatcher")
    c.label("case1"); c.emit("B8 02 00 00 00"); c.jump("EB", "dispatcher")
    c.label("case2"); c.emit("B8 03 00 00 00"); c.jump("EB", "dispatcher")
    c.label("case3"); c.emit("B8 00 00 00 00"); c.jump("EB", "dispatcher")
    c.label("default"); c.emit("C3")
    code = c.finish()
    targets = tuple(0x1000 + c.labels[f"case{i}"] for i in range(4))
    return code, targets


def test_bounded_jump_table_recovers_cases_and_selector():
    code, targets = _state_switch()
    context, data = _context(code, targets)
    findings, budget = analyze_control_flow(context, data)
    switch = next(item for item in findings if item.kind == "SWITCH")
    assert switch.confidence == "HIGH"
    assert switch.jump_table["case_count"] == 4
    assert switch.jump_table["case_targets"] == list(targets)
    assert switch.state_variable == {"kind": "REGISTER", "name": "a"}
    assert not budget["truncated"]


def test_x64_eight_byte_jump_table_entries_are_supported():
    code = bytes.fromhex("83 F8 02 77 07 FF 24 C5 00 20 00 00 C3 90 90 90 C3 90 90 90 C3 90 90 90 C3")
    targets = (0x1010, 0x1014, 0x1018)
    context, data = _context(code, targets, x64=True)
    findings, _ = analyze_control_flow(context, data)
    table = next(item for item in findings if item.kind in {"SWITCH", "JUMP_TABLE"})
    assert table.jump_table["entry_size"] == 8
    assert table.jump_table["case_targets"] == list(targets)


def test_state_machine_and_flattening_like_require_dispatch_reentry_and_state_writes():
    code, targets = _state_switch()
    context, data = _context(code, targets)
    findings, _ = analyze_control_flow(context, data)
    state = next(item for item in findings if item.kind == "STATE_MACHINE")
    flattening = next(item for item in findings if item.kind == "FLATTENING_LIKE")
    assert state.confidence == "HIGH"
    assert state.dispatcher_block == 0x1000
    assert len(state.state_updates) == 4
    assert flattening.confidence == "MEDIUM"


def test_large_direct_branch_structure_is_not_called_flattening():
    code = bytes.fromhex("83 F8 01 74 04 83 F8 02 75 02 90 C3")
    context, data = _context(code)
    findings, _ = analyze_control_flow(context, data)
    assert not any(item.kind in {"STATE_MACHINE", "FLATTENING_LIKE"} for item in findings)


def test_indirect_jump_without_valid_executable_table_stays_low():
    context, data = _context(bytes.fromhex("FF 24 85 00 20 40 00 C3"))
    findings, _ = analyze_control_flow(context, data)
    indirect = next(item for item in findings if item.kind == "INDIRECT_JUMP")
    assert indirect.confidence == "LOW"


def test_indexed_indirect_call_cluster_is_structural_only():
    code = bytes.fromhex("FF 14 85 00 20 40 00 FF 14 8D 00 20 40 00 FF 14 95 00 20 40 00 C3")
    context, data = _context(code)
    findings, _ = analyze_control_flow(context, data)
    cluster = next(item for item in findings if item.kind == "INDIRECT_CALL_CLUSTER")
    assert cluster.confidence == "MEDIUM"
    assert cluster.jump_table is None


def test_runtime_flattening_like_candidate_is_downgraded():
    code, targets = _state_switch()
    context, data = _context(code, targets, runtime="RUNTIME_LIKELY")
    findings, _ = analyze_control_flow(context, data)
    flattening = next(item for item in findings if item.kind == "FLATTENING_LIKE")
    assert flattening.confidence == "LOW"


def test_cfg_budget_truncation_is_explicit():
    context, data = _context(bytes.fromhex("90 C3"))
    _, budget = analyze_control_flow(context, data, budgets={"max_cfg_functions": 0})
    assert budget["truncated"] is True


def test_repeated_constant_predicate_is_only_a_low_opaque_like_hint():
    code = bytes.fromhex("83 F8 2A 74 00 83 FB 2A 75 00 83 F9 2A 74 00 C3")
    context, data = _context(code)
    findings, _ = analyze_control_flow(context, data)
    opaque = next(item for item in findings if item.kind == "OPAQUE_LIKE_CANDIDATE")
    assert opaque.confidence == "LOW"
