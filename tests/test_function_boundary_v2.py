from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.function_index import FunctionIndex


BASE = 0x400000


def _index(code: bytes, *, entry=0x1000, runtime=(), symbols=()):
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": 0,
                 "raw_size": len(code), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler("x86", BASE).disassemble_range(code, sections, 0x1000, len(code), skip_invalid=True)
    records = list(iter_instruction_details(instructions, "x86"))
    return FunctionIndex(records, sections, BASE, entry, runtime_functions=runtime, symbols=symbols)


def test_post_return_non_frame_prologue_is_split():
    context = _index(bytes.fromhex("C3 83 EC 10 90 C3"))
    assert context.owner(0x1000).rva == 0x1000
    assert context.owner(0x1001).rva == 0x1001
    assert context.owner(0x1001).source == "post-return prologue"
    assert context.owner(0x1001).to_dict()["boundary_confidence"] == "HEURISTIC"


def test_coff_symbol_lead_names_and_strengthens_boundary():
    context = _index(bytes.fromhex("C3 83 EC 10 C3"), symbols=({"rva": 0x1001, "name": "_worker"},))
    worker = next(function for function in context.functions if function.rva == 0x1001)
    assert worker.name == "_worker"
    assert worker.confidence == "high"
    assert worker.source == "COFF symbol table"
    assert worker.runtime_likelihood == "USER_CODE"
    assert worker.to_dict()["boundary_confidence"] == "CONFIRMED"


def test_known_crt_symbol_is_runtime_likely():
    context = _index(bytes.fromhex("C3"), symbols=({"rva": 0x1000, "name": "_memcmp"},))
    function = context.functions[0]
    assert function.runtime_likelihood == "RUNTIME_LIKELY"
    assert "runtime" in function.runtime_evidence[0]


def test_runtime_function_range_is_a_high_confidence_exact_lead():
    context = _index(bytes.fromhex("90 90 C3 90 C3"), runtime=((0x1000, 0x1003), (0x1003, 0x1005)))
    functions = {function.rva: function for function in context.functions}
    assert functions[0x1000].confidence == "high"
    assert functions[0x1003].end_rva_exclusive == 0x1005


def test_direct_jump_thunk_and_tail_target_are_explicit():
    # jmp 0x1010; padding; ret
    code = bytes.fromhex("E9 0B 00 00 00") + b"\x90" * 11 + b"\xC3"
    context = _index(code)
    thunk = next(function for function in context.functions if function.rva == 0x1000)
    assert thunk.is_thunk and thunk.thunk_target_rva == 0x1010
    assert thunk.runtime_likelihood == "THUNK"
    assert thunk.tail_call_targets == (0x1010,)
    assert context.owner(0x1010).rva == 0x1010


def test_shared_tail_is_left_unowned_and_reported():
    # caller calls two functions. Each conditional branch reaches the same tail.
    code = bytearray(b"\x90" * 0x31)
    code[0:11] = bytes.fromhex("E8 0B 00 00 00 E8 16 00 00 00 C3")
    code[0x10:0x18] = bytes.fromhex("75 1E C3 90 90 90 90 90")
    code[0x20:0x28] = bytes.fromhex("75 0E C3 90 90 90 90 90")
    code[0x30] = 0xC3
    context = _index(bytes(code))
    assert context.owner(0x1030) is None
    owners = {function.rva: function for function in context.functions}
    assert 0x1030 in owners[0x1010].shared_tail_rvas
    assert 0x1030 in owners[0x1020].shared_tail_rvas
    assert any(chunk.relation == "SHARED_EPILOGUE" for chunk in owners[0x1010].chunks)
    assert any(chunk.relation == "SHARED_EPILOGUE" for chunk in owners[0x1020].chunks)


def test_jump_connected_secondary_function_chunk_is_explicit():
    code = bytes.fromhex("90 EB 0D") + b"\xCC" * 13 + bytes.fromhex("83 F8 41 C3")
    context = _index(code)
    function = context.owner(0x1000)
    assert [chunk.relation for chunk in function.chunks] == ["PRIMARY", "TAIL"]
    assert any(ins.rva == 0x1010 for ins, _ in context.function_records[function.rva])


def test_entry_prefix_fallthrough_is_related_to_primary_body():
    # pop eax; body: push ebp; mov ebp,esp; ret
    context = _index(bytes.fromhex("58 55 8B EC C3"), entry=0x1000)
    logical = context.owner(0x1000)
    assert context.owner(0x1001) is logical
    assert logical.rva == 0x1000
    assert [chunk.relation for chunk in logical.chunks] == ["ENTRY_STUB", "BODY"]
    assert logical.to_dict()["boundary_confidence"] == "LIKELY"


def test_tiny_entry_call_stub_is_related_to_called_body():
    # call body; xor eax,eax; ret; body: push ebp; mov ebp,esp; ret
    context = _index(bytes.fromhex("E8 03 00 00 00 31 C0 C3 55 8B EC C3"), entry=0x1000)
    logical = context.owner(0x1000)
    assert context.owner(0x1008) is logical
    assert logical.rva == 0x1000
    assert [chunk.relation for chunk in logical.chunks] == ["ENTRY_STUB", "BODY"]
    assert not any(target == 0x1008 for _, target in context.calls)


def test_entry_call_with_nonconstant_tail_remains_separate():
    # call worker; add eax,1; ret; worker prologue
    context = _index(bytes.fromhex("E8 04 00 00 00 83 C0 01 C3 55 8B EC C3"), entry=0x1000)
    assert context.owner(0x1000).rva == 0x1000
    assert context.owner(0x1009).rva == 0x1009
