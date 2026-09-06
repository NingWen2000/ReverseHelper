import struct

from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.function_index import FunctionIndex
from reversehelper.input_sources import discover_input_sources


def context_for(code, architecture="x86-64", base=0x140000000, *, exports=()):
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": 0,
                 "raw_size": len(code), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler(architecture, base).disassemble_range(code, sections, 0x1000, len(code))
    records = list(iter_instruction_details(instructions, architecture))
    return FunctionIndex(records, sections, base, exports=exports,
                         runtime_functions=() if exports else ((0x1000, 0x1000 + len(code)),))


def import_call(context, name):
    call = next(ins for ins, decoded in context.records if decoded.mnemonic == "call")
    return [({"source_rva": call.rva}, "test.dll", {"name": name})]


def test_scanf_destination_and_width_are_recovered():
    # lea rdx,[rbp-40h]; lea rcx,[rip+format]; call rel32; ret
    code = bytes.fromhex("48 8D 55 C0 48 8D 0D 35 20 00 00 E8 00 00 00 00 C3")
    context = context_for(code)
    source = discover_input_sources(context, import_call(context, "scanf"), "x86-64",
                                    [{"rva": 0x3040, "value": "%31s"}])[0]
    assert source.source_type == "scanf"
    assert source.destination.kind == "STACK" and source.destination.offset == -0x40
    assert source.size_hint == 31 and source.confidence == "CONFIRMED"


def test_readfile_buffer_and_size_arguments_are_recovered():
    # mov r8d,20h; lea rdx,[rbp-30h]; xor ecx,ecx; call; ret
    code = bytes.fromhex("41 B8 20 00 00 00 48 8D 55 D0 31 C9 E8 00 00 00 00 C3")
    context = context_for(code)
    source = discover_input_sources(context, import_call(context, "ReadFile"), "x86-64")[0]
    assert source.destination.kind == "STACK" and source.destination.offset == -0x30
    assert source.size_hint == 0x20


def test_getcommandline_is_a_return_value_input_source():
    context = context_for(bytes.fromhex("E8 00 00 00 00 C3"))
    source = discover_input_sources(context, import_call(context, "GetCommandLineW"), "x86-64")[0]
    assert source.destination.kind == "RETURN_VALUE"
    assert source.destination.register == "a"


def test_x86_push_register_destination_is_traced_back_to_stack():
    # lea eax,[ebp-40h]; push 20h; push eax; push 0; call ReadFile; ret
    code = bytes.fromhex("8D 45 C0 6A 20 50 6A 00 E8 00 00 00 00 C3")
    context = context_for(code, "x86", 0x400000)
    source = discover_input_sources(context, import_call(context, "ReadFile"), "x86")[0]
    assert source.destination.kind == "STACK" and source.destination.offset == -0x40


def test_x86_esp_argument_slots_are_recovered():
    # lea eax,[ebp-40h]; mov [esp+8],20h; mov [esp+4],eax; mov [esp],0; call ReadFile; ret
    code = bytes.fromhex(
        "8D 45 C0 C7 44 24 08 20 00 00 00 89 44 24 04 "
        "C7 04 24 00 00 00 00 E8 00 00 00 00 C3"
    )
    context = context_for(code, "x86", 0x400000)
    source = discover_input_sources(context, import_call(context, "ReadFile"), "x86")[0]
    assert source.destination.kind == "STACK" and source.destination.offset == -0x40
    assert source.size_hint == 0x20


def test_argv_direct_compare_source_is_modeled_after_argc_check():
    # cmp [ebp+8],2; mov eax,[ebp+0c]; mov ecx,[eax+4]; ret
    code = bytes.fromhex("83 7D 08 02 8B 45 0C 8B 48 04 C3")
    context = context_for(code, "x86", 0x400000)
    source = discover_input_sources(context, [], "x86")[0]
    assert source.source_type == "argv[1]"
    assert source.destination.kind == "REGISTER" and source.destination.name == "c"


def test_argv_x64_early_load_is_recovered_when_argc_check_follows():
    # Save ABI args, reload argv after stack allocation, load before saved argc check.
    context = context_for(bytes.fromhex(
        "48 89 54 24 10 89 4C 24 08 48 83 EC 20 48 8B 54 24 30 "
        "48 8B 1A 48 8B 42 08 83 7C 24 28 02 48 83 C4 20 C3"
    ))
    source = next(item for item in discover_input_sources(context, [], "x86-64")
                  if item.source_type == "argv[1]")
    assert source.source_type == "argv[1]"
    assert source.confidence == "CONFIRMED"
    assert source.value_identity.base_object == {
        "kind": "ARGV", "object": "ArgvObject#1", "index": 1,
    }


def test_argv_unknown_scaled_index_is_conservative():
    context = context_for(bytes.fromhex(
        "48 89 54 24 10 89 4C 24 08 48 83 EC 20 48 8B 54 24 30 "
        "48 8B 1A 48 8B 42 08 48 8B 04 CA 83 7C 24 28 02 48 83 C4 20 C3"
    ))
    source = next(item for item in discover_input_sources(context, [], "x86-64")
                  if item.source_type == "argv[*]")
    assert source.source_type == "argv[*]"
    assert source.confidence == "LIKELY"
    assert source.value_identity.base_object["index"] is None


def test_export_buffer_argument_is_seeded_only_when_pointer_consumed_on_validation_path():
    # cmp byte ptr [rcx],0; je +3; xor byte ptr [rcx],1; ret
    code = bytes.fromhex("80 39 00 74 03 80 31 01 C3")
    context = context_for(code, exports=({"address_rva": 0x1000, "name": "check"},))
    sources = discover_input_sources(context, [], "x86-64")
    source = next(item for item in sources if item.source_type == "EXPORTED_ARGUMENT")
    assert source.destination.kind == "ARGUMENT" and source.destination.index == 0
    assert source.value_identity.base_object["kind"] == "EXPORTED_ARGUMENT"


def test_export_scalar_flag_is_not_promoted_to_external_input():
    # cmp ecx,1; sete al; ret -- scalar use, never dereferenced
    code = bytes.fromhex("83 F9 01 0F 94 C0 C3")
    context = context_for(code, exports=({"address_rva": 0x1000, "name": "configure"},))
    assert discover_input_sources(context, [], "x86-64") == []
