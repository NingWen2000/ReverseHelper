from reversehelper.dataflow_model import (
    DataFlowEdge, InputSource, InterproceduralFlowResult, InterproceduralTrace,
    RegisterLocation, ReturnValueLocation, StackLocation,
)
from reversehelper.findings import ValidationCandidate
from reversehelper.static_slice import build_static_slices


def candidate(rva=0x1020):
    return ValidationCandidate("validation", "FUN", 0x1000, 0x401020, rva, "MEMCMP", None, None,
                               None, None, None, "medium", ("test",), branch_rva=0x1025)


def input_source():
    return InputSource("input", "FUN", 0x1000, 0x401000, 0x1000, "scanf",
                       StackLocation(0x1000, -0x40), 31, "CONFIRMED", ("test",))


def flow(callsite=0x1020, *, transforms=(), edges=()):
    trace = InterproceduralTrace("input", tuple(edges),
        ({"caller_function_rva": 0x1000, "callsite_rva": callsite, "callee_rva": None,
          "argument_index": 0, "source": {}, "confidence": "CONFIRMED"},),
        (), tuple(transforms), (), (0x1000,), (), False)
    return InterproceduralFlowResult((trace,), {"max_call_depth": 3}, ())


def test_scanf_direct_compare_builds_confirmed_slice():
    slices, enriched = build_static_slices([input_source()], flow(), [candidate()])
    assert len(slices) == 1
    assert slices[0].validation_sink["validation_type"] == "MEMCMP"
    assert enriched[0].input_flow_to_validation == "CONFIRMED"


def test_false_same_function_context_remains_none():
    slices, enriched = build_static_slices([input_source()], flow(callsite=0x1050), [candidate()])
    assert slices == []
    assert enriched[0].input_flow_to_validation == "NONE"


def test_direct_argument_into_validation_function_is_possible_without_alias_proof():
    trace = InterproceduralTrace("input", (),
        ({"caller_function_rva": 0x1000, "callsite_rva": 0x1010, "callee_rva": 0x1040,
          "argument_index": 0, "source": {}, "confidence": "CONFIRMED"},),
        (), (), (), (0x1000, 0x1040), (), False)
    model = InterproceduralFlowResult((trace,), {}, ())
    sink = candidate()
    sink = ValidationCandidate(sink.id, sink.function, 0x1040, sink.address, 0x1050,
                               sink.validation_type, sink.input_source, sink.compare_target,
                               sink.compare_length, sink.success_branch, sink.failure_branch,
                               sink.confidence, sink.evidence)
    slices, enriched = build_static_slices([input_source()], model, [sink])
    assert slices[0].confidence == "POSSIBLE"
    assert slices[0].to_dict()["status"] == "PARTIAL_SLICE"
    assert slices[0].to_dict()["incomplete"] is True
    assert enriched[0].input_flow_to_validation == "POSSIBLE"


def test_transform_then_compare_is_visible():
    transform = {"function_rva": 0x1010, "instruction_rva": 0x1014,
                 "type": "XOR", "confidence": "CONFIRMED"}
    slices, _ = build_static_slices([input_source()], flow(transforms=(transform,)), [candidate()])
    assert slices[0].transforms[0]["type"] == "XOR"


def test_branch_after_validation_return_value_is_marked():
    edge = DataFlowEdge(RegisterLocation("a", 0x1040, 0x1048), ReturnValueLocation(0x1000, 0x1010, "a"),
                        0x401010, 0x1010, "RETURN", "LIKELY", "test return")
    slices, _ = build_static_slices([input_source()], flow(edges=(edge,)), [candidate()])
    assert slices[0].outcome_branch["return_value_controls_branch"] is True
    assert slices[0].confidence == "LIKELY"


def test_table_transform_is_retained_as_possible():
    transform = {"function_rva": 0x1010, "instruction_rva": 0x1014,
                 "type": "TABLE_LOOKUP", "confidence": "POSSIBLE"}
    slices, _ = build_static_slices([input_source()], flow(transforms=(transform,)), [candidate()])
    assert slices[0].transforms[0]["type"] == "TABLE_LOOKUP"
