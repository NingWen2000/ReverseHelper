"""Structured, serializable models for the bounded Quick static-flow analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, TypeAlias

from .value_identity import ValueIdentity


FlowConfidence = Literal["CONFIRMED", "LIKELY", "POSSIBLE"]
EdgeType = Literal["COPY", "ADDRESS", "ARGUMENT", "RETURN", "LOAD", "STORE", "TRANSFORM", "COMPARE"]


class _Location:
    kind: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def key(self) -> tuple[Any, ...]:
        return tuple(self.to_dict().values())


@dataclass(frozen=True, slots=True)
class RegisterLocation(_Location):
    name: str
    function_rva: int | None = None
    definition_rva: int | None = None
    kind: str = "REGISTER"


@dataclass(frozen=True, slots=True)
class StackLocation(_Location):
    function_rva: int
    offset: int
    base: str = "bp"
    definition_rva: int | None = None
    kind: str = "STACK"


@dataclass(frozen=True, slots=True)
class MemoryLocation(_Location):
    base: str | None
    index: str | None
    scale: int
    offset: int
    function_rva: int | None = None
    kind: str = "MEMORY"


@dataclass(frozen=True, slots=True)
class ArgumentLocation(_Location):
    function_rva: int
    index: int
    kind: str = "ARGUMENT"


@dataclass(frozen=True, slots=True)
class ReturnValueLocation(_Location):
    function_rva: int | None
    callsite_rva: int
    register: str
    kind: str = "RETURN_VALUE"


@dataclass(frozen=True, slots=True)
class GlobalLocation(_Location):
    rva: int
    address: int
    kind: str = "GLOBAL"


@dataclass(frozen=True, slots=True)
class ImmediateLocation(_Location):
    value: int
    kind: str = "IMMEDIATE"


@dataclass(frozen=True, slots=True)
class UnknownLocation(_Location):
    description: str
    kind: str = "UNKNOWN"


ValueLocation: TypeAlias = (
    RegisterLocation | StackLocation | MemoryLocation | ArgumentLocation |
    ReturnValueLocation | GlobalLocation | ImmediateLocation | UnknownLocation
)


@dataclass(frozen=True, slots=True)
class InputSource:
    id: str
    function: str | None
    function_rva: int | None
    callsite: int
    callsite_rva: int
    source_type: str
    destination: ValueLocation
    size_hint: int | None
    confidence: FlowConfidence
    evidence: tuple[str, ...]
    value_identity: ValueIdentity | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["destination"] = self.destination.to_dict()
        result["evidence"] = list(self.evidence)
        result["value_identity"] = self.value_identity.to_dict() if self.value_identity else None
        return result


@dataclass(frozen=True, slots=True)
class DataFlowEdge:
    source: ValueLocation
    destination: ValueLocation
    instruction_address: int
    instruction_rva: int
    edge_type: EdgeType
    confidence: FlowConfidence
    evidence: str
    value_identity: ValueIdentity | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(), "destination": self.destination.to_dict(),
            "instruction_address": self.instruction_address, "instruction_rva": self.instruction_rva,
            "edge_type": self.edge_type, "confidence": self.confidence, "evidence": self.evidence,
            "value_identity": self.value_identity.to_dict() if self.value_identity else None,
        }


@dataclass(frozen=True, slots=True)
class StaticSlice:
    id: str
    input_source: InputSource
    nodes: tuple[dict[str, Any], ...]
    edges: tuple[DataFlowEdge, ...]
    transforms: tuple[dict[str, Any], ...]
    validation_sink: dict[str, Any] | None
    outcome_branch: dict[str, Any] | None
    confidence: FlowConfidence
    warnings: tuple[str, ...]
    status: str = ""

    def to_dict(self) -> dict[str, Any]:
        status = self.status or (
            "PARTIAL_SLICE" if self.confidence == "POSSIBLE" or any("incomplete" in item.lower() for item in self.warnings)
            else "CONFIRMED_SLICE" if self.confidence == "CONFIRMED" else "LIKELY_SLICE"
        )
        return {
            "id": self.id, "input_source": self.input_source.to_dict(), "nodes": list(self.nodes),
            "edges": [edge.to_dict() for edge in self.edges], "transforms": list(self.transforms),
            "validation_sink": self.validation_sink, "outcome_branch": self.outcome_branch,
            "confidence": self.confidence, "status": status, "incomplete": status == "PARTIAL_SLICE",
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class StaticFlowBreak:
    id: str
    input_source: InputSource
    function_rva: int | None
    break_rva: int
    last_confirmed_node: dict[str, Any]
    next_unresolved_target: dict[str, Any] | None
    reason: str
    evidence: tuple[str, ...]
    confidence: FlowConfidence
    edges: tuple[DataFlowEdge, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "input_source": self.input_source.to_dict(),
            "function_rva": self.function_rva,
            "break_rva": self.break_rva,
            "last_confirmed_node": dict(self.last_confirmed_node),
            "next_unresolved_target": dict(self.next_unresolved_target) if self.next_unresolved_target else None,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "edges": [edge.to_dict() for edge in self.edges],
            "status": "PARTIAL_SLICE",
        }


@dataclass(frozen=True, slots=True)
class IntraFlowResult:
    edges: tuple[DataFlowEdge, ...]
    call_arguments: tuple[dict[str, Any], ...]
    comparisons: tuple[dict[str, Any], ...]
    transforms: tuple[dict[str, Any], ...]
    returns: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...]
    incomplete: bool = False
    budgets: dict[str, int] = field(default_factory=dict)
    mutations: tuple[dict[str, Any], ...] = ()
    output_parameters: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "edges": [edge.to_dict() for edge in self.edges],
            "call_arguments": list(self.call_arguments), "comparisons": list(self.comparisons),
            "transforms": list(self.transforms), "returns": list(self.returns),
            "warnings": list(self.warnings),
            "incomplete": self.incomplete,
            "budgets": dict(self.budgets),
            "mutations": list(self.mutations),
            "output_parameters": list(self.output_parameters),
        }


@dataclass(frozen=True, slots=True)
class InterproceduralTrace:
    input_source_id: str
    edges: tuple[DataFlowEdge, ...]
    call_arguments: tuple[dict[str, Any], ...]
    comparisons: tuple[dict[str, Any], ...]
    transforms: tuple[dict[str, Any], ...]
    returns: tuple[dict[str, Any], ...]
    functions_visited: tuple[int, ...]
    warnings: tuple[str, ...]
    incomplete: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_source_id": self.input_source_id, "edges": [edge.to_dict() for edge in self.edges],
            "call_arguments": list(self.call_arguments), "comparisons": list(self.comparisons),
            "transforms": list(self.transforms), "returns": list(self.returns),
            "functions_visited": list(self.functions_visited), "warnings": list(self.warnings),
            "incomplete": self.incomplete,
        }


@dataclass(frozen=True, slots=True)
class InterproceduralFlowResult:
    traces: tuple[InterproceduralTrace, ...]
    budgets: dict[str, int]
    warnings: tuple[str, ...]
    function_summaries: tuple["FunctionFlowSummary", ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"traces": [trace.to_dict() for trace in self.traces],
                "budgets": dict(self.budgets), "warnings": list(self.warnings),
                "function_summaries": [summary.to_dict() for summary in self.function_summaries]}


@dataclass(frozen=True, slots=True)
class ReturnSummary:
    kind: str
    argument_index: int | None
    offset: int
    confidence: FlowConfidence
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result


@dataclass(frozen=True, slots=True)
class ArgumentFlowSummary:
    kind: str
    source_argument: int
    destination_argument: int
    confidence: FlowConfidence
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result


@dataclass(frozen=True, slots=True)
class FunctionFlowSummary:
    function_rva: int
    returns: tuple[ReturnSummary, ...]
    mutates_arguments: tuple[int, ...]
    output_parameters: tuple[ArgumentFlowSummary, ...]
    confidence: FlowConfidence
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_rva": self.function_rva,
            "returns": [item.to_dict() for item in self.returns],
            "mutates_arguments": list(self.mutates_arguments),
            "output_parameters": [item.to_dict() for item in self.output_parameters],
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }
