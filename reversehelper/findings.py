"""Shared models for instruction-level reverse analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal


Severity = Literal["info", "low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]
Priority = Literal["low", "medium", "high"]


@dataclass(frozen=True, slots=True)
class Instruction:
    """One decoded instruction at its preferred static VA and file location."""

    address: int
    rva: int
    file_offset: int
    size: int
    raw_bytes: bytes
    mnemonic: str
    op_str: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "rva": self.rva,
            "file_offset": self.file_offset,
            "size": self.size,
            "bytes": self.raw_bytes.hex(" ").upper(),
            "mnemonic": self.mnemonic,
            "op_str": self.op_str,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    category: str
    title: str
    rva: int | None
    va: int | None
    file_offset: int | None
    section: str | None
    severity: Severity
    confidence: Confidence
    evidence: tuple[str, ...]
    reason: str
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "rva": self.rva,
            "va": self.va,
            "file_offset": self.file_offset,
            "section": self.section,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "reason": self.reason,
            "recommended_action": self.recommended_action,
        }


@dataclass(frozen=True, slots=True)
class ReverseTarget:
    category: str
    rva: int
    va: int
    file_offset: int | None
    section: str | None
    priority: Priority
    reason: str
    recommended_action: str
    finding_ids: tuple[str, ...]
    score: int = 0
    confidence: str = "low"
    target_type: str = "SUSPICIOUS_FUNCTION"
    function: str | None = None
    score_breakdown: tuple[dict[str, Any], ...] = ()
    evidence_sources: tuple[str, ...] = ()
    target_kind: str = "code_location"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "rva": self.rva,
            "va": self.va,
            "file_offset": self.file_offset,
            "section": self.section,
            "priority": self.priority,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
            "finding_ids": list(self.finding_ids),
            "score": self.score,
            "confidence": self.confidence,
            "type": self.target_type,
            "function": self.function,
            "score_breakdown": list(self.score_breakdown),
            "evidence_sources": list(self.evidence_sources),
            "target_kind": self.target_kind,
        }


@dataclass(frozen=True, slots=True)
class FunctionChunk:
    start_rva: int
    end_rva_exclusive: int
    relation: str
    confidence: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result


@dataclass(frozen=True, slots=True)
class Function:
    """A bounded function candidate; membership is not a contiguous address guess."""

    rva: int
    address: int
    name: str
    file_offset: int
    section: str | None
    source: str
    confidence: str
    instruction_rvas: tuple[int, ...]
    truncated: bool = False
    end_rva_exclusive: int | None = None
    boundary_reasons: tuple[str, ...] = ()
    is_thunk: bool = False
    thunk_target_rva: int | None = None
    tail_call_targets: tuple[int, ...] = ()
    shared_tail_rvas: tuple[int, ...] = ()
    runtime_likelihood: str = "UNKNOWN"
    runtime_evidence: tuple[str, ...] = ()
    chunks: tuple[FunctionChunk, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["boundary_source"] = self.source
        result["boundary_confidence"] = {"high": "CONFIRMED", "medium": "LIKELY", "low": "HEURISTIC"}.get(
            self.confidence, "HEURISTIC")
        result["boundary_evidence"] = list(self.boundary_reasons)
        result["ambiguous"] = bool(self.shared_tail_rvas)
        result["primary_range"] = next((chunk.to_dict() for chunk in self.chunks
                                        if chunk.relation in {"PRIMARY", "BODY"}), None)
        result["secondary_chunks"] = [chunk.to_dict() for chunk in self.chunks
                                      if chunk.relation not in {"PRIMARY", "BODY"}]
        return result


@dataclass(frozen=True, slots=True)
class CompareSite:
    """A comparison observation without a validation claim."""

    id: str
    function: str | None
    function_rva: int | None
    address: int
    rva: int
    compare_type: str
    operands: tuple[dict[str, Any], ...]
    length: int | None
    confidence: str
    evidence: tuple[str, ...]
    runtime_noise: bool = False
    compare_origin: str | None = None
    comparator_function: int | None = None
    thunk_chain: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DecisionSite:
    """A live comparison result that controls a conditional decision."""

    id: str
    compare_site_id: str
    function: str | None
    function_rva: int | None
    address: int
    rva: int
    decision_type: str
    branch_polarity: str | None
    success_branch: dict[str, Any] | None
    failure_branch: dict[str, Any] | None
    confidence: str
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ValidationCandidate:
    id: str
    function: str | None
    function_rva: int | None
    address: int
    rva: int
    validation_type: str
    input_source: dict[str, Any] | None
    compare_target: dict[str, Any] | None
    compare_length: int | None
    success_branch: dict[str, Any] | None
    failure_branch: dict[str, Any] | None
    confidence: str
    evidence: tuple[str, ...]
    branch_rva: int | None = None
    loop: bool = False
    length_check: dict[str, Any] | None = None
    context_only: bool = True
    input_flow_to_validation: str = "NONE"
    decision_type: str | None = None
    branch_polarity: str | None = None
    runtime_noise: bool = False
    unknown_fields: tuple[str, ...] = ()
    compare_origin: str | None = None
    comparator_function: int | None = None
    thunk_chain: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
