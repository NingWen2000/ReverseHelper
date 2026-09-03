"""Shared models for instruction-level reverse analysis."""

from __future__ import annotations

from dataclasses import dataclass
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
        }
