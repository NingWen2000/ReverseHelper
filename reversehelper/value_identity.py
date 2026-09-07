"""Lightweight value identity for bounded Quick data-flow recovery.

This intentionally models provenance and simple aliases only.  It is not SSA,
memory SSA, or a path-sensitive state engine.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Literal


AliasConfidence = Literal["EXACT_ALIAS", "BASE_ALIAS", "POSSIBLE_ALIAS"]
FlowConfidence = Literal["CONFIRMED", "LIKELY", "POSSIBLE"]


@dataclass(frozen=True, slots=True)
class ValueIdentity:
    id: str
    origin: str
    base_object: dict[str, Any]
    offset: int = 0
    index: str | None = None
    scale: int = 1
    confidence: FlowConfidence = "CONFIRMED"
    provenance: tuple[str, ...] = ()
    alias_confidence: AliasConfidence = "EXACT_ALIAS"
    version: int = 0
    merged_origins: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "origin": self.origin,
            "base_object": dict(self.base_object),
            "offset": self.offset,
            "index": self.index,
            "scale": self.scale,
            "confidence": self.confidence,
            "provenance": list(self.provenance),
            "alias_confidence": self.alias_confidence,
            "version": self.version,
            "merged_origins": list(self.merged_origins),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ValueIdentity":
        return cls(
            str(value["id"]), str(value["origin"]), dict(value["base_object"]),
            int(value.get("offset", 0)), value.get("index"), int(value.get("scale", 1)),
            value.get("confidence", "POSSIBLE"), tuple(value.get("provenance", ())),
            value.get("alias_confidence", "POSSIBLE_ALIAS"), int(value.get("version", 0)),
            tuple(value.get("merged_origins", ())),
        )

    def copied(self, evidence: str) -> "ValueIdentity":
        return replace(self, provenance=(*self.provenance[-11:], evidence))

    def derived(self, evidence: str, *, offset: int = 0, index: str | None = None,
                scale: int = 1, possible: bool = False, transformed: bool = False) -> "ValueIdentity":
        alias: AliasConfidence = "POSSIBLE_ALIAS" if possible else "BASE_ALIAS"
        confidence: FlowConfidence = "POSSIBLE" if possible else (
            "LIKELY" if self.confidence == "CONFIRMED" else self.confidence
        )
        return replace(
            self,
            offset=self.offset + offset,
            index=index or self.index,
            scale=scale if index else self.scale,
            confidence=confidence,
            alias_confidence=alias,
            version=self.version + int(transformed),
            provenance=(*self.provenance[-11:], evidence),
        )

    def transformed(self, evidence: str) -> "ValueIdentity":
        return replace(
            self,
            version=self.version + 1,
            provenance=(*self.provenance[-11:], evidence),
        )


@dataclass(frozen=True, slots=True)
class TrackedValue:
    location: Any
    identity: ValueIdentity

    def to_dict(self) -> dict[str, Any]:
        return self.location.to_dict()


def identity_for_source(source: Any) -> ValueIdentity:
    destination = source.destination.to_dict()
    return ValueIdentity(
        id=f"value-{source.id}",
        origin=source.id,
        base_object=destination,
        confidence=source.confidence,
        provenance=(f"input source {source.id}",),
    )


def merge_identities(left: ValueIdentity, right: ValueIdentity, evidence: str) -> ValueIdentity:
    """Conservatively represent a bounded two-way merge without claiming certainty."""
    if left.id == right.id:
        return left.copied(evidence)
    origins = tuple(dict.fromkeys((left.origin, *left.merged_origins, right.origin, *right.merged_origins)))
    return ValueIdentity(
        id="merge-" + "-".join(item.replace(" ", "_") for item in origins[:4]),
        origin=origins[0],
        base_object=dict(left.base_object) if left.base_object == right.base_object else {"kind": "MERGED"},
        confidence="POSSIBLE",
        provenance=(*left.provenance[-5:], *right.provenance[-5:], evidence),
        alias_confidence="POSSIBLE_ALIAS",
        version=max(left.version, right.version),
        merged_origins=origins,
    )
