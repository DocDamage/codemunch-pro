"""ROM-agnostic reverse-engineering evidence model.

This module defines generic records for indexing reverse-engineering work
without assuming a specific platform, ISA, or address mapping scheme.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


JSONScalar = str | int | float | bool | None
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


def _copy_mapping(value: dict[str, JSONValue]) -> dict[str, JSONValue]:
    """Return a shallow copy to avoid leaking mutable defaults."""
    return dict(value) if value else {}


@dataclass(frozen=True, slots=True)
class AddressLocation:
    """A generic address range within a named address space."""

    address_space: str
    start: int
    end: int
    unit: str = "byte"
    display: str = ""
    segment: str = ""
    attributes: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.start > self.end:
            raise ValueError("start must be <= end")

    @property
    def size(self) -> int:
        """Return the inclusive span length."""
        return (self.end - self.start) + 1

    def contains(self, address: int) -> bool:
        """Return True when the address falls within the location."""
        return self.start <= address <= self.end

    def overlaps(self, other: "AddressLocation") -> bool:
        """Return True when two locations overlap in the same address space."""
        if self.address_space != other.address_space:
            return False
        return not (self.end < other.start or other.end < self.start)

    def to_dict(self) -> dict[str, JSONValue]:
        """Serialize the location to a JSON-friendly mapping."""
        data = asdict(self)
        data["attributes"] = _copy_mapping(self.attributes)
        return data


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """An indexed artifact such as a manifest, note, report, or disassembly file."""

    artifact_id: str
    kind: str
    path: str
    sha256: str = ""
    title: str = ""
    media_type: str = ""
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, JSONValue]:
        """Serialize the artifact to a JSON-friendly mapping."""
        data = asdict(self)
        data["metadata"] = _copy_mapping(self.metadata)
        return data


@dataclass(frozen=True, slots=True)
class EntityRecord:
    """A reverse-engineering entity extracted from one or more artifacts."""

    entity_id: str
    kind: str
    name: str
    artifact_id: str = ""
    canonical_ref: str = ""
    location: AddressLocation | None = None
    summary: str = ""
    aliases: tuple[str, ...] = ()
    attributes: dict[str, JSONValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, JSONValue]:
        """Serialize the entity to a JSON-friendly mapping."""
        data = asdict(self)
        data["aliases"] = list(self.aliases)
        data["attributes"] = _copy_mapping(self.attributes)
        if self.location is not None:
            data["location"] = self.location.to_dict()
        return data


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """A concrete piece of evidence tied to one or more entities."""

    evidence_id: str
    kind: str
    artifact_id: str
    entity_ids: tuple[str, ...] = ()
    location: AddressLocation | None = None
    excerpt: str = ""
    confidence: float | None = None
    attributes: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> dict[str, JSONValue]:
        """Serialize the evidence to a JSON-friendly mapping."""
        data = asdict(self)
        data["entity_ids"] = list(self.entity_ids)
        data["attributes"] = _copy_mapping(self.attributes)
        if self.location is not None:
            data["location"] = self.location.to_dict()
        return data


@dataclass(frozen=True, slots=True)
class EdgeRecord:
    """A directed relationship between entities."""

    edge_id: str
    kind: str
    source_entity_id: str
    target_entity_id: str
    evidence_id: str = ""
    confidence: float | None = None
    attributes: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> dict[str, JSONValue]:
        """Serialize the edge to a JSON-friendly mapping."""
        data = asdict(self)
        data["attributes"] = _copy_mapping(self.attributes)
        return data


@dataclass(slots=True)
class ReverseEngineeringBundle:
    """A self-contained batch of indexed reverse-engineering artifacts."""

    artifacts: list[ArtifactRecord] = field(default_factory=list)
    entities: list[EntityRecord] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    edges: list[EdgeRecord] = field(default_factory=list)
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, JSONValue]:
        """Serialize the bundle to a JSON-friendly mapping."""
        return {
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "entities": [entity.to_dict() for entity in self.entities],
            "evidence": [item.to_dict() for item in self.evidence],
            "edges": [edge.to_dict() for edge in self.edges],
            "metadata": _copy_mapping(self.metadata),
        }

    def add_entity(self, entity: EntityRecord) -> None:
        """Append an entity to the bundle."""
        self.entities.append(entity)

    def add_evidence(self, evidence: EvidenceRecord) -> None:
        """Append an evidence record to the bundle."""
        self.evidence.append(evidence)

    def add_edge(self, edge: EdgeRecord) -> None:
        """Append an edge record to the bundle."""
        self.edges.append(edge)
