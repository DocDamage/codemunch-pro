"""Adapter layer for reverse engineering primitives."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    ReverseEngineeringBundle,
)


class AddressCodec(Protocol):
    """Protocol for address codecs that parse and format address references."""

    name: str

    def extract_refs(self, text: str) -> list[str]:
        """Extract address references from text."""
        ...

    def parse(self, ref: str) -> AddressLocation | None:
        """Parse a reference string into an AddressLocation."""
        ...

    def format(self, location: AddressLocation) -> str:
        """Format an AddressLocation back to canonical form."""
        ...

    def to_file_offset(self, location: AddressLocation) -> int | None:
        """Convert location to file offset."""
        ...


@dataclass
class FlatAddressCodec:
    """Flat address codec for simple linear addressing."""

    name: str = "flat"

    def extract_refs(self, text: str) -> list[str]:
        """Extract hex address references from text."""
        pattern = re.compile(r"(?<![A-Za-z0-9_])(?:0x|\$)([0-9A-Fa-f]+)(?![A-Za-z0-9_])")
        results = []
        for match in pattern.finditer(text):
            addr = int(match.group(1), 16)
            results.append(f"0x{addr:X}")
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        """Parse a flat address reference."""
        cleaned = ref.strip().lower().replace("_", "")
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]

        if not cleaned or not all(c in "0123456789abcdef" for c in cleaned):
            return None

        try:
            addr = int(cleaned, 16)
        except ValueError:
            return None

        return AddressLocation(
            address_space=self.name,
            start=addr,
            end=addr,
            display=f"0x{addr:X}",
            attributes={"address": addr, "file_offset": addr},
        )

    def format(self, location: AddressLocation) -> str:
        """Format an AddressLocation back to canonical form."""
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        addr = location.attributes.get("address")
        if not isinstance(addr, int):
            raise ValueError("missing address attribute")
        return f"0x{addr:X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        """Convert flat location to file offset (identity)."""
        if location.address_space != self.name:
            return None
        return location.attributes.get("address")


@dataclass
class SegmentedHexAddressCodec:
    """Segmented hex address codec (bank:offset format)."""

    name: str = "segmented-hex"

    def extract_refs(self, text: str) -> list[str]:
        """Extract segmented hex references like C3:2B00 from text."""
        pattern = re.compile(r"(?:^|[^A-Za-z0-9_])([0-9A-Fa-f]{1,2}):([0-9A-Fa-f]{4})(?![A-Za-z0-9_:])")
        results = []
        for match in pattern.finditer(text):
            segment = match.group(1).upper()
            offset = match.group(2).upper()
            results.append(f"{segment}:{offset}")
        
        # Also match $XX:$XXXX format
        pattern2 = re.compile(r"\$([0-9A-Fa-f]{1,2}):\$([0-9A-Fa-f]{4})")
        for match in pattern2.finditer(text):
            segment = match.group(1).upper()
            offset = match.group(2).upper()
            results.append(f"${segment}:${offset}")
        
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        """Parse a segmented hex reference like 'C3:2B00'."""
        raw = ref.strip().upper()
        
        # Handle $XX:$XXXX format
        if raw.startswith("$"):
            parts = raw.replace("$", "").split(":")
        else:
            parts = raw.split(":")
        
        if len(parts) != 2:
            return None

        try:
            segment = int(parts[0], 16)
            offset = int(parts[1], 16)
        except ValueError:
            return None

        # Linear address for comparison
        linear = (segment << 16) | offset

        return AddressLocation(
            address_space=self.name,
            start=linear,
            end=linear,
            display=f"{parts[0]}:{parts[1]}",
            segment=parts[0],
            attributes={
                "segment_value": segment,
                "offset_value": offset,
                "linear": linear,
            },
        )

    def format(self, location: AddressLocation) -> str:
        """Format an AddressLocation back to segmented form."""
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        segment = location.attributes.get("segment_value")
        offset = location.attributes.get("offset_value")
        if not isinstance(segment, int) or not isinstance(offset, int):
            raise ValueError("missing segment or offset")
        return f"{segment:02X}:{offset:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        """Convert segmented location to file offset (not supported)."""
        return None


class ReverseEngineeringImporter(ABC):
    """Abstract base class for reverse engineering importers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the importer name."""
        ...

    @abstractmethod
    def supports(self, path: Path) -> bool:
        """Check if this importer supports the given file."""
        ...

    @abstractmethod
    def ingest(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest a file and return a bundle."""
        ...


@dataclass
class NullImporter(ReverseEngineeringImporter):
    """Null importer that creates artifact-only bundles."""

    extensions: list[str]
    _name: str = "null"

    @property
    def name(self) -> str:
        return self._name

    def __post_init__(self) -> None:
        if isinstance(self.extensions, str):
            self.extensions = [self.extensions]

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in [ext.lower() for ext in self.extensions]

    def ingest(self, path: Path) -> ReverseEngineeringBundle:
        artifact = ArtifactRecord(
            artifact_id=path.as_posix(),
            kind="unknown",
            path=path.as_posix(),
        )
        return ReverseEngineeringBundle(artifacts=[artifact])


@dataclass
class AdapterRegistry:
    """Registry of importers and codecs."""

    _importers: list[ReverseEngineeringImporter] = field(default_factory=list)
    codecs: dict[str, AddressCodec] = field(default_factory=dict)

    def register_importer(self, importer: ReverseEngineeringImporter) -> None:
        """Register an importer."""
        self._importers.append(importer)

    def find_importers(self, path: Path) -> list[ReverseEngineeringImporter]:
        """Find importers that support the given path."""
        return [imp for imp in self._importers if imp.supports(path)]

    def register_codec(self, codec: AddressCodec) -> None:
        """Register an address codec."""
        self.codecs[codec.name] = codec
