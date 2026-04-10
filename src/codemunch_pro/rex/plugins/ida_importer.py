"""IDA Pro database importer.

This module provides an importer for IDA Pro database files (.i64 for 64-bit,
.idb for 32-bit). It extracts functions, data items, structures, enums,
cross-references, comments, and segments from IDA databases.

Note: IDA Pro uses a proprietary database format. This importer supports:
1. Direct parsing when IDA Pro is installed and idaapi/idautils are available
2. JSON export files from IDA Pro (File > Produce file > Create JSON file)
3. Stub implementation with TODO comments for standalone parsing
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)


@dataclass
class IdaProImporter:
    """Importer for IDA Pro database files (.i64, .idb).
    
    Extracts reverse engineering artifacts including functions, data items,
    structures, enums, cross-references, comments, and segments.
    
    Supports:
    - Direct IDA database files (.i64, .idb) when IDA API is available
    - JSON export files from IDA Pro
    """

    name: str = "ida-pro"
    _ida_available: bool = field(init=False, repr=False, default=False)
    _idaapi: Any = field(init=False, repr=False, default=None)
    _idautils: Any = field(init=False, repr=False, default=None)
    _idc: Any = field(init=False, repr=False, default=None)

    def __post_init__(self) -> None:
        """Initialize and check for IDA Python API availability."""
        try:
            # Try to import IDA Python modules
            import idaapi  # type: ignore
            import idautils  # type: ignore
            import idc  # type: ignore
            self._idaapi = idaapi
            self._idautils = idautils
            self._idc = idc
            self._ida_available = True
        except ImportError:
            self._ida_available = False

    def supports(self, path: Path) -> bool:
        """Check if this importer supports the given path.
        
        Supports:
        - .i64: IDA 64-bit database files
        - .idb: IDA 32-bit database files
        - .json: JSON export files from IDA Pro
        """
        suffix = path.suffix.lower()
        if suffix == ".json":
            # Check if it's an IDA JSON export
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                # IDA JSON exports typically have specific keys
                return any(
                    key in data
                    for key in ("functions", "structs", "enums", "segments", "idb")
                )
            except (json.JSONDecodeError, IOError):
                return False
        return suffix in (".i64", ".idb")

    def ingest(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest an IDA Pro database file and extract all artifacts.
        
        Args:
            path: Path to the .i64, .idb, or JSON export file
            
        Returns:
            ReverseEngineeringBundle containing all extracted entities
        """
        artifact = ArtifactRecord(
            artifact_id=path.as_posix(),
            kind="ida-database",
            path=path.as_posix(),
        )

        entities: list[EntityRecord] = []
        evidence: list[EvidenceRecord] = []
        edges: list[EdgeRecord] = []

        suffix = path.suffix.lower()

        if suffix == ".json":
            # Parse JSON export from IDA Pro
            self._parse_json_export(path, entities, evidence, edges)
        elif self._ida_available:
            # Use IDA Python API for direct database access
            self._parse_with_ida(path, entities, evidence, edges)
        else:
            # Stub implementation for standalone parsing
            self._parse_standalone(path, entities, evidence, edges)

        return ReverseEngineeringBundle(
            artifacts=[artifact],
            entities=entities,
            evidence=evidence,
            edges=edges,
            metadata={
                "source": "ida-pro",
                "ida_available": self._ida_available,
                "file_type": suffix,
            },
        )

    def _parse_json_export(
        self,
        path: Path,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
        edges: list[EdgeRecord],
    ) -> None:
        """Parse a JSON export file from IDA Pro.
        
        TODO: Implement full JSON export parsing
        This is a stub that demonstrates the expected structure.
        """
        data = json.loads(path.read_text(encoding="utf-8"))

        # Extract functions
        for i, func in enumerate(data.get("functions", [])):
            func_addr = func.get("ea", 0)
            func_name = func.get("name", "unnamed")
            entity = EntityRecord(
                entity_id=f"entity:function:{func_addr:X}:{i}:{func_name}",
                kind="function",
                name=func_name,
                canonical_ref=f"0x{func_addr:X}",
                location=self._create_location(
                    func_addr, func.get("size", 0)
                ),
                attributes={
                    "flags": func.get("flags", 0),
                    "type": "function",
                },
            )
            entities.append(entity)

        # Extract data items
        for item in data.get("data", []):
            entity = EntityRecord(
                entity_id=f"entity:data:{item.get('ea', 'unknown')}",
                kind="data",
                name=item.get("name", ""),
                canonical_ref=f"0x{item.get('ea', 0):X}",
                location=self._create_location(
                    item.get("ea", 0), item.get("size", 0)
                ),
                attributes={
                    "data_type": item.get("type", "unknown"),
                },
            )
            entities.append(entity)

        # Extract structures
        for struct in data.get("structs", []):
            entity = EntityRecord(
                entity_id=f"entity:struct:{struct.get('name', 'unknown')}",
                kind="structure",
                name=struct.get("name", "unnamed"),
                attributes={
                    "size": struct.get("size", 0),
                    "members": struct.get("members", []),
                },
            )
            entities.append(entity)

        # Extract enums
        for enum in data.get("enums", []):
            entity = EntityRecord(
                entity_id=f"entity:enum:{enum.get('name', 'unknown')}",
                kind="enum",
                name=enum.get("name", "unnamed"),
                attributes={
                    "values": enum.get("values", {}),
                },
            )
            entities.append(entity)

        # Extract segments
        for seg in data.get("segments", []):
            entity = EntityRecord(
                entity_id=f"entity:segment:{seg.get('name', 'unknown')}",
                kind="segment",
                name=seg.get("name", "unnamed"),
                location=self._create_location(
                    seg.get("start", 0),
                    seg.get("end", 0) - seg.get("start", 0),
                ),
                attributes={
                    "permissions": seg.get("perm", "---"),
                    "class": seg.get("class", ""),
                },
            )
            entities.append(entity)

        # Extract cross-references as edges
        for xref in data.get("xrefs", []):
            edge = EdgeRecord(
                edge_id=f"edge:xref:{xref.get('from', 0)}:{xref.get('to', 0)}",
                kind="cross-reference",
                source_entity_id=f"entity:function:{xref.get('from', 0)}",
                target_entity_id=f"entity:function:{xref.get('to', 0)}",
                attributes={
                    "type": xref.get("type", "unknown"),
                },
            )
            edges.append(edge)

        # Extract comments as evidence
        for comment in data.get("comments", []):
            ev = EvidenceRecord(
                evidence_id=f"evidence:comment:{comment.get('ea', 0)}",
                kind="comment",
                artifact_id=path.as_posix(),
                entity_ids=(f"entity:function:{comment.get('ea', 0)}",),
                excerpt=comment.get("text", ""),
                attributes={
                    "type": comment.get("type", "regular"),  # regular, repeatable, etc.
                },
            )
            evidence.append(ev)

    def _parse_with_ida(
        self,
        path: Path,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
        edges: list[EdgeRecord],
    ) -> None:
        """Parse IDA database using IDA Python API.
        
        This method is called when idaapi/idautils are available.
        
        TODO: Implement full IDA API integration
        """
        # Note: In a real implementation, this would:
        # 1. Open the database using idaapi.open_database()
        # 2. Iterate through functions using idautils.Functions()
        # 3. Extract data items, structures, enums
        # 4. Build cross-reference graph
        # 5. Extract comments
        # 6. Extract segment information
        
        # Stub implementation
        pass  # pragma: no cover

    def _parse_standalone(
        self,
        path: Path,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
        edges: list[EdgeRecord],
    ) -> None:
        """Parse IDA database without IDA API (standalone mode).
        
        IDA Pro uses a proprietary database format. Standalone parsing
        would require reverse engineering the format or using a library
        like python-idb (https://github.com/williballenthin/python-idb).
        
        TODO: Implement standalone parsing using python-idb or similar
        """
        # Check if python-idb is available
        try:
            import idb  # type: ignore
            self._parse_with_python_idb(path, entities, evidence, edges, idb)
            return
        except ImportError:
            pass

        # If no standalone library is available, create placeholder entities
        # indicating that the file was recognized but couldn't be parsed
        entity = EntityRecord(
            entity_id=f"entity:ida-database:{path.as_posix()}",
            kind="ida-database",
            name=path.name,
            canonical_ref=path.as_posix(),
            attributes={
                "note": "IDA database detected but parsing requires IDA Pro or python-idb",
                "parsing_status": "stub",
                "size": path.stat().st_size if path.exists() else 0,
            },
        )
        entities.append(entity)

    def _parse_with_python_idb(
        self,
        path: Path,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
        edges: list[EdgeRecord],
        idb_module: Any,
    ) -> None:
        """Parse IDA database using python-idb library.
        
        TODO: Implement python-idb integration
        """
        # This would use the python-idb library to parse the database
        # without requiring IDA Pro to be installed
        pass  # pragma: no cover

    def _create_location(self, address: int, size: int) -> AddressLocation | None:
        """Create an AddressLocation for the given address and size.
        
        Args:
            address: Start address
            size: Size in bytes
            
        Returns:
            AddressLocation or None if address is invalid
        """
        if address == 0 and size == 0:
            return None
        
        # Determine address space based on address value
        # This is a heuristic and may need adjustment for specific platforms
        address_space = "ida-virtual"
        if address < 0x10000:
            address_space = "ida-zero-page"
        elif address < 0x1000000:
            address_space = "ida-low"
        elif address >= 0x8000000000000000:
            address_space = "ida-kernel"
        
        return AddressLocation(
            address_space=address_space,
            start=address,
            end=address + size - 1 if size > 0 else address,
            display=f"0x{address:X}",
        )

    def _detect_platform(self, path: Path) -> str:
        """Detect the target platform from the IDA database.
        
        TODO: Implement platform detection
        This would examine the database to determine:
        - Processor type (x86, ARM, MIPS, etc.)
        - Address size (32-bit vs 64-bit)
        - Operating system
        
        Returns:
            Platform identifier string
        """
        # Stub implementation
        return "unknown"

    def _extract_functions_with_ida(
        self,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
    ) -> None:
        """Extract functions using IDA API.
        
        TODO: Implement function extraction
        Extracts:
        - Function name
        - Start address and size
        - Function flags (thumb, etc.)
        - Local variables
        - Stack frame information
        """
        pass  # pragma: no cover

    def _extract_data_with_ida(
        self,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
    ) -> None:
        """Extract data items using IDA API.
        
        TODO: Implement data extraction
        Extracts:
        - Data names and addresses
        - Data types (byte, word, dword, etc.)
        - Array information
        - String literals
        """
        pass  # pragma: no cover

    def _extract_structures_with_ida(self, entities: list[EntityRecord]) -> None:
        """Extract structures using IDA API.
        
        TODO: Implement structure extraction
        Extracts:
        - Structure names
        - Member names, types, and offsets
        - Nested structures
        - Union information
        """
        pass  # pragma: no cover

    def _extract_enums_with_ida(self, entities: list[EntityRecord]) -> None:
        """Extract enums using IDA API.
        
        TODO: Implement enum extraction
        Extracts:
        - Enum names
        - Member names and values
        - Bitfield information
        """
        pass  # pragma: no cover

    def _extract_xrefs_with_ida(self, edges: list[EdgeRecord]) -> None:
        """Extract cross-references using IDA API.
        
        TODO: Implement cross-reference extraction
        Extracts:
        - Code references (calls, jumps)
        - Data references (reads, writes)
        - Reference types (near, far, etc.)
        """
        pass  # pragma: no cover

    def _extract_comments_with_ida(self, evidence: list[EvidenceRecord]) -> None:
        """Extract comments using IDA API.
        
        TODO: Implement comment extraction
        Extracts:
        - Regular comments
        - Repeatable comments
        - Anterior comments (before address)
        - Posterior comments (after address)
        - Function comments
        """
        pass  # pragma: no cover

    def _extract_segments_with_ida(self, entities: list[EntityRecord]) -> None:
        """Extract segments using IDA API.
        
        TODO: Implement segment extraction
        Extracts:
        - Segment names
        - Start and end addresses
        - Permissions (read, write, execute)
        - Segment classes
        """
        pass  # pragma: no cover
