"""Binary Ninja analysis importer.

Supports importing from Binary Ninja .bndb database files and JSON exports.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
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
class BinaryNinjaImporter:
    """Importer for Binary Ninja analysis databases and exports.
    
    Supports:
    - Binary Ninja .bndb files (SQLite database format)
    - Binary Ninja JSON exports
    """

    name: str = "binary-ninja"

    def supports(self, path: Path) -> bool:
        """Check if this importer supports the given path.
        
        Supports:
        - .bndb files (Binary Ninja database)
        - .json files (Binary Ninja JSON export)
        """
        suffix = path.suffix.lower()
        if suffix == ".bndb":
            return True
        if suffix == ".json":
            # Try to detect if it's a Binary Ninja export
            try:
                data = json.loads(path.read_text())
                # Binary Ninja exports typically have these fields
                bn_keys = {"functions", "types", "symbols", "sections"}
                return bool(bn_keys & set(data.keys()))
            except (json.JSONDecodeError, IOError):
                return False
        return False

    def ingest(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest a Binary Ninja database or JSON export.
        
        Args:
            path: Path to .bndb file or JSON export
            
        Returns:
            ReverseEngineeringBundle with extracted entities
        """
        suffix = path.suffix.lower()
        
        if suffix == ".bndb":
            return self._ingest_bndb(path)
        elif suffix == ".json":
            return self._ingest_json(path)
        else:
            raise ValueError(f"Unsupported file format: {suffix}")

    def _ingest_bndb(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest a Binary Ninja .bndb SQLite database."""
        artifact = ArtifactRecord(
            artifact_id=path.as_posix(),
            kind="binary-ninja-database",
            path=path.as_posix(),
            title=path.name,
        )

        entities: list[EntityRecord] = []
        evidence: list[EvidenceRecord] = []
        edges: list[EdgeRecord] = []

        conn = None
        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()

            # Validate it's a valid BN database by checking for expected tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            
            # Binary Ninja databases typically have a 'functions' table
            # If no tables exist, this might be a newly created empty database
            if not tables:
                conn.close()
                artifact = ArtifactRecord(
                    artifact_id=path.as_posix(),
                    kind="binary-ninja-database",
                    path=path.as_posix(),
                    title=path.name,
                    metadata={"error": "Invalid or empty Binary Ninja database"},
                )
                return ReverseEngineeringBundle(
                    artifacts=[artifact],
                    entities=[],
                    evidence=[],
                    edges=[],
                )

            # Extract functions
            func_entities = self._extract_functions_from_db(cursor, path)
            entities.extend(func_entities)

            # Extract basic blocks
            block_entities, block_edges = self._extract_basic_blocks_from_db(
                cursor, path, func_entities
            )
            entities.extend(block_entities)
            edges.extend(block_edges)

            # Extract types
            type_entities = self._extract_types_from_db(cursor, path)
            entities.extend(type_entities)

            # Extract cross-references
            xref_edges = self._extract_xrefs_from_db(cursor, path)
            edges.extend(xref_edges)

            # Extract comments
            comment_entities, comment_evidence = self._extract_comments_from_db(
                cursor, path
            )
            entities.extend(comment_entities)
            evidence.extend(comment_evidence)

            # Extract tags
            tag_entities = self._extract_tags_from_db(cursor, path)
            entities.extend(tag_entities)

            conn.close()
        except sqlite3.Error as e:
            # If we can't read the database, return a minimal bundle with error
            if conn:
                conn.close()
            artifact = ArtifactRecord(
                artifact_id=path.as_posix(),
                kind="binary-ninja-database",
                path=path.as_posix(),
                title=path.name,
                metadata={"error": str(e)},
            )
            return ReverseEngineeringBundle(
                artifacts=[artifact],
                entities=[],
                evidence=[],
                edges=[],
            )

        return ReverseEngineeringBundle(
            artifacts=[artifact],
            entities=entities,
            evidence=evidence,
            edges=edges,
        )

    def _ingest_json(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest a Binary Ninja JSON export."""
        data = json.loads(path.read_text())
        
        artifact = ArtifactRecord(
            artifact_id=path.as_posix(),
            kind="binary-ninja-export",
            path=path.as_posix(),
            title=path.name,
        )

        entities: list[EntityRecord] = []
        evidence: list[EvidenceRecord] = []
        edges: list[EdgeRecord] = []

        # Extract functions
        for func in data.get("functions", []):
            func_entity = self._create_function_entity(func, path)
            entities.append(func_entity)

            # Extract basic blocks
            for block in func.get("basic_blocks", []):
                block_entity = self._create_block_entity(block, func_entity, path)
                entities.append(block_entity)
                edges.append(
                    EdgeRecord(
                        edge_id=f"edge:contains:{func_entity.entity_id}:{block_entity.entity_id}",
                        kind="contains",
                        source_entity_id=func_entity.entity_id,
                        target_entity_id=block_entity.entity_id,
                    )
                )

                # Extract instructions as evidence
                for instr in block.get("instructions", []):
                    ev = self._create_instruction_evidence(instr, block_entity, path)
                    evidence.append(ev)

            # Extract IL expressions
            for il_expr in func.get("il_expressions", []):
                il_entity = self._create_il_entity(il_expr, func_entity, path)
                entities.append(il_entity)
                edges.append(
                    EdgeRecord(
                        edge_id=f"edge:il_of:{il_entity.entity_id}:{func_entity.entity_id}",
                        kind="il_of",
                        source_entity_id=il_entity.entity_id,
                        target_entity_id=func_entity.entity_id,
                    )
                )

        # Extract types
        for type_info in data.get("types", []):
            type_entity = self._create_type_entity(type_info, path)
            entities.append(type_entity)

        # Extract cross-references
        for xref in data.get("cross_references", []):
            xref_edge = self._create_xref_edge(xref)
            if xref_edge:
                edges.append(xref_edge)

        # Extract comments
        for comment in data.get("comments", []):
            comment_entity, comment_ev = self._create_comment_records(comment, path)
            entities.append(comment_entity)
            evidence.append(comment_ev)

        # Extract tags
        for tag in data.get("tags", []):
            tag_entity = self._create_tag_entity(tag, path)
            entities.append(tag_entity)

        return ReverseEngineeringBundle(
            artifacts=[artifact],
            entities=entities,
            evidence=evidence,
            edges=edges,
        )

    def _extract_functions_from_db(
        self, cursor: sqlite3.Cursor, path: Path
    ) -> list[EntityRecord]:
        """Extract functions from Binary Ninja database."""
        entities = []
        try:
            # Binary Ninja stores functions in the 'functions' table
            cursor.execute("""
                SELECT id, start, name, platform 
                FROM functions 
                WHERE type = 'user' OR type = 'auto'
            """)
            for row in cursor.fetchall():
                func_id, start, name, platform = row
                entity = EntityRecord(
                    entity_id=f"entity:function:{path.as_posix()}:{func_id}",
                    kind="function",
                    name=name or f"sub_{start:X}",
                    artifact_id=path.as_posix(),
                    canonical_ref=f"0x{start:X}",
                    location=AddressLocation(
                        address_space="binary-ninja",
                        start=start,
                        end=start,
                        display=f"0x{start:X}",
                        attributes={
                            "platform": platform or "unknown",
                            "bn_func_id": func_id,
                        },
                    ),
                )
                entities.append(entity)
        except sqlite3.Error:
            # Table may not exist in this version
            pass
        return entities

    def _extract_basic_blocks_from_db(
        self,
        cursor: sqlite3.Cursor,
        path: Path,
        func_entities: list[EntityRecord],
    ) -> tuple[list[EntityRecord], list[EdgeRecord]]:
        """Extract basic blocks from Binary Ninja database."""
        entities = []
        edges = []
        try:
            cursor.execute("""
                SELECT bb.id, bb.start, bb.end, bb.function_id,
                       GROUP_CONCAT(instr.address || ':' || instr.text, ';')
                FROM basic_blocks bb
                LEFT JOIN instructions instr ON instr.block_id = bb.id
                GROUP BY bb.id
            """)
            for row in cursor.fetchall():
                block_id, start, end, func_id, instructions = row
                entity = EntityRecord(
                    entity_id=f"entity:block:{path.as_posix()}:{block_id}",
                    kind="basic_block",
                    name=f"block_{start:X}",
                    artifact_id=path.as_posix(),
                    canonical_ref=f"0x{start:X}",
                    location=AddressLocation(
                        address_space="binary-ninja",
                        start=start,
                        end=end,
                        display=f"0x{start:X}-0x{end:X}",
                        attributes={
                            "block_id": block_id,
                            "function_id": func_id,
                            "instruction_count": len(instructions.split(";")) if instructions else 0,
                        },
                    ),
                )
                entities.append(entity)

                # Link block to its function
                func_entity = next(
                    (f for f in func_entities if f"{func_id}" in f.entity_id), None
                )
                if func_entity:
                    edges.append(
                        EdgeRecord(
                            edge_id=f"edge:contains:{func_entity.entity_id}:{entity.entity_id}",
                            kind="contains",
                            source_entity_id=func_entity.entity_id,
                            target_entity_id=entity.entity_id,
                        )
                    )
        except sqlite3.Error:
            pass
        return entities, edges

    def _extract_types_from_db(
        self, cursor: sqlite3.Cursor, path: Path
    ) -> list[EntityRecord]:
        """Extract types (structures, enums, functions) from Binary Ninja database."""
        entities = []
        try:
            cursor.execute("""
                SELECT id, name, type_class, width, alignment
                FROM types
                WHERE name IS NOT NULL
            """)
            for row in cursor.fetchall():
                type_id, name, type_class, width, alignment = row
                entity = EntityRecord(
                    entity_id=f"entity:type:{path.as_posix()}:{type_id}",
                    kind=f"type_{type_class or 'unknown'}",
                    name=name,
                    artifact_id=path.as_posix(),
                    attributes={
                        "type_id": type_id,
                        "width": width,
                        "alignment": alignment,
                        "type_class": type_class,
                    },
                )
                entities.append(entity)
        except sqlite3.Error:
            pass
        return entities

    def _extract_xrefs_from_db(
        self, cursor: sqlite3.Cursor, path: Path
    ) -> list[EdgeRecord]:
        """Extract cross-references from Binary Ninja database."""
        edges = []
        try:
            cursor.execute("""
                SELECT from_addr, to_addr, xref_type
                FROM cross_references
            """)
            for row in cursor.fetchall():
                from_addr, to_addr, xref_type = row
                edges.append(
                    EdgeRecord(
                        edge_id=f"edge:xref:{from_addr:X}:{to_addr:X}",
                        kind=f"xref_{xref_type or 'generic'}",
                        source_entity_id=f"entity:reference:0x{from_addr:X}",
                        target_entity_id=f"entity:reference:0x{to_addr:X}",
                        attributes={
                            "from_addr": f"0x{from_addr:X}",
                            "to_addr": f"0x{to_addr:X}",
                            "xref_type": xref_type,
                        },
                    )
                )
        except sqlite3.Error:
            pass
        return edges

    def _extract_comments_from_db(
        self, cursor: sqlite3.Cursor, path: Path
    ) -> tuple[list[EntityRecord], list[EvidenceRecord]]:
        """Extract comments from Binary Ninja database."""
        entities = []
        evidence = []
        try:
            cursor.execute("""
                SELECT address, comment, comment_type
                FROM comments
            """)
            for row in cursor.fetchall():
                address, comment_text, comment_type = row
                entity = EntityRecord(
                    entity_id=f"entity:comment:{path.as_posix()}:{address:X}",
                    kind="comment",
                    name=f"comment_{address:X}",
                    artifact_id=path.as_posix(),
                    canonical_ref=f"0x{address:X}",
                    location=AddressLocation(
                        address_space="binary-ninja",
                        start=address,
                        end=address,
                        display=f"0x{address:X}",
                    ),
                    attributes={
                        "comment_type": comment_type,
                    },
                )
                entities.append(entity)

                ev = EvidenceRecord(
                    evidence_id=f"evidence:comment:{path.as_posix()}:{address:X}",
                    kind="comment",
                    artifact_id=path.as_posix(),
                    entity_ids=(entity.entity_id,),
                    excerpt=comment_text or "",
                    attributes={
                        "comment_type": comment_type,
                        "address": f"0x{address:X}",
                    },
                )
                evidence.append(ev)
        except sqlite3.Error:
            pass
        return entities, evidence

    def _extract_tags_from_db(
        self, cursor: sqlite3.Cursor, path: Path
    ) -> list[EntityRecord]:
        """Extract tags from Binary Ninja database."""
        entities = []
        try:
            cursor.execute("""
                SELECT id, address, tag_type, data
                FROM tags
            """)
            for row in cursor.fetchall():
                tag_id, address, tag_type, data = row
                entity = EntityRecord(
                    entity_id=f"entity:tag:{path.as_posix()}:{tag_id}",
                    kind="tag",
                    name=f"tag_{tag_type or 'unknown'}",
                    artifact_id=path.as_posix(),
                    canonical_ref=f"0x{address:X}" if address else "",
                    location=(
                        AddressLocation(
                            address_space="binary-ninja",
                            start=address,
                            end=address,
                            display=f"0x{address:X}",
                        )
                        if address
                        else None
                    ),
                    attributes={
                        "tag_type": tag_type,
                        "tag_data": data,
                    },
                )
                entities.append(entity)
        except sqlite3.Error:
            pass
        return entities

    def _create_function_entity(
        self, func: dict[str, Any], path: Path
    ) -> EntityRecord:
        """Create an EntityRecord from a JSON function definition."""
        start = func.get("start", 0)
        return EntityRecord(
            entity_id=f"entity:function:{path.as_posix()}:{func.get('name', 'unknown')}",
            kind="function",
            name=func.get("name", f"sub_{start:X}"),
            artifact_id=path.as_posix(),
            canonical_ref=f"0x{start:X}",
            location=AddressLocation(
                address_space="binary-ninja",
                start=start,
                end=func.get("end", start),
                display=f"0x{start:X}",
                attributes={
                    "platform": func.get("platform", "unknown"),
                    "return_type": func.get("return_type", ""),
                    "calling_convention": func.get("calling_convention", ""),
                },
            ),
        )

    def _create_block_entity(
        self, block: dict[str, Any], func: EntityRecord, path: Path
    ) -> EntityRecord:
        """Create an EntityRecord from a JSON basic block definition."""
        start = block.get("start", 0)
        end = block.get("end", start)
        return EntityRecord(
            entity_id=f"entity:block:{path.as_posix()}:{start:X}",
            kind="basic_block",
            name=f"block_{start:X}",
            artifact_id=path.as_posix(),
            canonical_ref=f"0x{start:X}",
            location=AddressLocation(
                address_space="binary-ninja",
                start=start,
                end=end,
                display=f"0x{start:X}-0x{end:X}",
                attributes={
                    "instruction_count": len(block.get("instructions", [])),
                },
            ),
        )

    def _create_instruction_evidence(
        self, instr: dict[str, Any], block: EntityRecord, path: Path
    ) -> EvidenceRecord:
        """Create an EvidenceRecord from a JSON instruction definition."""
        addr = instr.get("address", 0)
        return EvidenceRecord(
            evidence_id=f"evidence:instruction:{path.as_posix()}:{addr:X}",
            kind="instruction",
            artifact_id=path.as_posix(),
            entity_ids=(block.entity_id,),
            excerpt=instr.get("text", ""),
            location=AddressLocation(
                address_space="binary-ninja",
                start=addr,
                end=addr + instr.get("length", 1) - 1,
                display=f"0x{addr:X}",
            ),
            attributes={
                "bytes": instr.get("bytes", ""),
                "mnemonic": instr.get("mnemonic", ""),
            },
        )

    def _create_il_entity(
        self, il_expr: dict[str, Any], func: EntityRecord, path: Path
    ) -> EntityRecord:
        """Create an EntityRecord from a JSON IL expression definition."""
        addr = il_expr.get("address", 0)
        il_type = il_expr.get("il_type", "unknown")
        return EntityRecord(
            entity_id=f"entity:il:{path.as_posix()}:{il_type}:{addr:X}",
            kind=f"il_{il_type}",
            name=f"il_{il_type}_{addr:X}",
            artifact_id=path.as_posix(),
            canonical_ref=f"0x{addr:X}",
            location=AddressLocation(
                address_space="binary-ninja",
                start=addr,
                end=addr,
                display=f"0x{addr:X}",
            ),
            attributes={
                "il_type": il_type,
                "expression": il_expr.get("expression", ""),
                "operation": il_expr.get("operation", ""),
            },
        )

    def _create_type_entity(
        self, type_info: dict[str, Any], path: Path
    ) -> EntityRecord:
        """Create an EntityRecord from a JSON type definition."""
        type_id = type_info.get("id", "unknown")
        type_class = type_info.get("type_class", "unknown")
        return EntityRecord(
            entity_id=f"entity:type:{path.as_posix()}:{type_id}",
            kind=f"type_{type_class}",
            name=type_info.get("name", f"type_{type_id}"),
            artifact_id=path.as_posix(),
            attributes={
                "type_id": type_id,
                "type_class": type_class,
                "width": type_info.get("width", 0),
                "alignment": type_info.get("alignment", 0),
                "members": type_info.get("members", []),
                "underlying_type": type_info.get("underlying_type", ""),
            },
        )

    def _create_xref_edge(self, xref: dict[str, Any]) -> EdgeRecord | None:
        """Create an EdgeRecord from a JSON cross-reference definition."""
        from_addr = xref.get("from")
        to_addr = xref.get("to")
        if from_addr is None or to_addr is None:
            return None
        return EdgeRecord(
            edge_id=f"edge:xref:{from_addr:X}:{to_addr:X}",
            kind=f"xref_{xref.get('type', 'generic')}",
            source_entity_id=f"entity:reference:0x{from_addr:X}",
            target_entity_id=f"entity:reference:0x{to_addr:X}",
            attributes={
                "from_addr": f"0x{from_addr:X}",
                "to_addr": f"0x{to_addr:X}",
                "xref_type": xref.get("type", ""),
            },
        )

    def _create_comment_records(
        self, comment: dict[str, Any], path: Path
    ) -> tuple[EntityRecord, EvidenceRecord]:
        """Create EntityRecord and EvidenceRecord from a JSON comment definition."""
        addr = comment.get("address", 0)
        entity = EntityRecord(
            entity_id=f"entity:comment:{path.as_posix()}:{addr:X}",
            kind="comment",
            name=f"comment_{addr:X}",
            artifact_id=path.as_posix(),
            canonical_ref=f"0x{addr:X}",
            location=AddressLocation(
                address_space="binary-ninja",
                start=addr,
                end=addr,
                display=f"0x{addr:X}",
            ),
            attributes={
                "comment_type": comment.get("type", ""),
            },
        )

        ev = EvidenceRecord(
            evidence_id=f"evidence:comment:{path.as_posix()}:{addr:X}",
            kind="comment",
            artifact_id=path.as_posix(),
            entity_ids=(entity.entity_id,),
            excerpt=comment.get("text", ""),
            attributes={
                "comment_type": comment.get("type", ""),
                "address": f"0x{addr:X}",
            },
        )

        return entity, ev

    def _create_tag_entity(
        self, tag: dict[str, Any], path: Path
    ) -> EntityRecord:
        """Create an EntityRecord from a JSON tag definition."""
        tag_id = tag.get("id", "unknown")
        addr = tag.get("address")
        tag_type = tag.get("type", "unknown")
        return EntityRecord(
            entity_id=f"entity:tag:{path.as_posix()}:{tag_id}",
            kind="tag",
            name=f"tag_{tag_type}",
            artifact_id=path.as_posix(),
            canonical_ref=f"0x{addr:X}" if addr else "",
            location=(
                AddressLocation(
                    address_space="binary-ninja",
                    start=addr,
                    end=addr,
                    display=f"0x{addr:X}",
                )
                if addr
                else None
            ),
            attributes={
                "tag_type": tag_type,
                "tag_data": tag.get("data", {}),
            },
        )
