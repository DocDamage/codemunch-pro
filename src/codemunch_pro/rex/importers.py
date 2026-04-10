"""Importers for reverse engineering artifacts."""

from __future__ import annotations

import re
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
class GenericDocumentImporter:
    """Generic document importer for Markdown and JSON files."""

    chunk_lines: int = 10
    _ref_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Pattern to extract hex references (basic pattern, will be enhanced with codecs)
        self._ref_pattern = re.compile(r"(?:0x|\$)([0-9A-Fa-f]+)")

    @property
    def name(self) -> str:
        return "generic-document"

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in (".md", ".json", ".txt")

    def ingest(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest a document and extract references, sections, and chunks."""
        content = path.read_text(encoding="utf-8")
        lines = content.splitlines()
        
        artifact = ArtifactRecord(
            artifact_id=path.as_posix(),
            kind="note" if path.suffix == ".md" else "structured-data",
            path=path.as_posix(),
        )

        entities: list[EntityRecord] = []
        evidence: list[EvidenceRecord] = []
        edges: list[EdgeRecord] = []
        
        # Create document entity
        doc_entity = EntityRecord(
            entity_id=f"entity:document:{path.as_posix()}",
            kind="document",
            name=path.name,
            artifact_id=path.as_posix(),
        )
        entities.append(doc_entity)

        # Extract sections (markdown headers)
        section_pattern = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)
        for match in section_pattern.finditer(content):
            len(match.group(1))
            title = match.group(2).strip()
            section_entity = EntityRecord(
                entity_id=f"entity:section:{path.as_posix()}:{title}",
                kind="section",
                name=title,
                artifact_id=path.as_posix(),
            )
            entities.append(section_entity)
            
            # Create edge from document to section
            edges.append(EdgeRecord(
                edge_id=f"edge:contains:{doc_entity.entity_id}:{section_entity.entity_id}",
                kind="contains",
                source_entity_id=doc_entity.entity_id,
                target_entity_id=section_entity.entity_id,
            ))

        # Create evidence chunks
        for i, line in enumerate(lines):
            if line.strip():
                ev_id = f"evidence:{path.as_posix()}:line{i}"
                ev = EvidenceRecord(
                    evidence_id=ev_id,
                    kind="content",
                    artifact_id=path.as_posix(),
                    entity_ids=(doc_entity.entity_id,),
                    excerpt=line.strip(),
                )
                evidence.append(ev)

        # Extract references using codec patterns
        refs = self._extract_refs(content)
        
        # Build a map of line numbers to sections for reference->section linking
        for i, line in enumerate(lines):
            for entity in entities:
                if entity.kind == "section":
                    # Find which section this line belongs to
                    # Simple heuristic: lines after a section header belong to that section
                    pass
        
        # Track current section for each line
        current_section_for_line: dict[int, EntityRecord] = {}
        current_section = None
        for i, line in enumerate(lines):
            header_match = re.match(r"^(#{1,6})\s+(.+)$", line)
            if header_match:
                section_title = header_match.group(2).strip()
                # Find the section entity
                for entity in entities:
                    if entity.kind == "section" and entity.name == section_title:
                        current_section = entity
                        break
            current_section_for_line[i] = current_section
        
        for ref_info in refs:
            ref = ref_info["ref"]
            address_space = ref_info["address_space"]
            location = ref_info.get("location")
            
            entity = EntityRecord(
                entity_id=f"entity:reference:{path.as_posix()}:{ref}",
                kind="reference",
                name=ref,
                canonical_ref=ref,
                artifact_id=path.as_posix(),
                location=location,
            )
            entities.append(entity)
            
            # Create evidence
            ev = EvidenceRecord(
                evidence_id=f"evidence:{path.as_posix()}:{ref}",
                kind="reference-mention",
                artifact_id=path.as_posix(),
                entity_ids=(entity.entity_id,),
                attributes={"canonical_ref": ref, "address_space": address_space},
                location=location,
            )
            evidence.append(ev)
            
            # Create edge from document to reference
            edges.append(EdgeRecord(
                edge_id=f"edge:mentions:{doc_entity.entity_id}:{entity.entity_id}",
                kind="mentions",
                source_entity_id=doc_entity.entity_id,
                target_entity_id=entity.entity_id,
            ))
            
            # Find which section this reference appears in and create edge
            for i, line in enumerate(lines):
                if ref in line or ref.replace("0x", "$") in line:
                    section = current_section_for_line.get(i)
                    if section:
                        edges.append(EdgeRecord(
                            edge_id=f"edge:mentions:{section.entity_id}:{entity.entity_id}",
                            kind="mentions",
                            source_entity_id=section.entity_id,
                            target_entity_id=entity.entity_id,
                        ))
                        break

        return ReverseEngineeringBundle(
            artifacts=[artifact],
            entities=entities,
            evidence=evidence,
            edges=edges,
        )

    def _extract_refs(self, content: str) -> list[dict[str, Any]]:
        """Extract hex references from content using codec patterns."""
        refs = []
        seen = set()
        
        # Pattern 1: Segmented hex references like C3:2B00 or C3:$2B00
        # Also match $C3:$2B00 format
        segmented_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])([0-9A-Fa-f]{1,2}):(?:\$?)([0-9A-Fa-f]{4})(?![A-Za-z0-9_:])"
        )
        for match in segmented_pattern.finditer(content):
            segment = match.group(1).upper()
            offset = match.group(2).upper()
            ref = f"{segment}:{offset}"
            if ref not in seen:
                seen.add(ref)
                # Create AddressLocation for segmented address
                segment_val = int(segment, 16)
                offset_val = int(offset, 16)
                linear = (segment_val << 16) | offset_val
                location = AddressLocation(
                    address_space="segmented-hex",
                    start=linear,
                    end=linear,
                    display=ref,
                    segment=segment,
                    attributes={
                        "segment_value": segment_val,
                        "offset_value": offset_val,
                        "linear": linear,
                    },
                )
                refs.append({"ref": ref, "address_space": "segmented-hex", "location": location})
        
        # Pattern 2: Flat addresses with $ prefix like $4204
        dollar_pattern = re.compile(r"\$([0-9A-Fa-f]+)")
        for match in dollar_pattern.finditer(content):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                ref = f"0x{addr:X}"
                if ref not in seen:
                    seen.add(ref)
                    location = AddressLocation(
                        address_space="flat",
                        start=addr,
                        end=addr,
                        display=ref,
                        attributes={"address": addr, "file_offset": addr},
                    )
                    refs.append({"ref": ref, "address_space": "flat", "location": location})
            except ValueError:
                continue
        
        # Pattern 3: Standard 0x prefix
        hex_pattern = re.compile(r"0x([0-9A-Fa-f]+)")
        for match in hex_pattern.finditer(content):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                ref = f"0x{addr:X}"
                if ref not in seen:
                    seen.add(ref)
                    location = AddressLocation(
                        address_space="flat",
                        start=addr,
                        end=addr,
                        display=ref,
                        attributes={"address": addr, "file_offset": addr},
                    )
                    refs.append({"ref": ref, "address_space": "flat", "location": location})
            except ValueError:
                continue
        
        # Pattern 4: JSON values that look like hex bank identifiers (e.g., "bank":"C3")
        # Match quoted hex strings like "C3" or "0C" that could be bank numbers
        json_hex_pattern = re.compile(r'"[a-z_]*[bk]ank[a-z_]*"\s*:\s*"([0-9A-Fa-f]{1,4})"')
        for match in json_hex_pattern.finditer(content):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                ref = f"0x{addr:X}"
                if ref not in seen:
                    seen.add(ref)
                    location = AddressLocation(
                        address_space="flat",
                        start=addr,
                        end=addr,
                        display=ref,
                        attributes={"address": addr, "file_offset": addr, "source": "json_bank"},
                    )
                    refs.append({"ref": ref, "address_space": "flat", "location": location})
            except ValueError:
                continue
        
        return refs
