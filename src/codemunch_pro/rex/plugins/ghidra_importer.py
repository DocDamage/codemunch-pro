"""Ghidra project importer.

Supports Ghidra .gzf (Ghidra Zip File) and XML export files.
Extracts functions, symbols, data types, memory blocks, references, and bookmarks.
"""

from __future__ import annotations

import gzip
import zipfile
import xml.etree.ElementTree as ET
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
class GhidraFunction:
    """Represents a function extracted from Ghidra."""

    name: str
    entry_point: int
    body_start: int | None = None
    body_end: int | None = None
    return_type: str = ""
    signature: str = ""
    parameters: list[dict[str, Any]] = field(default_factory=list)
    namespace: str = ""


@dataclass
class GhidraSymbol:
    """Represents a symbol/label extracted from Ghidra."""

    name: str
    address: int
    symbol_type: str = ""
    namespace: str = ""


@dataclass
class GhidraMemoryBlock:
    """Represents a memory block extracted from Ghidra."""

    name: str
    start: int
    end: int
    permissions: dict[str, bool] = field(default_factory=dict)
    source: str = ""


@dataclass
class GhidraReference:
    """Represents a reference extracted from Ghidra."""

    from_addr: int
    to_addr: int
    ref_type: str = ""


@dataclass
class GhidraComment:
    """Represents a comment extracted from Ghidra."""

    address: int
    text: str
    comment_type: str = ""


@dataclass
class GhidraDataType:
    """Represents a data type extracted from Ghidra."""

    name: str
    kind: str  # struct, union, enum, typedef
    size: int = 0
    members: list[dict[str, Any]] = field(default_factory=list)


class GhidraImporter:
    """Importer for Ghidra project files (.gzf) and XML exports."""

    name: str = "ghidra"

    def supports(self, path: Path) -> bool:
        """Check if this importer supports the given path.

        Supports .gzf (Ghidra Zip File) and .xml extensions.
        """
        suffix = path.suffix.lower()
        if suffix not in (".gzf", ".xml"):
            return False

        if suffix == ".gzf":
            return self._is_valid_gzf(path)
        elif suffix == ".xml":
            return self._is_valid_xml(path)

        return False

    def _is_valid_gzf(self, path: Path) -> bool:
        """Check if file is a valid Ghidra Zip File."""
        try:
            with zipfile.ZipFile(path, "r") as zf:
                # Check for expected Ghidra archive structure
                files = zf.namelist()
                return any("program.info" in f or "program.data" in f for f in files)
        except (zipfile.BadZipFile, IOError):
            return False

    def _is_valid_xml(self, path: Path) -> bool:
        """Check if file is a valid Ghidra XML export."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            return "<PROGRAM" in content or "<program" in content
        except IOError:
            return False

    def ingest(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest a Ghidra file and return a ReverseEngineeringBundle."""
        suffix = path.suffix.lower()

        if suffix == ".gzf":
            data = self._parse_gzf(path)
        elif suffix == ".xml":
            data = self._parse_xml(path)
        else:
            raise ValueError(f"Unsupported file type: {suffix}")

        return self._build_bundle(path, data)

    def _parse_gzf(self, path: Path) -> dict[str, Any]:
        """Parse a Ghidra Zip File (.gzf)."""
        data: dict[str, Any] = {
            "functions": [],
            "symbols": [],
            "memory_blocks": [],
            "references": [],
            "comments": [],
            "data_types": [],
            "bookmarks": [],
            "program_info": {},
        }

        with zipfile.ZipFile(path, "r") as zf:
            # Parse program.info
            if "program.info" in zf.namelist():
                with zf.open("program.info") as info_file:
                    content = info_file.read()
                    if content[:2] == b"\x1f\x8b":  # gzip magic
                        content = gzip.decompress(content)
                    data["program_info"] = self._parse_program_info(content.decode("utf-8", errors="ignore"))

            # Parse program.data (contains functions, symbols, etc.)
            if "program.data" in zf.namelist():
                with zf.open("program.data") as data_file:
                    content = data_file.read()
                    if content[:2] == b"\x1f\x8b":  # gzip magic
                        content = gzip.decompress(content)
                    parsed = self._parse_program_data(content.decode("utf-8", errors="ignore"))
                    data.update(parsed)

        return data

    def _parse_xml(self, path: Path) -> dict[str, Any]:
        """Parse a Ghidra XML export file."""
        tree = ET.parse(path)
        root = tree.getroot()

        data: dict[str, Any] = {
            "functions": [],
            "symbols": [],
            "memory_blocks": [],
            "references": [],
            "comments": [],
            "data_types": [],
            "bookmarks": [],
            "program_info": {},
        }

        # Parse program info
        program_elem = root if root.tag.upper() == "PROGRAM" else (root.find(".//PROGRAM") or root.find(".//program"))
        if program_elem is not None:
            data["program_info"] = {
                "name": program_elem.get("NAME", "") or program_elem.get("name", ""),
                "language": program_elem.get("LANGUAGE", "") or program_elem.get("language", ""),
            }

        # Parse functions
        for func_elem in root.findall(".//FUNCTION") + root.findall(".//function"):
            func = self._parse_function_element(func_elem)
            if func:
                data["functions"].append(func)

        # Parse symbols/labels
        for sym_elem in root.findall(".//SYMBOL") + root.findall(".//symbol") + root.findall(".//LABEL") + root.findall(".//label"):
            sym = self._parse_symbol_element(sym_elem)
            if sym:
                data["symbols"].append(sym)

        # Parse memory blocks - look inside MEMORY_MAP as well
        memory_elems = []
        for path in [".//MEMORY_BLOCK", ".//memory_block", ".//MEMORY_SECTION", ".//memory_section"]:
            memory_elems.extend(root.findall(path))
        # Also check inside MEMORY_MAP
        for mem_map in root.findall(".//MEMORY_MAP") + root.findall(".//memory_map"):
            for path in [".//MEMORY_BLOCK", ".//memory_block", ".//MEMORY_SECTION", ".//memory_section"]:
                memory_elems.extend(mem_map.findall(path))
        
        for block_elem in memory_elems:
            block = self._parse_memory_block_element(block_elem)
            if block:
                data["memory_blocks"].append(block)

        # Parse references
        for ref_elem in root.findall(".//REFERENCE") + root.findall(".//reference") + root.findall(".//REF") + root.findall(".//ref"):
            ref = self._parse_reference_element(ref_elem)
            if ref:
                data["references"].append(ref)

        # Parse comments
        for comment_elem in root.findall(".//COMMENT") + root.findall(".//comment"):
            comment = self._parse_comment_element(comment_elem)
            if comment:
                data["comments"].append(comment)

        # Parse bookmarks
        for bookmark_elem in root.findall(".//BOOKMARK") + root.findall(".//bookmark"):
            bookmark = self._parse_bookmark_element(bookmark_elem)
            if bookmark:
                data["bookmarks"].append(bookmark)

        # Parse data types
        for type_elem in root.findall(".//DATATYPE") + root.findall(".//datatype") + root.findall(".//TYPE") + root.findall(".//type"):
            dtype = self._parse_data_type_element(type_elem)
            if dtype:
                data["data_types"].append(dtype)

        return data

    def _parse_program_info(self, content: str) -> dict[str, Any]:
        """Parse program.info content."""
        info: dict[str, Any] = {}
        for line in content.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                info[key.strip()] = value.strip()
        return info

    def _parse_program_data(self, content: str) -> dict[str, Any]:
        """Parse program.data content (XML format inside GZF)."""
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return {
                "functions": [],
                "symbols": [],
                "memory_blocks": [],
                "references": [],
                "comments": [],
                "data_types": [],
                "bookmarks": [],
            }

        data: dict[str, Any] = {
            "functions": [],
            "symbols": [],
            "memory_blocks": [],
            "references": [],
            "comments": [],
            "data_types": [],
            "bookmarks": [],
        }

        # Parse functions
        for func_elem in root.findall(".//FUNCTION"):
            func = self._parse_function_element(func_elem)
            if func:
                data["functions"].append(func)

        # Parse symbols
        for sym_elem in root.findall(".//SYMBOL"):
            sym = self._parse_symbol_element(sym_elem)
            if sym:
                data["symbols"].append(sym)

        # Parse memory blocks
        for block_elem in root.findall(".//MEMORY_BLOCK"):
            block = self._parse_memory_block_element(block_elem)
            if block:
                data["memory_blocks"].append(block)

        # Parse references
        for ref_elem in root.findall(".//REFERENCE"):
            ref = self._parse_reference_element(ref_elem)
            if ref:
                data["references"].append(ref)

        # Parse comments
        for comment_elem in root.findall(".//COMMENT"):
            comment = self._parse_comment_element(comment_elem)
            if comment:
                data["comments"].append(comment)

        # Parse bookmarks
        for bookmark_elem in root.findall(".//BOOKMARK"):
            bookmark = self._parse_bookmark_element(bookmark_elem)
            if bookmark:
                data["bookmarks"].append(bookmark)

        return data

    def _parse_function_element(self, elem: ET.Element) -> GhidraFunction | None:
        """Parse a function XML element."""
        try:
            name = elem.get("NAME", "") or elem.get("name", "")
            entry = elem.get("ENTRY_POINT", "") or elem.get("entry_point", "") or elem.get("ENTRY", "") or elem.get("entry", "")

            if not name or not entry:
                return None

            entry_point = self._parse_address(entry)
            if entry_point is None:
                return None

            body_start = elem.get("BODY_START") or elem.get("body_start")
            body_end = elem.get("BODY_END") or elem.get("body_end")
            signature = elem.get("SIGNATURE", "") or elem.get("signature", "")
            return_type = elem.get("RETURN_TYPE", "") or elem.get("return_type", "")
            namespace = elem.get("NAMESPACE", "") or elem.get("namespace", "")

            parameters = []
            for param_elem in elem.findall(".//PARAMETER") + elem.findall(".//parameter"):
                param = {
                    "name": param_elem.get("NAME", "") or param_elem.get("name", ""),
                    "type": param_elem.get("TYPE", "") or param_elem.get("type", ""),
                }
                parameters.append(param)

            return GhidraFunction(
                name=name,
                entry_point=entry_point,
                body_start=self._parse_address(body_start) if body_start else None,
                body_end=self._parse_address(body_end) if body_end else None,
                return_type=return_type,
                signature=signature,
                parameters=parameters,
                namespace=namespace,
            )
        except (ValueError, AttributeError):
            return None

    def _parse_symbol_element(self, elem: ET.Element) -> GhidraSymbol | None:
        """Parse a symbol XML element."""
        try:
            name = elem.get("NAME", "") or elem.get("name", "")
            address = elem.get("ADDRESS", "") or elem.get("address", "") or elem.get("ADDR", "") or elem.get("addr", "")

            if not name or not address:
                return None

            addr = self._parse_address(address)
            if addr is None:
                return None

            symbol_type = elem.get("TYPE", "") or elem.get("type", "")
            namespace = elem.get("NAMESPACE", "") or elem.get("namespace", "")

            return GhidraSymbol(
                name=name,
                address=addr,
                symbol_type=symbol_type,
                namespace=namespace,
            )
        except (ValueError, AttributeError):
            return None

    def _parse_memory_block_element(self, elem: ET.Element) -> GhidraMemoryBlock | None:
        """Parse a memory block XML element."""
        try:
            name = elem.get("NAME", "") or elem.get("name", "")
            start = elem.get("START", "") or elem.get("start", "") or elem.get("ADDRESS", "") or elem.get("address", "")
            size = elem.get("SIZE", "") or elem.get("size", "") or elem.get("LENGTH", "") or elem.get("length", "")
            end = elem.get("END", "") or elem.get("end", "")

            if not name or not start:
                return None

            start_addr = self._parse_address(start)
            if start_addr is None:
                return None

            if end:
                end_addr = self._parse_address(end)
            elif size:
                size_val = self._parse_address(size)
                end_addr = start_addr + size_val - 1 if size_val else start_addr
            else:
                end_addr = start_addr

            source = elem.get("SOURCE", "") or elem.get("source", "")

            permissions = {
                "read": elem.get("READ", "false").lower() == "true" or elem.get("read", "false").lower() == "true",
                "write": elem.get("WRITE", "false").lower() == "true" or elem.get("write", "false").lower() == "true",
                "execute": elem.get("EXECUTE", "false").lower() == "true" or elem.get("execute", "false").lower() == "true",
                "volatile": elem.get("VOLATILE", "false").lower() == "true" or elem.get("volatile", "false").lower() == "true",
            }

            return GhidraMemoryBlock(
                name=name,
                start=start_addr,
                end=end_addr,
                permissions=permissions,
                source=source,
            )
        except (ValueError, AttributeError):
            return None

    def _parse_reference_element(self, elem: ET.Element) -> GhidraReference | None:
        """Parse a reference XML element."""
        try:
            from_addr = elem.get("FROM", "") or elem.get("from", "") or elem.get("FROM_ADDRESS", "") or elem.get("from_address", "")
            to_addr = elem.get("TO", "") or elem.get("to", "") or elem.get("TO_ADDRESS", "") or elem.get("to_address", "")

            if not from_addr or not to_addr:
                return None

            from_parsed = self._parse_address(from_addr)
            to_parsed = self._parse_address(to_addr)

            if from_parsed is None or to_parsed is None:
                return None

            ref_type = elem.get("TYPE", "") or elem.get("type", "") or elem.get("USER_TYPE", "") or elem.get("user_type", "")

            return GhidraReference(
                from_addr=from_parsed,
                to_addr=to_parsed,
                ref_type=ref_type,
            )
        except (ValueError, AttributeError):
            return None

    def _parse_comment_element(self, elem: ET.Element) -> GhidraComment | None:
        """Parse a comment XML element."""
        try:
            address = elem.get("ADDRESS", "") or elem.get("address", "") or elem.get("ADDR", "") or elem.get("addr", "")
            text = elem.get("TEXT", "") or elem.get("text", "")

            if not address:
                return None

            addr = self._parse_address(address)
            if addr is None:
                return None

            comment_type = elem.get("TYPE", "") or elem.get("type", "") or elem.get("COMMENT_TYPE", "") or elem.get("comment_type", "")

            return GhidraComment(
                address=addr,
                text=text,
                comment_type=comment_type,
            )
        except (ValueError, AttributeError):
            return None

    def _parse_bookmark_element(self, elem: ET.Element) -> GhidraComment | None:
        """Parse a bookmark XML element (bookmarks are similar to comments)."""
        try:
            address = elem.get("ADDRESS", "") or elem.get("address", "") or elem.get("ADDR", "") or elem.get("addr", "")
            text = elem.get("NOTE", "") or elem.get("note", "") or elem.get("DESCRIPTION", "") or elem.get("description", "")

            if not address:
                return None

            addr = self._parse_address(address)
            if addr is None:
                return None

            bookmark_type = elem.get("TYPE", "") or elem.get("type", "")

            return GhidraComment(
                address=addr,
                text=text,
                comment_type=f"bookmark:{bookmark_type}",
            )
        except (ValueError, AttributeError):
            return None

    def _parse_data_type_element(self, elem: ET.Element) -> GhidraDataType | None:
        """Parse a data type XML element."""
        try:
            name = elem.get("NAME", "") or elem.get("name", "")
            kind = elem.get("KIND", "") or elem.get("kind", "") or elem.get("TYPE", "") or elem.get("type", "")
            size = elem.get("SIZE", "") or elem.get("size", "")

            if not name or not kind:
                return None

            size_int = int(size) if size else 0

            members = []
            for member_elem in elem.findall(".//MEMBER") + elem.findall(".//member") + elem.findall(".//FIELD") + elem.findall(".//field"):
                member = {
                    "name": member_elem.get("NAME", "") or member_elem.get("name", ""),
                    "type": member_elem.get("TYPE", "") or member_elem.get("type", ""),
                    "offset": member_elem.get("OFFSET", "") or member_elem.get("offset", ""),
                }
                members.append(member)

            return GhidraDataType(
                name=name,
                kind=kind,
                size=size_int,
                members=members,
            )
        except (ValueError, AttributeError):
            return None

    def _parse_address(self, addr: str) -> int | None:
        """Parse an address string to integer."""
        addr = addr.strip().lower()
        if addr.startswith("0x"):
            try:
                return int(addr[2:], 16)
            except ValueError:
                return None
        elif addr.startswith("$"):
            try:
                return int(addr[1:], 16)
            except ValueError:
                return None
        else:
            # Check if it contains hex digits a-f (clearly hex) or is a short hex value
            # If it's all digits 0-9 and longer than 8 chars, treat as decimal
            # Otherwise, try hex first, then decimal
            has_hex_letters = any(c in "abcdef" for c in addr)
            
            if has_hex_letters:
                # Definitely hex
                try:
                    return int(addr, 16)
                except ValueError:
                    return None
            else:
                # All digits 0-9 - could be decimal or hex
                # Try decimal first for numeric-only strings that look like decimal
                # (if it's longer than 8 chars and starts with 4-9, it's likely decimal)
                try:
                    # First try as hex since that's more common in RE
                    return int(addr, 16)
                except ValueError:
                    try:
                        return int(addr)
                    except ValueError:
                        return None

    def _build_bundle(self, path: Path, data: dict[str, Any]) -> ReverseEngineeringBundle:
        """Build a ReverseEngineeringBundle from parsed Ghidra data."""
        artifacts: list[ArtifactRecord] = []
        entities: list[EntityRecord] = []
        evidence: list[EvidenceRecord] = []
        edges: list[EdgeRecord] = []

        # Create main artifact
        artifact = ArtifactRecord(
            artifact_id=path.as_posix(),
            kind="ghidra-project",
            path=path.as_posix(),
            title=data.get("program_info", {}).get("name", path.name),
            metadata={
                "source_tool": "Ghidra",
                "file_type": path.suffix.lower(),
                **{k.lower(): v for k, v in data.get("program_info", {}).items()},
            },
        )
        artifacts.append(artifact)

        # Create memory block entities
        for block in data.get("memory_blocks", []):
            entity = EntityRecord(
                entity_id=f"entity:memory_block:{block.name}",
                kind="memory_block",
                name=block.name,
                artifact_id=artifact.artifact_id,
                location=AddressLocation(
                    address_space="flat",
                    start=block.start,
                    end=block.end,
                ),
                attributes={
                    "permissions": block.permissions,
                    "source": block.source,
                },
            )
            entities.append(entity)

        # Create function entities
        for func in data.get("functions", []):
            entity = EntityRecord(
                entity_id=f"entity:function:{func.entry_point:08x}",
                kind="function",
                name=func.name,
                artifact_id=artifact.artifact_id,
                canonical_ref=f"0x{func.entry_point:08x}",
                location=AddressLocation(
                    address_space="flat",
                    start=func.body_start if func.body_start else func.entry_point,
                    end=func.body_end if func.body_end else func.entry_point,
                    segment=func.namespace,
                ),
                attributes={
                    "entry_point": func.entry_point,
                    "return_type": func.return_type,
                    "signature": func.signature,
                    "parameters": func.parameters,
                    "namespace": func.namespace,
                },
            )
            entities.append(entity)

        # Create symbol entities
        for sym in data.get("symbols", []):
            entity = EntityRecord(
                entity_id=f"entity:symbol:{sym.address:08x}:{sym.name}",
                kind="symbol",
                name=sym.name,
                artifact_id=artifact.artifact_id,
                canonical_ref=f"0x{sym.address:08x}",
                location=AddressLocation(
                    address_space="flat",
                    start=sym.address,
                    end=sym.address,
                    segment=sym.namespace,
                ),
                attributes={
                    "symbol_type": sym.symbol_type,
                    "namespace": sym.namespace,
                },
            )
            entities.append(entity)

        # Create data type entities
        for dtype in data.get("data_types", []):
            entity = EntityRecord(
                entity_id=f"entity:data_type:{dtype.name}",
                kind="data_type",
                name=dtype.name,
                artifact_id=artifact.artifact_id,
                attributes={
                    "data_type_kind": dtype.kind,
                    "size": dtype.size,
                    "members": dtype.members,
                },
            )
            entities.append(entity)

        # Create reference edges
        for ref in data.get("references", []):
            source_id = f"entity:function:{ref.from_addr:08x}"
            target_id = f"entity:function:{ref.to_addr:08x}"

            # Try to find the actual entities
            source_exists = any(e.entity_id == source_id for e in entities)
            target_exists = any(e.entity_id == target_id for e in entities)

            # Create placeholder entities if they don't exist
            if not source_exists:
                entities.append(EntityRecord(
                    entity_id=source_id,
                    kind="function",
                    name=f"sub_{ref.from_addr:08x}",
                    artifact_id=artifact.artifact_id,
                    canonical_ref=f"0x{ref.from_addr:08x}",
                    location=AddressLocation(
                        address_space="flat",
                        start=ref.from_addr,
                        end=ref.from_addr,
                    ),
                ))

            if not target_exists:
                entities.append(EntityRecord(
                    entity_id=target_id,
                    kind="function",
                    name=f"sub_{ref.to_addr:08x}",
                    artifact_id=artifact.artifact_id,
                    canonical_ref=f"0x{ref.to_addr:08x}",
                    location=AddressLocation(
                        address_space="flat",
                        start=ref.to_addr,
                        end=ref.to_addr,
                    ),
                ))

            edge = EdgeRecord(
                edge_id=f"edge:reference:{ref.from_addr:08x}:{ref.to_addr:08x}",
                kind="reference",
                source_entity_id=source_id,
                target_entity_id=target_id,
                attributes={"ref_type": ref.ref_type},
            )
            edges.append(edge)

        # Create comment evidence
        for comment in data.get("comments", []) + data.get("bookmarks", []):
            ev = EvidenceRecord(
                evidence_id=f"evidence:comment:{comment.address:08x}:{comment.comment_type}",
                kind="comment",
                artifact_id=artifact.artifact_id,
                location=AddressLocation(
                    address_space="flat",
                    start=comment.address,
                    end=comment.address,
                ),
                excerpt=comment.text,
                attributes={"comment_type": comment.comment_type},
            )
            evidence.append(ev)

        return ReverseEngineeringBundle(
            artifacts=artifacts,
            entities=entities,
            evidence=evidence,
            edges=edges,
        )
