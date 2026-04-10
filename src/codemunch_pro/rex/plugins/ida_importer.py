"""IDA Pro database importer.

This module imports IDA Pro artifacts from:
1. JSON exports produced by IDA Pro.
2. Live IDA Python APIs when running inside IDA.
3. Standalone parsing via python-idb when available.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)

logger = logging.getLogger(__name__)
IDA_RECOVERABLE_ERRORS = (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError)


@dataclass
class IdaProImporter:
    """Importer for IDA Pro database files (.i64, .idb, JSON exports)."""

    name: str = "ida-pro"
    _ida_available: bool = field(init=False, repr=False, default=False)
    _idaapi: Any = field(init=False, repr=False, default=None)
    _idautils: Any = field(init=False, repr=False, default=None)
    _idc: Any = field(init=False, repr=False, default=None)
    _active_artifact_id: str = field(init=False, repr=False, default="")
    _ida_entity_ids_by_addr: dict[int, str] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize and detect IDA runtime availability."""
        try:
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
        """Check whether this importer supports the input path."""
        suffix = path.suffix.lower()
        if suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return isinstance(data, dict) and any(
                    key in data
                    for key in (
                        "functions",
                        "funcs",
                        "data",
                        "structs",
                        "structures",
                        "enums",
                        "segments",
                        "xrefs",
                        "comments",
                        "idb",
                    )
                )
            except (json.JSONDecodeError, OSError):
                return False

        return suffix in (".i64", ".idb")

    def ingest(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest an IDA source file into a reverse-engineering bundle."""
        artifact_id = path.as_posix()
        self._active_artifact_id = artifact_id
        self._ida_entity_ids_by_addr.clear()

        artifact = ArtifactRecord(
            artifact_id=artifact_id,
            kind="ida-database",
            path=artifact_id,
            title=path.name,
            metadata={
                "platform_guess": self._detect_platform(path),
            },
        )

        entities: list[EntityRecord] = []
        evidence: list[EvidenceRecord] = []
        edges: list[EdgeRecord] = []

        suffix = path.suffix.lower()
        if suffix == ".json":
            self._parse_json_export(path, entities, evidence, edges)
        elif self._ida_available:
            self._parse_with_ida(path, entities, evidence, edges)
        else:
            self._parse_standalone(path, entities, evidence, edges)

        self._active_artifact_id = ""
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
        """Parse a JSON export from IDA Pro."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse IDA JSON export %s: %s", path, exc)
            entities.append(
                EntityRecord(
                    entity_id=f"entity:ida-json:error:{path.name}",
                    kind="import-error",
                    name=path.name,
                    artifact_id=self._active_artifact_id,
                    attributes={"error": str(exc)},
                )
            )
            return

        if not isinstance(data, dict):
            entities.append(
                EntityRecord(
                    entity_id=f"entity:ida-json:invalid:{path.name}",
                    kind="import-error",
                    name=path.name,
                    artifact_id=self._active_artifact_id,
                    attributes={"error": "JSON root must be an object"},
                )
            )
            return

        by_addr: dict[int, str] = {}

        for index, func in enumerate(self._iter_dict_items(data, ("functions", "funcs"))):
            addr = self._extract_address(func, ("ea", "start_ea", "start", "address"))
            name = self._extract_name(func, f"sub_{index:04X}")
            if addr is None:
                continue

            func_id = f"entity:function:{addr:X}"
            if func_id in {e.entity_id for e in entities}:
                continue

            entity = EntityRecord(
                entity_id=func_id,
                kind="function",
                name=name,
                artifact_id=self._active_artifact_id,
                canonical_ref=f"0x{addr:X}",
                location=self._create_location(addr, self._extract_int(func.get("size"), 0)),
                attributes={
                    "flags": self._extract_int(func.get("flags"), 0),
                    "type": "function",
                },
            )
            entities.append(entity)
            by_addr[addr] = func_id

        for item in self._iter_dict_items(data, ("data", "globals", "items")):
            addr = self._extract_address(item, ("ea", "address", "start"))
            if addr is None:
                continue
            item_id = f"entity:data:{addr:X}"
            if item_id in {e.entity_id for e in entities}:
                continue

            name = self._extract_name(item, f"data_{addr:X}")
            entity = EntityRecord(
                entity_id=item_id,
                kind="data",
                name=name,
                artifact_id=self._active_artifact_id,
                canonical_ref=f"0x{addr:X}",
                location=self._create_location(addr, self._extract_int(item.get("size"), 0)),
                attributes={
                    "data_type": str(item.get("type", "unknown")),
                },
            )
            entities.append(entity)
            by_addr[addr] = item_id

        for struct in self._iter_dict_items(data, ("structs", "structures")):
            name = self._extract_name(struct, "unnamed_struct")
            entities.append(
                EntityRecord(
                    entity_id=f"entity:struct:{name}",
                    kind="structure",
                    name=name,
                    artifact_id=self._active_artifact_id,
                    attributes={
                        "size": self._extract_int(struct.get("size"), 0),
                        "members": struct.get("members", []),
                    },
                )
            )

        for enum in self._iter_dict_items(data, ("enums",)):
            name = self._extract_name(enum, "unnamed_enum")
            entities.append(
                EntityRecord(
                    entity_id=f"entity:enum:{name}",
                    kind="enum",
                    name=name,
                    artifact_id=self._active_artifact_id,
                    attributes={"values": enum.get("values", {})},
                )
            )

        for seg in self._iter_dict_items(data, ("segments",)):
            start = self._extract_address(seg, ("start", "start_ea", "ea", "address"))
            end = self._extract_address(seg, ("end", "end_ea"))
            if start is None:
                continue
            size = max(0, (end if end is not None else start) - start)
            name = self._extract_name(seg, f"seg_{start:X}")
            entities.append(
                EntityRecord(
                    entity_id=f"entity:segment:{name}:{start:X}",
                    kind="segment",
                    name=name,
                    artifact_id=self._active_artifact_id,
                    location=self._create_location(start, size),
                    attributes={
                        "permissions": str(seg.get("perm", "---")),
                        "class": str(seg.get("class", "")),
                    },
                )
            )

        for idx, xref in enumerate(self._iter_dict_items(data, ("xrefs", "crossrefs"))):
            src_addr = self._extract_address(xref, ("from", "frm", "src", "source"))
            dst_addr = self._extract_address(xref, ("to", "dst", "target"))
            if src_addr is None or dst_addr is None:
                continue

            src_id = self._ensure_reference_entity(src_addr, entities, by_addr)
            dst_id = self._ensure_reference_entity(dst_addr, entities, by_addr)
            edges.append(
                EdgeRecord(
                    edge_id=f"edge:xref:{src_addr:X}:{dst_addr:X}:{idx}",
                    kind="cross-reference",
                    source_entity_id=src_id,
                    target_entity_id=dst_id,
                    attributes={"type": str(xref.get("type", "unknown"))},
                )
            )

        for idx, comment in enumerate(self._iter_dict_items(data, ("comments",))):
            addr = self._extract_address(comment, ("ea", "address", "at"))
            text = str(comment.get("text", "")).strip()
            if addr is None or not text:
                continue

            entity_id = self._ensure_reference_entity(addr, entities, by_addr)
            evidence.append(
                EvidenceRecord(
                    evidence_id=f"evidence:comment:{addr:X}:{idx}",
                    kind="comment",
                    artifact_id=self._active_artifact_id,
                    entity_ids=(entity_id,),
                    location=self._create_location(addr, 1),
                    excerpt=text,
                    attributes={"type": str(comment.get("type", "regular"))},
                )
            )

    def _parse_with_ida(
        self,
        path: Path,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
        edges: list[EdgeRecord],
    ) -> None:
        """Parse with live IDA Python APIs (inside IDA runtime)."""
        entities.append(
            EntityRecord(
                entity_id=f"entity:ida-runtime:{path.name}",
                kind="ida-database",
                name=path.name,
                artifact_id=self._active_artifact_id,
                attributes={
                    "platform": self._detect_platform(path),
                    "mode": "ida-python",
                },
            )
        )

        self._extract_functions_with_ida(entities, evidence)
        self._extract_data_with_ida(entities, evidence)
        self._extract_structures_with_ida(entities)
        self._extract_enums_with_ida(entities)
        self._extract_segments_with_ida(entities)
        self._extract_comments_with_ida(evidence)
        self._extract_xrefs_with_ida(entities, edges)

    def _parse_standalone(
        self,
        path: Path,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
        edges: list[EdgeRecord],
    ) -> None:
        """Parse in standalone mode, preferring python-idb when available."""
        try:
            import idb  # type: ignore

            self._parse_with_python_idb(path, entities, evidence, edges, idb)
            return
        except ImportError:
            logger.debug("python-idb not installed; using metadata-only IDA fallback")

        entities.append(
            EntityRecord(
                entity_id=f"entity:ida-database:{path.as_posix()}",
                kind="ida-database",
                name=path.name,
                artifact_id=self._active_artifact_id,
                canonical_ref=path.as_posix(),
                attributes={
                    "parsing_status": "metadata-only",
                    "size": path.stat().st_size if path.exists() else 0,
                    "platform": self._detect_platform(path),
                },
            )
        )

    def _parse_with_python_idb(
        self,
        path: Path,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
        edges: list[EdgeRecord],
        idb_module: Any,
    ) -> None:
        """Parse with python-idb using a tolerant best-effort adapter."""
        opened = False
        db_obj: Any = None

        from_file = getattr(idb_module, "from_file", None)
        if callable(from_file):
            try:
                maybe_ctx = from_file(path.as_posix())
                if hasattr(maybe_ctx, "__enter__") and hasattr(maybe_ctx, "__exit__"):
                    with maybe_ctx as handle:
                        db_obj = handle
                        opened = True
                        self._extract_python_idb_content(db_obj, entities)
                else:
                    db_obj = maybe_ctx
                    opened = True
                    self._extract_python_idb_content(db_obj, entities)
            except IDA_RECOVERABLE_ERRORS as exc:
                logger.debug("python-idb parsing failed for %s: %s", path, exc)

        entities.append(
            EntityRecord(
                entity_id=f"entity:ida-python-idb:{path.name}",
                kind="ida-database",
                name=path.name,
                artifact_id=self._active_artifact_id,
                attributes={
                    "backend": "python-idb",
                    "opened": opened,
                    "platform": self._detect_platform(path),
                    "db_type": type(db_obj).__name__ if db_obj is not None else "unknown",
                },
            )
        )

    def _extract_python_idb_content(self, db_obj: Any, entities: list[EntityRecord]) -> None:
        """Extract function-like items from a python-idb object when possible."""
        candidates: Iterable[Any] = ()
        for attr in ("functions", "funcs", "Functions"):
            value = getattr(db_obj, attr, None)
            if callable(value):
                try:
                    value = value()
                except IDA_RECOVERABLE_ERRORS:
                    continue
            if isinstance(value, Iterable) and not isinstance(value, (str, bytes, dict)):
                candidates = value
                break

        for idx, item in enumerate(candidates):
            addr = self._extract_address(item, ("ea", "start_ea", "start", "address"))
            if addr is None:
                continue
            name = self._extract_name(item, f"sub_{idx:04X}")
            entities.append(
                EntityRecord(
                    entity_id=f"entity:function:{addr:X}",
                    kind="function",
                    name=name,
                    artifact_id=self._active_artifact_id,
                    canonical_ref=f"0x{addr:X}",
                    location=self._create_location(addr, self._extract_int(getattr(item, "size", None), 0)),
                    attributes={"source": "python-idb"},
                )
            )

    def _create_location(self, address: int, size: int) -> AddressLocation | None:
        """Create a location object from an address and byte size."""
        if address == 0 and size == 0:
            return None

        address_space = "ida-virtual"
        if address < 0x10000:
            address_space = "ida-zero-page"
        elif address < 0x1000000:
            address_space = "ida-low"
        elif address >= 0x8000000000000000:
            address_space = "ida-kernel"

        span = max(1, size)
        return AddressLocation(
            address_space=address_space,
            start=address,
            end=address + span - 1,
            display=f"0x{address:X}",
        )

    def _detect_platform(self, path: Path) -> str:
        """Detect the likely target platform from filename/extension/JSON metadata."""
        suffix = path.suffix.lower()
        name = path.name.lower()

        if suffix == ".i64":
            return "x86-64"
        if suffix == ".idb":
            return "x86-32"

        if suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for key in ("processor", "arch", "architecture", "platform"):
                        value = data.get(key)
                        if isinstance(value, str) and value.strip():
                            return value.strip().lower()
            except (json.JSONDecodeError, OSError):
                pass

        if "arm" in name:
            return "arm"
        if "mips" in name:
            return "mips"
        if "ppc" in name or "powerpc" in name:
            return "powerpc"
        return "unknown"

    def _extract_functions_with_ida(
        self,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
    ) -> None:
        """Extract functions using IDA APIs when available."""
        if self._idautils is None or self._idc is None:
            return

        try:
            functions = list(self._idautils.Functions())
        except IDA_RECOVERABLE_ERRORS as exc:
            logger.debug("IDA function extraction failed: %s", exc)
            return

        for ea in functions:
            try:
                addr = int(ea)
                name = str(self._idc.get_func_name(addr) or f"sub_{addr:X}")
                end = self._extract_int(self._idc.get_func_attr(addr, self._idc.FUNCATTR_END), addr + 1)
                size = max(1, end - addr)
                entity_id = f"entity:function:{addr:X}"
                entities.append(
                    EntityRecord(
                        entity_id=entity_id,
                        kind="function",
                        name=name,
                        artifact_id=self._active_artifact_id,
                        canonical_ref=f"0x{addr:X}",
                        location=self._create_location(addr, size),
                        attributes={"source": "idaapi"},
                    )
                )
                self._ida_entity_ids_by_addr[addr] = entity_id

                comment = self._idc.get_func_cmt(addr, False)
                if isinstance(comment, str) and comment.strip():
                    evidence.append(
                        EvidenceRecord(
                            evidence_id=f"evidence:func-comment:{addr:X}",
                            kind="comment",
                            artifact_id=self._active_artifact_id,
                            entity_ids=(entity_id,),
                            location=self._create_location(addr, 1),
                            excerpt=comment.strip(),
                            attributes={"type": "function"},
                        )
                    )
            except IDA_RECOVERABLE_ERRORS as exc:
                logger.debug("Skipping function %s: %s", ea, exc)

    def _extract_data_with_ida(
        self,
        entities: list[EntityRecord],
        evidence: list[EvidenceRecord],
    ) -> None:
        """Extract named data symbols from IDA APIs when available."""
        if self._idautils is None or self._idc is None:
            return

        names_iter = getattr(self._idautils, "Names", None)
        if not callable(names_iter):
            return

        try:
            for ea, name in names_iter():
                addr = int(ea)
                if addr in self._ida_entity_ids_by_addr:
                    continue
                symbol_name = str(name or f"data_{addr:X}")
                entity_id = f"entity:data:{addr:X}"
                entities.append(
                    EntityRecord(
                        entity_id=entity_id,
                        kind="data",
                        name=symbol_name,
                        artifact_id=self._active_artifact_id,
                        canonical_ref=f"0x{addr:X}",
                        location=self._create_location(addr, 1),
                        attributes={"source": "idaapi"},
                    )
                )
                self._ida_entity_ids_by_addr[addr] = entity_id
        except IDA_RECOVERABLE_ERRORS as exc:
            logger.debug("IDA data extraction failed: %s", exc)

    def _extract_structures_with_ida(self, entities: list[EntityRecord]) -> None:
        """Extract structure metadata using IDA APIs when available."""
        if self._idautils is None or self._idc is None:
            return

        struct_count_getter = getattr(self._idc, "get_struc_qty", None)
        if not callable(struct_count_getter):
            return

        try:
            count = int(struct_count_getter())
        except IDA_RECOVERABLE_ERRORS:
            return

        for idx in range(count):
            try:
                sid = self._idc.get_struc_id(idx)
                name = str(self._idc.get_struc_name(sid) or f"struct_{idx}")
                size = self._extract_int(self._idc.get_struc_size(sid), 0)
                entities.append(
                    EntityRecord(
                        entity_id=f"entity:struct:{name}:{sid}",
                        kind="structure",
                        name=name,
                        artifact_id=self._active_artifact_id,
                        attributes={"size": size, "source": "idaapi"},
                    )
                )
            except IDA_RECOVERABLE_ERRORS as exc:
                logger.debug("Skipping structure index %s: %s", idx, exc)

    def _extract_enums_with_ida(self, entities: list[EntityRecord]) -> None:
        """Extract enum metadata using IDA APIs when available."""
        if self._idc is None:
            return

        qty_getter = getattr(self._idc, "get_enum_qty", None)
        if not callable(qty_getter):
            return

        try:
            count = int(qty_getter())
        except IDA_RECOVERABLE_ERRORS:
            return

        for idx in range(count):
            try:
                eid = self._idc.getn_enum(idx)
                name = str(self._idc.get_enum_name(eid) or f"enum_{idx}")
                entities.append(
                    EntityRecord(
                        entity_id=f"entity:enum:{name}:{eid}",
                        kind="enum",
                        name=name,
                        artifact_id=self._active_artifact_id,
                        attributes={"source": "idaapi"},
                    )
                )
            except IDA_RECOVERABLE_ERRORS as exc:
                logger.debug("Skipping enum index %s: %s", idx, exc)

    def _extract_xrefs_with_ida(self, entities: list[EntityRecord], edges: list[EdgeRecord]) -> None:
        """Extract cross-reference edges using IDA APIs when available."""
        if self._idautils is None:
            return

        refs_from = getattr(self._idautils, "CodeRefsFrom", None)
        if not callable(refs_from):
            return

        for src_addr, src_entity_id in list(self._ida_entity_ids_by_addr.items()):
            try:
                for dst in refs_from(src_addr, 0):
                    dst_addr = int(dst)
                    dst_entity_id = self._ida_entity_ids_by_addr.get(dst_addr)
                    if dst_entity_id is None:
                        dst_entity_id = f"entity:reference:{dst_addr:X}"
                        self._ida_entity_ids_by_addr[dst_addr] = dst_entity_id
                        entities.append(
                            EntityRecord(
                                entity_id=dst_entity_id,
                                kind="reference",
                                name=f"loc_{dst_addr:X}",
                                artifact_id=self._active_artifact_id,
                                canonical_ref=f"0x{dst_addr:X}",
                                location=self._create_location(dst_addr, 1),
                                attributes={"source": "idaapi"},
                            )
                        )

                    edges.append(
                        EdgeRecord(
                            edge_id=f"edge:xref:{src_addr:X}:{dst_addr:X}",
                            kind="cross-reference",
                            source_entity_id=src_entity_id,
                            target_entity_id=dst_entity_id,
                            attributes={"source": "idaapi"},
                        )
                    )
            except IDA_RECOVERABLE_ERRORS as exc:
                logger.debug("Skipping xrefs for %s: %s", src_addr, exc)

    def _extract_comments_with_ida(self, evidence: list[EvidenceRecord]) -> None:
        """Extract repeatable and non-repeatable comments from IDA APIs."""
        if self._idautils is None or self._idc is None:
            return

        names_iter = getattr(self._idautils, "Names", None)
        if not callable(names_iter):
            return

        for ea, _ in names_iter():
            addr = self._extract_int(ea, -1)
            if addr < 0:
                continue
            entity_id = self._ida_entity_ids_by_addr.get(addr)
            if not entity_id:
                continue

            for repeatable, label in ((False, "regular"), (True, "repeatable")):
                try:
                    text = self._idc.get_cmt(addr, repeatable)
                except IDA_RECOVERABLE_ERRORS:
                    continue
                if not isinstance(text, str) or not text.strip():
                    continue

                evidence.append(
                    EvidenceRecord(
                        evidence_id=f"evidence:comment:{addr:X}:{label}",
                        kind="comment",
                        artifact_id=self._active_artifact_id,
                        entity_ids=(entity_id,),
                        location=self._create_location(addr, 1),
                        excerpt=text.strip(),
                        attributes={"type": label},
                    )
                )

    def _extract_segments_with_ida(self, entities: list[EntityRecord]) -> None:
        """Extract segment metadata using IDA APIs when available."""
        if self._idautils is None or self._idc is None:
            return

        segments_iter = getattr(self._idautils, "Segments", None)
        if not callable(segments_iter):
            return

        for start_ea in segments_iter():
            try:
                start = int(start_ea)
                end = self._extract_int(self._idc.get_segm_end(start), start)
                size = max(0, end - start)
                seg_name = str(self._idc.get_segm_name(start) or f"seg_{start:X}")
                entities.append(
                    EntityRecord(
                        entity_id=f"entity:segment:{seg_name}:{start:X}",
                        kind="segment",
                        name=seg_name,
                        artifact_id=self._active_artifact_id,
                        location=self._create_location(start, size),
                        attributes={"source": "idaapi"},
                    )
                )
            except IDA_RECOVERABLE_ERRORS as exc:
                logger.debug("Skipping segment at %s: %s", start_ea, exc)

    def _iter_dict_items(self, data: dict[str, Any], keys: tuple[str, ...]) -> list[dict[str, Any]]:
        """Return normalized lists of dictionary records from candidate keys."""
        results: list[dict[str, Any]] = []
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        results.append(item)
            elif isinstance(value, dict):
                for item in value.values():
                    if isinstance(item, dict):
                        results.append(item)
        return results

    def _extract_int(self, value: Any, default: int = 0) -> int:
        """Extract an integer from mixed int/str JSON values."""
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            text = value.strip().lower().replace("_", "")
            if not text:
                return default
            try:
                if text.startswith("0x"):
                    return int(text, 16)
                if text.startswith("$"):
                    return int(text[1:], 16)
                if any(ch in "abcdef" for ch in text):
                    return int(text, 16)
                return int(text, 10)
            except ValueError:
                return default
        return default

    def _extract_address(self, item: Any, keys: tuple[str, ...]) -> int | None:
        """Extract an address-like integer from dict/object values."""
        for key in keys:
            value: Any = None
            if isinstance(item, dict) and key in item:
                value = item.get(key)
            elif hasattr(item, key):
                value = getattr(item, key)

            addr = self._extract_int(value, -1)
            if addr >= 0:
                return addr
        return None

    def _extract_name(self, item: Any, fallback: str) -> str:
        """Extract a display name from dict/object values."""
        for key in ("name", "label", "symbol", "func_name"):
            value: Any = None
            if isinstance(item, dict):
                value = item.get(key)
            elif hasattr(item, key):
                value = getattr(item, key)

            if isinstance(value, str) and value.strip():
                return value.strip()
        return fallback

    def _ensure_reference_entity(
        self,
        address: int,
        entities: list[EntityRecord],
        by_addr: dict[int, str],
    ) -> str:
        """Ensure a generic reference entity exists for an address."""
        existing = by_addr.get(address)
        if existing is not None:
            return existing

        entity_id = f"entity:reference:{address:X}"
        entities.append(
            EntityRecord(
                entity_id=entity_id,
                kind="reference",
                name=f"loc_{address:X}",
                artifact_id=self._active_artifact_id,
                canonical_ref=f"0x{address:X}",
                location=self._create_location(address, 1),
                attributes={"source": "ida"},
            )
        )
        by_addr[address] = entity_id
        return entity_id
