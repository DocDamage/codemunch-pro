"""Export formats for other reverse-engineering tools.

This module provides exporters for various RE tools including:
- IDA Pro (Python scripts)
- Ghidra (XML import format)
- Binary Ninja (type definitions)
- Generic JSON and CSV formats
"""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore


@dataclass
class ExportOptions:
    """Options for controlling export behavior."""

    include_functions: bool = True
    include_data_labels: bool = True
    include_comments: bool = True
    include_structures: bool = True
    include_xrefs: bool = True
    min_confidence: float | None = None
    address_space_filter: str | None = None
    artifact_filter: str | None = None


@dataclass
class FunctionExport:
    """Function data for export."""

    name: str
    address: int
    signature: str = ""
    size: int = 0
    comment: str = ""
    return_type: str = ""
    parameters: list[dict[str, str]] = field(default_factory=list)


@dataclass
class DataLabelExport:
    """Data label for export."""

    name: str
    address: int
    data_type: str = ""
    size: int = 0
    comment: str = ""
    value: str = ""


@dataclass
class CommentExport:
    """Comment for export."""

    address: int
    text: str
    comment_type: str = "line"  # line, function, anterior, posterior


@dataclass
class StructureExport:
    """Structure/type for export."""

    name: str
    size: int = 0
    members: list[dict[str, Any]] = field(default_factory=list)
    comment: str = ""


@dataclass
class XrefExport:
    """Cross-reference for export."""

    from_address: int
    to_address: int
    xref_type: str = ""
    is_code: bool = True


@dataclass
class ExportBundle:
    """Bundle of all export data."""

    functions: list[FunctionExport] = field(default_factory=list)
    data_labels: list[DataLabelExport] = field(default_factory=list)
    comments: list[CommentExport] = field(default_factory=list)
    structures: list[StructureExport] = field(default_factory=list)
    xrefs: list[XrefExport] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseExporter(ABC):
    """Abstract base class for RE tool exporters."""

    def __init__(self, store: ReverseEngineeringStore, options: ExportOptions | None = None):
        self.store = store
        self.options = options or ExportOptions()

    @abstractmethod
    def export(self, output_path: Path) -> dict[str, Any]:
        """Export data to the specified path."""
        ...

    def _collect_data(self) -> ExportBundle:
        """Collect data from the store based on options."""
        bundle = ExportBundle()

        # Get all entities
        cursor = self.store._conn.cursor()
        cursor.execute("SELECT * FROM entities")
        rows = cursor.fetchall()

        for row in rows:
            entity_kind = row["kind"]
            location_json = row["location_json"]
            attributes_json = row["attributes_json"]

            # Apply filters
            if self.options.artifact_filter and row["artifact_id"] != self.options.artifact_filter:
                continue

            if self.options.min_confidence is not None:
                confidence = row.get("confidence")
                if confidence is not None and confidence < self.options.min_confidence:
                    continue

            # Parse location
            location = None
            if location_json:
                try:
                    loc_data = json.loads(location_json)
                    if self.options.address_space_filter:
                        if loc_data.get("address_space") != self.options.address_space_filter:
                            continue
                    location = loc_data
                except json.JSONDecodeError:
                    continue

            # Parse attributes
            attributes: dict[str, Any] = {}
            if attributes_json:
                try:
                    attributes = json.loads(attributes_json)
                except json.JSONDecodeError:
                    pass

            address = location.get("start", 0) if location else 0

            # Process based on entity kind
            if entity_kind == "function" and self.options.include_functions:
                func = FunctionExport(
                    name=row["name"],
                    address=address,
                    signature=attributes.get("signature", ""),
                    size=location.get("end", address) - address + 1 if location else 0,
                    comment=row["summary"],
                    return_type=attributes.get("return_type", ""),
                    parameters=attributes.get("parameters", []),
                )
                bundle.functions.append(func)

            elif entity_kind in ("data", "reference", "field") and self.options.include_data_labels:
                label = DataLabelExport(
                    name=row["name"],
                    address=address,
                    data_type=attributes.get("data_type", ""),
                    size=attributes.get("size", 0),
                    comment=row["summary"],
                    value=attributes.get("value", ""),
                )
                bundle.data_labels.append(label)

            elif entity_kind == "type" and self.options.include_structures:
                struct = StructureExport(
                    name=row["name"],
                    size=attributes.get("size", 0),
                    members=attributes.get("members", []),
                    comment=row["summary"],
                )
                bundle.structures.append(struct)

        # Collect comments from evidence
        if self.options.include_comments:
            cursor.execute("SELECT * FROM evidence WHERE kind = 'comment' OR excerpt LIKE '%:%'")
            for row in cursor.fetchall():
                location_json = row["location_json"]
                if not location_json:
                    continue

                try:
                    loc_data = json.loads(location_json)
                    address = loc_data.get("start", 0)

                    comment = CommentExport(
                        address=address,
                        text=row["excerpt"],
                        comment_type=attributes.get("comment_type", "line"),
                    )
                    bundle.comments.append(comment)
                except json.JSONDecodeError:
                    continue

        # Collect cross-references from edges
        if self.options.include_xrefs:
            cursor.execute("SELECT * FROM edges")
            for row in cursor.fetchall():
                # Get source and target entity addresses
                cursor.execute(
                    "SELECT location_json, kind FROM entities WHERE entity_id = ?",
                    (row["source_entity_id"],)
                )
                source_row = cursor.fetchone()

                cursor.execute(
                    "SELECT location_json, kind FROM entities WHERE entity_id = ?",
                    (row["target_entity_id"],)
                )
                target_row = cursor.fetchone()

                if source_row and target_row:
                    try:
                        source_loc = json.loads(source_row["location_json"]) if source_row["location_json"] else {}
                        target_loc = json.loads(target_row["location_json"]) if target_row["location_json"] else {}

                        xref = XrefExport(
                            from_address=source_loc.get("start", 0),
                            to_address=target_loc.get("start", 0),
                            xref_type=row["kind"],
                            is_code=source_row["kind"] == "function",
                        )
                        bundle.xrefs.append(xref)
                    except json.JSONDecodeError:
                        continue

        return bundle


class IDAExporter(BaseExporter):
    """Generate IDA Python scripts for importing data."""

    def export(self, output_path: Path) -> dict[str, Any]:
        """Export data as an IDA Python script."""
        bundle = self._collect_data()

        lines = [
            '# Generated by CodeMunch Pro - IDA Import Script',
            'import ida_auto',
            'import ida_bytes',
            'import ida_funcs',
            'import ida_name',
            'import ida_struct',
            'import ida_typeinf',
            'import ida_xref',
            'import idc',
            '',
            'def apply_imports():',
            '    """Apply all imported data from CodeMunch Pro."""',
            '    print("Applying CodeMunch Pro imports...")',
            '',
        ]

        # Add functions
        if bundle.functions:
            lines.append('    # Create functions')
            for func in bundle.functions:
                lines.append(f'    # Function: {func.name}')
                lines.append(f'    addr = 0x{func.address:X}')
                lines.append('    ida_funcs.add_func(addr)')
                if func.name:
                    safe_name = func.name.replace('"', '\\"')
                    lines.append(f'    ida_name.set_name(addr, "{safe_name}")')
                if func.comment:
                    safe_comment = func.comment.replace('"', '\\"').replace('\n', '\\n')
                    lines.append(f'    idc.set_func_cmt(addr, "{safe_comment}", 1)')
                lines.append('')

        # Add data labels
        if bundle.data_labels:
            lines.append('    # Create data labels')
            for label in bundle.data_labels:
                lines.append(f'    # Data: {label.name}')
                lines.append(f'    addr = 0x{label.address:X}')
                if label.name:
                    safe_name = label.name.replace('"', '\\"')
                    lines.append(f'    ida_name.set_name(addr, "{safe_name}")')
                if label.data_type:
                    lines.append(f'    # Type: {label.data_type}')
                if label.comment:
                    safe_comment = label.comment.replace('"', '\\"').replace('\n', '\\n')
                    lines.append(f'    idc.set_cmt(addr, "{safe_comment}", 1)')
                lines.append('')

        # Add comments
        if bundle.comments:
            lines.append('    # Add comments')
            for comment in bundle.comments:
                safe_text = comment.text.replace('"', '\\"').replace('\n', '\\n')
                lines.append(f'    idc.set_cmt(0x{comment.address:X}, "{safe_text}", 1)')
            lines.append('')

        # Add structures
        if bundle.structures:
            lines.append('    # Create structures')
            for struct in bundle.structures:
                lines.append(f'    # Structure: {struct.name}')
                lines.append(f'    sid = ida_struct.add_struc(ida_idaapi.BADADDR, "{struct.name}", 0)')
                if struct.members:
                    for i, member in enumerate(struct.members):
                        member_name = member.get("name", f"field_{i}")
                        member_type = member.get("type", "")
                        lines.append(f'    # Member: {member_name} ({member_type})')
                lines.append('')

        # Add cross-references
        if bundle.xrefs:
            lines.append('    # Add cross-references')
            for xref in bundle.xrefs:
                lines.append(f'    # XREF: 0x{xref.from_address:X} -> 0x{xref.to_address:X}')
            lines.append('')

        lines.extend([
            '    print("CodeMunch Pro imports applied successfully!")',
            '',
            'if __name__ == "__main__":',
            '    apply_imports()',
            '',
        ])

        # Write the script
        output_path = Path(output_path)
        if not output_path.suffix == ".py":
            output_path = output_path.with_suffix(".py")

        output_path.write_text("\n".join(lines), encoding="utf-8")

        return {
            "format": "ida_python",
            "path": str(output_path),
            "functions": len(bundle.functions),
            "data_labels": len(bundle.data_labels),
            "comments": len(bundle.comments),
            "structures": len(bundle.structures),
            "xrefs": len(bundle.xrefs),
        }


class GhidraExporter(BaseExporter):
    """Generate Ghidra XML import format."""

    def export(self, output_path: Path) -> dict[str, Any]:
        """Export data as Ghidra XML format."""
        bundle = self._collect_data()

        # Create XML structure
        root = ET.Element("ghidra_export")
        root.set("version", "1.0")
        root.set("source", "CodeMunch Pro")

        # Add functions
        if bundle.functions:
            functions_elem = ET.SubElement(root, "functions")
            for func in bundle.functions:
                func_elem = ET.SubElement(functions_elem, "function")
                func_elem.set("name", func.name)
                func_elem.set("address", f"0x{func.address:X}")
                if func.signature:
                    func_elem.set("signature", func.signature)
                if func.size:
                    func_elem.set("size", str(func.size))
                if func.return_type:
                    func_elem.set("return_type", func.return_type)
                if func.comment:
                    comment_elem = ET.SubElement(func_elem, "comment")
                    comment_elem.text = func.comment

                # Add parameters
                if func.parameters:
                    params_elem = ET.SubElement(func_elem, "parameters")
                    for param in func.parameters:
                        param_elem = ET.SubElement(params_elem, "parameter")
                        param_elem.set("name", param.get("name", ""))
                        param_elem.set("type", param.get("type", ""))

        # Add data labels
        if bundle.data_labels:
            data_elem = ET.SubElement(root, "data_labels")
            for label in bundle.data_labels:
                label_elem = ET.SubElement(data_elem, "label")
                label_elem.set("name", label.name)
                label_elem.set("address", f"0x{label.address:X}")
                if label.data_type:
                    label_elem.set("type", label.data_type)
                if label.size:
                    label_elem.set("size", str(label.size))
                if label.value:
                    label_elem.set("value", str(label.value))
                if label.comment:
                    comment_elem = ET.SubElement(label_elem, "comment")
                    comment_elem.text = label.comment

        # Add comments
        if bundle.comments:
            comments_elem = ET.SubElement(root, "comments")
            for comment in bundle.comments:
                comment_elem = ET.SubElement(comments_elem, "comment")
                comment_elem.set("address", f"0x{comment.address:X}")
                comment_elem.set("type", comment.comment_type)
                comment_elem.text = comment.text

        # Add structures
        if bundle.structures:
            structs_elem = ET.SubElement(root, "structures")
            for struct in bundle.structures:
                struct_elem = ET.SubElement(structs_elem, "structure")
                struct_elem.set("name", struct.name)
                if struct.size:
                    struct_elem.set("size", str(struct.size))
                if struct.comment:
                    struct_elem.set("comment", struct.comment)

                if struct.members:
                    members_elem = ET.SubElement(struct_elem, "members")
                    for member in struct.members:
                        member_elem = ET.SubElement(members_elem, "member")
                        member_elem.set("name", member.get("name", ""))
                        member_elem.set("type", member.get("type", ""))
                        if "offset" in member:
                            member_elem.set("offset", str(member["offset"]))
                        if "size" in member:
                            member_elem.set("size", str(member["size"]))

        # Add cross-references
        if bundle.xrefs:
            xrefs_elem = ET.SubElement(root, "cross_references")
            for xref in bundle.xrefs:
                xref_elem = ET.SubElement(xrefs_elem, "xref")
                xref_elem.set("from", f"0x{xref.from_address:X}")
                xref_elem.set("to", f"0x{xref.to_address:X}")
                xref_elem.set("type", xref.xref_type)
                xref_elem.set("is_code", "true" if xref.is_code else "false")

        # Write XML
        output_path = Path(output_path)
        if not output_path.suffix == ".xml":
            output_path = output_path.with_suffix(".xml")

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(output_path, encoding="utf-8", xml_declaration=True)

        return {
            "format": "ghidra_xml",
            "path": str(output_path),
            "functions": len(bundle.functions),
            "data_labels": len(bundle.data_labels),
            "comments": len(bundle.comments),
            "structures": len(bundle.structures),
            "xrefs": len(bundle.xrefs),
        }


class BinaryNinjaExporter(BaseExporter):
    """Generate Binary Ninja type definitions."""

    def export(self, output_path: Path) -> dict[str, Any]:
        """Export data as Binary Ninja Python script."""
        bundle = self._collect_data()

        lines = [
            '# Generated by CodeMunch Pro - Binary Ninja Import Script',
            'from binaryninja import *',
            '',
            'def apply_imports(bv):',
            '    """Apply all imported data from CodeMunch Pro."""',
            '    log_info("Applying CodeMunch Pro imports...")',
            '',
        ]

        # Add functions
        if bundle.functions:
            lines.append('    # Create functions')
            for func in bundle.functions:
                lines.append(f'    # Function: {func.name}')
                lines.append(f'    addr = 0x{func.address:X}')
                lines.append('    func = bv.get_function_at(addr)')
                lines.append('    if func is None:')
                lines.append('        func = bv.create_user_function(addr)')
                if func.name:
                    safe_name = func.name.replace('"', '\\"')
                    lines.append('    if func:')
                    lines.append(f'        func.name = "{safe_name}"')
                if func.comment:
                    safe_comment = func.comment.replace('"', '\\"')
                    lines.append(f'        func.comment = "{safe_comment}"')
                lines.append('')

        # Add data labels
        if bundle.data_labels:
            lines.append('    # Create data labels')
            for label in bundle.data_labels:
                lines.append(f'    # Data: {label.name}')
                lines.append(f'    addr = 0x{label.address:X}')
                if label.name:
                    safe_name = label.name.replace('"', '\\"')
                    lines.append(f'    bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, "{safe_name}"))')
                if label.data_type:
                    lines.append(f'    # Type: {label.data_type}')
                if label.comment:
                    safe_comment = label.comment.replace('"', '\\"')
                    lines.append(f'    bv.set_comment_at(addr, "{safe_comment}")')
                lines.append('')

        # Add comments
        if bundle.comments:
            lines.append('    # Add comments')
            for comment in bundle.comments:
                safe_text = comment.text.replace('"', '\\"')
                lines.append(f'    bv.set_comment_at(0x{comment.address:X}, "{safe_text}")')
            lines.append('')

        # Add structures
        if bundle.structures:
            lines.append('    # Create structures')
            for struct in bundle.structures:
                lines.append(f'    # Structure: {struct.name}')
                lines.append('    struct = Structure()')
                lines.append(f'    struct.name = "{struct.name}"')
                if struct.members:
                    for member in struct.members:
                        member_name = member.get("name", "")
                        member_type = member.get("type", "")
                        lines.append(f'    # Member: {member_name} ({member_type})')
                lines.append('    bv.define_user_data_var(0, struct)')
                lines.append('')

        # Add cross-references
        if bundle.xrefs:
            lines.append('    # Note: Cross-references are typically inferred by Binary Ninja')
            lines.append('    # The following are documented for reference:')
            for xref in bundle.xrefs:
                lines.append(f'    # XREF: 0x{xref.from_address:X} -> 0x{xref.to_address:X} ({xref.xref_type})')
            lines.append('')

        lines.extend([
            '    log_info("CodeMunch Pro imports applied successfully!")',
            '',
            '# Run with: apply_imports(bv)',
            '',
        ])

        # Write the script
        output_path = Path(output_path)
        if not output_path.suffix == ".py":
            output_path = output_path.with_suffix(".py")

        output_path.write_text("\n".join(lines), encoding="utf-8")

        return {
            "format": "binary_ninja",
            "path": str(output_path),
            "functions": len(bundle.functions),
            "data_labels": len(bundle.data_labels),
            "comments": len(bundle.comments),
            "structures": len(bundle.structures),
            "xrefs": len(bundle.xrefs),
        }


class JSONExporter(BaseExporter):
    """Generate generic JSON for external tools."""

    def export(self, output_path: Path) -> dict[str, Any]:
        """Export data as JSON."""
        bundle = self._collect_data()

        data = {
            "metadata": {
                "format": "codemunch_export",
                "version": "1.0",
                **bundle.metadata,
            },
            "functions": [
                {
                    "name": f.name,
                    "address": f"0x{f.address:X}",
                    "address_dec": f.address,
                    "signature": f.signature,
                    "size": f.size,
                    "comment": f.comment,
                    "return_type": f.return_type,
                    "parameters": f.parameters,
                }
                for f in bundle.functions
            ],
            "data_labels": [
                {
                    "name": d.name,
                    "address": f"0x{d.address:X}",
                    "address_dec": d.address,
                    "type": d.data_type,
                    "size": d.size,
                    "comment": d.comment,
                    "value": d.value,
                }
                for d in bundle.data_labels
            ],
            "comments": [
                {
                    "address": f"0x{c.address:X}",
                    "address_dec": c.address,
                    "text": c.text,
                    "type": c.comment_type,
                }
                for c in bundle.comments
            ],
            "structures": [
                {
                    "name": s.name,
                    "size": s.size,
                    "members": s.members,
                    "comment": s.comment,
                }
                for s in bundle.structures
            ],
            "cross_references": [
                {
                    "from_address": f"0x{x.from_address:X}",
                    "from_address_dec": x.from_address,
                    "to_address": f"0x{x.to_address:X}",
                    "to_address_dec": x.to_address,
                    "type": x.xref_type,
                    "is_code": x.is_code,
                }
                for x in bundle.xrefs
            ],
        }

        output_path = Path(output_path)
        if not output_path.suffix == ".json":
            output_path = output_path.with_suffix(".json")

        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return {
            "format": "json",
            "path": str(output_path),
            "functions": len(bundle.functions),
            "data_labels": len(bundle.data_labels),
            "comments": len(bundle.comments),
            "structures": len(bundle.structures),
            "xrefs": len(bundle.xrefs),
        }


class CSVExporter(BaseExporter):
    """Generate CSV for spreadsheets."""

    def export(self, output_path: Path) -> dict[str, Any]:
        """Export data as CSV files (one per data type)."""
        bundle = self._collect_data()

        output_path = Path(output_path)
        if output_path.suffix:
            # If a file with extension is given, use its parent directory
            output_dir = output_path.parent / output_path.stem
        else:
            output_dir = output_path

        output_dir.mkdir(parents=True, exist_ok=True)

        results = {
            "format": "csv",
            "directory": str(output_dir),
            "files": [],
        }

        # Export functions
        if bundle.functions:
            func_path = output_dir / "functions.csv"
            with open(func_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["name", "address", "address_hex", "signature", "size", "return_type", "comment"])
                for func in bundle.functions:
                    writer.writerow([
                        func.name,
                        func.address,
                        f"0x{func.address:X}",
                        func.signature,
                        func.size,
                        func.return_type,
                        func.comment,
                    ])
            results["files"].append(str(func_path))

        # Export data labels
        if bundle.data_labels:
            data_path = output_dir / "data_labels.csv"
            with open(data_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["name", "address", "address_hex", "type", "size", "value", "comment"])
                for label in bundle.data_labels:
                    writer.writerow([
                        label.name,
                        label.address,
                        f"0x{label.address:X}",
                        label.data_type,
                        label.size,
                        label.value,
                        label.comment,
                    ])
            results["files"].append(str(data_path))

        # Export comments
        if bundle.comments:
            comments_path = output_dir / "comments.csv"
            with open(comments_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["address", "address_hex", "text", "type"])
                for comment in bundle.comments:
                    writer.writerow([
                        comment.address,
                        f"0x{comment.address:X}",
                        comment.text,
                        comment.comment_type,
                    ])
            results["files"].append(str(comments_path))

        # Export structures
        if bundle.structures:
            structs_path = output_dir / "structures.csv"
            with open(structs_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["name", "size", "comment"])
                for struct in bundle.structures:
                    writer.writerow([
                        struct.name,
                        struct.size,
                        struct.comment,
                    ])
            results["files"].append(str(structs_path))

            # Also export structure members
            members_path = output_dir / "structure_members.csv"
            with open(members_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["structure_name", "member_name", "type", "offset", "size"])
                for struct in bundle.structures:
                    for member in struct.members:
                        writer.writerow([
                            struct.name,
                            member.get("name", ""),
                            member.get("type", ""),
                            member.get("offset", ""),
                            member.get("size", ""),
                        ])
            results["files"].append(str(members_path))

        # Export cross-references
        if bundle.xrefs:
            xrefs_path = output_dir / "cross_references.csv"
            with open(xrefs_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["from_address", "from_address_hex", "to_address", "to_address_hex", "type", "is_code"])
                for xref in bundle.xrefs:
                    writer.writerow([
                        xref.from_address,
                        f"0x{xref.from_address:X}",
                        xref.to_address,
                        f"0x{xref.to_address:X}",
                        xref.xref_type,
                        "yes" if xref.is_code else "no",
                    ])
            results["files"].append(str(xrefs_path))

        results["counts"] = {
            "functions": len(bundle.functions),
            "data_labels": len(bundle.data_labels),
            "comments": len(bundle.comments),
            "structures": len(bundle.structures),
            "xrefs": len(bundle.xrefs),
        }

        return results


# Export type registry
EXPORTER_MAP: dict[str, type[BaseExporter]] = {
    "ida": IDAExporter,
    "ida_python": IDAExporter,
    "ghidra": GhidraExporter,
    "ghidra_xml": GhidraExporter,
    "binary_ninja": BinaryNinjaExporter,
    "binja": BinaryNinjaExporter,
    "json": JSONExporter,
    "csv": CSVExporter,
}


def get_exporter(format_type: str, store: ReverseEngineeringStore, options: ExportOptions | None = None) -> BaseExporter:
    """Get an exporter instance for the specified format."""
    format_lower = format_type.lower()
    if format_lower not in EXPORTER_MAP:
        raise ValueError(f"Unknown export format: {format_type}. Available: {list(EXPORTER_MAP.keys())}")
    return EXPORTER_MAP[format_lower](store, options)
