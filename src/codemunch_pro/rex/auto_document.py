"""Auto-documentation generation for reverse-engineered functions.

This module provides LLM-powered documentation generation for functions
based on their context within the reverse-engineering database.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore


class OutputFormat(Enum):
    """Output format for generated documentation."""

    MARKDOWN = "markdown"
    PLAIN_TEXT = "plain_text"


@dataclass
class FunctionContext:
    """Context information about a function."""

    function_address: int
    function_name: str = ""
    entity_id: str = ""
    artifact_id: str = ""
    called_functions: list[dict[str, Any]] = field(default_factory=list)
    calling_functions: list[dict[str, Any]] = field(default_factory=list)
    string_references: list[dict[str, Any]] = field(default_factory=list)
    data_access_patterns: list[dict[str, Any]] = field(default_factory=list)
    disassembly: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DocumentationTemplate:
    """Generated documentation template for a function."""

    function_address: int
    function_name: str
    purpose: str = ""
    description: str = ""
    parameters: list[dict[str, Any]] = field(default_factory=list)
    return_values: list[dict[str, Any]] = field(default_factory=list)
    side_effects: list[str] = field(default_factory=list)
    related_functions: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_markdown(self) -> str:
        """Convert documentation to Markdown format."""
        lines = [
            f"## {self.function_name}",
            f"",
            f"**Address:** `0x{self.function_address:04X}`",
            f"",
        ]

        if self.purpose:
            lines.extend([f"### Purpose", f"", f"{self.purpose}", f""])

        if self.description:
            lines.extend([f"### Description", f"", f"{self.description}", f""])

        if self.parameters:
            lines.extend([f"### Parameters", f""])
            for param in self.parameters:
                name = param.get("name", "unknown")
                ptype = param.get("type", "unknown")
                desc = param.get("description", "")
                lines.append(f"- **{name}** (`{ptype}`): {desc}")
            lines.append("")

        if self.return_values:
            lines.extend([f"### Return Values", f""])
            for ret in self.return_values:
                rtype = ret.get("type", "unknown")
                desc = ret.get("description", "")
                lines.append(f"- (`{rtype}`): {desc}")
            lines.append("")

        if self.side_effects:
            lines.extend([f"### Side Effects", f""])
            for effect in self.side_effects:
                lines.append(f"- {effect}")
            lines.append("")

        if self.related_functions:
            lines.extend([f"### Related Functions", f""])
            for func in self.related_functions:
                name = func.get("name", "unknown")
                addr = func.get("address", 0)
                rel = func.get("relationship", "related")
                lines.append(f"- `{name}` (0x{addr:04X}) - {rel}")
            lines.append("")

        if self.notes:
            lines.extend([f"### Notes", f""])
            for note in self.notes:
                lines.append(f"- {note}")
            lines.append("")

        lines.append(f"*Documentation confidence: {self.confidence:.0%}*")
        lines.append("")

        return "\n".join(lines)

    def to_plain_text(self) -> str:
        """Convert documentation to plain text format."""
        lines = [
            f"Function: {self.function_name}",
            f"Address: 0x{self.function_address:04X}",
            f"",
        ]

        if self.purpose:
            lines.extend([f"PURPOSE:", f"  {self.purpose}", f""])

        if self.description:
            lines.extend([f"DESCRIPTION:", f"  {self.description}", f""])

        if self.parameters:
            lines.extend([f"PARAMETERS:"])
            for param in self.parameters:
                name = param.get("name", "unknown")
                ptype = param.get("type", "unknown")
                desc = param.get("description", "")
                lines.append(f"  - {name} ({ptype}): {desc}")
            lines.append("")

        if self.return_values:
            lines.extend([f"RETURN VALUES:"])
            for ret in self.return_values:
                rtype = ret.get("type", "unknown")
                desc = ret.get("description", "")
                lines.append(f"  - ({rtype}): {desc}")
            lines.append("")

        if self.side_effects:
            lines.extend([f"SIDE EFFECTS:"])
            for effect in self.side_effects:
                lines.append(f"  - {effect}")
            lines.append("")

        if self.related_functions:
            lines.extend([f"RELATED FUNCTIONS:"])
            for func in self.related_functions:
                name = func.get("name", "unknown")
                addr = func.get("address", 0)
                rel = func.get("relationship", "related")
                lines.append(f"  - {name} (0x{addr:04X}) - {rel}")
            lines.append("")

        if self.notes:
            lines.extend([f"NOTES:"])
            for note in self.notes:
                lines.append(f"  - {note}")
            lines.append("")

        lines.append(f"Confidence: {self.confidence:.0%}")
        lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert documentation to dictionary format."""
        return {
            "function_address": self.function_address,
            "function_name": self.function_name,
            "purpose": self.purpose,
            "description": self.description,
            "parameters": self.parameters,
            "return_values": self.return_values,
            "side_effects": self.side_effects,
            "related_functions": self.related_functions,
            "notes": self.notes,
            "confidence": self.confidence,
        }


class FunctionDocumenter:
    """Generate documentation for functions using LLM patterns.

    Analyzes function context including:
    - Called functions (what it uses)
    - Calling functions (what uses it)
    - String references
    - Data access patterns

    Generates documentation templates with:
    - Function purpose/behavior
    - Input parameters (if detectable)
    - Return values (if detectable)
    - Side effects
    - Related functions
    """

    def __init__(self, store: ReverseEngineeringStore):
        self.store = store

    def analyze_function(self, function_address: int, address_space: str = "") -> FunctionContext:
        """Analyze a function and gather context information.

        Args:
            function_address: The address of the function to analyze.
            address_space: Optional address space filter.

        Returns:
            FunctionContext containing all gathered information.
        """
        context = FunctionContext(function_address=function_address)

        # Find the function entity
        entity = self._find_function_entity(function_address, address_space)
        if entity is None:
            return context

        context.entity_id = entity.get("entity_id", "")
        context.function_name = entity.get("name", f"sub_{function_address:04X}")
        context.artifact_id = entity.get("artifact_id", "")

        # Get evidence (disassembly) for the function
        evidence_list = self.store.get_evidence_for_entity(context.entity_id, limit=100)
        context.evidence = [dict(e.to_dict()) for e in evidence_list]
        context.disassembly = [e.excerpt for e in evidence_list if e.excerpt]

        # Get neighbors (call relationships)
        edges = self.store.get_neighbors(context.entity_id, limit=100)

        for edge in edges:
            edge_dict = edge.to_dict()
            edge_kind = edge_dict.get("kind", "")

            if edge_kind == "calls":
                # This function calls another
                target_entity = self.store.get_entity(edge.target_entity_id)
                if target_entity:
                    target_addr = target_entity.location.start if target_entity.location else 0
                    context.called_functions.append({
                        "name": target_entity.name,
                        "address": target_addr,
                        "entity_id": target_entity.entity_id,
                    })
            elif edge_kind == "called_by":
                # This function is called by another
                source_entity = self.store.get_entity(edge.source_entity_id)
                if source_entity:
                    source_addr = source_entity.location.start if source_entity.location else 0
                    context.calling_functions.append({
                        "name": source_entity.name,
                        "address": source_addr,
                        "entity_id": source_entity.entity_id,
                    })
            elif edge_kind == "references_string":
                # String reference
                target_entity = self.store.get_entity(edge.target_entity_id)
                if target_entity:
                    context.string_references.append({
                        "text": target_entity.attributes.get("full_text", target_entity.name),
                        "address": target_entity.location.start if target_entity.location else 0,
                        "entity_id": target_entity.entity_id,
                    })
            elif edge_kind in ("reads", "writes"):
                # Data access pattern
                target_entity = self.store.get_entity(edge.target_entity_id)
                if target_entity:
                    context.data_access_patterns.append({
                        "access_type": edge_kind,
                        "name": target_entity.name,
                        "address": target_entity.location.start if target_entity.location else 0,
                        "entity_id": target_entity.entity_id,
                    })

        # Also check edges where this function is the source
        for edge in edges:
            if edge.source_entity_id == context.entity_id and edge.kind == "calls":
                target_entity = self.store.get_entity(edge.target_entity_id)
                if target_entity:
                    # Check if already added
                    if not any(f["entity_id"] == target_entity.entity_id for f in context.called_functions):
                        target_addr = target_entity.location.start if target_entity.location else 0
                        context.called_functions.append({
                            "name": target_entity.name,
                            "address": target_addr,
                            "entity_id": target_entity.entity_id,
                        })

        return context

    def generate_documentation(
        self,
        function_address: int,
        context_hint: str = "",
        address_space: str = "",
        output_format: OutputFormat = OutputFormat.MARKDOWN,
    ) -> DocumentationTemplate:
        """Generate documentation for a function.

        Args:
            function_address: The address of the function to document.
            context_hint: Optional hint about the function's purpose.
            address_space: Optional address space filter.
            output_format: Output format for the documentation.

        Returns:
            DocumentationTemplate with generated documentation.
        """
        context = self.analyze_function(function_address, address_space)

        doc = DocumentationTemplate(
            function_address=function_address,
            function_name=context.function_name or f"sub_{function_address:04X}",
        )

        # Analyze disassembly for patterns
        self._analyze_disassembly(doc, context)

        # Analyze call relationships
        self._analyze_call_relationships(doc, context)

        # Analyze string references for hints
        self._analyze_string_references(doc, context)

        # Analyze data access patterns
        self._analyze_data_access(doc, context)

        # Apply context hint if provided
        if context_hint:
            doc.notes.append(f"Context hint: {context_hint}")

        # Calculate confidence based on available information
        doc.confidence = self._calculate_confidence(doc, context)

        return doc

    def _find_function_entity(self, function_address: int, address_space: str = "") -> dict[str, Any] | None:
        """Find a function entity by address."""
        entities = self.store.list_entities(kind="function", limit=10000)
        for entity in entities:
            if entity.location and entity.location.start == function_address:
                if not address_space or entity.location.address_space == address_space:
                    return dict(entity.to_dict())
        return None

    def _analyze_disassembly(self, doc: DocumentationTemplate, context: FunctionContext) -> None:
        """Analyze disassembly for patterns."""
        if not context.disassembly:
            return

        # Look for common patterns
        instructions = " ".join(context.disassembly)

        # Check for stack frame setup
        if any("PHA" in line or "PHX" in line or "PHY" in line for line in context.disassembly):
            doc.notes.append("Preserves registers (pushes to stack)")

        if any("PLA" in line or "PLX" in line or "PLY" in line for line in context.disassembly):
            doc.notes.append("Restores registers (pops from stack)")

        # Check for return patterns
        return_count = sum(1 for line in context.disassembly if "RTS" in line or "RTL" in line)
        if return_count > 1:
            doc.notes.append(f"Multiple return paths ({return_count} return instructions)")

        # Check for branching (conditional logic)
        branch_count = sum(
            1 for line in context.disassembly
            if any(b in line for b in ["BNE", "BEQ", "BCC", "BCS", "BMI", "BPL", "BVC", "BVS"])
        )
        if branch_count > 0:
            doc.notes.append(f"Contains conditional logic ({branch_count} branches)")

        # Check for loops
        loop_count = sum(
            1 for line in context.disassembly
            if any(b in line for b in ["BRA", "JMP"])
        )
        if loop_count > 0:
            doc.notes.append(f"Contains jump/loop instructions ({loop_count})")

        # Look for memory access patterns
        if "LDA" in instructions or "LDX" in instructions or "LDY" in instructions:
            doc.notes.append("Reads from memory")
        if "STA" in instructions or "STX" in instructions or "STY" in instructions:
            doc.notes.append("Writes to memory")

        # Infer purpose from instruction mix
        if "JSR" in instructions or "JSL" in instructions:
            doc.purpose = "Calls subroutines/functions"
        elif "RTI" in instructions:
            doc.purpose = "Interrupt handler"
        elif "WAI" in instructions or "STP" in instructions:
            doc.purpose = "Power/state management"
        else:
            doc.purpose = "General computation"

    def _analyze_call_relationships(self, doc: DocumentationTemplate, context: FunctionContext) -> None:
        """Analyze call relationships."""
        # Add called functions as related
        for func in context.called_functions[:10]:  # Limit to 10
            doc.related_functions.append({
                "name": func["name"],
                "address": func["address"],
                "relationship": "calls",
            })

        # Add calling functions as related
        for func in context.calling_functions[:10]:  # Limit to 10
            doc.related_functions.append({
                "name": func["name"],
                "address": func["address"],
                "relationship": "called_by",
            })

        # Infer purpose from called functions
        if context.called_functions:
            called_names = [f["name"].lower() for f in context.called_functions]
            if any("print" in n or "draw" in n or "render" in n for n in called_names):
                doc.purpose = "Graphics/rendering function"
            elif any("read" in n or "load" in n or "get" in n for n in called_names):
                doc.purpose = "Data loading/reading function"
            elif any("write" in n or "store" in n or "set" in n for n in called_names):
                doc.purpose = "Data writing/storing function"
            elif any("init" in n or "setup" in n or "configure" in n for n in called_names):
                doc.purpose = "Initialization/configuration function"
            elif any("process" in n or "handle" in n or "update" in n for n in called_names):
                doc.purpose = "Processing/update function"

    def _analyze_string_references(self, doc: DocumentationTemplate, context: FunctionContext) -> None:
        """Analyze string references for hints."""
        if not context.string_references:
            return

        # Add string references as notes
        for ref in context.string_references[:5]:  # Limit to 5
            text = ref.get("text", "")
            if text:
                doc.notes.append(f"References string: \"{text[:50]}...\"" if len(text) > 50 else f"References string: \"{text}\"")

        # Try to infer purpose from strings
        all_text = " ".join([ref.get("text", "").lower() for ref in context.string_references])

        if any(kw in all_text for kw in ["error", "fail", "invalid", "wrong"]):
            doc.purpose = "Error handling/validation function"
        elif any(kw in all_text for kw in ["menu", "select", "option", "choice"]):
            doc.purpose = "Menu/selection handling"
        elif any(kw in all_text for kw in ["save", "load", "file", "data"]):
            doc.purpose = "File/data management function"
        elif any(kw in all_text for kw in ["music", "sound", "audio", "sfx"]):
            doc.purpose = "Audio/music control function"
        elif any(kw in all_text for kw in ["player", "enemy", "character", "sprite"]):
            doc.purpose = "Game entity management function"

    def _analyze_data_access(self, doc: DocumentationTemplate, context: FunctionContext) -> None:
        """Analyze data access patterns."""
        if not context.data_access_patterns:
            return

        reads = [p for p in context.data_access_patterns if p.get("access_type") == "reads"]
        writes = [p for p in context.data_access_patterns if p.get("access_type") == "writes"]

        if reads:
            doc.notes.append(f"Reads from {len(reads)} data location(s)")
        if writes:
            doc.notes.append(f"Writes to {len(writes)} data location(s)")

        # Add side effects for writes
        for write in writes[:3]:
            name = write.get("name", "unknown")
            doc.side_effects.append(f"Modifies {name}")

    def _calculate_confidence(self, doc: DocumentationTemplate, context: FunctionContext) -> float:
        """Calculate confidence score based on available information."""
        score = 0.0
        max_score = 10.0

        # Base score for having the function
        if context.entity_id:
            score += 1.0

        # Score for disassembly
        if context.disassembly:
            score += 2.0

        # Score for call relationships
        if context.called_functions:
            score += 1.5
        if context.calling_functions:
            score += 1.5

        # Score for string references
        if context.string_references:
            score += 2.0

        # Score for data access patterns
        if context.data_access_patterns:
            score += 1.0

        # Score for having inferred purpose
        if doc.purpose and doc.purpose != "General computation":
            score += 1.0

        return min(score / max_score, 1.0)

    def format_output(
        self,
        doc: DocumentationTemplate,
        output_format: OutputFormat = OutputFormat.MARKDOWN,
    ) -> str:
        """Format documentation to the specified output format.

        Args:
            doc: The documentation template to format.
            output_format: The desired output format.

        Returns:
            Formatted documentation string.
        """
        if output_format == OutputFormat.MARKDOWN:
            return doc.to_markdown()
        else:
            return doc.to_plain_text()
