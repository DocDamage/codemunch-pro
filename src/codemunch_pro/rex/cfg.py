"""Control Flow Graph (CFG) generation for reverse-engineering analysis.

This module provides classes for building, analyzing, and exporting Control Flow Graphs
for functions and code regions. Supports multiple export formats including DOT, GraphML,
and JSON.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from codemunch_pro.rex.model import AddressLocation, EntityRecord, EdgeRecord


@dataclass
class Instruction:
    """A single instruction within a basic block."""

    address: int
    opcode: str = ""
    operands: str = ""
    bytes_hex: str = ""
    comment: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize instruction to dictionary."""
        return {
            "address": self.address,
            "opcode": self.opcode,
            "operands": self.operands,
            "bytes": self.bytes_hex,
            "comment": self.comment,
        }


@dataclass
class BasicBlock:
    """A basic block in a Control Flow Graph.
    
    A basic block is a sequence of instructions with a single entry point
    and a single exit point (no branches except at the end).
    """

    start_addr: int
    end_addr: int = 0
    instructions: list[Instruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.end_addr == 0:
            self.end_addr = self.start_addr

    @property
    def size(self) -> int:
        """Return the size of the basic block in bytes."""
        return self.end_addr - self.start_addr + 1

    def add_instruction(self, instruction: Instruction) -> None:
        """Add an instruction to this basic block."""
        self.instructions.append(instruction)
        self.end_addr = max(self.end_addr, instruction.address)

    def add_successor(self, addr: int) -> None:
        """Add a successor block address."""
        if addr not in self.successors:
            self.successors.append(addr)

    def add_predecessor(self, addr: int) -> None:
        """Add a predecessor block address."""
        if addr not in self.predecessors:
            self.predecessors.append(addr)

    def contains(self, address: int) -> bool:
        """Check if the given address is within this block."""
        return self.start_addr <= address <= self.end_addr

    def to_dict(self) -> dict[str, Any]:
        """Serialize basic block to dictionary."""
        return {
            "start_addr": self.start_addr,
            "end_addr": self.end_addr,
            "size": self.size,
            "instructions": [instr.to_dict() for instr in self.instructions],
            "successors": self.successors,
            "predecessors": self.predecessors,
            "attributes": dict(self.attributes),
        }


class ControlFlowGraph:
    """A Control Flow Graph representing function control flow.
    
    The CFG consists of basic blocks and edges between them, representing
    the possible execution paths through a function or code region.
    """

    def __init__(self, name: str = "", entry_addr: int = 0):
        self.name = name
        self.entry_addr = entry_addr
        self.blocks: dict[int, BasicBlock] = {}
        self.edges: list[tuple[int, int, str]] = []  # (from_addr, to_addr, edge_type)
        self.attributes: dict[str, Any] = {}

    def add_block(self, block: BasicBlock) -> BasicBlock:
        """Add a basic block to the CFG."""
        self.blocks[block.start_addr] = block
        return block

    def get_block(self, addr: int) -> BasicBlock | None:
        """Get a basic block by its start address."""
        return self.blocks.get(addr)

    def find_block_containing(self, addr: int) -> BasicBlock | None:
        """Find the basic block containing the given address."""
        for block in self.blocks.values():
            if block.contains(addr):
                return block
        return None

    def add_edge(self, from_addr: int, to_addr: int, edge_type: str = "") -> None:
        """Add an edge between two basic blocks."""
        edge = (from_addr, to_addr, edge_type)
        if edge not in self.edges:
            self.edges.append(edge)
        
        # Update successor/predecessor relationships
        from_block = self.blocks.get(from_addr)
        to_block = self.blocks.get(to_addr)
        if from_block:
            from_block.add_successor(to_addr)
        if to_block:
            to_block.add_predecessor(from_addr)

    def traverse(
        self, 
        start_addr: int | None = None, 
        depth: int = 1,
        include_callees: bool = False,
    ) -> ControlFlowGraph:
        """Create a subgraph with depth-limited traversal.
        
        Args:
            start_addr: Address to start traversal from (default: entry_addr)
            depth: How many levels to traverse (1 = single function, 2 = with callees)
            include_callees: Whether to include callee functions at depth > 1
            
        Returns:
            A new ControlFlowGraph containing only the traversed portion
        """
        if start_addr is None:
            start_addr = self.entry_addr
            
        result = ControlFlowGraph(name=f"{self.name}_depth{depth}", entry_addr=start_addr)
        visited: set[int] = set()
        queue: list[tuple[int, int]] = [(start_addr, 0)]  # (addr, current_depth)
        
        while queue:
            addr, current_depth = queue.pop(0)
            
            if addr in visited or current_depth > depth:
                continue
            visited.add(addr)
            
            block = self.blocks.get(addr)
            if block:
                # Copy block to result
                new_block = BasicBlock(
                    start_addr=block.start_addr,
                    end_addr=block.end_addr,
                    instructions=list(block.instructions),
                    successors=list(block.successors) if current_depth < depth else [],
                    predecessors=list(block.predecessors),
                    attributes=dict(block.attributes),
                )
                result.add_block(new_block)
                
                # Add edges within traversal depth
                if current_depth < depth:
                    for succ_addr in block.successors:
                        result.add_edge(addr, succ_addr)
                        if succ_addr not in visited:
                            queue.append((succ_addr, current_depth + 1))
        
        return result

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics about the CFG."""
        total_instructions = sum(
            len(block.instructions) for block in self.blocks.values()
        )
        
        # Calculate cyclomatic complexity: E - N + 2P
        # E = edges, N = nodes, P = connected components (assume 1 for single function)
        num_nodes = len(self.blocks)
        num_edges = len(self.edges)
        cyclomatic = num_edges - num_nodes + 2 if num_nodes > 0 else 0
        
        return {
            "name": self.name,
            "entry_addr": self.entry_addr,
            "block_count": num_nodes,
            "edge_count": num_edges,
            "instruction_count": total_instructions,
            "cyclomatic_complexity": max(1, cyclomatic),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize CFG to dictionary."""
        return {
            "name": self.name,
            "entry_addr": self.entry_addr,
            "attributes": dict(self.attributes),
            "statistics": self.get_statistics(),
            "blocks": [block.to_dict() for block in self.blocks.values()],
            "edges": [
                {"from": e[0], "to": e[1], "type": e[2]} 
                for e in self.edges
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Export CFG to JSON format."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_dot(self) -> str:
        """Export CFG to Graphviz DOT format."""
        lines = [f'digraph "{self.name or "CFG"}" {{']
        lines.append('  rankdir=TB;')
        lines.append('  node [shape=box, style=filled, fontname="Helvetica"];')
        lines.append('  edge [fontname="Helvetica", fontsize=10];')
        lines.append('')
        
        # Color scheme for blocks
        entry_color = "#60A5FA"  # blue
        normal_color = "#34D399"  # green
        exit_color = "#F472B6"  # pink
        
        # Add nodes (basic blocks)
        for addr, block in sorted(self.blocks.items()):
            # Determine color based on block type
            if addr == self.entry_addr:
                color = entry_color
            elif not block.successors:
                color = exit_color
            else:
                color = normal_color
            
            # Create label
            label_lines = [f"Block 0x{addr:04X}"]
            if block.instructions:
                for instr in block.instructions[:5]:  # Limit to first 5 instructions
                    label_lines.append(f"  {instr.opcode} {instr.operands}".strip())
                if len(block.instructions) > 5:
                    label_lines.append("  ...")
            
            label = "\\n".join(label_lines)
            node_id = self._dot_id(f"block_{addr}")
            lines.append(
                f'  {node_id} [label="{label}", fillcolor="{color}"];'
            )
        
        lines.append('')
        
        # Add edges
        for from_addr, to_addr, edge_type in self.edges:
            from_id = self._dot_id(f"block_{from_addr}")
            to_id = self._dot_id(f"block_{to_addr}")
            edge_attrs = f' [label="{edge_type}"]' if edge_type else ""
            lines.append(f'  {from_id} -> {to_id}{edge_attrs};')
        
        lines.append('}')
        return "\n".join(lines)

    def to_graphml(self) -> str:
        """Export CFG to GraphML format."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"',
            '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '         xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
        ]
        
        # Define attributes
        lines.extend([
            '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="d1" for="node" attr.name="start_addr" attr.type="int"/>',
            '  <key id="d2" for="node" attr.name="end_addr" attr.type="int"/>',
            '  <key id="d3" for="node" attr.name="instruction_count" attr.type="int"/>',
            '  <key id="d4" for="edge" attr.name="edge_type" attr.type="string"/>',
        ])
        
        lines.append(f'  <graph id="{self.name or "CFG"}" edgedefault="directed">')
        
        # Add nodes
        for addr, block in self.blocks.items():
            node_id = f"n{addr}"
            label = f"Block 0x{addr:04X}"
            lines.append(f'    <node id="{node_id}">')
            lines.append(f'      <data key="d0">{label}</data>')
            lines.append(f'      <data key="d1">{block.start_addr}</data>')
            lines.append(f'      <data key="d2">{block.end_addr}</data>')
            lines.append(f'      <data key="d3">{len(block.instructions)}</data>')
            lines.append('    </node>')
        
        # Add edges
        edge_id = 0
        for from_addr, to_addr, edge_type in self.edges:
            lines.append(
                f'    <edge id="e{edge_id}" source="n{from_addr}" target="n{to_addr}">'
            )
            if edge_type:
                lines.append(f'      <data key="d4">{edge_type}</data>')
            lines.append('    </edge>')
            edge_id += 1
        
        lines.append('  </graph>')
        lines.append('</graphml>')
        
        return "\n".join(lines)

    @staticmethod
    def _dot_id(s: str) -> str:
        """Convert a string to a valid DOT identifier."""
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", s)
        if safe and safe[0].isdigit():
            safe = "n" + safe
        return safe or "node"

    @classmethod
    def from_entity(
        cls, 
        entity: EntityRecord, 
        store: Any | None = None,
    ) -> ControlFlowGraph:
        """Create a CFG from a function entity.
        
        Args:
            entity: The function entity to build CFG from
            store: Optional store to fetch additional information
            
        Returns:
            A ControlFlowGraph populated from the entity
        """
        cfg = cls(name=entity.name, entry_addr=0)
        
        if entity.location:
            cfg.entry_addr = entity.location.start
        
        # Add basic block for the function entry
        block = BasicBlock(start_addr=cfg.entry_addr)
        block.attributes["entity_id"] = entity.entity_id
        block.attributes["entity_kind"] = entity.kind
        cfg.add_block(block)
        
        return cfg


def build_cfg_from_evidence(
    evidence_list: list[Any],
    function_addr: int,
    function_name: str = "",
) -> ControlFlowGraph:
    """Build a CFG from disassembly evidence records.
    
    Args:
        evidence_list: List of evidence records containing disassembly
        function_addr: Starting address of the function
        function_name: Optional name for the function
        
    Returns:
        A ControlFlowGraph built from the evidence
    """
    cfg = ControlFlowGraph(
        name=function_name or f"func_0x{function_addr:04X}",
        entry_addr=function_addr,
    )
    
    # Create initial block at function entry
    entry_block = BasicBlock(start_addr=function_addr)
    cfg.add_block(entry_block)
    
    # Process evidence to extract basic blocks and edges
    # This is a simplified implementation - real disassembly would parse
    # actual instructions and branch targets
    
    for evidence in evidence_list:
        if hasattr(evidence, 'location') and evidence.location:
            addr = evidence.location.start
            # Check if we need to create a new block
            if addr not in cfg.blocks:
                block = BasicBlock(start_addr=addr)
                cfg.add_block(block)
    
    return cfg
