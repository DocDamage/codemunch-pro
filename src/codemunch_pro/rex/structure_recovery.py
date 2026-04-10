"""Data structure recovery and inference from access patterns.

This module provides heuristics to infer data structure layouts from
binary analysis data, including pointer detection, array detection,
string field detection, and nested structure detection.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field as dataclass_field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore


class FieldType(Enum):
    """Types of structure fields that can be inferred."""
    UNKNOWN = auto()
    POINTER = auto()
    ARRAY = auto()
    STRING = auto()
    INTEGER = auto()
    FLOAT = auto()
    STRUCT = auto()  # Nested structure
    BOOL = auto()
    ENUM = auto()


class HeuristicStrategy(Enum):
    """Heuristic strategies for structure inference."""
    CONSERVATIVE = auto()  # High confidence only
    BALANCED = auto()      # Moderate confidence
    AGGRESSIVE = auto()    # Include low confidence guesses


@dataclass
class StructureField:
    """Represents an inferred field in a data structure.
    
    Attributes:
        offset: Byte offset within the structure
        field_type: Inferred type of the field
        size: Size of the field in bytes
        name: Inferred or assigned field name
        confidence: Confidence score (0.0-1.0)
        element_count: For arrays, number of elements
        element_size: For arrays, size of each element
        target_address: For pointers, the pointed-to address if known
        string_encoding: For strings, the detected encoding
        nested_fields: For nested structures, child fields
        attributes: Additional metadata from analysis
    """
    offset: int
    field_type: FieldType = FieldType.UNKNOWN
    size: int = 0
    name: str = ""
    confidence: float = 0.0
    element_count: int = 1
    element_size: int = 0
    target_address: int | None = None
    string_encoding: str = ""
    nested_fields: list[StructureField] = dataclass_field(default_factory=list)
    attributes: dict[str, Any] = dataclass_field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "offset": self.offset,
            "field_type": self.field_type.name.lower(),
            "size": self.size,
            "name": self.name,
            "confidence": round(self.confidence, 3),
            "element_count": self.element_count,
            "element_size": self.element_size,
            "target_address": f"0x{self.target_address:08X}" if self.target_address else None,
            "string_encoding": self.string_encoding,
            "nested_fields": [f.to_dict() for f in self.nested_fields],
            "attributes": self.attributes,
        }


@dataclass
class DataStructure:
    """Represents an inferred data structure.
    
    Attributes:
        name: Structure name or identifier
        address: Memory address where the structure is located
        size: Total size of the structure in bytes
        fields: List of inferred fields
        address_space: Address space identifier
        confidence: Overall confidence score
        alignment: Detected alignment requirement
        attributes: Additional metadata
    """
    name: str = ""
    address: int = 0
    size: int = 0
    fields: list[StructureField] = dataclass_field(default_factory=list)
    address_space: str = "flat"
    confidence: float = 0.0
    alignment: int = 1
    attributes: dict[str, Any] = dataclass_field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "address": f"0x{self.address:08X}",
            "size": self.size,
            "field_count": len(self.fields),
            "fields": [f.to_dict() for f in self.fields],
            "address_space": self.address_space,
            "confidence": round(self.confidence, 3),
            "alignment": self.alignment,
            "attributes": self.attributes,
        }
    
    def get_field_at(self, offset: int) -> StructureField | None:
        """Get the field at the specified offset, if any."""
        for field in self.fields:
            if field.offset == offset:
                return field
            # Check if offset is within this field (for nested structures)
            if field.offset < offset < field.offset + field.size:
                if field.nested_fields:
                    return field.get_nested_field_at(offset - field.offset)
        return None
    
    def get_nested_field_at(self, relative_offset: int) -> StructureField | None:
        """Get a nested field at a relative offset within this structure."""
        for field in self.fields:
            if field.offset == relative_offset:
                return field
            if field.offset < relative_offset < field.offset + field.size:
                if field.nested_fields:
                    return field.get_nested_field_at(relative_offset - field.offset)
        return None


class StructureRecovery:
    """Heuristic-based data structure recovery from binary analysis.
    
    Uses multiple heuristics to infer data structure layouts:
    - Pointer detection: Identifies aligned addresses pointing to valid memory
    - Array detection: Recognizes repeating patterns at regular intervals
    - String detection: Finds null-terminated or length-prefixed strings
    - Nested structure detection: Identifies sub-structures by access patterns
    """
    
    def __init__(self, store: ReverseEngineeringStore | None = None):
        """Initialize the structure recovery analyzer.
        
        Args:
            store: Optional ReverseEngineeringStore for cross-referencing
        """
        self.store = store
        self._pointer_size = 4  # Default 32-bit
        self._min_confidence = 0.5
        self._strategy = HeuristicStrategy.BALANCED
        
        # Strategy-specific thresholds
        self._thresholds = {
            HeuristicStrategy.CONSERVATIVE: {
                "pointer_min_confidence": 0.8,
                "array_min_elements": 4,
                "array_min_confidence": 0.75,
                "string_min_confidence": 0.85,
                "nested_min_accesses": 5,
            },
            HeuristicStrategy.BALANCED: {
                "pointer_min_confidence": 0.6,
                "array_min_elements": 3,
                "array_min_confidence": 0.6,
                "string_min_confidence": 0.7,
                "nested_min_accesses": 3,
            },
            HeuristicStrategy.AGGRESSIVE: {
                "pointer_min_confidence": 0.4,
                "array_min_elements": 2,
                "array_min_confidence": 0.4,
                "string_min_confidence": 0.5,
                "nested_min_accesses": 2,
            },
        }
    
    def set_strategy(self, strategy: HeuristicStrategy | str) -> None:
        """Set the heuristic strategy.
        
        Args:
            strategy: Strategy to use (conservative, balanced, or aggressive)
        """
        if isinstance(strategy, str):
            strategy_map = {
                "conservative": HeuristicStrategy.CONSERVATIVE,
                "balanced": HeuristicStrategy.BALANCED,
                "aggressive": HeuristicStrategy.AGGRESSIVE,
            }
            self._strategy = strategy_map.get(strategy.lower(), HeuristicStrategy.BALANCED)
        else:
            self._strategy = strategy
        
        self._min_confidence = self._thresholds[self._strategy]["pointer_min_confidence"]
    
    def infer_structure(
        self,
        address: int,
        data: bytes,
        max_size: int | None = None,
        address_space: str = "flat",
        pointer_size: int = 4,
        base_address: int = 0,
    ) -> DataStructure:
        """Infer the structure layout at the given address.
        
        Args:
            address: Starting address of the structure
            data: Binary data to analyze
            max_size: Maximum size to analyze (default: len(data))
            address_space: Address space identifier
            pointer_size: Size of pointers in bytes (4 or 8)
            base_address: Base address of the data buffer
            
        Returns:
            Inferred DataStructure
        """
        self._pointer_size = pointer_size
        
        # If base_address is 0 but address is large, treat data as starting at address
        # This handles the case where data is a buffer extracted from a specific address
        if base_address == 0 and address > 0 and address > len(data):
            base_address = address
        
        if max_size is None:
            max_size = len(data) - (address - base_address)
        
        # Ensure we don't read past data bounds
        offset = address - base_address
        if offset < 0 or offset >= len(data):
            return DataStructure(
                name=f"struct_0x{address:08X}",
                address=address,
                size=0,
                address_space=address_space,
                confidence=0.0,
            )
        
        structure_data = data[offset:offset + max_size]
        actual_size = len(structure_data)
        
        structure = DataStructure(
            name=f"struct_0x{address:08X}",
            address=address,
            size=actual_size,
            address_space=address_space,
        )
        
        # Run heuristics
        fields = []
        
        # 1. Detect pointers
        pointer_fields = self._detect_pointers(structure_data, address, base_address)
        fields.extend(pointer_fields)
        
        # 2. Detect arrays
        array_fields = self._detect_arrays(structure_data, fields)
        fields.extend(array_fields)
        
        # 3. Detect strings
        string_fields = self._detect_strings(structure_data)
        fields.extend(string_fields)
        
        # 4. Detect integers (fill gaps)
        integer_fields = self._detect_integers(structure_data, fields)
        fields.extend(integer_fields)
        
        # 5. Detect nested structures
        nested_fields = self._detect_nested_structures(structure_data, fields, address)
        
        # Merge nested fields with parent
        final_fields = self._merge_fields(fields, nested_fields, actual_size)
        
        # Sort by offset
        final_fields.sort(key=lambda f: f.offset)
        
        structure.fields = final_fields
        structure.alignment = self._detect_alignment(final_fields)
        structure.confidence = self._calculate_overall_confidence(final_fields)
        
        return structure
    
    def _detect_pointers(
        self,
        data: bytes,
        structure_address: int,
        base_address: int,
    ) -> list[StructureField]:
        """Detect pointer fields in the data.
        
        Looks for values that could be valid addresses (aligned and within
        reasonable range of the structure).
        
        Args:
            data: Binary data to analyze
            structure_address: Address of the structure
            base_address: Base address of the data buffer
            
        Returns:
            List of detected pointer fields
        """
        fields = []
        thresholds = self._thresholds[self._strategy]
        
        # Define reasonable address ranges (architecture dependent)
        min_valid_addr = 0x1000  # Skip null page
        max_valid_addr = 0xFFFFFFFF if self._pointer_size == 4 else 0xFFFFFFFFFFFFFFFF
        
        for offset in range(0, len(data) - self._pointer_size + 1, self._pointer_size):
            # Check alignment
            if offset % self._pointer_size != 0:
                continue
            
            # Read value
            value_bytes = data[offset:offset + self._pointer_size]
            if self._pointer_size == 4:
                value = struct.unpack("<I", value_bytes)[0]
            else:
                value = struct.unpack("<Q", value_bytes)[0]
            
            # Skip null pointers
            if value == 0:
                continue
            
            # Check if value looks like a valid address
            if not (min_valid_addr <= value <= max_valid_addr):
                continue
            
            # Calculate confidence based on alignment and range
            confidence = 0.5
            
            # Higher confidence for aligned targets
            if value % self._pointer_size == 0:
                confidence += 0.2
            
            # Higher confidence for addresses in common ranges
            if 0x08000000 <= value <= 0xFFFFFFFF or 0x00000000 <= value <= 0x00FFFFFF:
                confidence += 0.1
            
            # Check if we have store data for this address
            if self.store and confidence >= thresholds["pointer_min_confidence"]:
                # Could verify against store here
                pass
            
            if confidence >= thresholds["pointer_min_confidence"]:
                field = StructureField(
                    offset=offset,
                    field_type=FieldType.POINTER,
                    size=self._pointer_size,
                    name=f"ptr_{offset:02X}",
                    confidence=confidence,
                    target_address=value,
                    attributes={"raw_value": f"0x{value:08X}"},
                )
                fields.append(field)
        
        return fields
    
    def _detect_arrays(
        self,
        data: bytes,
        existing_fields: list[StructureField],
    ) -> list[StructureField]:
        """Detect array fields by finding repeating patterns.
        
        Args:
            data: Binary data to analyze
            existing_fields: Fields already detected (to avoid overlap)
            
        Returns:
            List of detected array fields
        """
        fields = []
        thresholds = self._thresholds[self._strategy]
        min_elements = thresholds["array_min_elements"]
        min_confidence = thresholds["array_min_confidence"]
        
        # Track which offsets are already covered
        covered = set()
        for field in existing_fields:
            for i in range(field.size):
                covered.add(field.offset + i)
        
        # Try different element sizes
        for element_size in [1, 2, 4, 8]:
            offset = 0
            while offset < len(data) - element_size * min_elements:
                if offset in covered:
                    offset += 1
                    continue
                
                # Look for repeating pattern
                pattern = data[offset:offset + element_size]
                repeats = 1
                check_offset = offset + element_size
                
                while (
                    check_offset + element_size <= len(data)
                    and data[check_offset:check_offset + element_size] == pattern
                    and check_offset not in covered
                ):
                    repeats += 1
                    check_offset += element_size
                
                if repeats >= min_elements:
                    array_size = repeats * element_size
                    
                    # Calculate confidence
                    confidence = min(0.5 + (repeats - min_elements) * 0.1, 0.95)
                    
                    # Lower confidence for single-byte repeats (could be padding)
                    if element_size == 1 and pattern[0] in (0x00, 0xFF):
                        confidence *= 0.7
                    
                    if confidence >= min_confidence:
                        field = StructureField(
                            offset=offset,
                            field_type=FieldType.ARRAY,
                            size=array_size,
                            name=f"array_{offset:02X}",
                            confidence=confidence,
                            element_count=repeats,
                            element_size=element_size,
                            attributes={"pattern": pattern.hex()},
                        )
                        fields.append(field)
                        
                        # Mark as covered
                        for i in range(array_size):
                            covered.add(offset + i)
                        
                        offset += array_size
                    else:
                        offset += 1
                else:
                    offset += 1
        
        return fields
    
    def _detect_strings(self, data: bytes) -> list[StructureField]:
        """Detect string fields in the data.
        
        Looks for null-terminated and length-prefixed strings.
        
        Args:
            data: Binary data to analyze
            
        Returns:
            List of detected string fields
        """
        fields = []
        thresholds = self._thresholds[self._strategy]
        min_confidence = thresholds["string_min_confidence"]
        
        # ASCII printable range
        printable = set(range(0x20, 0x7F))
        printable.add(0x00)  # Null terminator
        printable.add(0x09)  # Tab
        printable.add(0x0A)  # Newline
        printable.add(0x0D)  # Carriage return
        
        offset = 0
        while offset < len(data):
            # Skip non-printable bytes
            if data[offset] not in printable:
                offset += 1
                continue
            
            # Check for null-terminated string
            if data[offset] != 0x00:
                string_start = offset
                while (
                    offset < len(data)
                    and data[offset] in printable
                    and data[offset] != 0x00
                ):
                    offset += 1
                
                string_len = offset - string_start
                
                # Check for null terminator
                if offset < len(data) and data[offset] == 0x00:
                    string_len += 1  # Include null
                    
                    # Calculate confidence based on string content
                    confidence = 0.5
                    string_data = data[string_start:string_start + string_len - 1]
                    
                    # Higher confidence for longer strings
                    if string_len >= 4:
                        confidence += 0.2
                    if string_len >= 8:
                        confidence += 0.1
                    
                    # Higher confidence for strings with spaces (likely text)
                    if b' ' in string_data:
                        confidence += 0.1
                    
                    # Higher confidence for strings starting with uppercase
                    if string_data and chr(string_data[0]).isupper():
                        confidence += 0.05
                    
                    if confidence >= min_confidence:
                        # Try to decode
                        encoding = "ascii"
                        try:
                            text = string_data.decode("ascii")
                        except UnicodeDecodeError:
                            try:
                                text = string_data.decode("utf-8")
                                encoding = "utf-8"
                            except UnicodeDecodeError:
                                text = string_data.decode("latin-1", errors="replace")
                                encoding = "latin-1"
                        
                        field = StructureField(
                            offset=string_start,
                            field_type=FieldType.STRING,
                            size=string_len,
                            name=f"str_{string_start:02X}",
                            confidence=confidence,
                            string_encoding=encoding,
                            attributes={"text": text[:50]},  # Truncate long strings
                        )
                        fields.append(field)
                        
                        offset += 1  # Skip null terminator
                else:
                    offset += 1
            else:
                offset += 1
        
        return fields
    
    def _detect_integers(
        self,
        data: bytes,
        existing_fields: list[StructureField],
    ) -> list[StructureField]:
        """Detect integer fields in gaps between other fields.
        
        Args:
            data: Binary data to analyze
            existing_fields: Fields already detected
            
        Returns:
            List of detected integer fields
        """
        fields = []
        
        # Find gaps
        covered_ranges = []
        for field in existing_fields:
            covered_ranges.append((field.offset, field.offset + field.size))
        covered_ranges.sort()
        
        # Merge overlapping ranges
        merged_ranges = []
        for start, end in covered_ranges:
            if merged_ranges and start <= merged_ranges[-1][1]:
                merged_ranges[-1] = (merged_ranges[-1][0], max(merged_ranges[-1][1], end))
            else:
                merged_ranges.append((start, end))
        
        # Fill gaps with integers
        current = 0
        for start, end in merged_ranges:
            if current < start:
                gap_size = start - current
                
                # Determine integer size based on gap and alignment
                if gap_size >= 8 and current % 8 == 0:
                    sizes = [8, 4, 2, 1]
                elif gap_size >= 4 and current % 4 == 0:
                    sizes = [4, 2, 1]
                elif gap_size >= 2 and current % 2 == 0:
                    sizes = [2, 1]
                else:
                    sizes = [1]
                
                offset = current
                remaining = gap_size
                
                for size in sizes:
                    while remaining >= size and offset % size == 0:
                        # Read value for analysis
                        value_bytes = data[offset:offset + size]
                        if size == 1:
                            value = value_bytes[0]
                        elif size == 2:
                            value = struct.unpack("<H", value_bytes)[0]
                        elif size == 4:
                            value = struct.unpack("<I", value_bytes)[0]
                        else:
                            value = struct.unpack("<Q", value_bytes)[0]
                        
                        # Determine if it looks like a boolean
                        if size == 1 and value in (0, 1):
                            field_type = FieldType.BOOL
                            name = f"bool_{offset:02X}"
                            confidence = 0.6
                        else:
                            field_type = FieldType.INTEGER
                            name = f"int{size*8}_{offset:02X}"
                            confidence = 0.4
                        
                        field = StructureField(
                            offset=offset,
                            field_type=field_type,
                            size=size,
                            name=name,
                            confidence=confidence,
                            attributes={"value": value},
                        )
                        fields.append(field)
                        
                        offset += size
                        remaining -= size
            
            current = max(current, end)
        
        # Handle trailing gap
        if current < len(data):
            gap_size = len(data) - current
            if gap_size >= 4 and current % 4 == 0:
                size = 4
            elif gap_size >= 2 and current % 2 == 0:
                size = 2
            else:
                size = 1
            
            while current + size <= len(data):
                field = StructureField(
                    offset=current,
                    field_type=FieldType.INTEGER,
                    size=size,
                    name=f"int{size*8}_{current:02X}",
                    confidence=0.3,
                )
                fields.append(field)
                current += size
        
        return fields
    
    def _detect_nested_structures(
        self,
        data: bytes,
        existing_fields: list[StructureField],
        parent_address: int,
    ) -> list[StructureField]:
        """Detect nested structures by analyzing access patterns.
        
        Args:
            data: Binary data to analyze
            existing_fields: Fields already detected
            parent_address: Address of the parent structure
            
        Returns:
            List of detected nested structure fields
        """
        fields = []
        thresholds = self._thresholds[self._strategy]
        min_accesses = thresholds["nested_min_accesses"]
        
        if not self.store:
            return fields
        
        # Look for regions with dense access patterns
        # This is a simplified heuristic - real implementation would use
        # actual access pattern data from the store
        
        # Group existing fields by proximity
        if len(existing_fields) < min_accesses:
            return fields
        
        # Sort fields by offset
        sorted_fields = sorted(existing_fields, key=lambda f: f.offset)
        
        # Look for clusters of fields that might form a substructure
        cluster_start = 0
        cluster_size = 0
        cluster_fields = []
        
        for i, field in enumerate(sorted_fields):
            if not cluster_fields:
                cluster_start = field.offset
                cluster_size = field.size
                cluster_fields = [field]
            elif field.offset - (cluster_start + cluster_size) <= 4:
                # Field is close enough to be part of cluster
                cluster_size = field.offset + field.size - cluster_start
                cluster_fields.append(field)
            else:
                # Gap too large, evaluate current cluster
                if len(cluster_fields) >= min_accesses and cluster_size >= 8:
                    # This could be a nested structure
                    nested = StructureField(
                        offset=cluster_start,
                        field_type=FieldType.STRUCT,
                        size=cluster_size,
                        name=f"nested_{cluster_start:02X}",
                        confidence=0.5 + min(len(cluster_fields) * 0.05, 0.3),
                        nested_fields=[
                            StructureField(
                                offset=f.offset - cluster_start,
                                field_type=f.field_type,
                                size=f.size,
                                name=f.name,
                                confidence=f.confidence,
                            )
                            for f in cluster_fields
                        ],
                    )
                    fields.append(nested)
                
                # Start new cluster
                cluster_start = field.offset
                cluster_size = field.size
                cluster_fields = [field]
        
        # Handle last cluster
        if len(cluster_fields) >= min_accesses and cluster_size >= 8:
            nested = StructureField(
                offset=cluster_start,
                field_type=FieldType.STRUCT,
                size=cluster_size,
                name=f"nested_{cluster_start:02X}",
                confidence=0.5 + min(len(cluster_fields) * 0.05, 0.3),
                nested_fields=[
                    StructureField(
                        offset=f.offset - cluster_start,
                        field_type=f.field_type,
                        size=f.size,
                        name=f.name,
                        confidence=f.confidence,
                    )
                    for f in cluster_fields
                ],
            )
            fields.append(nested)
        
        return fields
    
    def _merge_fields(
        self,
        primary: list[StructureField],
        nested: list[StructureField],
        max_size: int,
    ) -> list[StructureField]:
        """Merge nested structures with primary fields.
        
        Args:
            primary: Primary detected fields
            nested: Nested structure candidates
            max_size: Maximum structure size
            
        Returns:
            Merged field list
        """
        # Create a map of covered offsets
        covered = set()
        for field in primary:
            for i in range(field.size):
                if field.offset + i < max_size:
                    covered.add(field.offset + i)
        
        # Add nested structures that don't overlap with existing fields
        result = list(primary)
        
        for nested_field in nested:
            # Check if this nested field's range is covered
            nested_covered = all(
                nested_field.offset + i in covered
                for i in range(nested_field.size)
            )
            
            if nested_covered:
                # Replace the individual fields with the nested structure
                # Remove fields that are now part of the nested structure
                result = [
                    f for f in result
                    if not (nested_field.offset <= f.offset < nested_field.offset + nested_field.size)
                ]
                result.append(nested_field)
                
                # Update covered set
                for i in range(nested_field.offset, nested_field.offset + nested_field.size):
                    covered.add(i)
        
        return result
    
    def _detect_alignment(self, fields: list[StructureField]) -> int:
        """Detect the alignment requirement from field offsets.
        
        Args:
            fields: Detected fields
            
        Returns:
            Detected alignment (1, 2, 4, or 8)
        """
        if not fields:
            return 1
        
        # Check offsets for alignment patterns
        alignments = [1, 2, 4, 8]
        for alignment in reversed(alignments):
            if all(f.offset % alignment == 0 for f in fields):
                return alignment
        
        return 1
    
    def _calculate_overall_confidence(self, fields: list[StructureField]) -> float:
        """Calculate overall structure confidence from field confidences.
        
        Args:
            fields: Detected fields
            
        Returns:
            Overall confidence score
        """
        if not fields:
            return 0.0
        
        # Weight by field size
        total_size = sum(f.size for f in fields)
        if total_size == 0:
            return 0.0
        
        weighted_confidence = sum(
            f.confidence * f.size for f in fields
        ) / total_size
        
        return round(weighted_confidence, 3)


def infer_structure_from_access_patterns(
    store: ReverseEngineeringStore,
    address: int,
    max_size: int = 256,
    heuristic: str = "balanced",
) -> dict[str, Any]:
    """High-level function to infer a structure from access patterns.
    
    Args:
        store: ReverseEngineeringStore with analysis data
        address: Starting address of the structure
        max_size: Maximum size to analyze
        heuristic: Heuristic strategy ("conservative", "balanced", "aggressive")
        
    Returns:
        Dictionary with inferred structure information
    """
    recovery = StructureRecovery(store)
    recovery.set_strategy(heuristic)
    
    # Get data from store if available
    # For now, we'll create a dummy data buffer
    # In a real implementation, this would fetch from the store
    data = bytes(max_size)
    
    structure = recovery.infer_structure(
        address=address,
        data=data,
        max_size=max_size,
    )
    
    return structure.to_dict()
