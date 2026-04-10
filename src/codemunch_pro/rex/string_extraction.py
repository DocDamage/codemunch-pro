"""String extraction with cross-reference tracking for binary analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)


class StringType(Enum):
    """Types of string encoding in binary data."""
    NULL_TERMINATED = auto()
    LENGTH_PREFIXED_8 = auto()
    LENGTH_PREFIXED_16 = auto()
    LENGTH_PREFIXED_32 = auto()
    UTF16_LE = auto()
    UTF16_BE = auto()
    RAW = auto()


class StringEncoding(Enum):
    """Supported string encodings."""
    ASCII = "ascii"
    UTF8 = "utf-8"
    SHIFT_JIS = "shift_jis"
    UTF16_LE = "utf-16-le"
    UTF16_BE = "utf-16-be"
    ISO_8859_1 = "iso-8859-1"


@dataclass
class ExtractedString:
    """A string extracted from binary data."""
    address: int
    text: str
    encoding: StringEncoding
    string_type: StringType
    length: int
    raw_bytes: bytes = field(repr=False)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "address": self.address,
            "text": self.text,
            "encoding": self.encoding.value,
            "string_type": self.string_type.name.lower(),
            "length": self.length,
            "raw_bytes_length": len(self.raw_bytes),
        }


@dataclass
class StringXref:
    """A cross-reference to a string from code."""
    string_address: int
    code_address: int
    xref_type: str  # "direct", "pointer_table", "indirect"
    pointer_table_address: int | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result = {
            "string_address": self.string_address,
            "code_address": self.code_address,
            "xref_type": self.xref_type,
        }
        if self.pointer_table_address is not None:
            result["pointer_table_address"] = self.pointer_table_address
        return result


class StringExtractor:
    """Extract strings from binary data with multiple encoding support."""
    
    # Minimum printable ASCII range
    PRINTABLE_MIN = 32
    PRINTABLE_MAX = 126
    
    # Common string prefixes for length-prefixed strings
    PREFIX_LENGTHS = {
        StringType.LENGTH_PREFIXED_8: 1,
        StringType.LENGTH_PREFIXED_16: 2,
        StringType.LENGTH_PREFIXED_32: 4,
    }
    
    def __init__(
        self,
        min_length: int = 4,
        encodings: list[StringEncoding] | None = None,
        auto_detect: bool = True,
    ):
        """Initialize the string extractor.
        
        Args:
            min_length: Minimum string length to extract
            encodings: List of encodings to try (default: all)
            auto_detect: Whether to auto-detect encoding
        """
        self.min_length = min_length
        self.encodings = encodings or list(StringEncoding)
        self.auto_detect = auto_detect
    
    def extract_strings(
        self,
        data: bytes,
        base_address: int = 0,
    ) -> list[ExtractedString]:
        """Extract strings from binary data.
        
        Args:
            data: Binary data to analyze
            base_address: Base address for the data
            
        Returns:
            List of extracted strings
        """
        results: list[ExtractedString] = []
        seen_addresses: set[int] = set()
        
        # Try each encoding
        for encoding in self.encodings:
            if encoding in (StringEncoding.UTF16_LE, StringEncoding.UTF16_BE):
                strings = self._extract_utf16_strings(data, base_address, encoding)
            else:
                strings = self._extract_c_strings(data, base_address, encoding)
            
            for s in strings:
                if s.address not in seen_addresses:
                    seen_addresses.add(s.address)
                    results.append(s)
        
        # Sort by address
        results.sort(key=lambda x: x.address)
        return results
    
    def _is_printable(self, b: int, encoding: StringEncoding) -> bool:
        """Check if a byte is printable for the given encoding."""
        if encoding == StringEncoding.ASCII:
            return self.PRINTABLE_MIN <= b <= self.PRINTABLE_MAX or b in (0x09, 0x0A, 0x0D)
        elif encoding in (StringEncoding.UTF8, StringEncoding.SHIFT_JIS):
            # UTF-8 and Shift-JIS are multi-byte; accept printable ASCII and continuation bytes
            return (
                self.PRINTABLE_MIN <= b <= self.PRINTABLE_MAX
                or b in (0x09, 0x0A, 0x0D)
                or 0x80 <= b <= 0xFF  # Multi-byte sequence component
            )
        else:
            return self.PRINTABLE_MIN <= b <= self.PRINTABLE_MAX or b in (0x09, 0x0A, 0x0D)
    
    def _extract_c_strings(
        self,
        data: bytes,
        base_address: int,
        encoding: StringEncoding,
    ) -> list[ExtractedString]:
        """Extract null-terminated strings (C-style strings)."""
        results: list[ExtractedString] = []
        i = 0
        
        while i < len(data):
            # Skip non-printable bytes
            if not self._is_printable(data[i], encoding):
                i += 1
                continue
            
            # Start of potential string
            start = i
            raw_bytes = bytearray()
            
            # Collect printable bytes
            while i < len(data) and self._is_printable(data[i], encoding):
                raw_bytes.append(data[i])
                i += 1
            
            # Check if followed by null terminator
            if i < len(data) and data[i] == 0:
                raw_bytes.append(0)  # Include null
                
                # Try to decode
                try:
                    text = raw_bytes[:-1].decode(encoding.value, errors="strict")
                    if len(text) >= self.min_length:
                        results.append(ExtractedString(
                            address=base_address + start,
                            text=text,
                            encoding=encoding,
                            string_type=StringType.NULL_TERMINATED,
                            length=len(text),
                            raw_bytes=bytes(raw_bytes),
                        ))
                except UnicodeDecodeError:
                    pass
                
                i += 1  # Skip null terminator
        
        return results
    
    def _extract_utf16_strings(
        self,
        data: bytes,
        base_address: int,
        encoding: StringEncoding,
    ) -> list[ExtractedString]:
        """Extract UTF-16 encoded strings."""
        results: list[ExtractedString] = []
        
        # Determine byte order
        is_le = encoding == StringEncoding.UTF16_LE
        string_type = StringType.UTF16_LE if is_le else StringType.UTF16_BE
        
        i = 0
        while i < len(data) - 1:
            # Check for BOM
            if data[i:i+2] == b'\xff\xfe' and is_le:
                i += 2
                continue
            elif data[i:i+2] == b'\xfe\xff' and not is_le:
                i += 2
                continue
            
            # Try to read a UTF-16 character
            char_bytes = data[i:i+2]
            if len(char_bytes) < 2:
                break
            
            try:
                char = char_bytes.decode(encoding.value, errors="strict")
                # Check if it's printable
                if char.isprintable() or char in '\t\n\r':
                    # Start collecting string
                    start = i
                    text_chars = [char]
                    raw_bytes = bytearray(char_bytes)
                    i += 2
                    
                    # Collect more characters
                    while i < len(data) - 1:
                        char_bytes = data[i:i+2]
                        try:
                            next_char = char_bytes.decode(encoding.value, errors="strict")
                            if next_char.isprintable() or next_char in '\t\n\r':
                                text_chars.append(next_char)
                                raw_bytes.extend(char_bytes)
                                i += 2
                            elif next_char == '\x00':
                                # Null terminator
                                raw_bytes.extend(char_bytes)
                                i += 2
                                break
                            else:
                                break
                        except UnicodeDecodeError:
                            break
                    
                    text = ''.join(text_chars)
                    if len(text) >= self.min_length:
                        results.append(ExtractedString(
                            address=base_address + start,
                            text=text,
                            encoding=encoding,
                            string_type=string_type,
                            length=len(text),
                            raw_bytes=bytes(raw_bytes),
                        ))
                else:
                    i += 2
            except UnicodeDecodeError:
                i += 2
        
        return results
    
    def find_xrefs(
        self,
        data: bytes,
        strings: list[ExtractedString],
        base_address: int = 0,
        pointer_size: int = 4,
        address_range: tuple[int, int] | None = None,
    ) -> list[StringXref]:
        """Find cross-references to strings in the binary data.
        
        Args:
            data: Binary data to search for references
            strings: List of extracted strings to find references for
            base_address: Base address for the data
            pointer_size: Size of pointers (4 for 32-bit, 8 for 64-bit)
            address_range: Optional (start, end) of valid code/data addresses
            
        Returns:
            List of cross-references
        """
        xrefs: list[StringXref] = []
        string_addresses = {s.address for s in strings}
        
        # Determine address range for valid references
        if address_range:
            min_addr, max_addr = address_range
        else:
            min_addr = base_address
            max_addr = base_address + len(data)
        
        for string in strings:
            # Search for direct references (absolute addresses)
            addr_bytes_le = string.address.to_bytes(pointer_size, 'little')
            addr_bytes_be = string.address.to_bytes(pointer_size, 'big')
            
            # Find all occurrences
            for offset in self._find_all(data, addr_bytes_le):
                code_addr = base_address + offset
                if code_addr != string.address:  # Don't count string as its own xref
                    xrefs.append(StringXref(
                        string_address=string.address,
                        code_address=code_addr,
                        xref_type="direct",
                    ))
            
            # Search for big-endian references
            for offset in self._find_all(data, addr_bytes_be):
                code_addr = base_address + offset
                if code_addr != string.address:
                    xrefs.append(StringXref(
                        string_address=string.address,
                        code_address=code_addr,
                        xref_type="direct",
                    ))
            
            # Search for pointer table entries (relative addressing)
            # Common pattern: offset from a base in a pointer table
            if pointer_size == 4:
                # 32-bit relative offsets (common in ARM, etc.)
                rel_offset = string.address - base_address
                rel_bytes = rel_offset.to_bytes(4, 'little', signed=True)
                for offset in self._find_all(data, rel_bytes):
                    # Check if this looks like a pointer table entry
                    if self._is_likely_pointer_table(data, offset, pointer_size):
                        code_addr = base_address + offset
                        xrefs.append(StringXref(
                            string_address=string.address,
                            code_address=code_addr,
                            xref_type="pointer_table",
                            pointer_table_address=code_addr,
                        ))
        
        return xrefs
    
    def _find_all(self, data: bytes, pattern: bytes) -> list[int]:
        """Find all occurrences of a pattern in data."""
        positions: list[int] = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        return positions
    
    def _is_likely_pointer_table(self, data: bytes, offset: int, pointer_size: int) -> bool:
        """Check if offset looks like it's in a pointer table."""
        # Simple heuristic: check if adjacent entries also look like valid offsets
        if offset < pointer_size or offset + pointer_size * 2 > len(data):
            return False
        
        # Check for pattern of consecutive similar values (pointer table signature)
        prev_val = int.from_bytes(data[offset-pointer_size:offset], 'little', signed=True)
        curr_val = int.from_bytes(data[offset:offset+pointer_size], 'little', signed=True)
        next_val = int.from_bytes(data[offset+pointer_size:offset+pointer_size*2], 'little', signed=True)
        
        # In a pointer table, offsets are usually monotonically increasing or clustered
        return abs(curr_val - prev_val) < 0x10000 or abs(next_val - curr_val) < 0x10000


class BinaryStringImporter:
    """Importer for extracting strings from binary files."""
    
    def __init__(
        self,
        min_length: int = 4,
        encodings: list[StringEncoding] | None = None,
        find_xrefs: bool = True,
        pointer_size: int = 4,
    ):
        """Initialize the binary string importer.
        
        Args:
            min_length: Minimum string length to extract
            encodings: List of encodings to try
            find_xrefs: Whether to find cross-references
            pointer_size: Pointer size (4 for 32-bit, 8 for 64-bit)
        """
        self.min_length = min_length
        self.encodings = encodings
        self.find_xrefs = find_xrefs
        self.pointer_size = pointer_size
        self._extractor = StringExtractor(min_length, encodings)
    
    @property
    def name(self) -> str:
        return "binary-strings"
    
    def supports(self, path: Path) -> bool:
        """Check if this importer supports the given file."""
        # Support common binary file extensions
        binary_extensions = {
            '.bin', '.rom', '.iso', '.img', '.exe', '.dll', '.so',
            '.elf', '.prx', '.coff', '.o', '.obj', '.dol', '.rel',
            '.gba', '.nds', '.nes', '.sfc', '.smc', '.z64', '.n64',
            '.psx', '.ps2', '.pbp', '.cso', '.chd',
        }
        return path.suffix.lower() in binary_extensions
    
    def ingest(
        self,
        path: Path,
        base_address: int = 0,
        address_space: str = "flat",
    ) -> ReverseEngineeringBundle:
        """Extract strings from a binary file.
        
        Args:
            path: Path to the binary file
            base_address: Base address for the binary
            address_space: Name of the address space
            
        Returns:
            ReverseEngineeringBundle with strings and xrefs
        """
        data = path.read_bytes()
        
        # Extract strings
        strings = self._extractor.extract_strings(data, base_address)
        
        # Find cross-references if enabled
        xrefs: list[StringXref] = []
        if self.find_xrefs:
            xrefs = self._extractor.find_xrefs(
                data, strings, base_address, self.pointer_size
            )
        
        # Create bundle
        artifact = ArtifactRecord(
            artifact_id=path.as_posix(),
            kind="binary-strings",
            path=path.as_posix(),
        )
        
        entities: list[EntityRecord] = []
        evidence: list[EvidenceRecord] = []
        edges: list[EdgeRecord] = []
        
        # Create entity for each string
        for s in strings:
            entity_id = f"entity:string:{path.as_posix()}:{s.address:08X}"
            location = AddressLocation(
                address_space=address_space,
                start=s.address,
                end=s.address + len(s.raw_bytes) - 1,
                display=f"0x{s.address:08X}",
                attributes={
                    "encoding": s.encoding.value,
                    "string_type": s.string_type.name.lower(),
                    "length": s.length,
                },
            )
            
            entity = EntityRecord(
                entity_id=entity_id,
                kind="string",
                name=s.text[:50] + "..." if len(s.text) > 50 else s.text,
                canonical_ref=f"0x{s.address:08X}",
                artifact_id=artifact.artifact_id,
                location=location,
                attributes={
                    "full_text": s.text,
                    "raw_bytes_length": len(s.raw_bytes),
                },
            )
            entities.append(entity)
            
            # Create evidence for the string
            ev_id = f"evidence:string:{path.as_posix()}:{s.address:08X}"
            ev = EvidenceRecord(
                evidence_id=ev_id,
                kind="string_content",
                artifact_id=artifact.artifact_id,
                entity_ids=(entity_id,),
                excerpt=s.text,
                location=location,
                attributes={
                    "encoding": s.encoding.value,
                    "string_type": s.string_type.name.lower(),
                },
            )
            evidence.append(ev)
        
        # Create edges for cross-references
        for xref in xrefs:
            # Find the source entity (code location)
            source_entity_id = f"entity:code:{path.as_posix()}:{xref.code_address:08X}"
            
            # Find the target entity (string)
            target_entity_id = f"entity:string:{path.as_posix()}:{xref.string_address:08X}"
            
            # Check if target exists
            target_exists = any(e.entity_id == target_entity_id for e in entities)
            if not target_exists:
                continue
            
            edge_id = f"edge:references_string:{source_entity_id}:{target_entity_id}"
            edge = EdgeRecord(
                edge_id=edge_id,
                kind="references_string",
                source_entity_id=source_entity_id,
                target_entity_id=target_entity_id,
                attributes={
                    "xref_type": xref.xref_type,
                    "code_address": xref.code_address,
                    "string_address": xref.string_address,
                },
            )
            edges.append(edge)
        
        return ReverseEngineeringBundle(
            artifacts=[artifact],
            entities=entities,
            evidence=evidence,
            edges=edges,
            metadata={
                "string_count": len(strings),
                "xref_count": len(xrefs),
                "min_length": self.min_length,
                "encodings": [e.value for e in (self.encodings or list(StringEncoding))],
            },
        )


def extract_strings_from_bytes(
    data: bytes,
    base_address: int = 0,
    min_length: int = 4,
    encodings: list[StringEncoding] | None = None,
) -> list[ExtractedString]:
    """Convenience function to extract strings from bytes.
    
    Args:
        data: Binary data to analyze
        base_address: Base address for the data
        min_length: Minimum string length
        encodings: List of encodings to try
        
    Returns:
        List of extracted strings
    """
    extractor = StringExtractor(min_length=min_length, encodings=encodings)
    return extractor.extract_strings(data, base_address)
