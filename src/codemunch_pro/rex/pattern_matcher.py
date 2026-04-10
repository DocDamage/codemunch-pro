"""Byte pattern matching with wildcards for binary data analysis.

This module provides pattern matching capabilities for searching binary data
with support for wildcards, bit masks, and character classes. Useful for
finding sequences in ROMs, memory dumps, and executable files.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable


class Endianness(Enum):
    """Byte order for multi-byte pattern matching."""
    NATIVE = auto()
    BIG = auto()
    LITTLE = auto()

    def to_struct_format(self, size: int) -> str:
        """Convert to struct format character with endianness prefix."""
        endian_prefix = {
            Endianness.NATIVE: "@",
            Endianness.BIG: ">",
            Endianness.LITTLE: "<",
        }[self]
        
        if size == 1:
            return f"{endian_prefix}B"
        elif size == 2:
            return f"{endian_prefix}H"
        elif size == 4:
            return f"{endian_prefix}I"
        elif size == 8:
            return f"{endian_prefix}Q"
        else:
            raise ValueError(f"Unsupported size: {size}")


@dataclass(frozen=True)
class PatternToken:
    """A single token in a byte pattern."""
    value: int | None = None  # None means wildcard
    mask: int = 0xFF  # Bit mask for partial matching (default: match all bits)
    
    def matches(self, byte: int) -> bool:
        """Check if a byte matches this token."""
        if self.value is None:
            return True
        return (byte & self.mask) == (self.value & self.mask)


@dataclass
class BytePattern:
    """A parsed byte pattern for binary searching.
    
    Supports patterns like:
    - "A9 ?? 8D 00 21" - hex bytes with wildcards
    - "A9 ?D 00 21" - wildcard on nibble
    - "A9 8D [01] 21" - character class (bit mask)
    - "LDA $2100" - with named wildcards (not yet implemented)
    
    Whitespace is ignored. Patterns are case-insensitive.
    """
    tokens: list[PatternToken] = field(default_factory=list)
    endianness: Endianness = Endianness.BIG
    raw_pattern: str = ""
    
    # Character class definitions
    DIGIT_CLASS = 0x30  # '0'-'9': 0x30-0x39
    UPPER_CLASS = 0x41  # 'A'-'Z': 0x41-0x5A
    LOWER_CLASS = 0x61  # 'a'-'z': 0x61-0x7A
    ALPHA_CLASS = 0x01  # Custom: any letter
    ALNUM_CLASS = 0x02  # Custom: alphanumeric
    PRINT_CLASS = 0x03  # Custom: printable ASCII
    
    @classmethod
    def parse(
        cls,
        pattern: str,
        endianness: Endianness = Endianness.BIG,
    ) -> "BytePattern":
        """Parse a pattern string into a BytePattern.
        
        Args:
            pattern: Pattern string (e.g., "A9 ?? 8D 00 21")
            endianness: Byte order for multi-byte values (default: BIG)
            
        Returns:
            Parsed BytePattern
            
        Raises:
            ValueError: If pattern is invalid
        """
        tokens: list[PatternToken] = []
        raw_pattern = pattern
        
        # Normalize whitespace
        pattern = pattern.strip().upper()
        
        # Split into tokens
        parts = re.split(r'\s+', pattern)
        
        for part in parts:
            if not part:
                continue
                
            token = cls._parse_token(part)
            tokens.append(token)
        
        return cls(
            tokens=tokens,
            endianness=endianness,
            raw_pattern=raw_pattern,
        )
    
    @classmethod
    def _parse_token(cls, part: str) -> PatternToken:
        """Parse a single pattern token."""
        # Check for character class notation [xx] or [x-x]
        if part.startswith("[") and part.endswith("]"):
            return cls._parse_character_class(part[1:-1])
        
        # Check for double wildcard "??" first (must check before single "?")
        if part == "??" or part == "*":
            return PatternToken(value=None)
        
        # Check for single wildcard "?"
        if part == "?":
            return PatternToken(value=None)
        
        # Check for wildcard on nibble (e.g., "?D" or "A?")
        if "?" in part:
            return cls._parse_nibble_wildcard(part)
        
        # Regular hex byte
        try:
            value = int(part, 16)
            if not 0 <= value <= 255:
                raise ValueError(f"Byte value out of range: {part}")
            return PatternToken(value=value)
        except ValueError:
            raise ValueError(f"Invalid pattern token: {part}")
    
    @classmethod
    def _parse_character_class(cls, content: str) -> PatternToken:
        """Parse character class like [0-9], [A-F], or [01] for bit mask."""
        content = content.strip()
        
        # Check for range like "0-9" or "A-F"
        if "-" in content and len(content) == 3:
            start, end = content.split("-")
            start_val = ord(start)
            end_val = ord(end)
            
            # Create mask based on common ASCII ranges
            if start == "0" and end == "9":
                # Match digits: 0x30-0x39
                return PatternToken(value=0x30, mask=0xF0)
            elif start == "A" and end == "F":
                # Match A-F: 0x41-0x46
                return PatternToken(value=0x40, mask=0xF8)
            elif start == "A" and end == "Z":
                # Match A-Z: 0x41-0x5A
                return PatternToken(value=0x40, mask=0xE0)
            elif start == "a" and end == "z":
                # Match a-z: 0x61-0x7A
                return PatternToken(value=0x60, mask=0xE0)
        
        # Check for bit mask pattern like [01] for matching 0 or 1
        if content in ("01", "10"):
            # Match either 0 or 1 in the low bit
            return PatternToken(value=0x00, mask=0xFE)
        
        # Check for specific class names
        if content == "DIGIT":
            return PatternToken(value=0x30, mask=0xF0)
        if content == "ALPHA":
            # Match letters (rough mask - matches more precisely in practice)
            return PatternToken(value=0x40, mask=0xC0)
        if content == "ALNUM":
            # Match alphanumeric
            return PatternToken(value=0x30, mask=0xF0)
        if content == "PRINT":
            # Match printable ASCII (0x20-0x7E)
            return PatternToken(value=0x20, mask=0xE0)
        
        raise ValueError(f"Unknown character class: [{content}]")
    
    @classmethod
    def _parse_nibble_wildcard(cls, part: str) -> PatternToken:
        """Parse pattern with wildcard nibble like '?D' or 'A?'."""
        if len(part) != 2:
            raise ValueError(f"Invalid nibble wildcard: {part}")
        
        if part[0] == "?":
            # Low nibble wildcard (high nibble specified)
            high = int(part[1], 16)
            return PatternToken(value=high << 4, mask=0x0F)
        elif part[1] == "?":
            # High nibble wildcard (low nibble specified)
            low = int(part[0], 16)
            return PatternToken(value=low, mask=0xF0)
        else:
            raise ValueError(f"Invalid nibble wildcard: {part}")
    
    @property
    def length(self) -> int:
        """Return the length of the pattern in bytes."""
        return len(self.tokens)
    
    def matches(self, data: bytes, offset: int = 0) -> bool:
        """Check if data at offset matches this pattern.
        
        Args:
            data: Binary data to check
            offset: Starting offset in data
            
        Returns:
            True if pattern matches at offset
        """
        if offset + len(self.tokens) > len(data):
            return False
        
        for i, token in enumerate(self.tokens):
            if not token.matches(data[offset + i]):
                return False
        
        return True
    
    def __len__(self) -> int:
        return len(self.tokens)
    
    def __repr__(self) -> str:
        return f"BytePattern({self.raw_pattern!r}, {len(self.tokens)} bytes)"


@dataclass
class PatternMatch:
    """A match result from pattern searching."""
    offset: int
    pattern: BytePattern
    matched_bytes: bytes
    context_before: bytes
    context_after: bytes
    
    def to_dict(self) -> dict:
        """Convert match to dictionary representation."""
        return {
            "offset": self.offset,
            "pattern": self.pattern.raw_pattern,
            "matched_bytes": self.matched_bytes.hex(),
            "context_before": self.context_before.hex() if self.context_before else "",
            "context_after": self.context_after.hex() if self.context_after else "",
        }


@dataclass
class PatternMatcher:
    """Matcher for searching binary data with byte patterns.
    
    Provides efficient pattern matching with support for:
    - Wildcards (? or ??)
    - Bit masks for partial matching
    - Character classes
    - Context extraction
    """
    
    context_size: int = 16  # Bytes of context before/after match
    
    def search(
        self,
        data: bytes,
        pattern: BytePattern | str,
        start: int = 0,
        end: int | None = None,
    ) -> list[PatternMatch]:
        """Search for pattern in data.
        
        Args:
            data: Binary data to search
            pattern: Pattern to search for (or pattern string)
            start: Starting offset (default: 0)
            end: Ending offset (default: len(data))
            
        Returns:
            List of PatternMatch objects
        """
        if isinstance(pattern, str):
            pattern = BytePattern.parse(pattern)
        
        if end is None:
            end = len(data)
        
        matches: list[PatternMatch] = []
        pattern_len = len(pattern)
        
        # Simple sliding window search
        for offset in range(start, end - pattern_len + 1):
            if pattern.matches(data, offset):
                # Calculate context boundaries
                context_start = max(0, offset - self.context_size)
                context_end = min(len(data), offset + pattern_len + self.context_size)
                
                match = PatternMatch(
                    offset=offset,
                    pattern=pattern,
                    matched_bytes=data[offset:offset + pattern_len],
                    context_before=data[context_start:offset],
                    context_after=data[offset + pattern_len:context_end],
                )
                matches.append(match)
        
        return matches
    
    def search_all(
        self,
        data: bytes,
        patterns: list[BytePattern | str],
        start: int = 0,
        end: int | None = None,
    ) -> dict[str, list[PatternMatch]]:
        """Search for multiple patterns in data.
        
        Args:
            data: Binary data to search
            patterns: List of patterns to search for
            start: Starting offset (default: 0)
            end: Ending offset (default: len(data))
            
        Returns:
            Dictionary mapping pattern strings to match lists
        """
        results: dict[str, list[PatternMatch]] = {}
        
        for pat in patterns:
            if isinstance(pat, str):
                pat_str = pat
                pat_obj = BytePattern.parse(pat)
            else:
                pat_str = pat.raw_pattern
                pat_obj = pat
            
            results[pat_str] = self.search(data, pat_obj, start, end)
        
        return results
    
    def find_first(
        self,
        data: bytes,
        pattern: BytePattern | str,
        start: int = 0,
        end: int | None = None,
    ) -> PatternMatch | None:
        """Find first occurrence of pattern in data.
        
        Args:
            data: Binary data to search
            pattern: Pattern to search for
            start: Starting offset (default: 0)
            end: Ending offset (default: len(data))
            
        Returns:
            First PatternMatch or None if not found
        """
        matches = self.search(data, pattern, start, end)
        return matches[0] if matches else None
    
    def count(
        self,
        data: bytes,
        pattern: BytePattern | str,
        start: int = 0,
        end: int | None = None,
    ) -> int:
        """Count occurrences of pattern in data.
        
        Args:
            data: Binary data to search
            pattern: Pattern to search for
            start: Starting offset (default: 0)
            end: Ending offset (default: len(data))
            
        Returns:
            Number of matches
        """
        return len(self.search(data, pattern, start, end))


def parse_pattern(pattern: str, endianness: Endianness = Endianness.BIG) -> BytePattern:
    """Parse a pattern string into a BytePattern.
    
    Convenience function for creating patterns.
    
    Args:
        pattern: Pattern string (e.g., "A9 ?? 8D 00 21")
        endianness: Byte order (default: BIG)
        
    Returns:
        Parsed BytePattern
    """
    return BytePattern.parse(pattern, endianness)


def search_pattern(
    data: bytes,
    pattern: str | BytePattern,
    context_size: int = 16,
) -> list[PatternMatch]:
    """Search for a pattern in binary data.
    
    Convenience function for one-off searches.
    
    Args:
        data: Binary data to search
        pattern: Pattern string or BytePattern
        context_size: Bytes of context to include
        
    Returns:
        List of PatternMatch objects
    """
    matcher = PatternMatcher(context_size=context_size)
    return matcher.search(data, pattern)


def format_match(match: PatternMatch, show_context: bool = True) -> str:
    """Format a match for display.
    
    Args:
        match: PatternMatch to format
        show_context: Whether to show context
        
    Returns:
        Formatted string representation
    """
    lines = [
        f"Offset 0x{match.offset:08X}: {match.matched_bytes.hex()}",
    ]
    
    if show_context:
        if match.context_before:
            lines.append(f"  Before: {match.context_before.hex()}")
        if match.context_after:
            lines.append(f"  After:  {match.context_after.hex()}")
    
    return "\n".join(lines)
