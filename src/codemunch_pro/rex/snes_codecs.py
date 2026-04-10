"""SNES ROM address codecs for LoROM and HiROM formats."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from codemunch_pro.rex.model import AddressLocation


@dataclass(slots=True)
class SnesLoRomCodec:
    """SNES LoROM address codec.
    
    LoROM maps ROM in 32KB chunks at $8000-$FFFF in each bank.
    Banks are numbered 0-127 (or 0-255 for 4MB+ ROMs).
    """
    name: str = "snes-lorom"
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])([0-9]{1,3}):([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        """Extract SNES LoROM address references."""
        results = []
        seen = set()
        for match in self._banked_pattern.finditer(text):
            bank_str = match.group(1)
            high_byte = match.group(2)
            low_byte = match.group(3)
            try:
                bank = int(bank_str)
                addr = int(high_byte + low_byte, 16)
                if 0 <= bank <= 255 and 0x8000 <= addr <= 0xFFFF:
                    ref = f"{bank}:${addr:04X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        """Parse a LoROM reference like '80:$8000' or '$008000'."""
        raw = ref.strip().replace("_", "")
        
        # Handle bank:addr format
        if ":" in raw and not raw.startswith(("$", "0x", "0X")):
            parts = raw.split(":", 1)
            if len(parts) != 2:
                return None
            bank_str, addr_str = parts
            try:
                bank = int(bank_str)
            except ValueError:
                return None
            if not 0 <= bank <= 255:
                return None
            try:
                addr = int(addr_str.replace("$", "").replace("0x", ""), 16)
            except ValueError:
                return None
            if not 0x8000 <= addr <= 0xFFFF:
                return None
            file_offset = self._calculate_file_offset(bank, addr)
            return AddressLocation(
                address_space=self.name,
                start=(bank << 16) | addr,
                end=(bank << 16) | addr,
                display=f"{bank}:${addr:04X}",
                segment=f"bank{bank}",
                attributes={
                    "bank": bank,
                    "address": addr,
                    "address_hex": f"${addr:04X}",
                    "type": "snes_lorom",
                    "file_offset": file_offset,
                },
            )
        
        # Handle $XXXXXX format
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) != 6 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            full_addr = int(cleaned, 16)
        except ValueError:
            return None
        bank = full_addr >> 16
        addr = full_addr & 0xFFFF
        if not 0x8000 <= addr <= 0xFFFF:
            return None
        file_offset = self._calculate_file_offset(bank, addr)
        return AddressLocation(
            address_space=self.name,
            start=full_addr,
            end=full_addr,
            display=f"{bank}:${addr:04X}",
            segment=f"bank{bank}",
            attributes={
                "bank": bank,
                "address": addr,
                "address_hex": f"${addr:04X}",
                "type": "snes_lorom",
                "file_offset": file_offset,
            },
        )

    def _calculate_file_offset(self, bank: int, addr: int) -> int:
        """Calculate file offset from SNES LoROM address."""
        # LoROM: ignore bit 15, shift bank, add lower 15 bits
        return ((bank & 0x7F) << 15) | (addr & 0x7FFF)

    def format(self, location: AddressLocation) -> str:
        """Format an AddressLocation back to canonical LoROM form."""
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        bank = location.attributes.get("bank")
        addr = location.attributes.get("address")
        if not isinstance(bank, int) or not isinstance(addr, int):
            raise ValueError("SNES LoROM location missing bank or address attribute")
        return f"{bank}:${addr:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        """Convert SNES LoROM location to file offset."""
        if location.address_space != self.name:
            return None
        bank = location.attributes.get("bank")
        addr = location.attributes.get("address")
        if not isinstance(bank, int) or not isinstance(addr, int):
            return None
        return self._calculate_file_offset(bank, addr)


@dataclass(slots=True)
class SnesHiRomCodec:
    """SNES HiROM address codec.
    
    HiROM maps ROM linearly starting at $C00000.
    Banks are numbered 0-63 (or 0-127 for larger ROMs).
    """
    name: str = "snes-hirom"
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])([0-9]{1,3}):([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        """Extract SNES HiROM address references."""
        results = []
        seen = set()
        for match in self._banked_pattern.finditer(text):
            bank_str = match.group(1)
            high_byte = match.group(2)
            low_byte = match.group(3)
            try:
                bank = int(bank_str)
                addr = int(high_byte + low_byte, 16)
                if 0x40 <= bank <= 0x7F and 0x0000 <= addr <= 0xFFFF:
                    ref = f"{bank}:${addr:04X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        """Parse a HiROM reference like 'C0:$0000' or '$C00000'."""
        raw = ref.strip().replace("_", "")
        
        # Handle bank:addr format
        if ":" in raw and not raw.startswith(("$", "0x", "0X")):
            parts = raw.split(":", 1)
            if len(parts) != 2:
                return None
            bank_str, addr_str = parts
            try:
                bank = int(bank_str)
            except ValueError:
                return None
            if not 0x40 <= bank <= 0x7F:
                return None
            try:
                addr = int(addr_str.replace("$", "").replace("0x", ""), 16)
            except ValueError:
                return None
            if not 0x0000 <= addr <= 0xFFFF:
                return None
            file_offset = self._calculate_file_offset(bank, addr)
            return AddressLocation(
                address_space=self.name,
                start=(bank << 16) | addr,
                end=(bank << 16) | addr,
                display=f"{bank}:${addr:04X}",
                segment=f"bank{bank}",
                attributes={
                    "bank": bank,
                    "address": addr,
                    "address_hex": f"${addr:04X}",
                    "type": "snes_hirom",
                    "file_offset": file_offset,
                },
            )
        
        # Handle $XXXXXX format
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) != 6 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            full_addr = int(cleaned, 16)
        except ValueError:
            return None
        bank = full_addr >> 16
        addr = full_addr & 0xFFFF
        if not 0x40 <= bank <= 0x7F:
            return None
        file_offset = self._calculate_file_offset(bank, addr)
        return AddressLocation(
            address_space=self.name,
            start=full_addr,
            end=full_addr,
            display=f"{bank}:${addr:04X}",
            segment=f"bank{bank}",
            attributes={
                "bank": bank,
                "address": addr,
                "address_hex": f"${addr:04X}",
                "type": "snes_hirom",
                "file_offset": file_offset,
            },
        )

    def _calculate_file_offset(self, bank: int, addr: int) -> int:
        """Calculate file offset from SNES HiROM address."""
        # HiROM: linear mapping from $C00000
        return ((bank - 0xC0) << 16) | addr

    def format(self, location: AddressLocation) -> str:
        """Format an AddressLocation back to canonical HiROM form."""
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        bank = location.attributes.get("bank")
        addr = location.attributes.get("address")
        if not isinstance(bank, int) or not isinstance(addr, int):
            raise ValueError("SNES HiROM location missing bank or address attribute")
        return f"{bank}:${addr:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        """Convert SNES HiROM location to file offset."""
        if location.address_space != self.name:
            return None
        bank = location.attributes.get("bank")
        addr = location.attributes.get("address")
        if not isinstance(bank, int) or not isinstance(addr, int):
            return None
        return self._calculate_file_offset(bank, addr)
