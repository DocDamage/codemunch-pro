"""ROM-specific address codecs for various gaming platforms."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from codemunch_pro.rex.model import AddressLocation


@dataclass(slots=True)
class GbaRomCodec:
    """Game Boy Advance ROM address codec."""
    name: str = "gba-rom"
    _gba_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._gba_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:0x)?([0-9A-Fa-f]{8})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_])\$([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        for match in self._gba_pattern.finditer(text):
            addr_str = match.group(1) if match.group(1) else match.group(2)
            if addr_str:
                try:
                    addr = int(addr_str, 16)
                    if self._is_valid_gba_address(addr):
                        normalized = self._normalize_address(addr)
                        results.append(f"0x{normalized:08X}")
                except ValueError:
                    continue
        return results

    def _is_valid_gba_address(self, addr: int) -> bool:
        return (
            (0x08000000 <= addr <= 0x09FFFFFF) or
            (0x0A000000 <= addr <= 0x0BFFFFFF) or
            (0x0C000000 <= addr <= 0x0DFFFFFF)
        )

    def _normalize_address(self, addr: int) -> int:
        if 0x0A000000 <= addr <= 0x0BFFFFFF:
            return addr - 0x0A000000 + 0x08000000
        if 0x0C000000 <= addr <= 0x0DFFFFFF:
            return addr - 0x0C000000 + 0x08000000
        return addr

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 8 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            address = int(cleaned, 16)
        except ValueError:
            return None
        if not self._is_valid_gba_address(address):
            return None
        normalized = self._normalize_address(address)
        file_offset = self._calculate_file_offset(normalized)
        return AddressLocation(
            address_space=self.name,
            start=normalized,
            end=normalized,
            display=f"0x{normalized:08X}",
            segment="rom",
            attributes={
                "address": normalized,
                "address_hex": f"0x{normalized:08X}",
                "original_address": address,
                "type": "gba_rom",
                "file_offset": file_offset,
            },
        )

    def _calculate_file_offset(self, address: int) -> int | None:
        if 0x08000000 <= address <= 0x09FFFFFF:
            return address - 0x08000000
        return None

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("GBA ROM location missing address attribute")
        return f"0x{address:08X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        return self._calculate_file_offset(address)


@dataclass(slots=True)
class NesPrgCodec:
    """NES PRG ROM address codec."""
    name: str = "nes-prg"
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)
    _linear_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])(\d+):([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )
        self._linear_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:\$|0x)([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        for match in self._banked_pattern.finditer(text):
            bank_str = match.group(1)
            addr_str = match.group(2)
            try:
                bank = int(bank_str)
                addr = int(addr_str, 16)
                if 0x8000 <= addr <= 0xFFFF:
                    results.append(f"{bank}:{addr:04X}")
            except ValueError:
                continue
        for match in self._linear_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if 0x8000 <= addr <= 0xFFFF:
                    results.append(f"0:{addr:04X}")
            except ValueError:
                continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        if ":" in raw and not raw.startswith(("$", "0x", "0X")):
            return self._parse_banked(raw)
        return self._parse_linear(raw)

    def _parse_banked(self, raw: str) -> AddressLocation | None:
        parts = raw.split(":", 1)
        if len(parts) != 2:
            return None
        bank_str, addr_str = parts
        try:
            bank = int(bank_str)
        except ValueError:
            return None
        if bank < 0:
            return None
        try:
            cpu_addr = int(addr_str, 16)
        except ValueError:
            return None
        if not 0x8000 <= cpu_addr <= 0xFFFF:
            return None
        file_offset = self._calculate_file_offset(bank, cpu_addr)
        return AddressLocation(
            address_space=self.name,
            start=cpu_addr,
            end=cpu_addr,
            display=f"{bank}:{cpu_addr:04X}",
            segment=f"bank{bank}",
            attributes={
                "bank": bank,
                "cpu_address": cpu_addr,
                "cpu_address_hex": f"${cpu_addr:04X}",
                "type": "nes_prg",
                "file_offset": file_offset,
            },
        )

    def _parse_linear(self, raw: str) -> AddressLocation | None:
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 4 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            cpu_addr = int(cleaned, 16)
        except ValueError:
            return None
        if not 0x8000 <= cpu_addr <= 0xFFFF:
            return None
        bank = 0
        file_offset = self._calculate_file_offset(bank, cpu_addr)
        return AddressLocation(
            address_space=self.name,
            start=cpu_addr,
            end=cpu_addr,
            display=f"{bank}:{cpu_addr:04X}",
            segment="bank0",
            attributes={
                "bank": bank,
                "cpu_address": cpu_addr,
                "cpu_address_hex": f"${cpu_addr:04X}",
                "type": "nes_prg",
                "file_offset": file_offset,
            },
        )

    def _calculate_file_offset(self, bank: int, cpu_addr: int) -> int:
        return (bank * 0x4000) + (cpu_addr - 0x8000)

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        bank = location.attributes.get("bank")
        cpu_addr = location.attributes.get("cpu_address")
        if not isinstance(bank, int) or not isinstance(cpu_addr, int):
            raise ValueError("NES PRG location missing bank or cpu_address attribute")
        return f"{bank}:{cpu_addr:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        bank = location.attributes.get("bank")
        cpu_addr = location.attributes.get("cpu_address")
        if not isinstance(bank, int) or not isinstance(cpu_addr, int):
            return None
        return self._calculate_file_offset(bank, cpu_addr)


@dataclass(slots=True)
class GameBoyRomCodec:
    """Game Boy ROM address codec."""
    name: str = "gb-rom"
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)
    _linear_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])([0-9]+):([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )
        self._linear_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:\$|0x)([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        for match in self._banked_pattern.finditer(text):
            bank_str = match.group(1)
            addr_str = match.group(2)
            try:
                bank = int(bank_str)
                addr = int(addr_str, 16)
                if self._is_valid_gb_address(bank, addr):
                    results.append(f"{bank:02d}:{addr:04X}")
            except ValueError:
                continue
        for match in self._linear_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if addr <= 0x3FFF:
                    results.append(f"00:{addr:04X}")
            except ValueError:
                continue
        return results

    def _is_valid_gb_address(self, bank: int, addr: int) -> bool:
        if bank < 0:
            return False
        if bank == 0:
            return addr <= 0x3FFF
        else:
            return 0x4000 <= addr <= 0x7FFF

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        if ":" in raw and not raw.startswith(("$", "0x", "0X")):
            return self._parse_banked(raw)
        return self._parse_linear(raw)

    def _parse_banked(self, raw: str) -> AddressLocation | None:
        parts = raw.split(":", 1)
        if len(parts) != 2:
            return None
        bank_str, addr_str = parts
        try:
            bank = int(bank_str)
        except ValueError:
            return None
        if bank < 0:
            return None
        try:
            address = int(addr_str, 16)
        except ValueError:
            return None
        if not self._is_valid_gb_address(bank, address):
            return None
        file_offset = self._calculate_file_offset(bank, address)
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"{bank:02d}:{address:04X}",
            segment=f"bank{bank}",
            attributes={
                "bank": bank,
                "address": address,
                "address_hex": f"${address:04X}",
                "type": "gb_rom",
                "file_offset": file_offset,
            },
        )

    def _parse_linear(self, raw: str) -> AddressLocation | None:
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 4 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            address = int(cleaned, 16)
        except ValueError:
            return None
        if address > 0x3FFF:
            return None
        bank = 0
        file_offset = self._calculate_file_offset(bank, address)
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"{bank:02d}:{address:04X}",
            segment="bank0",
            attributes={
                "bank": bank,
                "address": address,
                "address_hex": f"${address:04X}",
                "type": "gb_rom",
                "file_offset": file_offset,
            },
        )

    def _calculate_file_offset(self, bank: int, address: int) -> int:
        if bank == 0:
            return address
        else:
            return (bank * 0x4000) + (address - 0x4000)

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        bank = location.attributes.get("bank")
        address = location.attributes.get("address")
        if not isinstance(bank, int) or not isinstance(address, int):
            raise ValueError("Game Boy ROM location missing bank or address attribute")
        return f"{bank:02d}:{address:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        bank = location.attributes.get("bank")
        address = location.attributes.get("address")
        if not isinstance(bank, int) or not isinstance(address, int):
            return None
        return self._calculate_file_offset(bank, address)


@dataclass(slots=True)
class GenesisRomCodec:
    """Sega Genesis/Mega Drive ROM address codec."""
    name: str = "genesis-rom"
    _linear_pattern: re.Pattern[str] = field(init=False, repr=False)
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._linear_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:\$|0x)([0-9A-Fa-f]{1,6})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])([0-3]):([0-9A-Fa-f]{1,5})(?![A-Za-z0-9_:])"
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        for match in self._linear_pattern.finditer(text):
            addr_str = match.group(1)
            addr = int(addr_str, 16)
            results.append(f"${addr:06X}")
        for match in self._banked_pattern.finditer(text):
            bank_str = match.group(1)
            offset_str = match.group(2)
            bank = int(bank_str)
            offset = int(offset_str, 16)
            results.append(f"{bank}:{offset:04X}")
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        if ":" in raw and not raw.startswith(("$", "0x", "0X")):
            return self._parse_banked(raw)
        return self._parse_linear(raw)

    def _parse_linear(self, raw: str) -> AddressLocation | None:
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 6 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            address = int(cleaned, 16)
        except ValueError:
            return None
        if not 0 <= address <= 0xFFFFFF:
            return None
        addr_type = self._get_address_type(address)
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"${address:06X}",
            segment="linear",
            attributes={
                "address": address,
                "address_hex": f"${address:06X}",
                "type": addr_type,
                "linear": True,
                "file_offset": self._calculate_file_offset(address),
            },
        )

    def _parse_banked(self, raw: str) -> AddressLocation | None:
        parts = raw.split(":", 1)
        if len(parts) != 2:
            return None
        bank_str, offset_str = parts
        try:
            bank = int(bank_str)
        except ValueError:
            return None
        if not 0 <= bank <= 3:
            return None
        try:
            offset = int(offset_str, 16)
        except ValueError:
            return None
        if not 0 <= offset <= 0x1FFFFF:
            return None
        address = 0x800000 + (bank << 21) + offset
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"{bank}:{offset:04X}",
            segment=f"bank{bank}",
            attributes={
                "address": address,
                "address_hex": f"${address:06X}",
                "bank": bank,
                "offset": offset,
                "type": "ssf2_banked",
                "linear": False,
                "file_offset": self._calculate_file_offset(address),
            },
        )

    def _get_address_type(self, address: int) -> str:
        if address <= 0x3FFFFF:
            return "linear_rom"
        if 0x800000 <= address <= 0xFFFFFF:
            return "ssf2_banked"
        return "reserved"

    def _calculate_file_offset(self, address: int) -> int | None:
        if address <= 0x3FFFFF:
            return address
        if 0x800000 <= address <= 0xFFFFFF:
            bank_index = (address >> 21) - 4
            if not 0 <= bank_index <= 3:
                return None
            return (bank_index * 0x200000) + (address & 0x1FFFFF)
        return None

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        bank = location.attributes.get("bank")
        offset = location.attributes.get("offset")
        if isinstance(bank, int) and isinstance(offset, int):
            return f"{bank}:{offset:04X}"
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("Genesis ROM location missing address attribute")
        return f"${address:06X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        return self._calculate_file_offset(address)


@dataclass(slots=True)
class SmsRomCodec:
    """Sega Master System / Game Gear ROM address codec."""
    name: str = "sms-rom"
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)
    _linear_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])([0-9]+):([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )
        self._linear_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:\$|0x)([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        for match in self._banked_pattern.finditer(text):
            page_str = match.group(1)
            offset_str = match.group(2)
            try:
                page = int(page_str)
                offset = int(offset_str, 16)
                if self._is_valid_sms_page_offset(page, offset):
                    results.append(f"{page}:{offset:04X}")
            except ValueError:
                continue
        for match in self._linear_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if addr <= 0xBFFF:
                    results.append(f"0x{addr:04X}")
            except ValueError:
                continue
        return results

    def _is_valid_sms_page_offset(self, page: int, offset: int) -> bool:
        if page < 0 or page > 63:
            return False
        if offset < 0 or offset > 0x3FFF:
            return False
        return True

    def _cpu_addr_to_page_offset(self, cpu_addr: int) -> tuple[int, int] | None:
        if cpu_addr <= 0x3FFF:
            return (0, cpu_addr)
        elif cpu_addr <= 0x7FFF:
            return (1, cpu_addr - 0x4000)
        elif cpu_addr <= 0xBFFF:
            return (2, cpu_addr - 0x8000)
        else:
            return None

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        if ":" in raw and not raw.startswith(("$", "0x", "0X")):
            return self._parse_banked(raw)
        return self._parse_linear(raw)

    def _parse_banked(self, raw: str) -> AddressLocation | None:
        parts = raw.split(":", 1)
        if len(parts) != 2:
            return None
        page_str, offset_str = parts
        try:
            page = int(page_str)
        except ValueError:
            return None
        if page < 0 or page > 63:
            return None
        try:
            offset = int(offset_str, 16)
        except ValueError:
            return None
        if offset < 0 or offset > 0x3FFF:
            return None
        if page == 0:
            cpu_addr = offset
        elif page == 1:
            cpu_addr = 0x4000 + offset
        else:
            cpu_addr = 0x8000 + offset
        file_offset = self._calculate_file_offset(page, offset)
        return AddressLocation(
            address_space=self.name,
            start=cpu_addr,
            end=cpu_addr,
            display=f"{page}:{offset:04X}",
            segment=f"page{page}",
            attributes={
                "page": page,
                "offset": offset,
                "cpu_address": cpu_addr,
                "cpu_address_hex": f"${cpu_addr:04X}",
                "type": "sms_rom",
                "file_offset": file_offset,
            },
        )

    def _parse_linear(self, raw: str) -> AddressLocation | None:
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 4 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            cpu_addr = int(cleaned, 16)
        except ValueError:
            return None
        if cpu_addr > 0xBFFF:
            return None
        page_offset = self._cpu_addr_to_page_offset(cpu_addr)
        if page_offset is None:
            return None
        page, offset = page_offset
        file_offset = self._calculate_file_offset(page, offset)
        return AddressLocation(
            address_space=self.name,
            start=cpu_addr,
            end=cpu_addr,
            display=f"0x{cpu_addr:04X}",
            segment=f"page{page}",
            attributes={
                "page": page,
                "offset": offset,
                "cpu_address": cpu_addr,
                "cpu_address_hex": f"${cpu_addr:04X}",
                "type": "sms_rom",
                "file_offset": file_offset,
            },
        )

    def _calculate_file_offset(self, page: int, offset: int) -> int:
        return (page * 0x4000) + offset

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        page = location.attributes.get("page")
        offset = location.attributes.get("offset")
        if isinstance(page, int) and isinstance(offset, int):
            return f"{page}:{offset:04X}"
        cpu_addr = location.attributes.get("cpu_address")
        if isinstance(cpu_addr, int):
            return f"0x{cpu_addr:04X}"
        raise ValueError("SMS ROM location missing page/offset or cpu_address attribute")

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        page = location.attributes.get("page")
        offset = location.attributes.get("offset")
        if isinstance(page, int) and isinstance(offset, int):
            return self._calculate_file_offset(page, offset)
        return None


@dataclass(slots=True)
class N64RomCodec:
    """Nintendo 64 ROM address codec."""
    name: str = "n64-rom"
    _pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:0x)?([8-9a-bA-B][0-9A-Fa-f]{7})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_])\$([0-9A-Fa-f]{8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        seen = set()
        for match in self._pattern.finditer(text):
            addr_str = match.group(1) if match.group(1) else match.group(2)
            if addr_str:
                try:
                    addr = int(addr_str, 16)
                    if 0x80000000 <= addr <= 0x9FFFFFFF:
                        addr = 0xB0000000 + (addr - 0x80000000)
                    elif 0xA0000000 <= addr <= 0xBFFFFFFF:
                        if addr < 0xB0000000:
                            addr = 0xB0000000 + (addr - 0xA0000000)
                    else:
                        continue
                    canonical = f"0x{addr:08X}"
                    if canonical not in seen:
                        results.append(canonical)
                        seen.add(canonical)
                except ValueError:
                    continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) != 8 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            address = int(cleaned, 16)
        except ValueError:
            return None
        if not (0x80000000 <= address <= 0x9FFFFFFF or 0xA0000000 <= address <= 0xBFFFFFFF):
            return None
        original_address = address
        if 0x80000000 <= address <= 0x9FFFFFFF:
            region = "kseg0"
            address = 0xB0000000 + (address - 0x80000000)
        elif address < 0xB0000000:
            region = "kseg1"
            address = 0xB0000000 + (address - 0xA0000000)
        else:
            region = "kseg1"
        file_offset = (address - 0xB0000000) + 0x1000
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"0x{address:08X}",
            segment="kseg1",
            attributes={
                "address": address,
                "address_hex": f"0x{address:08X}",
                "original_address": original_address,
                "region": region,
                "type": "n64_rom",
                "file_offset": file_offset,
            },
        )

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("N64 ROM location missing address attribute")
        return f"0x{address:08X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        return (address - 0xB0000000) + 0x1000


@dataclass(slots=True)
class PsxExeCodec:
    """Sony PlayStation 1 EXE/PS-X EXE address codec."""
    name: str = "psx-exe"
    default_load_base: int = 0x80010000
    _psx_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._psx_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:0x)?([89ABab][0-9A-Fa-f]{7})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_])\$([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        for match in self._psx_pattern.finditer(text):
            addr_str = match.group(1) if match.group(1) else match.group(2)
            if addr_str:
                try:
                    addr = int(addr_str, 16)
                    if self._is_valid_psx_address(addr):
                        results.append(f"0x{addr:08X}")
                except ValueError:
                    continue
        return results

    def _is_valid_psx_address(self, addr: int) -> bool:
        if 0x80000000 <= addr <= 0x9FFFFFFF:
            return True
        if 0xA0000000 <= addr <= 0xBFFFFFFF:
            return True
        return False

    def _get_memory_region(self, addr: int) -> str:
        if 0x80000000 <= addr <= 0x9FFFFFFF:
            if addr <= 0x801FFFFF:
                return "kseg0_ram"
            return "kseg0"
        if 0xA0000000 <= addr <= 0xBFFFFFFF:
            if addr <= 0xA01FFFFF:
                return "kseg1_ram"
            return "kseg1"
        return "unknown"

    def _normalize_address(self, addr: int) -> int:
        if 0xA0000000 <= addr <= 0xA0200000:
            return addr - 0xA0000000 + 0x80000000
        return addr

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 8 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            address = int(cleaned, 16)
        except ValueError:
            return None
        if not self._is_valid_psx_address(address):
            return None
        normalized = self._normalize_address(address)
        load_base = self.default_load_base
        file_offset = self._calculate_file_offset(normalized, load_base)
        memory_region = self._get_memory_region(address)
        return AddressLocation(
            address_space=self.name,
            start=normalized,
            end=normalized,
            display=f"0x{normalized:08X}",
            segment=memory_region,
            attributes={
                "address": normalized,
                "address_hex": f"0x{normalized:08X}",
                "original_address": address,
                "original_address_hex": f"0x{address:08X}",
                "memory_region": memory_region,
                "type": "psx_exe",
                "file_offset": file_offset,
                "load_base": load_base,
                "is_cached": 0x80000000 <= address <= 0x9FFFFFFF,
                "is_uncached": 0xA0000000 <= address <= 0xBFFFFFFF,
            },
        )

    def _calculate_file_offset(self, address: int, load_base: int | None = None) -> int | None:
        if load_base is None:
            load_base = self.default_load_base
        if address >= load_base:
            return address - load_base
        return None

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("PSX EXE location missing address attribute")
        return f"0x{address:08X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        load_base = location.attributes.get("load_base")
        return self._calculate_file_offset(address, load_base)


@dataclass(slots=True)
class PcEngineRomCodec:
    """PC Engine/TurboGrafx-16 ROM address codec."""
    name: str = "pce-rom"
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)
    _physical_pattern: re.Pattern[str] = field(init=False, repr=False)
    _cpu_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])(\d{1,3}):([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )
        self._physical_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])P:([0-9A-Fa-f]{1,6})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )
        self._cpu_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:\$|0x)([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        seen = set()
        for match in self._physical_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if addr <= 0x1FFFFF:
                    ref = f"P:{addr:06X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        for match in self._banked_pattern.finditer(text):
            bank_str = match.group(1)
            addr_str = match.group(2)
            try:
                bank = int(bank_str)
                addr = int(addr_str, 16)
                if bank <= 255 and addr <= 0x1FFF:
                    ref = f"{bank}:{addr:04X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        for match in self._cpu_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if addr <= 0x1FFF:
                    ref = f"0:{addr:04X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        cleaned = raw.upper()
        if cleaned.startswith("P:"):
            return self._parse_physical(cleaned)
        if ":" in cleaned:
            return self._parse_banked(cleaned)
        return self._parse_cpu(raw)

    def _parse_physical(self, raw: str) -> AddressLocation | None:
        addr_str = raw[2:]
        if not addr_str or len(addr_str) > 6:
            return None
        try:
            physical_addr = int(addr_str, 16)
        except ValueError:
            return None
        if physical_addr > 0x1FFFFF:
            return None
        bank = physical_addr // 0x2000
        offset = physical_addr % 0x2000
        return AddressLocation(
            address_space=self.name,
            start=physical_addr,
            end=physical_addr,
            display=f"P:{physical_addr:06X}",
            segment="physical",
            attributes={
                "physical_address": physical_addr,
                "physical_address_hex": f"P:{physical_addr:06X}",
                "bank": bank,
                "offset": offset,
                "type": "pce_physical",
                "file_offset": physical_addr,
            },
        )

    def _parse_banked(self, raw: str) -> AddressLocation | None:
        cleaned = raw.replace("$", "")
        parts = cleaned.split(":", 1)
        if len(parts) != 2:
            return None
        bank_str, addr_str = parts
        try:
            bank = int(bank_str)
        except ValueError:
            return None
        if bank < 0 or bank > 255:
            return None
        try:
            offset = int(addr_str, 16)
        except ValueError:
            return None
        if offset > 0x1FFF:
            return None
        physical_addr = (bank * 0x2000) + offset
        if physical_addr > 0x1FFFFF:
            return None
        return AddressLocation(
            address_space=self.name,
            start=physical_addr,
            end=physical_addr,
            display=f"{bank}:{offset:04X}",
            segment=f"bank{bank}",
            attributes={
                "physical_address": physical_addr,
                "physical_address_hex": f"P:{physical_addr:06X}",
                "bank": bank,
                "offset": offset,
                "offset_hex": f"${offset:04X}",
                "type": "pce_banked",
                "file_offset": physical_addr,
            },
        )

    def _parse_cpu(self, raw: str) -> AddressLocation | None:
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 4 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            offset = int(cleaned, 16)
        except ValueError:
            return None
        if offset > 0x1FFF:
            return None
        bank = 0
        physical_addr = offset
        return AddressLocation(
            address_space=self.name,
            start=physical_addr,
            end=physical_addr,
            display=f"{bank}:{offset:04X}",
            segment="bank0",
            attributes={
                "physical_address": physical_addr,
                "physical_address_hex": f"P:{physical_addr:06X}",
                "bank": bank,
                "offset": offset,
                "offset_hex": f"${offset:04X}",
                "type": "pce_banked",
                "file_offset": physical_addr,
            },
        )

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        addr_type = location.attributes.get("type")
        if addr_type == "pce_physical":
            physical_addr = location.attributes.get("physical_address")
            if not isinstance(physical_addr, int):
                raise ValueError("PCE ROM location missing physical_address attribute")
            return f"P:{physical_addr:06X}"
        else:
            bank = location.attributes.get("bank")
            offset = location.attributes.get("offset")
            if not isinstance(bank, int) or not isinstance(offset, int):
                raise ValueError("PCE ROM location missing bank or offset attribute")
            return f"{bank}:{offset:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        physical_addr = location.attributes.get("physical_address")
        if isinstance(physical_addr, int):
            return physical_addr
        bank = location.attributes.get("bank")
        offset = location.attributes.get("offset")
        if isinstance(bank, int) and isinstance(offset, int):
            return (bank * 0x2000) + offset
        return None


@dataclass(slots=True)
class C64PrgCodec:
    """Commodore 64 PRG file address codec."""
    name: str = "c64-prg"
    default_load_address: int = 0x0801
    _address_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._address_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:\$|0x)([0-9A-Fa-f]{1,4})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        for match in self._address_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if 0x0000 <= addr <= 0xFFFF:
                    results.append(f"${addr:04X}")
            except ValueError:
                continue
        return results

    def parse(self, ref: str, *, load_address: int | None = None) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 4 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            address = int(cleaned, 16)
        except ValueError:
            return None
        if not 0x0000 <= address <= 0xFFFF:
            return None
        load_addr = load_address if load_address is not None else self.default_load_address
        file_offset = self._calculate_file_offset(address, load_addr)
        addr_type = self._get_address_type(address)
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"${address:04X}",
            segment=addr_type,
            attributes={
                "address": address,
                "address_hex": f"${address:04X}",
                "load_address": load_addr,
                "load_address_hex": f"${load_addr:04X}",
                "type": "c64_prg",
                "file_offset": file_offset,
            },
        )

    def _get_address_type(self, address: int) -> str:
        if address <= 0x00FF:
            return "zero_page"
        elif address <= 0x01FF:
            return "stack"
        elif address <= 0x03FF:
            return "basic_buffer"
        elif address <= 0x07FF:
            return "screen"
        elif address <= 0x9FFF:
            return "basic_ram"
        elif address <= 0xBFFF:
            return "basic_rom"
        elif address <= 0xCFFF:
            return "ram"
        elif address <= 0xDFFF:
            return "io_or_char_rom"
        else:
            return "kernal_rom"

    def _calculate_file_offset(self, address: int, load_address: int) -> int | None:
        if address < load_address:
            return None
        return (address - load_address) + 2

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("C64 PRG location missing address attribute")
        return f"${address:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        load_address = location.attributes.get("load_address")
        if not isinstance(address, int) or not isinstance(load_address, int):
            return None
        return self._calculate_file_offset(address, load_address)


@dataclass(slots=True)
class Atari2600RomCodec:
    """Atari 2600 ROM address codec."""
    name: str = "atari2600-rom"
    cart_size: int = 0x1000
    bankswitch_type: str = "standard"
    selected_bank: int = 0
    _address_pattern: re.Pattern[str] = field(init=False, repr=False)
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._address_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:\$|0x)(1[0-9A-Fa-f]{3})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])(\d{1,2}):(1[0-9A-Fa-f]{3})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )

    def extract_refs(self, text: str) -> list[str]:
        results = []
        seen = set()
        for match in self._address_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if 0x1000 <= addr <= 0x1FFF:
                    ref = f"${addr:04X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        for match in self._banked_pattern.finditer(text):
            bank_str = match.group(1)
            addr_str = match.group(2)
            try:
                bank = int(bank_str)
                addr = int(addr_str, 16)
                if bank <= 15 and 0x1000 <= addr <= 0x1FFF:
                    ref = f"{bank}:${addr:04X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        if ":" in raw and not raw.startswith(("$", "0x", "0X")):
            return self._parse_banked(raw)
        return self._parse_linear(raw)

    def _parse_linear(self, raw: str) -> AddressLocation | None:
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 4 or not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            address = int(cleaned, 16)
        except ValueError:
            return None
        if not 0x1000 <= address <= 0x1FFF:
            return None
        file_offset = self._calculate_file_offset(address)
        cart_type = self._get_cart_type()
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"${address:04X}",
            segment="cart",
            attributes={
                "address": address,
                "address_hex": f"${address:04X}",
                "type": "a26_rom",
                "cart_type": cart_type,
                "cart_size": self.cart_size,
                "bankswitch_type": self.bankswitch_type,
                "selected_bank": self.selected_bank,
                "file_offset": file_offset,
            },
        )

    def _parse_banked(self, raw: str) -> AddressLocation | None:
        parts = raw.split(":", 1)
        if len(parts) != 2:
            return None
        bank_str, addr_str = parts
        try:
            bank = int(bank_str)
        except ValueError:
            return None
        if bank < 0 or bank > 15:
            return None
        try:
            address = int(addr_str, 16)
        except ValueError:
            return None
        if not 0x1000 <= address <= 0x1FFF:
            return None
        file_offset = self._calculate_banked_file_offset(bank, address)
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"{bank}:${address:04X}",
            segment=f"bank{bank}",
            attributes={
                "address": address,
                "address_hex": f"${address:04X}",
                "bank": bank,
                "type": "a26_banked",
                "cart_type": self._get_cart_type(),
                "cart_size": self.cart_size,
                "bankswitch_type": self.bankswitch_type,
                "selected_bank": bank,
                "file_offset": file_offset,
            },
        )

    def _get_cart_type(self) -> str:
        if self.cart_size <= 0x800:
            return "2KB"
        elif self.cart_size <= 0x1000:
            return "4KB"
        elif self.cart_size <= 0x2000:
            return "8KB"
        elif self.cart_size <= 0x4000:
            return "16KB"
        else:
            return "32KB+"

    def _calculate_file_offset(self, address: int) -> int | None:
        if address < 0x1000 or address > 0x1FFF:
            return None
        if self.cart_size == 0x800:
            return address & 0x7FF
        else:
            return address - 0x1000

    def _calculate_banked_file_offset(self, bank: int, address: int) -> int | None:
        bank_size = self._get_bank_size()
        if bank_size == 0:
            return None
        bank_offset = address & (bank_size - 1)
        return (bank * bank_size) + bank_offset

    def _get_bank_size(self) -> int:
        if self.bankswitch_type in ("parker_bros", "tigervision"):
            return 0x800
        elif self.bankswitch_type == "f8":
            return 0x1000
        elif self.bankswitch_type == "f6":
            return 0x1000
        elif self.cart_size > 0x1000:
            return 0x800
        else:
            return self.cart_size

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        bank = location.attributes.get("bank")
        address = location.attributes.get("address")
        if isinstance(bank, int):
            return f"{bank}:${address:04X}"
        if not isinstance(address, int):
            raise ValueError("Atari 2600 ROM location missing address attribute")
        return f"${address:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        bank = location.attributes.get("bank")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        if isinstance(bank, int):
            return self._calculate_banked_file_offset(bank, address)
        if address < 0x1000 or address > 0x1FFF:
            return None
        return address - 0x1000


@dataclass(slots=True)
class SaturnRomCodec:
    """Sega Saturn ROM address codec."""
    name: str = "saturn-rom"
    _hex_pattern: re.Pattern[str] = field(init=False, repr=False)
    _banked_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._hex_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])(?:0x)?([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )
        self._banked_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])(\d{1,3}):([0-9A-Fa-f]{1,6})(?![A-Za-z0-9_:])",
            re.IGNORECASE
        )

    def _is_valid_address(self, addr: int) -> bool:
        return (
            (0x00000000 <= addr <= 0x03FFFFFF) or
            (0x22000000 <= addr <= 0x24FFFFFF) or
            (0x25000000 <= addr <= 0x27FFFFFF) or
            (0x06000000 <= addr <= 0x07FFFFFF)
        )

    def _normalize_address(self, addr: int) -> int:
        if 0x22000000 <= addr <= 0x24FFFFFF:
            return addr - 0x22000000
        if 0x25000000 <= addr <= 0x27FFFFFF:
            return addr - 0x25000000 + 0x03000000
        if 0x06000000 <= addr <= 0x07FFFFFF:
            return addr - 0x06000000
        return addr

    def _get_region(self, addr: int) -> str:
        if 0x00000000 <= addr <= 0x01FFFFFF:
            return "boot_rom"
        if 0x02000000 <= addr <= 0x03FFFFFF:
            return "extended_rom"
        if 0x22000000 <= addr <= 0x24FFFFFF:
            return "cs0"
        if 0x25000000 <= addr <= 0x27FFFFFF:
            return "cs1"
        if 0x06000000 <= addr <= 0x07FFFFFF:
            return "cs2"
        return "unknown"

    def extract_refs(self, text: str) -> list[str]:
        results = []
        seen = set()
        for match in self._hex_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if self._is_valid_address(addr):
                    normalized = self._normalize_address(addr)
                    ref = f"0x{normalized:08X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        for match in self._banked_pattern.finditer(text):
            bank_str = match.group(1)
            offset_str = match.group(2)
            try:
                bank = int(bank_str)
                offset = int(offset_str, 16)
                if 0 <= bank <= 255 and 0 <= offset <= 0xFFFFFF:
                    ref = f"{bank}:{offset:06X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip()
        banked_match = re.match(r"^(\d{1,3}):([0-9A-Fa-f]{1,6})$", raw, re.IGNORECASE)
        if banked_match:
            bank = int(banked_match.group(1))
            offset = int(banked_match.group(2), 16)
            if bank > 255 or offset > 0xFFFFFF:
                return None
            address = bank * 0x100000 + offset
            return AddressLocation(
                address_space=self.name,
                start=address,
                end=address,
                display=f"{bank}:{offset:06X}",
                segment="banked",
                attributes={
                    "address": address,
                    "bank": bank,
                    "offset": offset,
                    "type": "saturn_banked",
                    "region": "banked",
                    "file_offset": address,
                },
            )
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 8:
            return None
        if not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            addr = int(cleaned, 16)
        except ValueError:
            return None
        if not self._is_valid_address(addr):
            return None
        normalized = self._normalize_address(addr)
        region = self._get_region(addr)
        return AddressLocation(
            address_space=self.name,
            start=normalized,
            end=normalized,
            display=f"0x{normalized:08X}",
            segment=region,
            attributes={
                "address": normalized,
                "original_address": addr,
                "type": "saturn_rom",
                "region": region,
                "file_offset": normalized,
            },
        )

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        bank = location.attributes.get("bank")
        offset = location.attributes.get("offset")
        if isinstance(bank, int) and isinstance(offset, int):
            return f"{bank}:{offset:06X}"
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("Saturn ROM location missing address attribute")
        return f"0x{address:08X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        return address


@dataclass(slots=True)
class XboxXbeCodec:
    """Original Xbox XBE (Xbox Executable) address codec."""
    name: str = "xbox-xbe"
    default_base_address: int = 0x00100000
    _hex_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._hex_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])(?:0x)?([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def _is_valid_address(self, addr: int) -> bool:
        return 0 <= addr <= 0xFFFFFFFF

    def _is_user_space(self, addr: int) -> bool:
        return 0 <= addr <= 0x7FFFFFFF

    def _is_kernel_space(self, addr: int) -> bool:
        return 0x80000000 <= addr <= 0xFFFFFFFF

    def _is_kernel_export(self, addr: int) -> bool:
        return 0x80000000 <= addr <= 0x800003FF

    def _calculate_file_offset(self, addr: int, base: int | None = None) -> int | None:
        if base is None:
            base = self.default_base_address
        if not self._is_user_space(addr):
            return None
        if addr < base:
            return None
        return addr - base

    def extract_refs(self, text: str) -> list[str]:
        results = []
        seen = set()
        for match in self._hex_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if self._is_valid_address(addr):
                    ref = f"0x{addr:08X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().lower()
        if raw.startswith("0x"):
            raw = raw[2:]
        elif raw.startswith("$"):
            raw = raw[1:]
        if len(raw) < 1 or len(raw) > 8:
            return None
        if not all(c in "0123456789abcdef" for c in raw):
            return None
        try:
            addr = int(raw, 16)
        except ValueError:
            return None
        if not self._is_valid_address(addr):
            return None
        is_user = self._is_user_space(addr)
        is_kernel = self._is_kernel_space(addr)
        file_offset = self._calculate_file_offset(addr)
        segment = "user" if is_user else "kernel"
        region = "user" if is_user else "kernel"
        return AddressLocation(
            address_space=self.name,
            start=addr,
            end=addr,
            display=f"0x{addr:08X}",
            segment=segment,
            attributes={
                "address": addr,
                "region": region,
                "is_user_space": is_user,
                "is_kernel_space": is_kernel,
                "is_kernel_export": self._is_kernel_export(addr),
                "file_offset": file_offset,
            },
        )

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("XBE location missing address attribute")
        return f"0x{address:08X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        return self._calculate_file_offset(address)


@dataclass(slots=True)
class Ps2ElfCodec:
    """PlayStation 2 ELF address codec."""
    name: str = "ps2-elf"
    default_ee_load_base: int = 0x00100000
    default_segment_file_offset: int = 0x1000
    _hex_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._hex_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_])(?:0x)?([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def _is_valid_address(self, addr: int) -> bool:
        return (
            (0x00000000 <= addr <= 0x01FFFFFF) or
            (0x20000000 <= addr <= 0x21FFFFFF) or
            (0x30000000 <= addr <= 0x31FFFFFF) or
            (0xBC000000 <= addr <= 0xBC1FFFFF) or
            (0x12000000 <= addr <= 0x1200FFFF)
        )

    def _get_memory_region(self, addr: int) -> tuple[str, int, str]:
        if 0x00000000 <= addr <= 0x01FFFFFF:
            return ("ee_ram", addr, "ee_ram")
        if 0x20000000 <= addr <= 0x21FFFFFF:
            normalized = addr - 0x20000000
            return ("ee_ram_mirror1", normalized, "ee_ram")
        if 0x30000000 <= addr <= 0x31FFFFFF:
            normalized = addr - 0x30000000
            return ("ee_ram_mirror2", normalized, "ee_ram")
        if 0xBC000000 <= addr <= 0xBC1FFFFF:
            return ("iop_ram", addr, "iop_ram")
        if 0x12000000 <= addr <= 0x1200FFFF:
            return ("gs_registers", addr, "gs_registers")
        return ("unknown", addr, "unknown")

    def _calculate_file_offset(
        self,
        addr: int,
        region: str,
        load_base: int | None = None,
        segment_offset: int | None = None
    ) -> int | None:
        if region not in ("ee_ram", "ee_ram_mirror1", "ee_ram_mirror2"):
            return None
        if load_base is None:
            load_base = self.default_ee_load_base
        if segment_offset is None:
            segment_offset = self.default_segment_file_offset
        if region == "ee_ram_mirror1":
            normalized = addr - 0x20000000
        elif region == "ee_ram_mirror2":
            normalized = addr - 0x30000000
        else:
            normalized = addr
        if normalized >= load_base:
            return (normalized - load_base) + segment_offset
        else:
            return normalized + segment_offset

    def extract_refs(self, text: str) -> list[str]:
        results = []
        seen = set()
        for match in self._hex_pattern.finditer(text):
            addr_str = match.group(1)
            try:
                addr = int(addr_str, 16)
                if self._is_valid_address(addr):
                    ref = f"0x{addr:08X}"
                    if ref not in seen:
                        results.append(ref)
                        seen.add(ref)
            except ValueError:
                continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().lower()
        if raw.startswith("0x"):
            raw = raw[2:]
        elif raw.startswith("$"):
            raw = raw[1:]
        if len(raw) < 1 or len(raw) > 8:
            return None
        if not all(c in "0123456789abcdef" for c in raw):
            return None
        try:
            addr = int(raw, 16)
        except ValueError:
            return None
        if not self._is_valid_address(addr):
            return None
        region, normalized, mirror_offset = self._get_memory_region(addr)
        file_offset = self._calculate_file_offset(addr, region)
        is_ee = region in ("ee_ram", "ee_ram_mirror1", "ee_ram_mirror2")
        is_iop = region == "iop_ram"
        is_gs = region == "gs_registers"
        attrs: dict[str, object] = {
            "address": normalized,
            "original_address": addr,
            "memory_region": region,
            "type": "ps2_elf",
            "is_ee_ram": is_ee,
            "is_iop_ram": is_iop,
            "is_gs_registers": is_gs,
            "file_offset": file_offset,
        }
        if region in ("ee_ram_mirror1", "ee_ram_mirror2"):
            attrs["mirror_offset"] = mirror_offset
        return AddressLocation(
            address_space=self.name,
            start=normalized,
            end=normalized,
            display=f"0x{normalized:08X}",
            segment=region,
            attributes=attrs,
        )

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("PS2 ELF location missing address attribute")
        return f"0x{address:08X}"

    def to_file_offset(
        self,
        location: AddressLocation,
        load_base: int | None = None,
        segment_file_offset: int | None = None
    ) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        region = location.attributes.get("memory_region")
        if not isinstance(address, int) or not isinstance(region, str):
            return None
        if region not in ("ee_ram", "ee_ram_mirror1", "ee_ram_mirror2"):
            return None
        if load_base is None:
            load_base = self.default_ee_load_base
        if segment_file_offset is None:
            segment_file_offset = self.default_segment_file_offset
        return (address - load_base) + segment_file_offset


@dataclass
class ArcadeRomCodec:
    """Arcade ROM address codec for MAME-style ROM regions."""
    name: str = "arcade-rom"
    region_bases: dict[str, int] = field(default_factory=lambda: {
        "maincpu": 0x00000,
        "cpu1": 0x00000,
        "cpu2": 0x00000,
        "audiocpu": 0x10000,
        "soundcpu": 0x10000,
        "gfx1": 0x20000,
        "gfx2": 0x40000,
        "gfx3": 0x60000,
        "sprites": 0x60000,
        "tiles": 0x80000,
        "proms": 0xA0000,
        "plds": 0xA0000,
    })

    def __post_init__(self) -> None:
        pass

    def extract_refs(self, text: str) -> list[str]:
        pattern = r'\b(' + '|'.join(self.region_bases.keys()) + r'):([0-9A-Fa-f]{1,6})\b'
        matches = re.findall(pattern, text)
        return [f"{region}:{addr}" for region, addr in matches]

    def parse(self, ref: str) -> AddressLocation | None:
        match = re.match(r'^(\w+):([0-9A-Fa-f]{1,6})$', ref)
        if not match:
            return None
        region = match.group(1)
        addr_str = match.group(2)
        if region not in self.region_bases:
            return None
        try:
            address = int(addr_str, 16)
        except ValueError:
            return None
        if address > 0xFFFFFF:
            return None
        base = self.region_bases[region]
        file_offset = base + address
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"{region}:{addr_str.upper()}",
            segment=region,
            attributes={
                "type": "arcade_rom",
                "region": region,
                "address": address,
                "file_offset": file_offset,
            },
        )

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        region = location.attributes.get("region")
        address = location.attributes.get("address")
        if not isinstance(region, str):
            raise ValueError("Arcade ROM location missing region attribute")
        if not isinstance(address, int):
            raise ValueError("Arcade ROM location missing address attribute")
        return f"{region}:{address:04X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        if location.address_space != self.name:
            return None
        region = location.attributes.get("region")
        address = location.attributes.get("address")
        if not isinstance(region, str) or not isinstance(address, int):
            return None
        if region not in self.region_bases:
            return None
        return self.region_bases[region] + address


# Additional stub codecs for compatibility

@dataclass(slots=True)
class AtariJaguarRomCodec:
    """Atari Jaguar ROM address codec.

    The Atari Jaguar uses a 24-bit address space with the Motorola 68000 CPU
    and custom GPU/DSP chips (Tom and Jerry).

    Memory Map:
        - 68000 RAM: 0x000000-0x1FFFFF (2MB)
        - Cartridge ROM: 0x800000-0x9FFFFF (2MB)
        - Extended Cartridge: 0xA00000-0xDFFFFF (4MB)
        - Boot ROM: 0xE00000-0xE1FFFF (128KB)
        - GPU RAM (Tom): 0xF00000-0xF0FFFF (64KB)
        - DSP RAM (Jerry): 0xF10000-0xF1FFFF (64KB)

    Address formats:
        - "$XXXXXX" (dollar sign prefix with 6 hex digits)
        - "0x00XXXXXX" (0x prefix with 8 hex digits, upper 2 bytes ignored)
        - Raw hex (6 hex digits)

    File offset is calculated only for cartridge addresses (0x800000-0xDFFFFF)
    as offset = address - 0x800000.
    """

    name: str = "jaguar-rom"
    _jaguar_pattern: re.Pattern[str] = field(init=False, repr=False)

    # Memory region definitions: (start, end, region_name, segment_name, is_cartridge, is_boot_rom)
    _regions: list[tuple[int, int, str, str, bool, bool]] = field(default_factory=lambda: [
        (0x000000, 0x1FFFFF, "ram", "ram", False, False),
        (0x800000, 0x9FFFFF, "cart_rom", "cart", True, False),
        (0xA00000, 0xDFFFFF, "cart_rom", "cart", True, False),
        (0xE00000, 0xE1FFFF, "boot_rom", "boot", False, True),
        (0xF00000, 0xF0FFFF, "gpu_ram", "gpu_ram", False, False),
        (0xF10000, 0xF1FFFF, "dsp_ram", "dsp_ram", False, False),
    ])

    def __post_init__(self) -> None:
        # Pattern matches:
        # - $XXXXXX (dollar prefix + 6 hex digits)
        # - 0x00XXXXXX or 0x00800000 (0x prefix + 8 hex digits, will be normalized to 24-bit)
        # - Raw 6-digit hex like 800000 or 001000
        self._jaguar_pattern = re.compile(
            r"(?<![A-Za-z0-9_])\$([0-9A-Fa-f]{6})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_])0x00([0-9A-Fa-f]{6})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_])0x([0-9A-Fa-f]{8})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_\$])([0-9A-Fa-f]{6})(?![A-Za-z0-9_])",
            re.IGNORECASE,
        )

    def _get_region(self, address: int) -> tuple[str, str, bool, bool] | None:
        """Get region info for an address. Returns (region, segment, is_cart, is_boot) or None."""
        for start, end, region, segment, is_cart, is_boot in self._regions:
            if start <= address <= end:
                return (region, segment, is_cart, is_boot)
        return None

    def _calculate_file_offset(self, address: int) -> int | None:
        """Calculate file offset for cartridge addresses."""
        if 0x800000 <= address <= 0xDFFFFF:
            return address - 0x800000
        return None

    def extract_refs(self, text: str) -> list[str]:
        """Extract Jaguar address references from text.

        Returns canonical "$XXXXXX" format for all matches.
        """
        results = []
        seen = set()
        for match in self._jaguar_pattern.finditer(text):
            addr_str = match.group(1) or match.group(2) or match.group(3) or match.group(4)
            if addr_str:
                try:
                    addr = int(addr_str, 16)
                    # Only accept 24-bit addresses (0x000000-0xFFFFFF)
                    if 0 <= addr <= 0xFFFFFF:
                        canonical = f"${addr:06X}"
                        if canonical not in seen:
                            seen.add(canonical)
                            results.append(canonical)
                except ValueError:
                    continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        """Parse a Jaguar address reference into an AddressLocation."""
        raw = ref.strip().replace("_", "")
        cleaned = raw.lower()

        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]

        # Must be 6 hex digits (24-bit) or 8 hex digits (will use lower 24 bits)
        if len(cleaned) == 8:
            # For 8-digit addresses, use lower 24 bits (last 6 hex digits)
            cleaned = cleaned[2:]

        if len(cleaned) != 6 or not all(c in "0123456789abcdef" for c in cleaned):
            return None

        try:
            address = int(cleaned, 16)
        except ValueError:
            return None

        # Address must be in valid 24-bit range
        if not (0 <= address <= 0xFFFFFF):
            return None

        region_info = self._get_region(address)
        if region_info is None:
            # Address is valid but not in a known region
            region, segment, is_cart, is_boot = ("unknown", "unknown", False, False)
        else:
            region, segment, is_cart, is_boot = region_info

        file_offset = self._calculate_file_offset(address)

        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"${address:06X}",
            segment=segment,
            attributes={
                "address": address,
                "region": region,
                "is_cartridge": is_cart,
                "is_boot_rom": is_boot,
                "file_offset": file_offset,
            },
        )

    def format(self, location: AddressLocation) -> str:
        """Format an AddressLocation as a canonical Jaguar address string."""
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("Jaguar ROM location missing address attribute")
        return f"${address:06X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        """Convert an AddressLocation to a file offset."""
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        return self._calculate_file_offset(address)


@dataclass(slots=True)
class DreamcastBinCodec:
    """Sega Dreamcast BIN/IP.BIN address codec.

    The Sega Dreamcast uses a Hitachi SH-4 CPU (SuperH RISC) with a 32-bit
    address space divided into multiple memory regions.

    Memory Map:
        - Boot ROM: 0x00000000-0x0001FFFF (128KB, mirrored at 0x00200000)
        - Flash ROM: 0x00200000-0x0021FFFF (128KB system flash)
        - Sound RAM: 0x00800000-0x00807FFF (128KB AICA sound RAM)
        - VRAM: 0x05000000-0x057FFFFF (8MB, 32-bit accessible)
        - Main RAM (P1, cacheable): 0x0C000000-0x0CFFFFFF (16MB)
        - Main RAM (P2, non-cacheable): 0x8C000000-0x8CFFFFFF (16MB)

    For BIN files, the file offset is calculated relative to the Main RAM
    base address (0x8C000000 for P2, which is the most common load address).

    Address formats:
        - "0x8C000000" (full 32-bit hex with 0x prefix)
        - "$8C000000" (full 32-bit hex with dollar sign)
        - "0x0C010000" (P1 cacheable RAM address)

    Examples:
        "0x8C000000" -> Main RAM P2 base (non-cacheable)
        "0x8C010000" -> Main RAM P2 + 0x10000
        "0x0C000000" -> Main RAM P1 base (cacheable)
        "0x05000000" -> VRAM base
    """

    name: str = "dreamcast-bin"
    _pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Pattern for Dreamcast addresses: 0xXXXXXXXX or $XXXXXXXX
        self._pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:0x)?([0-9A-Fa-f]{8})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_])\$([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def _is_valid_address(self, addr: int) -> bool:
        """Check if address is in a valid Dreamcast memory region."""
        # Boot ROM: 0x00000000-0x0001FFFF
        if 0x00000000 <= addr <= 0x0001FFFF:
            return True
        # Boot ROM mirror: 0x00200000-0x0021FFFF
        if 0x00200000 <= addr <= 0x0021FFFF:
            return True
        # Flash ROM: 0x00200000-0x0021FFFF (same range as boot mirror)
        # Sound RAM: 0x00800000-0x00807FFF
        if 0x00800000 <= addr <= 0x00807FFF:
            return True
        # VRAM: 0x05000000-0x057FFFFF (8MB)
        if 0x05000000 <= addr <= 0x057FFFFF:
            return True
        # Main RAM P1 (cacheable): 0x0C000000-0x0CFFFFFF
        if 0x0C000000 <= addr <= 0x0CFFFFFF:
            return True
        # Main RAM P2 (non-cacheable): 0x8C000000-0x8CFFFFFF
        if 0x8C000000 <= addr <= 0x8CFFFFFF:
            return True
        return False

    def _get_region_info(self, addr: int) -> tuple[str, str]:
        """Get (region_name, memory_type) tuple for an address."""
        if 0x00000000 <= addr <= 0x0001FFFF:
            return ("boot_rom", "rom")
        if 0x00200000 <= addr <= 0x0021FFFF:
            return ("flash_rom", "rom")
        if 0x00800000 <= addr <= 0x00807FFF:
            return ("sound_ram", "ram")
        if 0x05000000 <= addr <= 0x057FFFFF:
            return ("vram", "vram")
        if 0x0C000000 <= addr <= 0x0CFFFFFF:
            return ("main_ram_p1", "ram")
        if 0x8C000000 <= addr <= 0x8CFFFFFF:
            return ("main_ram_p2", "ram")
        return ("unknown", "unknown")

    def _normalize_address(self, addr: int) -> int:
        """Normalize P1 addresses to P2 for canonical form."""
        # P1 (cacheable) and P2 (non-cacheable) are the same physical RAM
        # Normalize P1 to P2 for consistency
        if 0x0C000000 <= addr <= 0x0CFFFFFF:
            return addr - 0x0C000000 + 0x8C000000
        return addr

    def extract_refs(self, text: str) -> list[str]:
        """Extract Dreamcast BIN address references from text.

        Matches patterns like:
            - "0x8C000000", "0x8CFFFFFF" (Main RAM P2 addresses)
            - "0x0C000000", "0x0CFFFFFF" (Main RAM P1 addresses)
            - "$8C000000", "$0C010000" (with dollar sign)
            - "0x05000000" (VRAM addresses)
            - "0x00800000" (Sound RAM addresses)

        Returns:
            List of matched address strings in canonical form (0x8CXXXXXX)
        """
        results = []
        seen = set()

        for match in self._pattern.finditer(text):
            addr_str = match.group(1) if match.group(1) else match.group(2)
            if addr_str:
                try:
                    addr = int(addr_str, 16)
                    if self._is_valid_address(addr):
                        # Normalize P1 addresses to P2 for canonical form
                        normalized = self._normalize_address(addr)
                        ref = f"0x{normalized:08X}"
                        if ref not in seen:
                            results.append(ref)
                            seen.add(ref)
                except ValueError:
                    continue

        return results

    def parse(self, ref: str) -> AddressLocation | None:
        """Parse a Dreamcast BIN reference into an AddressLocation.

        Args:
            ref: A reference string like "0x8C000000", "$8C010000",
                 "0x0C000000", or "0x05000000"

        Returns:
            AddressLocation with address type and memory region info in attributes,
            or None if invalid
        """
        raw = ref.strip().replace("_", "")

        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]

        if len(cleaned) < 1 or len(cleaned) > 8:
            return None
        if not all(c in "0123456789abcdef" for c in cleaned):
            return None

        try:
            address = int(cleaned, 16)
        except ValueError:
            return None

        if not self._is_valid_address(address):
            return None

        region, mem_type = self._get_region_info(address)
        file_offset = self._calculate_file_offset(address, region)

        # Normalize P1 to P2 for canonical storage
        normalized_address = self._normalize_address(address)

        return AddressLocation(
            address_space=self.name,
            start=normalized_address,
            end=normalized_address,
            display=f"0x{normalized_address:08X}",
            segment=region,
            attributes={
                "address": normalized_address,
                "original_address": address,
                "address_hex": f"0x{normalized_address:08X}",
                "original_address_hex": f"0x{address:08X}",
                "region": region,
                "memory_type": mem_type,
                "type": "dreamcast_bin",
                "file_offset": file_offset,
            },
        )

    def _calculate_file_offset(self, address: int, region: str) -> int | None:
        """Calculate file offset from Dreamcast address.

        For BIN files, the offset is calculated relative to the Main RAM base.
        P1 (cacheable) addresses are mapped as if they were P2 addresses.
        """
        if region == "main_ram_p2":
            return address - 0x8C000000
        if region == "main_ram_p1":
            # P1 is the same physical RAM as P2, map to same offset
            # Handle both normalized (P2) and original (P1) address formats
            if 0x8C000000 <= address <= 0x8CFFFFFF:
                # Address is already normalized to P2 form
                return address - 0x8C000000
            else:
                # Address is in original P1 form
                return address - 0x0C000000
        # Other regions don't have a simple file offset in BIN files
        return None

    def format(self, location: AddressLocation) -> str:
        """Format an AddressLocation back to canonical Dreamcast BIN form."""
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")

        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("Dreamcast BIN location missing address attribute")

        return f"0x{address:08X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        """Convert Dreamcast BIN location to file offset."""
        if location.address_space != self.name:
            return None

        address = location.attributes.get("address")
        region = location.attributes.get("region")

        if not isinstance(address, int):
            return None
        if not isinstance(region, str):
            # Try to determine region from address
            region, _ = self._get_region_info(address)

        return self._calculate_file_offset(address, region)


@dataclass(slots=True)
class ThreeDoIsoCodec:
    """3DO ISO address codec (stub)."""
    name: str = "3do-iso"
    
    def __post_init__(self) -> None:
        pass
    
    def extract_refs(self, text: str) -> list[str]:
        return []
    
    def parse(self, ref: str) -> AddressLocation | None:
        return None
    
    def format(self, location: AddressLocation) -> str:
        raise ValueError("Not implemented")
    
    def to_file_offset(self, location: AddressLocation) -> int | None:
        return None


@dataclass(slots=True)
class NdsRomCodec:
    """Nintendo DS ROM address codec.

    The Nintendo DS has a dual-processor architecture:
        - ARM9: Main CPU for game logic, graphics processing
        - ARM7: I/O processor for sound, WiFi, touch screen

    Memory Map:
        - ARM9 Main RAM: 0x02000000-0x023FFFFF (4MB on DS)
          Extended to 0x02FFFFFF (16MB) on DSi/TWL
        - Shared WRAM: 0x03000000-0x037FFFFF (configurable split)
        - ARM7 WRAM: 0x03800000-0x0380FFFF (64KB dedicated)
        - VRAM: 0x06000000-0x068FFFFF (656KB, multiple banks)
        - GBA Slot ROM: 0x08000000-0x09FFFFFF (GBA cartridge space)

    Address formats:
        - "0x02000000" (full 32-bit hex with prefix)
        - "$2000000" (dollar prefix, 7 hex digits typical for DS)

    Examples:
        "0x02000000" -> ARM9 RAM base
        "0x02004000" -> ARM9 RAM + 0x4000
        "0x03800000" -> ARM7 WRAM base
        "0x08000000" -> GBA Slot ROM base
    """

    name: str = "nds-rom"
    _pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Pattern for DS addresses: 0x02xxxxxx, 0x03xxxxxx, 0x06xxxxxx, 0x08xxxxxx, $ prefixed
        self._pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:0x)?([0-9A-Fa-f]{8})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_])\$([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def _is_valid_address(self, addr: int) -> bool:
        """Check if address is in a valid NDS memory region."""
        # ARM9 Main RAM: 0x02000000-0x023FFFFF (DS), up to 0x02FFFFFF (DSi)
        if 0x02000000 <= addr <= 0x02FFFFFF:
            return True
        # Shared WRAM: 0x03000000-0x037FFFFF
        if 0x03000000 <= addr <= 0x037FFFFF:
            return True
        # ARM7 WRAM: 0x03800000-0x0380FFFF
        if 0x03800000 <= addr <= 0x0380FFFF:
            return True
        # VRAM: 0x06000000-0x068FFFFF
        if 0x06000000 <= addr <= 0x068FFFFF:
            return True
        # GBA Slot ROM: 0x08000000-0x09FFFFFF
        if 0x08000000 <= addr <= 0x09FFFFFF:
            return True
        return False

    def _get_region_info(self, addr: int) -> tuple[str, str]:
        """Get (region_name, cpu) tuple for an address."""
        if 0x02000000 <= addr <= 0x023FFFFF:
            return ("arm9_ram", "arm9")
        if 0x02400000 <= addr <= 0x02FFFFFF:
            return ("arm9_ram_extended", "arm9")
        if 0x03000000 <= addr <= 0x037FFFFF:
            return ("shared_wram", "both")
        if 0x03800000 <= addr <= 0x0380FFFF:
            return ("arm7_wram", "arm7")
        if 0x06000000 <= addr <= 0x068FFFFF:
            return ("vram", "arm9")
        if 0x08000000 <= addr <= 0x09FFFFFF:
            return ("gba_slot", "gba")
        return ("unknown", "unknown")

    def extract_refs(self, text: str) -> list[str]:
        """Extract NDS ROM address references from text.

        Matches patterns like:
            - "0x02000000", "0x023FFFFF" (ARM9 RAM addresses)
            - "0x03800000" (ARM7 WRAM)
            - "0x08000000" (GBA Slot)
            - "$2000000", "$3800000" (with dollar sign)

        Returns:
            List of matched address strings in canonical form (0xXXXXXXXX)
        """
        results = []
        seen = set()

        for match in self._pattern.finditer(text):
            addr_str = match.group(1) if match.group(1) else match.group(2)
            if addr_str:
                try:
                    addr = int(addr_str, 16)
                    if self._is_valid_address(addr):
                        ref = f"0x{addr:08X}"
                        if ref not in seen:
                            results.append(ref)
                            seen.add(ref)
                except ValueError:
                    continue

        return results

    def parse(self, ref: str) -> AddressLocation | None:
        """Parse an NDS ROM reference into an AddressLocation.

        Args:
            ref: A reference string like "0x02000000", "$2000000", or "0x08000000"

        Returns:
            AddressLocation with address type and CPU region info in attributes,
            or None if invalid
        """
        raw = ref.strip().replace("_", "")

        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]

        if len(cleaned) < 1 or len(cleaned) > 8:
            return None
        if not all(c in "0123456789abcdef" for c in cleaned):
            return None

        try:
            address = int(cleaned, 16)
        except ValueError:
            return None

        if not self._is_valid_address(address):
            return None

        region, cpu = self._get_region_info(address)
        file_offset = self._calculate_file_offset(address, region)

        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"0x{address:08X}",
            segment=region,
            attributes={
                "address": address,
                "address_hex": f"0x{address:08X}",
                "region": region,
                "cpu": cpu,
                "type": "nds_rom",
                "file_offset": file_offset,
            },
        )

    def _calculate_file_offset(self, address: int, region: str) -> int | None:
        """Calculate file offset from NDS ROM address."""
        # For ARM9 RAM, return offset from base
        if region == "arm9_ram":
            return address - 0x02000000
        # For ARM7 WRAM, return offset from base
        if region == "arm7_wram":
            return address - 0x03800000
        # For GBA slot, similar to GBA ROM
        if region == "gba_slot":
            return address - 0x08000000
        # Shared WRAM and VRAM don't have simple file offsets
        return None

    def format(self, location: AddressLocation) -> str:
        """Format an AddressLocation back to canonical NDS ROM form."""
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")

        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("NDS ROM location missing address attribute")

        return f"0x{address:08X}"

    def to_file_offset(self, location: AddressLocation) -> int | None:
        """Convert NDS ROM location to file offset."""
        if location.address_space != self.name:
            return None

        address = location.attributes.get("address")
        region = location.attributes.get("region")

        if not isinstance(address, int):
            return None
        if not isinstance(region, str):
            return None

        return self._calculate_file_offset(address, region)


class PspElfCodec:
    """PlayStation Portable (PSP) ELF/PRX address codec.

    The PSP uses a MIPS R4000-based CPU (Allegrex) with the following memory map:

    Memory regions:
        - Scratchpad RAM: 0x00010000-0x00013FFF (16KB, fast on-chip RAM)
        - VRAM: 0x04000000-0x048FFFFF (8MB, frame buffer, also mappable to 0x40000000)
        - User memory: 0x08800000-0x0BFFFFFF (main user RAM, 56MB)
        - Kernel memory (cached): 0x08000000-0x083FFFFF (4MB)
        - Kernel memory (uncached): 0x88000000-0x883FFFFF (4MB, system)

    Address formats:
        - "0x08800000" (32-bit hex with prefix, canonical form)
        - "$8800000" (dollar prefix, 7-8 hex digits)
        - "8800000" (8 hex digits without prefix)

    File offset calculation:
        - For user addresses: offset = address - load_base (default 0x08800000)
        - For kernel cached (0x08xxxxxx): offset = address - 0x08000000
        - For kernel uncached (0x88xxxxxx): offset = address - 0x88000000
        - For VRAM: offset = address - 0x04000000 + vram_base_offset
        - Scratchpad has no file offset in ELF/PRX files

    Modules typically load at 0x08800000 (user space). PRX files are relocatable
    ELF files with additional PSP-specific sections.

    Examples:
        "0x08800000" -> file offset 0 (module base)
        "0x08801234" -> file offset 0x1234
        "0x88000000" -> file offset 0 (kernel uncached base)
    """

    name: str = "psp-elf"
    default_load_base: int = 0x08800000
    vram_base_offset: int = 0x00000000
    _hex_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._hex_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:0x)?([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])|"
            r"(?<![A-Za-z0-9_])\$([0-9A-Fa-f]{1,8})(?![A-Za-z0-9_])",
            re.IGNORECASE
        )

    def _is_valid_psp_address(self, addr: int) -> bool:
        if 0x00010000 <= addr <= 0x00013FFF:
            return True
        if 0x04000000 <= addr <= 0x048FFFFF:
            return True
        if 0x08000000 <= addr <= 0x083FFFFF:
            return True
        if 0x08800000 <= addr <= 0x0BFFFFFF:
            return True
        if 0x88000000 <= addr <= 0x883FFFFF:
            return True
        return False

    def _get_memory_region(self, addr: int) -> tuple[str, str]:
        if 0x00010000 <= addr <= 0x00013FFF:
            return ("scratchpad", "scratchpad")
        if 0x04000000 <= addr <= 0x048FFFFF:
            return ("vram", "vram")
        if 0x08000000 <= addr <= 0x083FFFFF:
            return ("kernel_cached", "kernel")
        if 0x08800000 <= addr <= 0x0BFFFFFF:
            return ("user", "user")
        if 0x88000000 <= addr <= 0x883FFFFF:
            return ("kernel_uncached", "kernel")
        return ("unknown", "unknown")

    def _calculate_file_offset(self, addr: int, load_base: int | None = None) -> int | None:
        region, _ = self._get_memory_region(addr)
        if region == "user":
            if load_base is None:
                load_base = self.default_load_base
            if addr >= load_base:
                return addr - load_base
            return None
        if region == "kernel_cached":
            return addr - 0x08000000
        if region == "kernel_uncached":
            return addr - 0x88000000
        if region == "vram":
            return (addr - 0x04000000) + self.vram_base_offset
        return None

    def extract_refs(self, text: str) -> list[str]:
        results = []
        seen = set()
        for match in self._hex_pattern.finditer(text):
            addr_str = match.group(1) if match.group(1) else match.group(2)
            if addr_str:
                try:
                    # Check if this is a 7-digit address starting with 8-F
                    # These should be treated as kernel addresses (0x8xxxxxxx, 0x9xxxxxxx, etc.)
                    # For example, "8800000" should become 0x88000000, not 0x08800000
                    if len(addr_str) == 7 and addr_str[0].upper() in "89ABCDEF":
                        # Pad with '0' at the end to make it 8 digits
                        # "8800000" -> "88000000" (0x88000000)
                        kernel_addr = int(addr_str + "0", 16)
                        if self._is_valid_psp_address(kernel_addr):
                            ref = f"0x{kernel_addr:08X}"
                            if ref not in seen:
                                results.append(ref)
                                seen.add(ref)
                    else:
                        addr = int(addr_str, 16)
                        if self._is_valid_psp_address(addr):
                            ref = f"0x{addr:08X}"
                            if ref not in seen:
                                results.append(ref)
                                seen.add(ref)
                except ValueError:
                    continue
        return results

    def parse(self, ref: str) -> AddressLocation | None:
        raw = ref.strip().replace("_", "")
        cleaned = raw.lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("$"):
            cleaned = cleaned[1:]
        if len(cleaned) < 1 or len(cleaned) > 8:
            return None
        if not all(c in "0123456789abcdef" for c in cleaned):
            return None
        try:
            address = int(cleaned, 16)
        except ValueError:
            return None
        if not self._is_valid_psp_address(address):
            return None
        region, segment = self._get_memory_region(address)
        file_offset = self._calculate_file_offset(address)
        is_kernel = region in ("kernel_cached", "kernel_uncached")
        is_user = region == "user"
        attrs: dict[str, object] = {
            "address": address,
            "address_hex": f"0x{address:08X}",
            "memory_region": region,
            "type": "psp_elf",
            "is_user_space": is_user,
            "is_kernel_space": is_kernel,
            "file_offset": file_offset,
        }
        if region == "user":
            attrs["load_base"] = self.default_load_base
        elif region == "kernel_cached":
            attrs["kernel_base"] = 0x08000000
        elif region == "kernel_uncached":
            attrs["kernel_base"] = 0x88000000
        elif region == "vram":
            attrs["vram_base"] = 0x04000000
        elif region == "scratchpad":
            attrs["scratchpad_base"] = 0x00010000
        return AddressLocation(
            address_space=self.name,
            start=address,
            end=address,
            display=f"0x{address:08X}",
            segment=segment,
            attributes=attrs,
        )

    def format(self, location: AddressLocation) -> str:
        if location.address_space != self.name:
            raise ValueError(f"unsupported address space: {location.address_space}")
        address = location.attributes.get("address")
        if not isinstance(address, int):
            raise ValueError("PSP ELF location missing address attribute")
        return f"0x{address:08X}"

    def to_file_offset(self, location: AddressLocation, load_base: int | None = None) -> int | None:
        if location.address_space != self.name:
            return None
        address = location.attributes.get("address")
        if not isinstance(address, int):
            return None
        return self._calculate_file_offset(address, load_base)
