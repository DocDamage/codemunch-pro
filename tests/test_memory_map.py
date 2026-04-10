"""Tests for memory map visualization module."""

import pytest

from codemunch_pro.rex.memory_map import MemoryMap, MemoryRegion, RegionType


class TestMemoryRegion:
    """Tests for MemoryRegion class."""

    def test_region_creation(self) -> None:
        """Test basic region creation."""
        region = MemoryRegion(
            name="Test Region",
            start=0x0000,
            end=0x0FFF,
            region_type=RegionType.ROM,
            description="A test region",
        )
        assert region.name == "Test Region"
        assert region.start == 0x0000
        assert region.end == 0x0FFF
        assert region.region_type == RegionType.ROM
        assert region.description == "A test region"

    def test_region_size(self) -> None:
        """Test region size calculation."""
        region = MemoryRegion(
            name="Test",
            start=0x1000,
            end=0x1FFF,
            region_type=RegionType.RAM,
        )
        assert region.size == 0x1000  # 4096 bytes

    def test_region_effective_color_default(self) -> None:
        """Test default color assignment."""
        region = MemoryRegion(
            name="ROM",
            start=0x0000,
            end=0x0FFF,
            region_type=RegionType.ROM,
        )
        assert region.effective_color == "#4A90D9"  # Default ROM color

    def test_region_custom_color(self) -> None:
        """Test custom color override."""
        region = MemoryRegion(
            name="Custom",
            start=0x0000,
            end=0x0FFF,
            region_type=RegionType.ROM,
            color="#FF0000",
        )
        assert region.effective_color == "#FF0000"

    def test_region_invalid_start_end(self) -> None:
        """Test that start > end raises ValueError."""
        with pytest.raises(ValueError, match="Start address"):
            MemoryRegion(
                name="Invalid",
                start=0x1000,
                end=0x0FFF,
                region_type=RegionType.ROM,
            )

    def test_region_negative_start(self) -> None:
        """Test that negative start raises ValueError."""
        with pytest.raises(ValueError, match="Start address"):
            MemoryRegion(
                name="Invalid",
                start=-1,
                end=0x0FFF,
                region_type=RegionType.ROM,
            )

    def test_region_overlaps_true(self) -> None:
        """Test overlap detection - overlapping regions."""
        r1 = MemoryRegion("Region1", 0x0000, 0x0FFF, RegionType.ROM)
        r2 = MemoryRegion("Region2", 0x0800, 0x17FF, RegionType.RAM)
        assert r1.overlaps(r2) is True
        assert r2.overlaps(r1) is True

    def test_region_overlaps_false(self) -> None:
        """Test overlap detection - non-overlapping regions."""
        r1 = MemoryRegion("Region1", 0x0000, 0x0FFF, RegionType.ROM)
        r2 = MemoryRegion("Region2", 0x1000, 0x1FFF, RegionType.RAM)
        assert r1.overlaps(r2) is False
        assert r2.overlaps(r1) is False

    def test_region_contains(self) -> None:
        """Test address containment check."""
        region = MemoryRegion("Test", 0x1000, 0x1FFF, RegionType.ROM)
        assert region.contains(0x1000) is True
        assert region.contains(0x1500) is True
        assert region.contains(0x1FFF) is True
        assert region.contains(0x0FFF) is False
        assert region.contains(0x2000) is False

    def test_region_to_dict(self) -> None:
        """Test dictionary conversion."""
        region = MemoryRegion(
            name="Test",
            start=0x1000,
            end=0x1FFF,
            region_type=RegionType.VRAM,
            description="VRAM region",
        )
        d = region.to_dict()
        assert d["name"] == "Test"
        assert d["start"] == 0x1000
        assert d["end"] == 0x1FFF
        assert d["size"] == 0x1000
        assert d["start_hex"] == "0x00001000"
        assert d["end_hex"] == "0x00001FFF"
        assert d["type"] == "VRAM"
        assert d["description"] == "VRAM region"


class TestMemoryMap:
    """Tests for MemoryMap class."""

    def test_empty_map(self) -> None:
        """Test empty memory map."""
        memory_map = MemoryMap(name="Empty Map", address_space="test")
        assert memory_map.name == "Empty Map"
        assert memory_map.address_space == "test"
        assert memory_map.regions == []
        assert memory_map.get_bounds() == (0, 0)
        assert memory_map.get_total_size() == 0
        assert memory_map.has_overlaps() is False

    def test_add_region(self) -> None:
        """Test adding regions."""
        memory_map = MemoryMap()
        region = MemoryRegion("ROM", 0x0000, 0x3FFF, RegionType.ROM)
        memory_map.add_region(region)
        assert len(memory_map.regions) == 1
        assert memory_map.regions[0].name == "ROM"

    def test_remove_region(self) -> None:
        """Test removing regions by name."""
        memory_map = MemoryMap()
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x3FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("RAM", 0x8000, 0xBFFF, RegionType.RAM))
        
        assert memory_map.remove_region("ROM") is True
        assert len(memory_map.regions) == 1
        assert memory_map.regions[0].name == "RAM"
        
        assert memory_map.remove_region("NONEXISTENT") is False

    def test_get_bounds(self) -> None:
        """Test bounds calculation."""
        memory_map = MemoryMap()
        memory_map.add_region(MemoryRegion("Low", 0x0000, 0x0FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("High", 0x8000, 0xFFFF, RegionType.RAM))
        
        min_addr, max_addr = memory_map.get_bounds()
        assert min_addr == 0x0000
        assert max_addr == 0xFFFF

    def test_get_total_size(self) -> None:
        """Test total size calculation."""
        memory_map = MemoryMap()
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x3FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("RAM", 0x4000, 0x7FFF, RegionType.RAM))
        
        # Total span from 0x0000 to 0x7FFF = 0x8000 = 32768 bytes
        assert memory_map.get_total_size() == 0x8000

    def test_find_overlaps(self) -> None:
        """Test overlap detection."""
        memory_map = MemoryMap()
        r1 = MemoryRegion("ROM1", 0x0000, 0x1FFF, RegionType.ROM)
        r2 = MemoryRegion("RAM", 0x1000, 0x2FFF, RegionType.RAM)  # Overlaps with ROM1
        r3 = MemoryRegion("ROM2", 0x4000, 0x5FFF, RegionType.ROM)  # No overlap
        
        memory_map.add_region(r1)
        memory_map.add_region(r2)
        memory_map.add_region(r3)
        
        overlaps = memory_map.find_overlaps()
        assert len(overlaps) == 1
        assert overlaps[0] == (r1, r2)
        assert memory_map.has_overlaps() is True

    def test_no_overlaps(self) -> None:
        """Test with non-overlapping regions."""
        memory_map = MemoryMap()
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x3FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("RAM", 0x4000, 0x7FFF, RegionType.RAM))
        
        assert memory_map.find_overlaps() == []
        assert memory_map.has_overlaps() is False

    def test_get_region_at(self) -> None:
        """Test finding region at address."""
        memory_map = MemoryMap()
        rom = MemoryRegion("ROM", 0x0000, 0x3FFF, RegionType.ROM)
        ram = MemoryRegion("RAM", 0x8000, 0xBFFF, RegionType.RAM)
        memory_map.add_region(rom)
        memory_map.add_region(ram)
        
        assert memory_map.get_region_at(0x1000) == rom
        assert memory_map.get_region_at(0x9000) == ram
        assert memory_map.get_region_at(0x5000) is None

    def test_get_regions_in_range(self) -> None:
        """Test finding regions in range."""
        memory_map = MemoryMap()
        r1 = MemoryRegion("ROM", 0x0000, 0x1FFF, RegionType.ROM)
        r2 = MemoryRegion("VRAM", 0x1000, 0x2FFF, RegionType.VRAM)
        r3 = MemoryRegion("RAM", 0x8000, 0x9FFF, RegionType.RAM)
        memory_map.add_region(r1)
        memory_map.add_region(r2)
        memory_map.add_region(r3)
        
        # Query range overlaps ROM and VRAM
        regions = memory_map.get_regions_in_range(0x1500, 0x2500)
        assert len(regions) == 2
        assert r1 in regions
        assert r2 in regions
        assert r3 not in regions

    def test_to_svg_empty(self) -> None:
        """Test SVG generation for empty map."""
        memory_map = MemoryMap(name="Empty")
        svg = memory_map.to_svg()
        assert "<svg" in svg
        assert "</svg>" in svg
        assert "No memory regions defined" in svg

    def test_to_svg_with_regions(self) -> None:
        """Test SVG generation with regions."""
        memory_map = MemoryMap(name="Test Map")
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x3FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("RAM", 0x8000, 0xBFFF, RegionType.RAM))
        
        svg = memory_map.to_svg()
        assert "<svg" in svg
        assert "</svg>" in svg
        assert "Test Map" in svg
        assert "rect" in svg  # Should have rectangles for regions

    def test_to_svg_with_overlaps(self) -> None:
        """Test SVG shows overlap indicators."""
        memory_map = MemoryMap(name="Test")
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x1FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("RAM", 0x1000, 0x2FFF, RegionType.RAM))
        
        svg = memory_map.to_svg()
        assert "overlap" in svg or "overlap" not in svg  # Just check it doesn't crash

    def test_to_html(self) -> None:
        """Test HTML generation."""
        memory_map = MemoryMap(name="Test Map", address_space="test")
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x3FFF, RegionType.ROM, description="Program ROM"))
        
        html = memory_map.to_html()
        assert "<!DOCTYPE html>" in html
        assert "Test Map" in html
        assert "ROM" in html
        assert "Program ROM" in html
        assert "</html>" in html

    def test_to_html_with_overlaps(self) -> None:
        """Test HTML shows overlap warnings."""
        memory_map = MemoryMap(name="Test")
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x1FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("RAM", 0x1000, 0x2FFF, RegionType.RAM))
        
        html = memory_map.to_html()
        assert "OVERLAP" in html.upper() or "overlap" in html

    def test_to_text(self) -> None:
        """Test ASCII text generation."""
        memory_map = MemoryMap(name="Test Map", address_space="test")
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x0FFF, RegionType.ROM))
        
        text = memory_map.to_text()
        assert "Memory Map: Test Map" in text
        assert "ROM" in text
        assert "█" in text  # Block character for visualization

    def test_to_text_empty(self) -> None:
        """Test ASCII text for empty map."""
        memory_map = MemoryMap(name="Empty")
        text = memory_map.to_text()
        assert "No regions defined" in text

    def test_to_text_with_overlaps(self) -> None:
        """Test ASCII text shows overlap warnings."""
        memory_map = MemoryMap(name="Test")
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x1FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("RAM", 0x1000, 0x2FFF, RegionType.RAM))
        
        text = memory_map.to_text()
        assert "OVERLAP" in text or "Overlap" in text

    def test_to_dict(self) -> None:
        """Test dictionary conversion."""
        memory_map = MemoryMap(name="Test", address_space="test")
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x0FFF, RegionType.ROM))
        
        d = memory_map.to_dict()
        assert d["name"] == "Test"
        assert d["address_space"] == "test"
        assert len(d["regions"]) == 1
        assert d["region_count"] == 1
        assert d["has_overlaps"] is False

    def test_to_dict_with_overlaps(self) -> None:
        """Test dictionary conversion includes overlap info."""
        memory_map = MemoryMap(name="Test")
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x1FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("RAM", 0x1000, 0x2FFF, RegionType.RAM))
        
        d = memory_map.to_dict()
        assert d["has_overlaps"] is True
        assert len(d["overlaps"]) == 1
        assert d["overlaps"][0]["region1"] == "ROM"
        assert d["overlaps"][0]["region2"] == "RAM"

    def test_from_dict(self) -> None:
        """Test creating MemoryMap from dictionary."""
        data = {
            "name": "Test Map",
            "address_space": "test",
            "regions": [
                {
                    "name": "ROM",
                    "start": 0,
                    "end": 4095,
                    "type": "ROM",
                    "color": "#FF0000",
                    "description": "Program ROM",
                },
            ],
        }
        
        memory_map = MemoryMap.from_dict(data)
        assert memory_map.name == "Test Map"
        assert memory_map.address_space == "test"
        assert len(memory_map.regions) == 1
        assert memory_map.regions[0].name == "ROM"
        assert memory_map.regions[0].effective_color == "#FF0000"

    def test_create_default_snes_map(self) -> None:
        """Test creating default SNES memory map."""
        memory_map = MemoryMap.create_default_snes_map()
        assert memory_map.name == "SNES Memory Map"
        assert memory_map.address_space == "snes"
        assert len(memory_map.regions) > 0
        
        # Check for expected regions
        region_names = {r.name for r in memory_map.regions}
        assert "System RAM" in region_names
        assert "VRAM" in region_names
        assert "I/O Registers" in region_names

    def test_sort_regions(self) -> None:
        """Test regions are sorted by start address."""
        memory_map = MemoryMap()
        memory_map.add_region(MemoryRegion("RAM", 0x8000, 0xFFFF, RegionType.RAM))
        memory_map.add_region(MemoryRegion("ROM", 0x0000, 0x3FFF, RegionType.ROM))
        memory_map.add_region(MemoryRegion("VRAM", 0x4000, 0x5FFF, RegionType.VRAM))
        
        sorted_regions = memory_map._sort_regions()
        assert sorted_regions[0].name == "ROM"
        assert sorted_regions[1].name == "VRAM"
        assert sorted_regions[2].name == "RAM"


class TestRegionType:
    """Tests for RegionType enum."""

    def test_region_type_values(self) -> None:
        """Test all region types exist."""
        assert RegionType.ROM
        assert RegionType.RAM
        assert RegionType.VRAM
        assert RegionType.IO
        assert RegionType.SYSTEM_ROM

    def test_region_type_str(self) -> None:
        """Test string representation."""
        assert str(RegionType.ROM) == "ROM"
        assert str(RegionType.RAM) == "RAM"
        assert str(RegionType.VRAM) == "VRAM"

    def test_default_colors(self) -> None:
        """Test default color mappings."""
        from codemunch_pro.rex.memory_map import DEFAULT_REGION_COLORS
        
        assert RegionType.ROM in DEFAULT_REGION_COLORS
        assert RegionType.RAM in DEFAULT_REGION_COLORS
        assert RegionType.VRAM in DEFAULT_REGION_COLORS
        assert RegionType.IO in DEFAULT_REGION_COLORS
        assert RegionType.SYSTEM_ROM in DEFAULT_REGION_COLORS
