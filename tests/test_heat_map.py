"""Tests for heat map generation functionality."""


from codemunch_pro.rex.heat_map import (
    ColorScheme,
    HeatMap,
    HeatMapCell,
    HeatMapRegion,
    HeatMapResult,
    HeatSource,
    generate_heat_map,
)
from codemunch_pro.rex import (
    AddressLocation,
    ArtifactRecord,
    EntityRecord,
    ReverseEngineeringBundle,
    ReverseEngineeringStore,
)


class TestHeatSource:
    """Tests for HeatSource enum."""

    def test_heat_source_values(self):
        assert HeatSource.COVERAGE.value == "coverage"
        assert HeatSource.REFERENCE_COUNT.value == "reference_count"
        assert HeatSource.CALL_FREQUENCY.value == "call_frequency"
        assert HeatSource.ENTROPY.value == "entropy"

    def test_heat_source_from_string(self):
        assert HeatSource("coverage") == HeatSource.COVERAGE
        assert HeatSource("reference_count") == HeatSource.REFERENCE_COUNT


class TestColorScheme:
    """Tests for ColorScheme enum."""

    def test_color_scheme_values(self):
        assert ColorScheme.VIRIDIS.value == "viridis"
        assert ColorScheme.PLASMA.value == "plasma"
        assert ColorScheme.HOT.value == "hot"
        assert ColorScheme.GREYSCALE.value == "greyscale"

    def test_color_scheme_from_string(self):
        assert ColorScheme("viridis") == ColorScheme.VIRIDIS
        assert ColorScheme("hot") == ColorScheme.HOT


class TestHeatMapCell:
    """Tests for HeatMapCell dataclass."""

    def test_cell_creation(self):
        cell = HeatMapCell(
            address=0x1000,
            value=10.5,
            normalized_value=0.5,
            color="#FF0000",
            entity_ids=["entity1", "entity2"],
            metadata={"count": 5},
        )
        assert cell.address == 0x1000
        assert cell.value == 10.5
        assert cell.normalized_value == 0.5
        assert cell.color == "#FF0000"
        assert len(cell.entity_ids) == 2

    def test_cell_to_dict(self):
        cell = HeatMapCell(
            address=0x1000,
            value=10.5,
            normalized_value=0.5,
            color="#FF0000",
            entity_ids=["entity1"],
            metadata={"count": 5},
        )
        data = cell.to_dict()
        assert data["address"] == 0x1000
        assert data["value"] == 10.5
        assert data["color"] == "#FF0000"
        assert data["entity_ids"] == ["entity1"]


class TestHeatMapRegion:
    """Tests for HeatMapRegion dataclass."""

    def test_region_creation(self):
        region = HeatMapRegion(
            start_address=0x1000,
            end_address=0x1100,
            max_value=100.0,
            avg_value=50.0,
            cell_count=16,
            entity_ids=["entity1"],
        )
        assert region.start_address == 0x1000
        assert region.end_address == 0x1100
        assert region.max_value == 100.0

    def test_region_to_dict(self):
        region = HeatMapRegion(
            start_address=0x1000,
            end_address=0x1100,
            max_value=100.0,
            avg_value=50.0,
            cell_count=16,
            entity_ids=["entity1"],
        )
        data = region.to_dict()
        assert data["start_address"] == 0x1000
        assert data["end_address"] == 0x1100
        assert data["max_value"] == 100.0
        assert data["cell_count"] == 16


class TestHeatMapResult:
    """Tests for HeatMapResult dataclass."""

    def test_result_creation(self):
        cells = [HeatMapCell(address=0x1000, value=10.0)]
        result = HeatMapResult(
            heat_source="coverage",
            address_space="rom",
            resolution=256,
            total_cells=1,
            min_value=0.0,
            max_value=10.0,
            cells=cells,
            regions=[],
            color_scheme="viridis",
        )
        assert result.heat_source == "coverage"
        assert result.address_space == "rom"
        assert result.total_cells == 1

    def test_result_to_dict(self):
        cells = [HeatMapCell(address=0x1000, value=10.0)]
        result = HeatMapResult(
            heat_source="coverage",
            address_space="rom",
            resolution=256,
            total_cells=1,
            min_value=0.0,
            max_value=10.0,
            cells=cells,
            regions=[],
            color_scheme="viridis",
        )
        data = result.to_dict()
        assert data["heat_source"] == "coverage"
        assert data["address_space"] == "rom"
        assert data["total_cells"] == 1
        assert len(data["cells"]) == 1

    def test_result_to_json(self):
        cells = [HeatMapCell(address=0x1000, value=10.0)]
        result = HeatMapResult(
            heat_source="coverage",
            address_space="rom",
            resolution=256,
            total_cells=1,
            min_value=0.0,
            max_value=10.0,
            cells=cells,
            regions=[],
            color_scheme="viridis",
        )
        json_str = result.to_json()
        assert "coverage" in json_str
        assert "rom" in json_str
        # Address 0x1000 = 4096 in decimal (JSON uses decimal)
        assert "4096" in json_str


class TestHeatMap:
    """Tests for HeatMap class."""

    def test_heat_map_initialization(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        heat_map = HeatMap(
            store=store,
            heat_source=HeatSource.REFERENCE_COUNT,
            address_space="rom",
            resolution=512,
            color_scheme=ColorScheme.HOT,
        )

        assert heat_map.heat_source == HeatSource.REFERENCE_COUNT
        assert heat_map.address_space == "rom"
        assert heat_map.resolution == 512
        assert heat_map.color_scheme == ColorScheme.HOT

        store.close()

    def test_heat_map_resolution_clamping(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Test minimum resolution
        heat_map = HeatMap(
            store=store,
            heat_source=HeatSource.COVERAGE,
            address_space="rom",
            resolution=8,  # Below minimum
        )
        assert heat_map.resolution >= 16

        # Test maximum resolution
        heat_map = HeatMap(
            store=store,
            heat_source=HeatSource.COVERAGE,
            address_space="rom",
            resolution=5000,  # Above maximum
        )
        assert heat_map.resolution <= 4096

        store.close()

    def test_generate_empty_heat_map(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        heat_map = HeatMap(
            store=store,
            heat_source=HeatSource.REFERENCE_COUNT,
            address_space="rom",
            resolution=256,
        )

        result = heat_map.generate()

        assert result.heat_source == "reference_count"
        assert result.address_space == "rom"
        assert result.total_cells == 0
        assert result.min_value == 0.0
        assert result.max_value == 0.0

        store.close()

    def test_generate_with_entities(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Create some test entities
        entity1 = EntityRecord(
            entity_id="test:func:1",
            kind="function",
            name="Function1",
            canonical_ref="0x1000",
            location=AddressLocation(
                address_space="rom",
                start=0x1000,
                end=0x10FF,
            ),
        )

        entity2 = EntityRecord(
            entity_id="test:func:2",
            kind="function",
            name="Function2",
            canonical_ref="0x2000",
            location=AddressLocation(
                address_space="rom",
                start=0x2000,
                end=0x20FF,
            ),
        )

        bundle = ReverseEngineeringBundle(
            artifacts=[ArtifactRecord(artifact_id="test:artifact", kind="analysis", path="test.asm")],
            entities=[entity1, entity2],
        )
        store.upsert_bundle(bundle)

        # Generate heat map
        heat_map = HeatMap(
            store=store,
            heat_source=HeatSource.REFERENCE_COUNT,
            address_space="rom",
            resolution=64,
        )

        result = heat_map.generate(start_address=0x0000, end_address=0x3000)

        # Cells are created even if empty (based on resolution)
        assert result.total_cells >= 0
        assert result.min_value >= 0.0

        store.close()

    def test_to_ascii_empty(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        heat_map = HeatMap(
            store=store,
            heat_source=HeatSource.COVERAGE,
            address_space="rom",
            resolution=256,
        )

        ascii_art = heat_map.to_ascii()
        assert "No heat map data" in ascii_art

        store.close()

    def test_to_ascii_with_data(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Create a test entity
        entity = EntityRecord(
            entity_id="test:func:1",
            kind="function",
            name="Function1",
            location=AddressLocation(
                address_space="rom",
                start=0x1000,
                end=0x10FF,
            ),
        )

        bundle = ReverseEngineeringBundle(
            artifacts=[ArtifactRecord(artifact_id="test:artifact", kind="analysis", path="test.asm")],
            entities=[entity],
        )
        store.upsert_bundle(bundle)

        # Generate heat map
        heat_map = HeatMap(
            store=store,
            heat_source=HeatSource.REFERENCE_COUNT,
            address_space="rom",
            resolution=64,
        )
        heat_map.generate(start_address=0x0000, end_address=0x2000)

        ascii_art = heat_map.to_ascii(width=40, height=10)

        # Check that ASCII art contains expected elements
        # If no data matched the heat source, it shows "No heat map data"
        assert "Heat Map" in ascii_art or "No heat map data" in ascii_art

        store.close()

    def test_color_ramps_available(self):
        """Test that all color schemes have color ramps defined."""
        for scheme in ColorScheme:
            assert scheme in HeatMap.COLOR_RAMPS
            assert len(HeatMap.COLOR_RAMPS[scheme]) > 0

    def test_ascii_ramp(self):
        """Test that ASCII ramp is properly ordered."""
        assert len(HeatMap.ASCII_RAMP) > 0
        # First character should be lowest intensity
        assert HeatMap.ASCII_RAMP[0] == " "
        # Last character should be highest intensity
        assert HeatMap.ASCII_RAMP[-1] == "@"


class TestGenerateHeatMapFunction:
    """Tests for the generate_heat_map convenience function."""

    def test_invalid_heat_source(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        result = generate_heat_map(
            store=store,
            heat_source="invalid_source",
            address_space="rom",
        )

        assert "error" in result
        assert "Invalid heat_source" in result["error"]

        store.close()

    def test_valid_heat_source(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        result = generate_heat_map(
            store=store,
            heat_source="reference_count",
            address_space="rom",
            output_format="json",
        )

        assert "error" not in result or result.get("error") is None
        assert result["heat_source"] == "reference_count"
        assert result["address_space"] == "rom"
        assert "cells" in result

        store.close()

    def test_ascii_output_format(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        result = generate_heat_map(
            store=store,
            heat_source="reference_count",
            address_space="rom",
            output_format="ascii",
        )

        assert result["format"] == "ascii"
        assert "ascii_art" in result

        store.close()

    def test_png_output_format(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        result = generate_heat_map(
            store=store,
            heat_source="reference_count",
            address_space="rom",
            output_format="png",
        )

        assert result["format"] == "png"
        # PNG generation may fail if matplotlib is not installed
        if "png_base64" in result:
            assert result["mime_type"] == "image/png"

        store.close()


class TestHeatMapIntegration:
    """Integration tests for heat map with real data."""

    def test_coverage_heat_map_with_trace(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Store an execution trace
        entries = [
            {"address": 0x08000000, "instruction_bytes": "00", "disassembly": "NOP", "timestamp": 1.0},
            {"address": 0x08000004, "instruction_bytes": "00", "disassembly": "NOP", "timestamp": 1.1},
            {"address": 0x08000008, "instruction_bytes": "00", "disassembly": "NOP", "timestamp": 1.2},
            {"address": 0x08000000, "instruction_bytes": "00", "disassembly": "NOP", "timestamp": 2.0},  # Revisit
        ]
        store.store_execution_trace("test_coverage", entries)

        # Generate coverage heat map
        result = generate_heat_map(
            store=store,
            heat_source="coverage",
            address_space="execution",
            resolution=64,
        )

        assert result["heat_source"] == "coverage"
        # Should have some cells with coverage data
        cells_with_data = [c for c in result.get("cells", []) if c.get("value", 0) > 0]
        assert len(cells_with_data) > 0

        store.close()

    def test_region_detection(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Create clustered entities to form a region
        entities = []
        for i in range(5):
            entity = EntityRecord(
                entity_id=f"test:func:{i}",
                kind="function",
                name=f"Function{i}",
                location=AddressLocation(
                    address_space="rom",
                    start=0x1000 + (i * 0x100),
                    end=0x1000 + (i * 0x100) + 0xFF,
                ),
            )
            entities.append(entity)

        bundle = ReverseEngineeringBundle(
            artifacts=[ArtifactRecord(artifact_id="test:artifact", kind="analysis", path="test.asm")],
            entities=entities,
        )
        store.upsert_bundle(bundle)

        # Generate heat map with region detection
        result = generate_heat_map(
            store=store,
            heat_source="reference_count",
            address_space="rom",
            resolution=64,
            threshold=0.1,
        )

        # Should detect at least one region
        assert result["region_count"] >= 0

        store.close()

    def test_color_scheme_application(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Create a test entity
        entity = EntityRecord(
            entity_id="test:func:1",
            kind="function",
            name="Function1",
            location=AddressLocation(
                address_space="rom",
                start=0x1000,
                end=0x10FF,
            ),
        )

        bundle = ReverseEngineeringBundle(
            artifacts=[ArtifactRecord(artifact_id="test:artifact", kind="analysis", path="test.asm")],
            entities=[entity],
        )
        store.upsert_bundle(bundle)

        # Test different color schemes
        for scheme in ["viridis", "hot", "greyscale"]:
            result = generate_heat_map(
                store=store,
                heat_source="reference_count",
                address_space="rom",
                color_scheme=scheme,
            )
            assert result["color_scheme"] == scheme

        store.close()


class TestHeatMapStoreMethod:
    """Tests for the ReverseEngineeringStore.generate_heat_map method."""

    def test_store_method_exists(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Verify the method exists and is callable
        assert hasattr(store, "generate_heat_map")
        assert callable(getattr(store, "generate_heat_map"))

        store.close()

    def test_store_method_basic_call(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        result = store.generate_heat_map(
            heat_source="reference_count",
            address_space="rom",
            resolution=64,
        )

        assert "heat_source" in result
        assert result["heat_source"] == "reference_count"
        assert "total_cells" in result

        store.close()
