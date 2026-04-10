"""Heat map generation for reverse-engineering visualization.

This module provides heat map generation for visualizing various metrics
over address spaces, such as code coverage, function reference counts,
call frequency, and entropy values.
"""

from __future__ import annotations

import base64
import io
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore


class HeatSource(str, Enum):
    """Types of heat sources for heat map generation."""

    COVERAGE = "coverage"
    REFERENCE_COUNT = "reference_count"
    CALL_FREQUENCY = "call_frequency"
    ENTROPY = "entropy"


class ColorScheme(str, Enum):
    """Color schemes for heat map visualization."""

    VIRIDIS = "viridis"
    PLASMA = "plasma"
    INFERNO = "inferno"
    MAGMA = "magma"
    HOT = "hot"
    COOL = "cool"
    JET = "jet"
    GREYSCALE = "greyscale"
    RED_GREEN = "red_green"
    BLUE_YELLOW = "blue_yellow"


@dataclass
class HeatMapCell:
    """A single cell in a heat map."""

    address: int
    value: float
    normalized_value: float = 0.0
    color: str = ""
    entity_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert cell to dictionary."""
        return {
            "address": self.address,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "color": self.color,
            "entity_ids": self.entity_ids,
            "metadata": dict(self.metadata),
        }


@dataclass
class HeatMapRegion:
    """A region of high heat in the heat map."""

    start_address: int
    end_address: int
    max_value: float
    avg_value: float
    cell_count: int
    entity_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert region to dictionary."""
        return {
            "start_address": self.start_address,
            "end_address": self.end_address,
            "max_value": self.max_value,
            "avg_value": self.avg_value,
            "cell_count": self.cell_count,
            "entity_ids": self.entity_ids,
        }


@dataclass
class HeatMapResult:
    """Result of heat map generation."""

    heat_source: str
    address_space: str
    resolution: int
    total_cells: int
    min_value: float
    max_value: float
    cells: list[HeatMapCell] = field(default_factory=list)
    regions: list[HeatMapRegion] = field(default_factory=list)
    color_scheme: str = "viridis"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "heat_source": self.heat_source,
            "address_space": self.address_space,
            "resolution": self.resolution,
            "total_cells": self.total_cells,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "cells": [cell.to_dict() for cell in self.cells],
            "regions": [region.to_dict() for region in self.regions],
            "color_scheme": self.color_scheme,
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        """Convert result to JSON string."""
        import json

        return json.dumps(self.to_dict(), indent=2)


class HeatMap:
    """Heat map generator for reverse-engineering data visualization."""

    # ASCII characters for terminal rendering (from low to high intensity)
    ASCII_RAMP = " .:-=+*#%@"

    # Color ramps for different schemes (RGB tuples)
    COLOR_RAMPS: dict[ColorScheme, list[tuple[int, int, int]]] = {
        ColorScheme.VIRIDIS: [
            (68, 1, 84),
            (72, 35, 116),
            (64, 67, 135),
            (52, 94, 141),
            (41, 120, 142),
            (32, 144, 140),
            (34, 167, 132),
            (68, 190, 112),
            (121, 209, 81),
            (189, 223, 38),
            (253, 231, 36),
        ],
        ColorScheme.PLASMA: [
            (13, 8, 135),
            (75, 3, 161),
            (125, 3, 168),
            (168, 34, 150),
            (203, 70, 121),
            (229, 107, 93),
            (248, 148, 65),
            (253, 190, 39),
            (240, 249, 33),
        ],
        ColorScheme.INFERNO: [
            (0, 0, 4),
            (40, 11, 84),
            (101, 21, 110),
            (159, 42, 99),
            (212, 72, 66),
            (245, 125, 21),
            (250, 193, 39),
            (252, 255, 164),
        ],
        ColorScheme.MAGMA: [
            (0, 0, 4),
            (28, 16, 68),
            (79, 18, 123),
            (129, 37, 129),
            (181, 54, 122),
            (229, 80, 100),
            (251, 135, 97),
            (254, 194, 135),
            (252, 253, 191),
        ],
        ColorScheme.HOT: [
            (0, 0, 0),
            (87, 0, 0),
            (158, 0, 0),
            (220, 0, 0),
            (255, 0, 0),
            (255, 76, 0),
            (255, 147, 0),
            (255, 215, 0),
            (255, 255, 0),
            (255, 255, 255),
        ],
        ColorScheme.COOL: [
            (0, 255, 255),
            (38, 214, 255),
            (76, 172, 255),
            (114, 131, 255),
            (152, 89, 255),
            (190, 48, 255),
            (229, 6, 255),
            (255, 0, 203),
            (255, 0, 152),
            (255, 0, 101),
            (255, 0, 50),
            (255, 0, 0),
        ],
        ColorScheme.JET: [
            (0, 0, 131),
            (0, 0, 255),
            (0, 127, 255),
            (0, 255, 255),
            (127, 255, 127),
            (255, 255, 0),
            (255, 127, 0),
            (255, 0, 0),
            (127, 0, 0),
        ],
        ColorScheme.GREYSCALE: [
            (0, 0, 0),
            (28, 28, 28),
            (56, 56, 56),
            (85, 85, 85),
            (113, 113, 113),
            (141, 141, 141),
            (170, 170, 170),
            (198, 198, 198),
            (227, 227, 227),
            (255, 255, 255),
        ],
        ColorScheme.RED_GREEN: [
            (255, 0, 0),
            (255, 64, 0),
            (255, 128, 0),
            (255, 191, 0),
            (255, 255, 0),
            (191, 255, 0),
            (128, 255, 0),
            (64, 255, 0),
            (0, 255, 0),
        ],
        ColorScheme.BLUE_YELLOW: [
            (0, 0, 255),
            (36, 28, 237),
            (72, 57, 219),
            (109, 85, 201),
            (145, 113, 182),
            (182, 142, 164),
            (218, 170, 146),
            (255, 198, 127),
            (255, 227, 109),
            (255, 255, 91),
        ],
    }

    def __init__(
        self,
        store: ReverseEngineeringStore,
        heat_source: HeatSource,
        address_space: str,
        resolution: int = 256,
        color_scheme: ColorScheme = ColorScheme.VIRIDIS,
    ):
        """Initialize heat map generator.

        Args:
            store: The reverse engineering store to query.
            heat_source: Type of heat source to visualize.
            address_space: Address space to visualize.
            resolution: Number of cells in the heat map (default 256).
            color_scheme: Color scheme for visualization (default viridis).
        """
        self.store = store
        self.heat_source = heat_source
        self.address_space = address_space
        self.resolution = max(16, min(resolution, 4096))  # Clamp resolution
        self.color_scheme = color_scheme
        self._cells: list[HeatMapCell] = []
        self._min_value: float = 0.0
        self._max_value: float = 0.0

    def generate(
        self,
        start_address: int | None = None,
        end_address: int | None = None,
        threshold: float = 0.0,
    ) -> HeatMapResult:
        """Generate the heat map.

        Args:
            start_address: Optional start address (inclusive).
            end_address: Optional end address (inclusive).
            threshold: Minimum value threshold for region detection.

        Returns:
            HeatMapResult containing the generated heat map data.
        """
        # Collect raw heat data based on source type
        raw_data = self._collect_heat_data()

        if not raw_data:
            return HeatMapResult(
                heat_source=self.heat_source.value,
                address_space=self.address_space,
                resolution=self.resolution,
                total_cells=0,
                min_value=0.0,
                max_value=0.0,
                cells=[],
                regions=[],
                color_scheme=self.color_scheme.value,
            )

        # Determine address range
        all_addresses = [addr for addr, _, _, _ in raw_data]
        if start_address is None:
            start_address = min(all_addresses)
        if end_address is None:
            end_address = max(all_addresses)

        # Create cells
        self._cells = self._create_cells(raw_data, start_address, end_address)

        # Calculate statistics
        values = [cell.value for cell in self._cells]
        self._min_value = min(values) if values else 0.0
        self._max_value = max(values) if values else 0.0

        # Normalize values and assign colors
        self._normalize_and_color_cells()

        # Detect high-heat regions
        regions = self._detect_regions(threshold)

        return HeatMapResult(
            heat_source=self.heat_source.value,
            address_space=self.address_space,
            resolution=self.resolution,
            total_cells=len(self._cells),
            min_value=self._min_value,
            max_value=self._max_value,
            cells=self._cells,
            regions=regions,
            color_scheme=self.color_scheme.value,
            metadata={
                "address_range": {
                    "start": start_address,
                    "end": end_address,
                },
                "threshold": threshold,
            },
        )

    def _collect_heat_data(self) -> list[tuple[int, float, list[str], dict[str, Any]]]:
        """Collect raw heat data from the store based on heat source type.

        Returns:
            List of (address, value, entity_ids, metadata) tuples.
        """
        if self.heat_source == HeatSource.COVERAGE:
            return self._collect_coverage_data()
        elif self.heat_source == HeatSource.REFERENCE_COUNT:
            return self._collect_reference_data()
        elif self.heat_source == HeatSource.CALL_FREQUENCY:
            return self._collect_call_frequency_data()
        elif self.heat_source == HeatSource.ENTROPY:
            return self._collect_entropy_data()
        return []

    def _collect_coverage_data(
        self,
    ) -> list[tuple[int, float, list[str], dict[str, Any]]]:
        """Collect code coverage data from execution traces."""
        data: list[tuple[int, float, list[str], dict[str, Any]]] = []

        # Get all execution trace artifacts
        traces = self.store.list_execution_traces(limit=1000)

        for trace in traces:
            capture_id = trace["capture_id"]
            trace_data = self.store.get_execution_trace(capture_id)

            if trace_data:
                for entry in trace_data.get("entries", []):
                    attrs = entry.get("attributes", {})
                    address = attrs.get("address", 0)
                    timestamp = attrs.get("timestamp", 0)

                    # Count executions per address
                    existing = next((d for d in data if d[0] == address), None)
                    if existing:
                        # Update count
                        idx = data.index(existing)
                        count = existing[1] + 1
                        entity_ids = existing[2] + [entry.get("evidence_id", "")]
                        data[idx] = (address, count, entity_ids, {"timestamp": timestamp})
                    else:
                        data.append(
                            (address, 1.0, [entry.get("evidence_id", "")], {"timestamp": timestamp})
                        )

        return data

    def _collect_reference_data(
        self,
    ) -> list[tuple[int, float, list[str], dict[str, Any]]]:
        """Collect function/data reference count data."""
        data: list[tuple[int, float, list[str], dict[str, Any]]] = []

        # Get all entities in the address space
        entities = self.store.list_entities(
            address_space=self.address_space,
            limit=10000,
        )

        for entity in entities:
            if entity.location:
                # Count edges (references) for this entity
                edges = self.store.get_neighbors(entity.entity_id, limit=1000)
                ref_count = len(edges)

                if ref_count > 0:
                    data.append(
                        (
                            entity.location.start,
                            float(ref_count),
                            [entity.entity_id],
                            {"name": entity.name, "kind": entity.kind},
                        )
                    )

        return data

    def _collect_call_frequency_data(
        self,
    ) -> list[tuple[int, float, list[str], dict[str, Any]]]:
        """Collect function call frequency data."""
        data: list[tuple[int, float, list[str], dict[str, Any]]] = []

        # Get function entities
        entities = self.store.list_entities(
            kind="function",
            address_space=self.address_space,
            limit=10000,
        )

        for entity in entities:
            if entity.location:
                # Count call edges
                edges = self.store.get_neighbors(entity.entity_id, limit=1000)
                call_count = sum(
                    1 for e in edges if e.kind in ("calls", "called_by")
                )

                if call_count > 0:
                    data.append(
                        (
                            entity.location.start,
                            float(call_count),
                            [entity.entity_id],
                            {"name": entity.name},
                        )
                    )

        return data

    def _collect_entropy_data(
        self,
    ) -> list[tuple[int, float, list[str], dict[str, Any]]]:
        """Collect entropy analysis data."""
        data: list[tuple[int, float, list[str], dict[str, Any]]] = []

        # Get evidence with entropy data in the address space
        # This would typically be pre-computed entropy values stored in evidence
        entities = self.store.list_entities(
            address_space=self.address_space,
            limit=10000,
        )

        for entity in entities:
            if entity.location:
                # Check if entity has entropy in attributes
                entropy = entity.attributes.get("entropy")
                if entropy is not None:
                    data.append(
                        (
                            entity.location.start,
                            float(entropy),
                            [entity.entity_id],
                            {"name": entity.name, "kind": entity.kind},
                        )
                    )

        return data

    def _create_cells(
        self,
        raw_data: list[tuple[int, float, list[str], dict[str, Any]]],
        start_address: int,
        end_address: int,
    ) -> list[HeatMapCell]:
        """Create heat map cells from raw data."""
        if start_address >= end_address or not raw_data:
            return []

        address_range = end_address - start_address + 1
        cell_size = max(1, address_range // self.resolution)

        # Create cell buckets
        num_cells = min(self.resolution, (address_range + cell_size - 1) // cell_size)
        buckets: list[list[tuple[int, float, list[str], dict[str, Any]]]] = [
            [] for _ in range(num_cells)
        ]

        # Distribute data into buckets
        for address, value, entity_ids, meta in raw_data:
            if start_address <= address <= end_address:
                cell_idx = min((address - start_address) // cell_size, num_cells - 1)
                buckets[cell_idx].append((address, value, entity_ids, meta))

        # Create cells from buckets
        cells: list[HeatMapCell] = []
        for i, bucket in enumerate(buckets):
            if bucket:
                # Calculate cell address (start of cell range)
                cell_address = start_address + (i * cell_size)

                # Aggregate values (sum for counts, max for entropy)
                if self.heat_source == HeatSource.ENTROPY:
                    value = max(v for _, v, _, _ in bucket)
                else:
                    value = sum(v for _, v, _, _ in bucket)

                # Collect all entity IDs
                all_entity_ids: list[str] = []
                for _, _, eids, _ in bucket:
                    all_entity_ids.extend(eids)

                # Merge metadata
                merged_metadata: dict[str, Any] = {"count": len(bucket)}

                cells.append(
                    HeatMapCell(
                        address=cell_address,
                        value=value,
                        entity_ids=list(set(all_entity_ids)),
                        metadata=merged_metadata,
                    )
                )
            else:
                # Empty cell
                cell_address = start_address + (i * cell_size)
                cells.append(
                    HeatMapCell(
                        address=cell_address,
                        value=0.0,
                        entity_ids=[],
                        metadata={"count": 0},
                    )
                )

        return cells

    def _normalize_and_color_cells(self) -> None:
        """Normalize cell values and assign colors."""
        if not self._cells or self._max_value == self._min_value:
            return

        value_range = self._max_value - self._min_value
        color_ramp = self.COLOR_RAMPS.get(self.color_scheme, self.COLOR_RAMPS[ColorScheme.VIRIDIS])

        for cell in self._cells:
            # Normalize to 0-1
            if value_range > 0:
                cell.normalized_value = (cell.value - self._min_value) / value_range
            else:
                cell.normalized_value = 0.0

            # Assign color from ramp
            color_idx = int(cell.normalized_value * (len(color_ramp) - 1))
            color_idx = max(0, min(color_idx, len(color_ramp) - 1))
            r, g, b = color_ramp[color_idx]
            cell.color = f"#{r:02X}{g:02X}{b:02X}"

    def _detect_regions(self, threshold: float) -> list[HeatMapRegion]:
        """Detect high-heat regions in the heat map."""
        regions: list[HeatMapRegion] = []

        if not self._cells:
            return regions

        # Calculate actual threshold value
        if threshold > 0:
            threshold_value = self._min_value + (threshold * (self._max_value - self._min_value))
        else:
            threshold_value = self._min_value

        # Find contiguous regions above threshold
        current_region: list[HeatMapCell] = []

        for cell in self._cells:
            if cell.value >= threshold_value and cell.value > 0:
                current_region.append(cell)
            else:
                if len(current_region) >= 2:  # Minimum region size
                    region = self._create_region(current_region)
                    if region:
                        regions.append(region)
                current_region = []

        # Handle last region
        if len(current_region) >= 2:
            region = self._create_region(current_region)
            if region:
                regions.append(region)

        # Sort by max value descending
        regions.sort(key=lambda r: r.max_value, reverse=True)

        return regions[:50]  # Limit to top 50 regions

    def _create_region(self, cells: list[HeatMapCell]) -> HeatMapRegion | None:
        """Create a HeatMapRegion from a list of cells."""
        if not cells:
            return None

        values = [c.value for c in cells]
        all_entity_ids: list[str] = []
        for c in cells:
            all_entity_ids.extend(c.entity_ids)

        # Estimate end address (assume uniform cell size)
        if len(cells) > 1:
            cell_size = cells[1].address - cells[0].address
            end_address = cells[-1].address + cell_size - 1
        else:
            end_address = cells[0].address

        return HeatMapRegion(
            start_address=cells[0].address,
            end_address=end_address,
            max_value=max(values),
            avg_value=sum(values) / len(values),
            cell_count=len(cells),
            entity_ids=list(set(all_entity_ids)),
        )

    def to_ascii(self, width: int = 80, height: int = 24) -> str:
        """Generate ASCII art representation of the heat map.

        Args:
            width: Width of the output in characters.
            height: Height of the output in characters.

        Returns:
            ASCII art string.
        """
        if not self._cells:
            return "No heat map data to display."

        lines: list[str] = []

        # Header
        lines.append(f"Heat Map: {self.heat_source.value} ({self.address_space})")
        lines.append(f"Range: 0x{self._cells[0].address:08X} - 0x{self._cells[-1].address:08X}")
        lines.append(f"Values: {self._min_value:.2f} - {self._max_value:.2f}")
        lines.append("")

        # Calculate cells per character
        cells_per_char = max(1, len(self._cells) // width)

        # Generate heat bar
        for row in range(height):
            line_chars: list[str] = []
            for col in range(width):
                cell_idx = min(col * cells_per_char, len(self._cells) - 1)
                cell = self._cells[cell_idx]

                # Map normalized value to ASCII character
                char_idx = int(cell.normalized_value * (len(self.ASCII_RAMP) - 1))
                char_idx = max(0, min(char_idx, len(self.ASCII_RAMP) - 1))
                line_chars.append(self.ASCII_RAMP[char_idx])

            lines.append("".join(line_chars))

        # Legend
        lines.append("")
        legend = ""
        for i, char in enumerate(self.ASCII_RAMP):
            pct = i / (len(self.ASCII_RAMP) - 1) * 100
            if i % 2 == 0:
                legend += f"{char}:{pct:.0f}% "
        lines.append(legend)

        return "\n".join(lines)

    def to_png_base64(self, width: int = 800, height: int = 200) -> str | None:
        """Generate PNG image as base64 string.

        Args:
            width: Width of the image in pixels.
            height: Height of the image in pixels.

        Returns:
            Base64 encoded PNG string, or None if matplotlib is not available.
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib.colors as mcolors
            from matplotlib.patches import Rectangle
        except ImportError:
            return None

        if not self._cells:
            return None

        # Create figure
        fig, ax = plt.subplots(figsize=(width / 100, height / 100), dpi=100)

        # Get color ramp
        color_ramp = self.COLOR_RAMPS.get(self.color_scheme, self.COLOR_RAMPS[ColorScheme.VIRIDIS])
        cmap = mcolors.ListedColormap([(r / 255, g / 255, b / 255) for r, g, b in color_ramp])

        # Draw cells as rectangles
        if len(self._cells) > 1:
            cell_width = width / len(self._cells)

            for i, cell in enumerate(self._cells):
                color_idx = int(cell.normalized_value * (len(color_ramp) - 1))
                color_idx = max(0, min(color_idx, len(color_ramp) - 1))
                color = [c / 255 for c in color_ramp[color_idx]]

                rect = Rectangle(
                    (i * cell_width, 0),
                    cell_width,
                    height,
                    facecolor=color,
                    edgecolor="none",
                )
                ax.add_patch(rect)

        # Styling
        ax.set_xlim(0, width)
        ax.set_ylim(0, height)
        ax.set_title(f"Heat Map: {self.heat_source.value} ({self.address_space})")
        ax.set_xlabel("Address")
        ax.set_ylabel("Intensity")
        ax.set_xticks([])
        ax.set_yticks([])

        # Add colorbar
        sm = plt.cm.ScalarMappable(cmap=cmap, norm=mcolors.Normalize(vmin=self._min_value, vmax=self._max_value))
        sm.set_array([])
        plt.colorbar(sm, ax=ax, orientation="horizontal", pad=0.05, label="Value")

        plt.tight_layout()

        # Save to buffer
        buf = io.BytesIO()
        plt.savefig(buf, format="png", bbox_inches="tight")
        buf.seek(0)

        # Encode as base64
        img_base64 = base64.b64encode(buf.read()).decode("utf-8")
        plt.close(fig)

        return img_base64


def generate_heat_map(
    store: ReverseEngineeringStore,
    heat_source: str,
    address_space: str,
    resolution: int = 256,
    color_scheme: str = "viridis",
    start_address: int | None = None,
    end_address: int | None = None,
    threshold: float = 0.0,
    output_format: str = "json",
) -> dict[str, Any]:
    """Generate a heat map for visualization.

    This is a convenience function that creates a HeatMap and returns
    the result in the requested format.

    Args:
        store: The reverse engineering store.
        heat_source: Type of heat source (coverage, reference_count, call_frequency, entropy).
        address_space: Address space to visualize.
        resolution: Number of cells in the heat map (default 256).
        color_scheme: Color scheme name (default "viridis").
        start_address: Optional start address.
        end_address: Optional end address.
        threshold: Minimum value threshold for region detection (0.0-1.0).
        output_format: Output format - "json", "ascii", or "png".

    Returns:
        Dictionary containing the heat map result.
    """
    try:
        source = HeatSource(heat_source.lower())
    except ValueError:
        return {
            "error": f"Invalid heat_source: {heat_source}. Valid values: {[s.value for s in HeatSource]}",
        }

    try:
        scheme = ColorScheme(color_scheme.lower())
    except ValueError:
        scheme = ColorScheme.VIRIDIS

    heat_map = HeatMap(
        store=store,
        heat_source=source,
        address_space=address_space,
        resolution=resolution,
        color_scheme=scheme,
    )

    result = heat_map.generate(
        start_address=start_address,
        end_address=end_address,
        threshold=threshold,
    )

    output: dict[str, Any] = {
        "heat_source": result.heat_source,
        "address_space": result.address_space,
        "resolution": result.resolution,
        "total_cells": result.total_cells,
        "min_value": result.min_value,
        "max_value": result.max_value,
        "color_scheme": result.color_scheme,
        "region_count": len(result.regions),
        "regions": [r.to_dict() for r in result.regions[:10]],  # Top 10 regions
    }

    if output_format == "json":
        output["format"] = "json"
        output["cells"] = [c.to_dict() for c in result.cells]
    elif output_format == "ascii":
        output["format"] = "ascii"
        output["ascii_art"] = heat_map.to_ascii()
    elif output_format == "png":
        output["format"] = "png"
        png_data = heat_map.to_png_base64()
        if png_data:
            output["png_base64"] = png_data
            output["mime_type"] = "image/png"
        else:
            output["error"] = "PNG generation requires matplotlib. Install with: pip install matplotlib"
    else:
        output["format"] = "json"
        output["cells"] = [c.to_dict() for c in result.cells]

    return output
