"""Memory map visualization data generation for reverse engineering.

This module provides classes for representing and visualizing memory layouts
with support for multiple region types, overlap detection, and various output formats.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class RegionType(Enum):
    """Types of memory regions."""
    ROM = auto()
    RAM = auto()
    VRAM = auto()
    IO = auto()
    SYSTEM_ROM = auto()
    
    def __str__(self) -> str:
        return self.name


# Default colors for region types (accessible, web-friendly colors)
DEFAULT_REGION_COLORS: dict[RegionType, str] = {
    RegionType.ROM: "#4A90D9",        # Blue
    RegionType.RAM: "#5CB85C",        # Green
    RegionType.VRAM: "#9B59B6",       # Purple
    RegionType.IO: "#E74C3C",         # Red
    RegionType.SYSTEM_ROM: "#F39C12", # Orange
}


@dataclass(frozen=True)
class MemoryRegion:
    """Represents a single memory region.
    
    Attributes:
        name: Human-readable name for the region
        start: Start address (inclusive)
        end: End address (inclusive)
        region_type: Type of memory region
        color: Color for visualization (hex string)
        description: Optional description
    """
    name: str
    start: int
    end: int
    region_type: RegionType = RegionType.ROM
    color: str = ""
    description: str = ""
    
    def __post_init__(self) -> None:
        """Validate region and set default color."""
        if self.start > self.end:
            raise ValueError(f"Start address {self.start:#x} must be <= end address {self.end:#x}")
        if self.start < 0:
            raise ValueError(f"Start address must be non-negative, got {self.start}")
    
    @property
    def size(self) -> int:
        """Return the size of the region in bytes."""
        return self.end - self.start + 1
    
    @property
    def effective_color(self) -> str:
        """Return the color, using default if not specified."""
        return self.color if self.color else DEFAULT_REGION_COLORS.get(self.region_type, "#888888")
    
    def overlaps(self, other: MemoryRegion) -> bool:
        """Check if this region overlaps with another."""
        return not (self.end < other.start or self.start > other.end)
    
    def contains(self, address: int) -> bool:
        """Check if an address is within this region."""
        return self.start <= address <= self.end
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "start": self.start,
            "end": self.end,
            "size": self.size,
            "start_hex": f"0x{self.start:08X}",
            "end_hex": f"0x{self.end:08X}",
            "type": self.region_type.name,
            "color": self.effective_color,
            "description": self.description,
        }


@dataclass
class MemoryMap:
    """Represents a full memory layout with multiple regions.
    
    Attributes:
        name: Name of this memory map
        address_space: Address space identifier
        regions: List of memory regions
    """
    name: str = "Memory Map"
    address_space: str = "default"
    regions: list[MemoryRegion] = field(default_factory=list)
    
    def add_region(self, region: MemoryRegion) -> None:
        """Add a memory region to the map."""
        self.regions.append(region)
    
    def remove_region(self, region_name: str) -> bool:
        """Remove a region by name. Returns True if found and removed."""
        for i, region in enumerate(self.regions):
            if region.name == region_name:
                self.regions.pop(i)
                return True
        return False
    
    def find_overlaps(self) -> list[tuple[MemoryRegion, MemoryRegion]]:
        """Find all overlapping region pairs.
        
        Returns:
            List of tuples containing overlapping region pairs.
        """
        overlaps: list[tuple[MemoryRegion, MemoryRegion]] = []
        for i, region1 in enumerate(self.regions):
            for region2 in self.regions[i + 1:]:
                if region1.overlaps(region2):
                    overlaps.append((region1, region2))
        return overlaps
    
    def has_overlaps(self) -> bool:
        """Check if any regions overlap."""
        return len(self.find_overlaps()) > 0
    
    def get_region_at(self, address: int) -> MemoryRegion | None:
        """Get the region containing a specific address."""
        for region in self.regions:
            if region.contains(address):
                return region
        return None
    
    def get_regions_in_range(self, start: int, end: int) -> list[MemoryRegion]:
        """Get all regions that overlap with a given address range."""
        results: list[MemoryRegion] = []
        for region in self.regions:
            if not (region.end < start or region.start > end):
                results.append(region)
        return results
    
    def get_bounds(self) -> tuple[int, int]:
        """Get the minimum and maximum addresses in the map.
        
        Returns:
            Tuple of (min_start, max_end). Returns (0, 0) if no regions.
        """
        if not self.regions:
            return (0, 0)
        min_start = min(r.start for r in self.regions)
        max_end = max(r.end for r in self.regions)
        return (min_start, max_end)
    
    def get_total_size(self) -> int:
        """Get the total size of all unique address space covered."""
        if not self.regions:
            return 0
        min_addr, max_addr = self.get_bounds()
        return max_addr - min_addr + 1
    
    def _sort_regions(self) -> list[MemoryRegion]:
        """Return regions sorted by start address."""
        return sorted(self.regions, key=lambda r: r.start)
    
    def to_svg(
        self,
        width: int = 800,
        height: int = 400,
        show_addresses: bool = True,
        show_labels: bool = True,
    ) -> str:
        """Generate SVG visualization of the memory map.
        
        Args:
            width: SVG width in pixels
            height: SVG height in pixels
            show_addresses: Whether to show address labels
            show_labels: Whether to show region labels
            
        Returns:
            SVG string
        """
        if not self.regions:
            return self._generate_empty_svg(width, height)
        
        # Calculate layout
        min_addr, max_addr = self.get_bounds()
        total_size = max_addr - min_addr + 1
        
        # Padding and dimensions
        padding = 40
        chart_top = padding
        chart_bottom = height - padding
        chart_height = chart_bottom - chart_top
        left_margin = 80 if show_addresses else 20
        right_margin = 20
        chart_width = width - left_margin - right_margin
        
        # Build SVG
        lines: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            f'  <defs>',
            f'    <style>',
            f'      .region {{ stroke: #333; stroke-width: 1; }}',
            f'      .address-label {{ font-family: monospace; font-size: 11px; fill: #666; }}',
            f'      .region-label {{ font-family: sans-serif; font-size: 12px; fill: #fff; font-weight: bold; }}',
            f'      .title {{ font-family: sans-serif; font-size: 16px; fill: #333; font-weight: bold; }}',
            f'      .overlap {{ fill: none; stroke: #ff0000; stroke-width: 3; stroke-dasharray: 5,5; }}',
            f'    </style>',
            f'  </defs>',
            f'  <rect width="100%" height="100%" fill="#f8f9fa"/>',
            f'  <text x="{width//2}" y="25" text-anchor="middle" class="title">{html.escape(self.name)}</text>',
        ]
        
        # Draw regions
        sorted_regions = self._sort_regions()
        region_height = chart_height / max(len(sorted_regions), 1)
        
        for i, region in enumerate(sorted_regions):
            y = chart_top + i * region_height
            
            # Calculate x position based on address
            rel_start = (region.start - min_addr) / total_size
            rel_size = region.size / total_size
            
            x = left_margin + rel_start * chart_width
            region_width = max(rel_size * chart_width, 2)  # Min 2px width
            
            # Draw region rectangle
            color = region.effective_color
            lines.append(
                f'  <rect x="{x:.1f}" y="{y:.1f}" width="{region_width:.1f}" '
                f'height="{region_height * 0.8:.1f}" fill="{color}" class="region" rx="3"/>'
            )
            
            # Calculate center y position for labels
            label_y = y + region_height * 0.4
            
            # Add region label if there's room
            if show_labels and region_width > 60:
                lines.append(
                    f'  <text x="{x + region_width/2:.1f}" y="{label_y:.1f}" '
                    f'text-anchor="middle" dominant-baseline="middle" class="region-label">'
                    f'{html.escape(region.name[:20])}</text>'
                )
            
            # Add address labels
            if show_addresses:
                lines.append(
                    f'  <text x="{left_margin - 5:.1f}" y="{label_y:.1f}" '
                    f'text-anchor="end" dominant-baseline="middle" class="address-label">'
                    f'0x{region.start:06X}</text>'
                )
        
        # Draw overlap indicators
        overlaps = self.find_overlaps()
        for region1, region2 in overlaps:
            # Find region indices for positioning
            try:
                idx1 = sorted_regions.index(region1)
                idx2 = sorted_regions.index(region2)
                
                # Calculate overlap region
                overlap_start = max(region1.start, region2.start)
                overlap_end = min(region1.end, region2.end)
                
                rel_start = (overlap_start - min_addr) / total_size
                rel_size = (overlap_end - overlap_start + 1) / total_size
                
                x = left_margin + rel_start * chart_width
                overlap_width = max(rel_size * chart_width, 2)
                
                y1 = chart_top + idx1 * region_height
                y2 = chart_top + idx2 * region_height
                
                # Draw overlap indicator
                lines.append(
                    f'  <rect x="{x:.1f}" y="{min(y1, y2):.1f}" width="{overlap_width:.1f}" '
                    f'height="{abs(y2 - y1) + region_height * 0.8:.1f}" class="overlap" rx="3"/>'
                )
            except ValueError:
                continue
        
        lines.append('</svg>')
        return '\n'.join(lines)
    
    def _generate_empty_svg(self, width: int, height: int) -> str:
        """Generate an empty SVG when no regions exist."""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#f8f9fa"/>
  <text x="{width//2}" y="{height//2}" text-anchor="middle" font-family="sans-serif" font-size="16" fill="#666">
    No memory regions defined
  </text>
</svg>'''
    
    def to_html(
        self,
        interactive: bool = True,
        width: int = 800,
    ) -> str:
        """Generate HTML visualization with optional interactivity.
        
        Args:
            interactive: Whether to include interactive JavaScript
            width: Width of the visualization in pixels
            
        Returns:
            HTML string
        """
        svg_content = self.to_svg(width=width, height=400)
        
        # Build region table rows
        rows: list[str] = []
        for region in self._sort_regions():
            rows.append(
                f'<tr data-region="{html.escape(region.name)}">'
                f'<td style="padding:8px;border-bottom:1px solid #ddd;background:{region.effective_color}20;">'
                f'<span style="display:inline-block;width:12px;height:12px;background:{region.effective_color};margin-right:8px;"></span>'
                f'{html.escape(region.name)}</td>'
                f'<td style="padding:8px;border-bottom:1px solid #ddd;font-family:monospace;">0x{region.start:08X}</td>'
                f'<td style="padding:8px;border-bottom:1px solid #ddd;font-family:monospace;">0x{region.end:08X}</td>'
                f'<td style="padding:8px;border-bottom:1px solid #ddd;font-family:monospace;">{region.size:,}</td>'
                f'<td style="padding:8px;border-bottom:1px solid #ddd;">{region.region_type.name}</td>'
                f'<td style="padding:8px;border-bottom:1px solid #ddd;color:#666;">{html.escape(region.description)}</td>'
                f'</tr>'
            )
        
        # Overlap warnings
        overlaps = self.find_overlaps()
        overlap_section = ""
        if overlaps:
            overlap_items = []
            for r1, r2 in overlaps:
                overlap_items.append(
                    f'<li style="color:#c00;"><strong>{html.escape(r1.name)}</strong> overlaps with '
                    f'<strong>{html.escape(r2.name)}</strong> at 0x{max(r1.start, r2.start):08X} - '
                    f'0x{min(r1.end, r2.end):08X}</li>'
                )
            overlap_section = f'''
            <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:15px;margin:20px 0;">
                <h3 style="margin-top:0;color:#856404;">⚠️ Overlapping Regions Detected</h3>
                <ul style="margin-bottom:0;">{''.join(overlap_items)}</ul>
            </div>'''
        
        # Statistics
        min_addr, max_addr = self.get_bounds()
        stats = f'''
        <div style="background:#e9ecef;border-radius:4px;padding:15px;margin:20px 0;">
            <h3 style="margin-top:0;">Statistics</h3>
            <table style="width:100%;border-collapse:collapse;">
                <tr><td style="padding:4px;">Total Regions:</td><td style="padding:4px;font-weight:bold;">{len(self.regions)}</td></tr>
                <tr><td style="padding:4px;">Address Range:</td><td style="padding:4px;font-family:monospace;">0x{min_addr:08X} - 0x{max_addr:08X}</td></tr>
                <tr><td style="padding:4px;">Total Size:</td><td style="padding:4px;font-family:monospace;">{self.get_total_size():,} bytes</td></tr>
                <tr><td style="padding:4px;">Overlaps:</td><td style="padding:4px;color:{'#c00' if overlaps else '#5cb85c'};">{'Yes' if overlaps else 'No'}</td></tr>
            </table>
        </div>'''
        
        # Interactive JavaScript
        script = ""
        if interactive:
            script = '''
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const rows = document.querySelectorAll('tr[data-region]');
            rows.forEach(row => {
                row.addEventListener('mouseenter', function() {
                    this.style.backgroundColor = '#f5f5f5';
                });
                row.addEventListener('mouseleave', function() {
                    this.style.backgroundColor = '';
                });
            });
        });
    </script>'''
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(self.name)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: {width + 40}px; margin: 0 auto; padding: 20px; background: #fff; }}
        h1, h2 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ text-align: left; padding: 8px; background: #f0f0f0; border-bottom: 2px solid #ddd; }}
        tr:hover {{ background-color: #f9f9f9; }}
        .svg-container {{ background: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 10px; margin: 20px 0; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>{html.escape(self.name)}</h1>
    <p>Address Space: <code>{html.escape(self.address_space)}</code></p>
    
    {overlap_section}
    
    <div class="svg-container">
        {svg_content}
    </div>
    
    {stats}
    
    <h2>Memory Regions</h2>
    <table>
        <thead>
            <tr>
                <th>Name</th>
                <th>Start</th>
                <th>End</th>
                <th>Size</th>
                <th>Type</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows) if rows else '<tr><td colspan="6" style="text-align:center;padding:20px;color:#666;">No regions defined</td></tr>'}
        </tbody>
    </table>
    {script}
</body>
</html>'''
    
    def to_text(
        self,
        max_width: int = 80,
        show_addresses: bool = True,
    ) -> str:
        """Generate ASCII art text representation.
        
        Args:
            max_width: Maximum width of the output in characters
            show_addresses: Whether to show address labels
            
        Returns:
            ASCII art string
        """
        if not self.regions:
            return f"Memory Map: {self.name}\n{'=' * max_width}\nNo regions defined."
        
        lines: list[str] = [
            f"Memory Map: {self.name}",
            f"Address Space: {self.address_space}",
            "=" * max_width,
        ]
        
        # Calculate bounds for scaling
        min_addr, max_addr = self.get_bounds()
        total_size = max_addr - min_addr + 1
        
        # Width for addresses
        addr_width = 18 if show_addresses else 0
        bar_width = max_width - addr_width - 10
        
        # Sort and display regions
        sorted_regions = self._sort_regions()
        
        for region in sorted_regions:
            # Calculate position and width
            rel_start = (region.start - min_addr) / total_size
            rel_size = region.size / total_size
            
            start_pos = int(rel_start * bar_width)
            width = max(int(rel_size * bar_width), 1)
            
            # Build bar
            bar = " " * start_pos + "█" * width
            bar = bar.ljust(bar_width)
            
            # Type indicator
            type_char = region.region_type.name[0]
            
            # Address info
            addr_info = ""
            if show_addresses:
                addr_info = f"0x{region.start:06X}-{region.end:06X} "
            
            lines.append(f"{addr_info}[{bar}] {type_char} {region.name}")
            
            # Show overlap indicator if any
            for other in sorted_regions:
                if region != other and region.overlaps(other):
                    lines.append(f"{' ' * addr_width}  ⚠ OVERLAP with {other.name}")
                    break
        
        lines.append("=" * max_width)
        
        # Summary statistics
        overlaps = self.find_overlaps()
        lines.append(f"Total regions: {len(self.regions)}")
        lines.append(f"Address range: 0x{min_addr:08X} - 0x{max_addr:08X}")
        lines.append(f"Overlaps detected: {'YES' if overlaps else 'No'}")
        
        return '\n'.join(lines)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "address_space": self.address_space,
            "regions": [r.to_dict() for r in self.regions],
            "bounds": {
                "min": self.get_bounds()[0],
                "max": self.get_bounds()[1],
                "min_hex": f"0x{self.get_bounds()[0]:08X}",
                "max_hex": f"0x{self.get_bounds()[1]:08X}",
            },
            "total_size": self.get_total_size(),
            "region_count": len(self.regions),
            "has_overlaps": self.has_overlaps(),
            "overlaps": [
                {
                    "region1": r1.name,
                    "region2": r2.name,
                    "overlap_start": max(r1.start, r2.start),
                    "overlap_end": min(r1.end, r2.end),
                    "overlap_start_hex": f"0x{max(r1.start, r2.start):08X}",
                    "overlap_end_hex": f"0x{min(r1.end, r2.end):08X}",
                }
                for r1, r2 in self.find_overlaps()
            ],
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MemoryMap:
        """Create a MemoryMap from a dictionary."""
        memory_map = cls(
            name=data.get("name", "Memory Map"),
            address_space=data.get("address_space", "default"),
        )
        
        for region_data in data.get("regions", []):
            region = MemoryRegion(
                name=region_data["name"],
                start=region_data["start"],
                end=region_data["end"],
                region_type=RegionType[region_data.get("type", "ROM")],
                color=region_data.get("color", ""),
                description=region_data.get("description", ""),
            )
            memory_map.add_region(region)
        
        return memory_map
    
    @classmethod
    def create_default_snes_map(cls) -> MemoryMap:
        """Create a default memory map for SNES (Super Nintendo)."""
        memory_map = cls(
            name="SNES Memory Map",
            address_space="snes",
        )
        
        # SNES memory regions (simplified)
        regions = [
            ("System RAM", 0x7E0000, 0x7FFFFF, RegionType.RAM, "128KB Work RAM"),
            ("Save RAM", 0x700000, 0x71FFFF, RegionType.RAM, "Cartridge Save RAM"),
            ("VRAM", 0x000000, 0x0000FFFF, RegionType.VRAM, "Video RAM (separate bus)"),
            ("OAM", 0x00010000, 0x000101FF, RegionType.VRAM, "Object Attribute Memory"),
            ("CGRAM", 0x00010200, 0x000103FF, RegionType.VRAM, "Color Generator RAM"),
            ("I/O Registers", 0x002100, 0x0021FF, RegionType.IO, "Hardware registers"),
            ("ROM Bank $00-$3F", 0x008000, 0x3FFFFF, RegionType.ROM, "Program ROM Low"),
            ("ROM Bank $80-$BF", 0x808000, 0xBFFFFF, RegionType.ROM, "Program ROM High"),
            ("System ROM", 0x00FFE0, 0x00FFFF, RegionType.SYSTEM_ROM, "Interrupt vectors"),
        ]
        
        for name, start, end, region_type, desc in regions:
            memory_map.add_region(MemoryRegion(
                name=name,
                start=start,
                end=end,
                region_type=region_type,
                description=desc,
            ))
        
        return memory_map
