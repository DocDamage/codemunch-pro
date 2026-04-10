"""Entropy analysis for detecting packed/encrypted data in binary files.

This module provides Shannon entropy analysis with sliding window support
for identifying regions of high entropy that typically indicate compressed
or encrypted data.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EntropyWindow:
    """A single entropy measurement window."""

    start: int
    end: int
    entropy: float
    byte_values: tuple[int, ...] | None = None

    @property
    def size(self) -> int:
        """Return the size of the window in bytes."""
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class PackedRegion:
    """A detected packed/encrypted region with entropy metrics."""

    start: int
    end: int
    avg_entropy: float
    max_entropy: float
    min_entropy: float
    confidence: float

    @property
    def size(self) -> int:
        """Return the size of the region in bytes."""
        return self.end - self.start


class EntropyAnalyzer:
    """Shannon entropy analyzer for binary data.

    Provides sliding window analysis and visualization data generation
    for detecting packed, compressed, or encrypted regions.
    """

    # Typical entropy thresholds
    HIGH_ENTROPY_THRESHOLD = 7.5  # Very likely encrypted/compressed
    MEDIUM_ENTROPY_THRESHOLD = 7.0  # Possibly packed
    LOW_ENTROPY_THRESHOLD = 6.0  # Normal code/data

    def __init__(self, window_size: int = 256, step_size: int | None = None):
        """Initialize the entropy analyzer.

        Args:
            window_size: Size of the sliding window in bytes (default 256).
            step_size: Step size for sliding window (default window_size // 2).
        """
        self.window_size = max(1, window_size)
        self.step_size = step_size or (self.window_size // 2)

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence.

        Args:
            data: Byte sequence to analyze.

        Returns:
            Entropy value in bits per byte (0.0 to 8.0).
        """
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        length = len(data)
        entropy = 0.0

        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    def analyze_sliding_window(
        self,
        data: bytes,
        include_byte_values: bool = False,
    ) -> list[EntropyWindow]:
        """Analyze data using a sliding window approach.

        Args:
            data: Byte sequence to analyze.
            include_byte_values: Whether to include raw byte values in results.

        Returns:
            List of entropy windows with measurements.
        """
        if not data or self.window_size <= 0:
            return []

        windows: list[EntropyWindow] = []
        data_len = len(data)

        for start in range(0, data_len, self.step_size):
            end = min(start + self.window_size, data_len)
            window_data = data[start:end]

            # Skip windows that are too small
            if len(window_data) < self.window_size // 2:
                continue

            entropy = self.calculate_entropy(window_data)
            byte_values = tuple(window_data) if include_byte_values else None

            windows.append(
                EntropyWindow(
                    start=start,
                    end=end,
                    entropy=entropy,
                    byte_values=byte_values,
                )
            )

        return windows

    def detect_packed_regions(
        self,
        data: bytes,
        threshold: float = 7.2,
        min_region_size: int = 512,
        merge_gap: int = 256,
    ) -> list[PackedRegion]:
        """Detect regions likely to be packed or encrypted.

        Args:
            data: Byte sequence to analyze.
            threshold: Entropy threshold for high-entropy detection.
            min_region_size: Minimum size for a region to be reported.
            merge_gap: Maximum gap between high-entropy windows to merge.

        Returns:
            List of detected packed/encrypted regions.
        """
        windows = self.analyze_sliding_window(data)
        if not windows:
            return []

        # Find high-entropy windows
        high_entropy_windows = [w for w in windows if w.entropy >= threshold]
        if not high_entropy_windows:
            return []

        # Merge adjacent/overlapping windows into regions
        regions: list[list[EntropyWindow]] = []
        current_region: list[EntropyWindow] = [high_entropy_windows[0]]

        for window in high_entropy_windows[1:]:
            last_window = current_region[-1]
            # Check if windows should be merged
            if window.start - last_window.end <= merge_gap:
                current_region.append(window)
            else:
                regions.append(current_region)
                current_region = [window]

        if current_region:
            regions.append(current_region)

        # Convert to PackedRegion objects
        packed_regions: list[PackedRegion] = []
        for region_windows in regions:
            start = region_windows[0].start
            end = region_windows[-1].end
            size = end - start

            if size < min_region_size:
                continue

            entropies = [w.entropy for w in region_windows]
            avg_entropy = sum(entropies) / len(entropies)
            max_entropy = max(entropies)
            min_entropy = min(entropies)

            # Calculate confidence based on entropy values
            confidence = self._calculate_confidence(avg_entropy, max_entropy, size)

            packed_regions.append(
                PackedRegion(
                    start=start,
                    end=end,
                    avg_entropy=avg_entropy,
                    max_entropy=max_entropy,
                    min_entropy=min_entropy,
                    confidence=confidence,
                )
            )

        return packed_regions

    def _calculate_confidence(
        self, avg_entropy: float, max_entropy: float, size: int
    ) -> float:
        """Calculate confidence score for a packed region detection.

        Args:
            avg_entropy: Average entropy of the region.
            max_entropy: Maximum entropy in the region.
            size: Size of the region in bytes.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        # Higher entropy = higher confidence
        entropy_score = min(avg_entropy / 8.0, 1.0)

        # Peak entropy contributes to confidence
        peak_score = min(max_entropy / 8.0, 1.0)

        # Larger regions are more likely to be intentionally packed
        size_score = min(size / 4096, 1.0)  # Normalize to 4KB

        # Weighted combination
        confidence = (entropy_score * 0.4 + peak_score * 0.4 + size_score * 0.2)
        return round(min(confidence, 1.0), 3)

    def generate_heatmap_data(
        self,
        data: bytes,
        normalize: bool = True,
    ) -> list[dict[str, float | int]]:
        """Generate heatmap data for visualization.

        Args:
            data: Byte sequence to analyze.
            normalize: Whether to normalize entropy values to 0-1 range.

        Returns:
            List of dictionaries with position and entropy values.
        """
        windows = self.analyze_sliding_window(data)
        result: list[dict[str, float | int]] = []

        for window in windows:
            entry: dict[str, float | int] = {
                "start": window.start,
                "end": window.end,
                "entropy": window.entropy,
            }
            if normalize:
                entry["normalized"] = round(window.entropy / 8.0, 3)
            result.append(entry)

        return result

    def analyze_address_space(
        self,
        data: bytes,
        base_address: int = 0,
    ) -> dict[str, list[dict[str, float | int | str]]]:
        """Analyze an address space and return structured results.

        Args:
            data: Byte sequence to analyze.
            base_address: Base address for the data (for display purposes).

        Returns:
            Dictionary with entropy windows and packed regions.
        """
        windows = self.analyze_sliding_window(data)
        packed_regions = self.detect_packed_regions(data)

        window_results: list[dict[str, float | int | str]] = []
        for window in windows:
            window_results.append({
                "address_start": f"0x{base_address + window.start:08X}",
                "address_end": f"0x{base_address + window.end:08X}",
                "offset_start": window.start,
                "offset_end": window.end,
                "entropy": round(window.entropy, 3),
                "classification": self._classify_entropy(window.entropy),
            })

        region_results: list[dict[str, float | int | str]] = []
        for region in packed_regions:
            region_results.append({
                "address_start": f"0x{base_address + region.start:08X}",
                "address_end": f"0x{base_address + region.end:08X}",
                "offset_start": region.start,
                "offset_end": region.end,
                "size": region.size,
                "avg_entropy": round(region.avg_entropy, 3),
                "max_entropy": round(region.max_entropy, 3),
                "min_entropy": round(region.min_entropy, 3),
                "confidence": region.confidence,
            })

        return {
            "windows": window_results,
            "packed_regions": region_results,
        }

    def _classify_entropy(self, entropy: float) -> str:
        """Classify entropy level for display purposes.

        Args:
            entropy: Entropy value.

        Returns:
            Classification string.
        """
        if entropy >= self.HIGH_ENTROPY_THRESHOLD:
            return "high"
        elif entropy >= self.MEDIUM_ENTROPY_THRESHOLD:
            return "medium"
        elif entropy >= self.LOW_ENTROPY_THRESHOLD:
            return "normal"
        else:
            return "low"

    def get_statistics(self, data: bytes) -> dict[str, float | int]:
        """Get overall entropy statistics for the data.

        Args:
            data: Byte sequence to analyze.

        Returns:
            Dictionary with entropy statistics.
        """
        if not data:
            return {
                "total_entropy": 0.0,
                "avg_window_entropy": 0.0,
                "max_window_entropy": 0.0,
                "min_window_entropy": 0.0,
                "high_entropy_windows": 0,
                "total_windows": 0,
            }

        total_entropy = self.calculate_entropy(data)
        windows = self.analyze_sliding_window(data)

        if not windows:
            return {
                "total_entropy": round(total_entropy, 3),
                "avg_window_entropy": 0.0,
                "max_window_entropy": 0.0,
                "min_window_entropy": 0.0,
                "high_entropy_windows": 0,
                "total_windows": 0,
            }

        entropies = [w.entropy for w in windows]
        high_entropy_count = sum(
            1 for e in entropies if e >= self.HIGH_ENTROPY_THRESHOLD
        )

        return {
            "total_entropy": round(total_entropy, 3),
            "avg_window_entropy": round(sum(entropies) / len(entropies), 3),
            "max_window_entropy": round(max(entropies), 3),
            "min_window_entropy": round(min(entropies), 3),
            "high_entropy_windows": high_entropy_count,
            "total_windows": len(windows),
        }
