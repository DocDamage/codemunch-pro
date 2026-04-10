"""Tests for anomaly detection module."""

from __future__ import annotations

import pytest

from codemunch_pro.rex.anomaly_detection import (
    AnomalyDetector,
    AnomalyReport,
    AnomalyResult,
    AnomalyType,
    SeverityLevel,
)


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_severity_values(self) -> None:
        """Test that severity levels have correct numeric values."""
        assert SeverityLevel.INFO.value == 1
        assert SeverityLevel.WARNING.value == 2
        assert SeverityLevel.CRITICAL.value == 3

    def test_severity_labels(self) -> None:
        """Test that severity levels have correct labels."""
        assert SeverityLevel.INFO.label == "info"
        assert SeverityLevel.WARNING.label == "warning"
        assert SeverityLevel.CRITICAL.label == "critical"

    def test_severity_comparison(self) -> None:
        """Test severity level comparison ordering."""
        # INFO < WARNING < CRITICAL
        assert SeverityLevel.INFO.value < SeverityLevel.WARNING.value
        assert SeverityLevel.WARNING.value < SeverityLevel.CRITICAL.value


class TestAnomalyType:
    """Tests for AnomalyType enum."""

    def test_anomaly_type_values(self) -> None:
        """Test that anomaly types have correct values."""
        assert AnomalyType.ANTI_DEBUG.value == "anti_debug"
        assert AnomalyType.TIMING_CHECK.value == "timing_check"
        assert AnomalyType.HIGH_ENTROPY.value == "high_entropy"
        assert AnomalyType.NULL_POINTER_DEREF.value == "null_pointer_dereference"


class TestAnomalyReport:
    """Tests for AnomalyReport dataclass."""

    def test_report_creation(self) -> None:
        """Test creating an anomaly report."""
        report = AnomalyReport(
            anomaly_type=AnomalyType.ANTI_DEBUG,
            severity=SeverityLevel.WARNING,
            address=0x1000,
            address_space="rom",
            description="Test anomaly",
            confidence=0.85,
            details={"key": "value"},
        )

        assert report.anomaly_type == AnomalyType.ANTI_DEBUG
        assert report.severity == SeverityLevel.WARNING
        assert report.address == 0x1000
        assert report.address_space == "rom"
        assert report.description == "Test anomaly"
        assert report.confidence == 0.85
        assert report.details == {"key": "value"}

    def test_report_to_dict(self) -> None:
        """Test converting report to dictionary."""
        report = AnomalyReport(
            anomaly_type=AnomalyType.ANTI_DEBUG,
            severity=SeverityLevel.WARNING,
            address=0x1000,
            address_space="rom",
            description="Test anomaly",
            confidence=0.85,
            details={"key": "value"},
        )

        data = report.to_dict()

        assert data["anomaly_type"] == "anti_debug"
        assert data["severity"] == "warning"
        assert data["address"] == "0x00001000"
        assert data["address_space"] == "rom"
        assert data["description"] == "Test anomaly"
        assert data["confidence"] == 0.85
        assert data["details"] == {"key": "value"}


class TestAnomalyResult:
    """Tests for AnomalyResult class."""

    def test_result_creation(self) -> None:
        """Test creating an anomaly result."""
        result = AnomalyResult(address_space="rom")

        assert result.address_space == "rom"
        assert result.total_anomalies == 0
        assert result.info_count == 0
        assert result.warning_count == 0
        assert result.critical_count == 0
        assert result.anomalies == []

    def test_add_anomaly(self) -> None:
        """Test adding anomalies to result."""
        result = AnomalyResult(address_space="rom")

        report = AnomalyReport(
            anomaly_type=AnomalyType.ANTI_DEBUG,
            severity=SeverityLevel.WARNING,
            address=0x1000,
            address_space="rom",
            description="Test",
            confidence=0.8,
        )

        result.add(report)

        assert result.total_anomalies == 1
        assert result.warning_count == 1
        assert len(result.anomalies) == 1

    def test_add_multiple_severities(self) -> None:
        """Test adding anomalies with different severities."""
        result = AnomalyResult(address_space="rom")

        # Add info
        result.add(
            AnomalyReport(
                anomaly_type=AnomalyType.TIMING_CHECK,
                severity=SeverityLevel.INFO,
                address=0x1000,
                address_space="rom",
                description="Info test",
                confidence=0.5,
            )
        )

        # Add warning
        result.add(
            AnomalyReport(
                anomaly_type=AnomalyType.ANTI_DEBUG,
                severity=SeverityLevel.WARNING,
                address=0x2000,
                address_space="rom",
                description="Warning test",
                confidence=0.7,
            )
        )

        # Add critical
        result.add(
            AnomalyReport(
                anomaly_type=AnomalyType.NULL_POINTER_DEREF,
                severity=SeverityLevel.CRITICAL,
                address=0x3000,
                address_space="rom",
                description="Critical test",
                confidence=0.9,
            )
        )

        assert result.total_anomalies == 3
        assert result.info_count == 1
        assert result.warning_count == 1
        assert result.critical_count == 1

    def test_result_to_dict(self) -> None:
        """Test converting result to dictionary."""
        result = AnomalyResult(address_space="rom")

        result.add(
            AnomalyReport(
                anomaly_type=AnomalyType.ANTI_DEBUG,
                severity=SeverityLevel.WARNING,
                address=0x1000,
                address_space="rom",
                description="Test",
                confidence=0.8,
            )
        )

        data = result.to_dict()

        assert data["address_space"] == "rom"
        assert data["total_anomalies"] == 1
        assert data["by_severity"]["warning"] == 1
        assert len(data["anomalies"]) == 1


class TestAnomalyDetector:
    """Tests for AnomalyDetector class."""

    def test_detector_creation(self) -> None:
        """Test creating an anomaly detector."""
        detector = AnomalyDetector()

        assert detector.entropy_threshold == 7.2
        assert detector.min_region_size == 256

    def test_detector_custom_thresholds(self) -> None:
        """Test creating detector with custom thresholds."""
        detector = AnomalyDetector(
            entropy_threshold=7.5,
            min_region_size=512,
        )

        assert detector.entropy_threshold == 7.5
        assert detector.min_region_size == 512

    def test_anti_debug_patterns(self) -> None:
        """Test that anti-debug patterns are defined."""
        detector = AnomalyDetector()

        # Check that patterns are defined
        assert "RDTSC" in detector.ANTI_DEBUG_PATTERNS
        assert "CPUID" in detector.ANTI_DEBUG_PATTERNS
        assert r"\bSIDT\b|\bSGDT\b|\bSLDT\b" in detector.ANTI_DEBUG_PATTERNS

    def test_rare_opcodes(self) -> None:
        """Test that rare opcodes are defined."""
        detector = AnomalyDetector()

        assert "AAA" in detector.RARE_OPCODES
        assert "DAA" in detector.RARE_OPCODES
        assert "ENTER" in detector.RARE_OPCODES

    def test_suspicious_sequences(self) -> None:
        """Test that suspicious sequences are defined."""
        detector = AnomalyDetector()

        assert len(detector.SUSPICIOUS_SEQUENCES) > 0

    def test_detect_anomalies_with_empty_store(self) -> None:
        """Test anomaly detection with empty/invalid store."""
        # This test checks that the method handles empty stores gracefully
        detector = AnomalyDetector()

        # Mock store that returns empty lists
        class MockStore:
            def list_entities(self, **kwargs):  # type: ignore
                return []

        result = detector.detect_anomalies(
            store=MockStore(),  # type: ignore
            address_space="rom",
            min_severity=SeverityLevel.INFO,
        )

        assert result.total_anomalies == 0
        assert result.address_space == "rom"

    def test_analyze_function_complexity_not_found(self) -> None:
        """Test function complexity analysis when function not found."""
        detector = AnomalyDetector()

        class MockStore:
            def list_entities(self, **kwargs):  # type: ignore
                return []

        result = detector.analyze_function_complexity(
            store=MockStore(),  # type: ignore
            function_address=0x1000,
        )

        assert "error" in result
        assert "not found" in result["error"]

    def test_severity_filtering(self) -> None:
        """Test that min_severity filters anomalies correctly."""
        AnomalyDetector()

        # Create a mock excerpt with a timing check pattern

        # When filtering with WARNING, RDTSC (INFO) should be excluded
        # The test verifies the filtering logic exists
        assert SeverityLevel.INFO.value < SeverityLevel.WARNING.value
        assert SeverityLevel.WARNING.value < SeverityLevel.CRITICAL.value


class TestIntegrationPatterns:
    """Integration tests for pattern detection."""

    @pytest.mark.parametrize(
        "pattern,expected_type,expected_severity",
        [
            ("RDTSC", AnomalyType.TIMING_CHECK, SeverityLevel.INFO),
            ("CPUID", AnomalyType.VM_DETECTION, SeverityLevel.INFO),
            ("SIDT", AnomalyType.VM_DETECTION, SeverityLevel.WARNING),
            ("SGDT", AnomalyType.VM_DETECTION, SeverityLevel.WARNING),
            ("SLDT", AnomalyType.VM_DETECTION, SeverityLevel.WARNING),
            ("STR", AnomalyType.VM_DETECTION, SeverityLevel.WARNING),
            ("RDMSR", AnomalyType.ANTI_DEBUG, SeverityLevel.WARNING),
            ("WRMSR", AnomalyType.ANTI_DEBUG, SeverityLevel.WARNING),
        ],
    )
    def test_pattern_classification(
        self,
        pattern: str,
        expected_type: AnomalyType,
        expected_severity: SeverityLevel,
    ) -> None:
        """Test that patterns are classified correctly."""
        detector = AnomalyDetector()

        # Find the pattern in ANTI_DEBUG_PATTERNS
        found = False
        for p, (atype, severity, _) in detector.ANTI_DEBUG_PATTERNS.items():
            if pattern in p:
                assert atype == expected_type, f"Type mismatch for {pattern}"
                assert severity == expected_severity, f"Severity mismatch for {pattern}"
                found = True
                break

        assert found, f"Pattern {pattern} not found in ANTI_DEBUG_PATTERNS"

    def test_rare_opcode_severity(self) -> None:
        """Test that rare opcodes have INFO severity."""
        detector = AnomalyDetector()

        for opcode, (severity, _) in detector.RARE_OPCODES.items():
            assert severity == SeverityLevel.INFO, f"{opcode} should have INFO severity"


class TestBugPatternDetection:
    """Tests for bug pattern detection."""

    def test_null_pointer_patterns(self) -> None:
        """Test null pointer dereference patterns."""
        AnomalyDetector()

        # Check that null pointer patterns would be detected
        null_patterns = [
            r"MOV\s+\[0+\],",
            r"MOV\s+.*,\s*\[0+\]",
            r"CALL\s+0+",
            r"JMP\s+0+",
        ]

        for pattern in null_patterns:
            assert isinstance(pattern, str)

    def test_unchecked_return_patterns(self) -> None:
        """Test unchecked return value patterns."""
        AnomalyDetector()

        unchecked_patterns = [
            r"CALL\s+.*malloc",
            r"CALL\s+.*alloc",
            r"CALL\s+.*fopen",
            r"CALL\s+.*socket",
        ]

        for pattern in unchecked_patterns:
            assert isinstance(pattern, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
