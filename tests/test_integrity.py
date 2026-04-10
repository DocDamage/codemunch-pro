"""Tests for the integrity checking module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from codemunch_pro.rex.integrity import (
    IntegrityChecker,
    IntegrityIssue,
    IntegrityReport,
    IssueType,
    Severity,
)
from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    ReverseEngineeringBundle,
)
from codemunch_pro.rex.storage import ReverseEngineeringStore


class TestIntegrityIssue:
    """Tests for IntegrityIssue dataclass."""

    def test_issue_creation(self) -> None:
        """Test creating an integrity issue."""
        issue = IntegrityIssue(
            issue_type=IssueType.ORPHANED_REFERENCE,
            severity=Severity.ERROR,
            message="Test message",
            entity_id="entity1",
            artifact_id="artifact1",
            details={"key": "value"},
            auto_fixable=True,
            fix_action="remove_entity",
        )

        assert issue.issue_type == IssueType.ORPHANED_REFERENCE
        assert issue.severity == Severity.ERROR
        assert issue.message == "Test message"
        assert issue.entity_id == "entity1"
        assert issue.artifact_id == "artifact1"
        assert issue.details == {"key": "value"}
        assert issue.auto_fixable is True
        assert issue.fix_action == "remove_entity"

    def test_issue_to_dict(self) -> None:
        """Test converting issue to dictionary."""
        issue = IntegrityIssue(
            issue_type=IssueType.OVERLAPPING_FUNCTION,
            severity=Severity.WARNING,
            message="Functions overlap",
            entity_id="func1",
            details={"overlap_size": 10},
        )

        d = issue.to_dict()
        assert d["issue_type"] == "overlapping_function"
        assert d["severity"] == "warning"
        assert d["message"] == "Functions overlap"
        assert d["entity_id"] == "func1"
        assert d["details"]["overlap_size"] == 10


class TestIntegrityReport:
    """Tests for IntegrityReport dataclass."""

    def test_report_creation(self) -> None:
        """Test creating an integrity report."""
        report = IntegrityReport(
            issues=[],
            stats={"entities": 10},
        )

        assert report.issues == []
        assert report.stats == {"entities": 10}
        assert report.checked_at != ""  # Should auto-generate timestamp

    def test_issue_counts(self) -> None:
        """Test issue counting methods."""
        issues = [
            IntegrityIssue(IssueType.ORPHANED_REFERENCE, Severity.ERROR, "Error 1"),
            IntegrityIssue(IssueType.ORPHANED_REFERENCE, Severity.ERROR, "Error 2"),
            IntegrityIssue(IssueType.OVERLAPPING_FUNCTION, Severity.WARNING, "Warning 1"),
            IntegrityIssue(IssueType.MISSING_EVIDENCE, Severity.INFO, "Info 1"),
            IntegrityIssue(IssueType.CIRCULAR_DEPENDENCY, Severity.CRITICAL, "Critical 1"),
        ]

        report = IntegrityReport(issues=issues)

        assert report.error_count == 3  # 2 ERROR + 1 CRITICAL
        assert report.warning_count == 1
        assert report.info_count == 1

    def test_get_by_severity(self) -> None:
        """Test filtering issues by severity."""
        issues = [
            IntegrityIssue(IssueType.ORPHANED_REFERENCE, Severity.ERROR, "Error 1"),
            IntegrityIssue(IssueType.OVERLAPPING_FUNCTION, Severity.WARNING, "Warning 1"),
            IntegrityIssue(IssueType.MISSING_EVIDENCE, Severity.INFO, "Info 1"),
        ]

        report = IntegrityReport(issues=issues)
        errors = report.get_by_severity(Severity.ERROR)

        assert len(errors) == 1
        assert errors[0].message == "Error 1"

    def test_get_by_type(self) -> None:
        """Test filtering issues by type."""
        issues = [
            IntegrityIssue(IssueType.ORPHANED_REFERENCE, Severity.ERROR, "Error 1"),
            IntegrityIssue(IssueType.ORPHANED_REFERENCE, Severity.ERROR, "Error 2"),
            IntegrityIssue(IssueType.OVERLAPPING_FUNCTION, Severity.WARNING, "Warning 1"),
        ]

        report = IntegrityReport(issues=issues)
        orphaned = report.get_by_type(IssueType.ORPHANED_REFERENCE)

        assert len(orphaned) == 2

    def test_to_dict(self) -> None:
        """Test converting report to dictionary."""
        issues = [
            IntegrityIssue(IssueType.ORPHANED_REFERENCE, Severity.ERROR, "Error 1"),
            IntegrityIssue(IssueType.OVERLAPPING_FUNCTION, Severity.WARNING, "Warning 1"),
        ]

        report = IntegrityReport(
            issues=issues,
            stats={"entities": 10, "edges": 5},
        )

        d = report.to_dict()
        assert d["summary"]["total_issues"] == 2
        assert d["summary"]["errors"] == 1
        assert d["summary"]["warnings"] == 1
        assert d["stats"]["entities"] == 10
        assert len(d["issues"]) == 2


class TestIntegrityChecker:
    """Tests for IntegrityChecker class."""

    @pytest.fixture
    def temp_db(self) -> Path:
        """Create a temporary database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "test.db"

    @pytest.fixture
    def store(self, temp_db: Path) -> ReverseEngineeringStore:
        """Create a test store."""
        store = ReverseEngineeringStore(temp_db)
        yield store
        store.close()  # Ensure connection is closed for cleanup

    def test_empty_store(self, store: ReverseEngineeringStore) -> None:
        """Test checking an empty store."""
        checker = IntegrityChecker(store)
        report = checker.check_all()

        assert len(report.issues) == 0
        assert report.stats["entities"] == 0
        assert report.stats["artifacts"] == 0

    def test_orphaned_reference_detection(self, store: ReverseEngineeringStore) -> None:
        """Test detection of orphaned references."""
        # Create entity with non-existent artifact
        bundle = ReverseEngineeringBundle(
            entities=[
                EntityRecord(
                    entity_id="entity1",
                    kind="function",
                    name="test_func",
                    artifact_id="non_existent_artifact",
                )
            ]
        )
        store.upsert_bundle(bundle)

        checker = IntegrityChecker(store)
        report = checker.check_all()

        orphaned = [i for i in report.issues if i.issue_type == IssueType.ORPHANED_REFERENCE]
        assert len(orphaned) == 1
        assert orphaned[0].entity_id == "entity1"
        assert orphaned[0].auto_fixable is True

    def test_overlapping_function_detection(self, store: ReverseEngineeringStore) -> None:
        """Test detection of overlapping functions."""
        bundle = ReverseEngineeringBundle(
            artifacts=[
                ArtifactRecord(
                    artifact_id="test.asm",
                    kind="assembly",
                    path="test.asm",
                )
            ],
            entities=[
                EntityRecord(
                    entity_id="func1",
                    kind="function",
                    name="function1",
                    artifact_id="test.asm",
                    location=AddressLocation(
                        address_space="rom",
                        start=0x1000,
                        end=0x1100,
                    ),
                ),
                EntityRecord(
                    entity_id="func2",
                    kind="function",
                    name="function2",
                    artifact_id="test.asm",
                    location=AddressLocation(
                        address_space="rom",
                        start=0x1050,  # Overlaps with func1
                        end=0x1150,
                    ),
                ),
            ],
        )
        store.upsert_bundle(bundle)

        checker = IntegrityChecker(store)
        report = checker.check_all()

        overlaps = [i for i in report.issues if i.issue_type == IssueType.OVERLAPPING_FUNCTION]
        assert len(overlaps) == 1
        # Check that overlap was detected (overlap is 0x1100 - 0x1050 + 1 = 177 bytes in decimal)
        assert overlaps[0].details["overlap_size"] == 177

    def test_invalid_address_range_detection(self, store: ReverseEngineeringStore) -> None:
        """Test detection of invalid address ranges."""
        # Note: AddressLocation validates this in __post_init__, so we need to bypass it
        # by directly inserting into the database. We also need to mock _json_to_location
        # to not raise an error.
        cursor = store._conn.cursor()
        cursor.execute(
            """
            INSERT INTO entities (entity_id, kind, name, location_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                "bad_entity",
                "function",
                "bad_func",
                json.dumps({
                    "address_space": "rom",
                    "start": 0x2000,
                    "end": 0x1000,  # Invalid: start > end
                }),
            ),
        )
        store._conn.commit()

        # Mock _json_to_location to not validate (for testing purposes)
        original_json_to_location = store._json_to_location

        def mock_json_to_location(json_str: str | None):
            if json_str is None:
                return None
            data = json.loads(json_str)
            # Create a simple mock object with the required attributes
            class MockLocation:
                def __init__(self, data):
                    self.address_space = data.get("address_space", "")
                    self.start = data.get("start", 0)
                    self.end = data.get("end", 0)
                    self.unit = data.get("unit", "byte")
                    self.display = data.get("display", "")
                    self.segment = data.get("segment", "")
                    self.attributes = data.get("attributes", {})
            return MockLocation(data)

        store._json_to_location = mock_json_to_location

        try:
            checker = IntegrityChecker(store)
            report = checker.check_all()

            invalid = [i for i in report.issues if i.issue_type == IssueType.INVALID_ADDRESS_RANGE]
            assert len(invalid) == 1
            assert invalid[0].entity_id == "bad_entity"
        finally:
            store._json_to_location = original_json_to_location

    def test_broken_cross_reference_detection(self, store: ReverseEngineeringStore) -> None:
        """Test detection of broken cross-references."""
        # Create edge with non-existent source entity
        cursor = store._conn.cursor()
        cursor.execute(
            """
            INSERT INTO edges (edge_id, kind, source_entity_id, target_entity_id)
            VALUES (?, ?, ?, ?)
            """,
            ("edge1", "calls", "non_existent_source", "non_existent_target"),
        )
        store._conn.commit()

        checker = IntegrityChecker(store)
        report = checker.check_all()

        broken = [i for i in report.issues if i.issue_type == IssueType.BROKEN_CROSS_REFERENCE]
        assert len(broken) == 2  # Both source and target are broken
        assert all(i.auto_fixable for i in broken)

    def test_circular_dependency_detection(self, store: ReverseEngineeringStore) -> None:
        """Test detection of circular dependencies."""
        bundle = ReverseEngineeringBundle(
            artifacts=[
                ArtifactRecord(
                    artifact_id="test.asm",
                    kind="assembly",
                    path="test.asm",
                )
            ],
            entities=[
                EntityRecord(
                    entity_id="entity_a",
                    kind="function",
                    name="function_a",
                    artifact_id="test.asm",
                ),
                EntityRecord(
                    entity_id="entity_b",
                    kind="function",
                    name="function_b",
                    artifact_id="test.asm",
                ),
                EntityRecord(
                    entity_id="entity_c",
                    kind="function",
                    name="function_c",
                    artifact_id="test.asm",
                ),
            ],
            edges=[
                # Create cycle: A -> B -> C -> A
                EdgeRecord(
                    edge_id="edge_ab",
                    kind="depends_on",
                    source_entity_id="entity_a",
                    target_entity_id="entity_b",
                ),
                EdgeRecord(
                    edge_id="edge_bc",
                    kind="depends_on",
                    source_entity_id="entity_b",
                    target_entity_id="entity_c",
                ),
                EdgeRecord(
                    edge_id="edge_ca",
                    kind="depends_on",
                    source_entity_id="entity_c",
                    target_entity_id="entity_a",
                ),
            ],
        )
        store.upsert_bundle(bundle)

        checker = IntegrityChecker(store)
        report = checker.check_all()

        cycles = [i for i in report.issues if i.issue_type == IssueType.CIRCULAR_DEPENDENCY]
        assert len(cycles) >= 1  # At least one cycle should be detected

    def test_invalid_confidence_detection(self, store: ReverseEngineeringStore) -> None:
        """Test detection of invalid confidence values."""
        # Note: EdgeRecord validates confidence in __post_init__, so we bypass it
        # by inserting directly into the database
        bundle = ReverseEngineeringBundle(
            artifacts=[
                ArtifactRecord(
                    artifact_id="test.asm",
                    kind="assembly",
                    path="test.asm",
                )
            ],
            entities=[
                EntityRecord(
                    entity_id="entity1",
                    kind="function",
                    name="test_func",
                    artifact_id="test.asm",
                    attributes={"confidence": 1.5},  # Invalid: > 1.0
                )
            ],
        )
        store.upsert_bundle(bundle)

        # Insert invalid edge directly
        cursor = store._conn.cursor()
        cursor.execute(
            """
            INSERT INTO edges (edge_id, kind, source_entity_id, target_entity_id, confidence)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("edge1", "calls", "entity1", "entity1", -0.5),  # Invalid: < 0.0
        )
        store._conn.commit()

        checker = IntegrityChecker(store)
        report = checker.check_all()

        invalid = [i for i in report.issues if i.issue_type == IssueType.INVALID_CONFIDENCE]
        assert len(invalid) == 2  # One for entity, one for edge
        assert all(i.auto_fixable for i in invalid)

    def test_fix_issues(self, store: ReverseEngineeringStore) -> None:
        """Test fixing issues."""
        # Create a broken edge
        cursor = store._conn.cursor()
        cursor.execute(
            """
            INSERT INTO edges (edge_id, kind, source_entity_id, target_entity_id)
            VALUES (?, ?, ?, ?)
            """,
            ("broken_edge", "calls", "missing_source", "missing_target"),
        )
        store._conn.commit()

        checker = IntegrityChecker(store)
        report = checker.check_all()

        # Find auto-fixable issues
        auto_fixable = report.get_auto_fixable()
        assert len(auto_fixable) > 0

        # Fix them
        fix_result = checker.fix_issues(auto_fixable)
        assert fix_result["fixed_count"] > 0

        # Verify the edge was removed
        cursor.execute("SELECT COUNT(*) FROM edges WHERE edge_id = ?", ("broken_edge",))
        count = cursor.fetchone()[0]
        assert count == 0

    def test_fix_confidence_clamping(self, store: ReverseEngineeringStore) -> None:
        """Test fixing invalid confidence by clamping."""
        bundle = ReverseEngineeringBundle(
            artifacts=[
                ArtifactRecord(
                    artifact_id="test.asm",
                    kind="assembly",
                    path="test.asm",
                )
            ],
            entities=[
                EntityRecord(
                    entity_id="entity1",
                    kind="function",
                    name="test_func",
                    artifact_id="test.asm",
                    attributes={"confidence": 2.0},  # Invalid: > 1.0
                )
            ],
        )
        store.upsert_bundle(bundle)

        checker = IntegrityChecker(store)
        report = checker.check_all()

        # Fix the issue
        auto_fixable = report.get_auto_fixable()
        checker.fix_issues(auto_fixable)

        # Verify confidence was clamped
        entity = store.get_entity("entity1")
        assert entity is not None
        assert entity.attributes["confidence"] == 1.0


class TestStorageIntegration:
    """Tests for storage integration methods."""

    @pytest.fixture
    def temp_db(self) -> Path:
        """Create a temporary database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "test.db"

    @pytest.fixture
    def store(self, temp_db: Path) -> ReverseEngineeringStore:
        """Create a test store."""
        store = ReverseEngineeringStore(temp_db)
        yield store
        store.close()  # Ensure connection is closed for cleanup

    def test_check_integrity_method(self, store: ReverseEngineeringStore) -> None:
        """Test the check_integrity method on the store."""
        result = store.check_integrity()

        assert "summary" in result
        assert "stats" in result
        assert "issues" in result
        assert "checked_at" in result

    def test_fix_integrity_issues_dry_run(self, store: ReverseEngineeringStore) -> None:
        """Test fix_integrity_issues without auto-fix."""
        result = store.fix_integrity_issues(auto_fix=False)

        assert result["auto_fix"] is False
        assert "would_fix_count" in result
        assert "issues" in result

    def test_fix_integrity_issues_with_auto_fix(self, store: ReverseEngineeringStore) -> None:
        """Test fix_integrity_issues with auto-fix enabled."""
        # Add a broken edge
        cursor = store._conn.cursor()
        cursor.execute(
            """
            INSERT INTO edges (edge_id, kind, source_entity_id, target_entity_id)
            VALUES (?, ?, ?, ?)
            """,
            ("broken_edge", "calls", "missing_source", "missing_target"),
        )
        store._conn.commit()

        result = store.fix_integrity_issues(auto_fix=True)

        assert result["auto_fix"] is True
        assert result["fixed_count"] > 0


class TestEnums:
    """Tests for enum classes."""

    def test_severity_enum(self) -> None:
        """Test Severity enum values."""
        assert Severity.INFO.value == "info"
        assert Severity.WARNING.value == "warning"
        assert Severity.ERROR.value == "error"
        assert Severity.CRITICAL.value == "critical"

    def test_issue_type_enum(self) -> None:
        """Test IssueType enum values."""
        assert IssueType.ORPHANED_REFERENCE.value == "orphaned_reference"
        assert IssueType.OVERLAPPING_FUNCTION.value == "overlapping_function"
        assert IssueType.INVALID_ADDRESS_RANGE.value == "invalid_address_range"
        assert IssueType.MISSING_EVIDENCE.value == "missing_evidence"
        assert IssueType.BROKEN_CROSS_REFERENCE.value == "broken_cross_reference"
        assert IssueType.CIRCULAR_DEPENDENCY.value == "circular_dependency"
