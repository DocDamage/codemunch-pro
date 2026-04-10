"""Tests for regression testing functionality."""


import pytest

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)
from codemunch_pro.rex.regression import (
    AnalysisSnapshot,
    MetricDiff,
    RegressionReport,
    RegressionTester,
)
from codemunch_pro.rex.storage import ReverseEngineeringStore


@pytest.fixture
def temp_db_path(tmp_path):
    """Create a temporary database path."""
    return tmp_path / "test_regression.db"


@pytest.fixture
def store(temp_db_path):
    """Create a ReverseEngineeringStore with test data."""
    store = ReverseEngineeringStore(temp_db_path)

    # Create test bundle with entities
    bundle = ReverseEngineeringBundle(
        artifacts=[
            ArtifactRecord(
                artifact_id="test://artifact1",
                kind="manifest",
                path="/test/manifest1.json",
                title="Test Manifest 1",
            ),
        ],
        entities=[
            EntityRecord(
                entity_id="func:0x1234",
                kind="function",
                name="sub_1234",
                artifact_id="test://artifact1",
                canonical_ref="0x1234",
                location=AddressLocation(
                    address_space="flat",
                    start=0x1234,
                    end=0x1250,
                ),
            ),
            EntityRecord(
                entity_id="data:0x2000",
                kind="data",
                name="data_2000",
                artifact_id="test://artifact1",
                canonical_ref="0x2000",
                location=AddressLocation(
                    address_space="flat",
                    start=0x2000,
                    end=0x2010,
                ),
            ),
            EntityRecord(
                entity_id="ref:0x3000",
                kind="reference",
                name="ref_3000",
                artifact_id="test://artifact1",
                canonical_ref="0x3000",
            ),
        ],
        evidence=[
            EvidenceRecord(
                evidence_id="ev:1",
                kind="disassembly",
                artifact_id="test://artifact1",
                entity_ids=("func:0x1234",),
                excerpt="LDA #$01",
                confidence=0.95,
            ),
            EvidenceRecord(
                evidence_id="ev:2",
                kind="comment",
                artifact_id="test://artifact1",
                entity_ids=("func:0x1234",),
                excerpt="Main entry point",
                confidence=0.80,
            ),
        ],
        edges=[
            EdgeRecord(
                edge_id="edge:1",
                kind="calls",
                source_entity_id="func:0x1234",
                target_entity_id="data:0x2000",
                confidence=0.90,
            ),
        ],
    )

    store.upsert_bundle(bundle)
    yield store
    store.close()


@pytest.fixture
def tester(store):
    """Create a RegressionTester instance."""
    return RegressionTester(store)


class TestAnalysisSnapshot:
    """Tests for AnalysisSnapshot dataclass."""

    def test_to_dict(self):
        """Test converting snapshot to dictionary."""
        from datetime import datetime

        snapshot = AnalysisSnapshot(
            snapshot_id="test_snapshot",
            created_at=datetime(2024, 1, 1, 12, 0, 0),
            version_tag="v1.0",
            entity_counts={"function": 5, "data": 3},
            confidence_scores={"avg": 0.85},
        )

        data = snapshot.to_dict()
        assert data["snapshot_id"] == "test_snapshot"
        assert data["version_tag"] == "v1.0"
        assert data["entity_counts"]["function"] == 5

    def test_from_dict(self):
        """Test creating snapshot from dictionary."""
        from datetime import datetime

        data = {
            "snapshot_id": "test_snapshot",
            "created_at": "2024-01-01T12:00:00",
            "version_tag": "v1.0",
            "entity_counts": {"function": 5},
            "evidence_counts": {},
            "edge_counts": {},
            "confidence_scores": {},
            "reference_coverage": {},
            "artifact_stats": {},
            "metadata": {},
        }

        snapshot = AnalysisSnapshot.from_dict(data)
        assert snapshot.snapshot_id == "test_snapshot"
        assert snapshot.version_tag == "v1.0"
        assert snapshot.created_at == datetime(2024, 1, 1, 12, 0, 0)


class TestRegressionTester:
    """Tests for RegressionTester class."""

    def test_create_snapshot(self, tester):
        """Test creating a snapshot."""
        snapshot = tester.create_snapshot("v1.0", {"author": "test"})

        assert snapshot.version_tag == "v1.0"
        assert snapshot.metadata["author"] == "test"
        assert "function" in snapshot.entity_counts
        assert "data" in snapshot.entity_counts
        assert snapshot.entity_counts["function"] == 1
        assert snapshot.entity_counts["data"] == 1

    def test_get_entity_counts_by_kind(self, tester):
        """Test getting entity counts by kind."""
        counts = tester._get_entity_counts_by_kind()

        assert counts["function"] == 1
        assert counts["data"] == 1
        assert counts["reference"] == 1

    def test_get_evidence_counts_by_kind(self, tester):
        """Test getting evidence counts by kind."""
        counts = tester._get_evidence_counts_by_kind()

        assert counts["disassembly"] == 1
        assert counts["comment"] == 1

    def test_get_edge_counts_by_kind(self, tester):
        """Test getting edge counts by kind."""
        counts = tester._get_edge_counts_by_kind()

        assert counts["calls"] == 1

    def test_get_confidence_statistics(self, tester):
        """Test getting confidence score statistics."""
        stats = tester._get_confidence_statistics()

        assert "evidence_confidence_avg" in stats
        assert "evidence_confidence_min" in stats
        assert "evidence_confidence_max" in stats
        assert stats["evidence_with_confidence"] == 2

    def test_compare_snapshots(self, tester):
        """Test comparing two snapshots."""
        snapshot_a = tester.create_snapshot("v1.0")
        snapshot_b = tester.create_snapshot("v2.0")

        report = tester.compare_snapshots(snapshot_a, snapshot_b)

        assert report.version_a == "v1.0"
        assert report.version_b == "v2.0"
        assert len(report.entity_diffs) > 0

    def test_compare_counts(self, tester):
        """Test comparing count dictionaries."""
        before = {"function": 10, "data": 5}
        after = {"function": 12, "data": 4, "new_kind": 3}

        diffs = tester._compare_counts(before, after, "entity")

        # Should have diffs for all unique keys
        diff_names = [d.metric_name for d in diffs]
        assert "entity_function" in diff_names
        assert "entity_data" in diff_names
        assert "entity_new_kind" in diff_names

        # Check function diff
        func_diff = next(d for d in diffs if d.metric_name == "entity_function")
        assert func_diff.before == 10
        assert func_diff.after == 12
        assert func_diff.absolute_change == 2
        assert func_diff.relative_change == 0.2

    def test_detect_significant_change(self, tester):
        """Test detecting significant changes."""
        # Create a report with no significant changes
        report = RegressionReport(
            version_a="v1",
            version_b="v2",
            snapshot_a_id="s1",
            snapshot_b_id="s2",
            created_at=__import__("datetime").datetime.now(),
        )

        # Add a non-significant diff
        report.entity_diffs = [
            MetricDiff(
                metric_name="test",
                before=10,
                after=10,
                absolute_change=0,
                relative_change=0.0,
                significant=False,
                severity="info",
            ),
        ]

        assert not tester.detect_significant_change(report)

        # Add a significant diff
        report.entity_diffs.append(
            MetricDiff(
                metric_name="test2",
                before=10,
                after=20,
                absolute_change=10,
                relative_change=1.0,
                significant=True,
                severity="warning",
            ),
        )

        assert tester.detect_significant_change(report)


class TestRegressionReport:
    """Tests for RegressionReport dataclass."""

    def test_to_dict(self):
        """Test converting report to dictionary."""
        from datetime import datetime

        report = RegressionReport(
            version_a="v1.0",
            version_b="v2.0",
            snapshot_a_id="snap_a",
            snapshot_b_id="snap_b",
            created_at=datetime(2024, 1, 1, 12, 0, 0),
            entity_diffs=[
                MetricDiff(
                    metric_name="function",
                    before=10,
                    after=12,
                    absolute_change=2,
                    relative_change=0.2,
                    significant=True,
                    severity="warning",
                ),
            ],
            summary={"total_change": 2},
        )

        data = report.to_dict()
        assert data["version_a"] == "v1.0"
        assert data["version_b"] == "v2.0"
        assert len(data["entity_diffs"]) == 1
        assert data["entity_diffs"][0]["metric_name"] == "function"
        assert data["summary"]["total_change"] == 2


class TestStorageIntegration:
    """Tests for regression testing integration with ReverseEngineeringStore."""

    def test_create_analysis_snapshot(self, store):
        """Test store.create_analysis_snapshot method."""
        result = store.create_analysis_snapshot("v1.0", {"test": True})

        assert result["version_tag"] == "v1.0"
        assert result["metadata"]["test"] is True
        assert "snapshot_id" in result
        assert "entity_counts" in result

    def test_get_analysis_history(self, store):
        """Test store.get_analysis_history method."""
        # Create two snapshots
        store.create_analysis_snapshot("v1.0")
        store.create_analysis_snapshot("v2.0")

        history = store.get_analysis_history(limit=10)

        assert history["count"] == 2
        assert len(history["snapshots"]) == 2

    def test_get_analysis_history_with_filter(self, store):
        """Test filtering analysis history."""
        store.create_analysis_snapshot("release_v1.0")
        store.create_analysis_snapshot("release_v2.0")
        store.create_analysis_snapshot("dev_branch")

        history = store.get_analysis_history(version_filter="release")

        assert history["count"] == 2
        for snap in history["snapshots"]:
            assert "release" in snap["version_tag"]

    def test_compare_analysis_versions(self, store):
        """Test store.compare_analysis_versions method."""
        # Create snapshots
        store.create_analysis_snapshot("v1.0")
        store.create_analysis_snapshot("v2.0")

        result = store.compare_analysis_versions("v1.0", "v2.0")

        assert "version_a" in result
        assert "version_b" in result
        assert "entity_diffs" in result
        assert "comparison_id" in result

    def test_compare_analysis_versions_not_found(self, store):
        """Test comparing non-existent versions."""
        result = store.compare_analysis_versions("nonexistent", "also_missing")

        assert "error" in result

    def test_delete_analysis_snapshot(self, store):
        """Test deleting a snapshot."""
        # Create and get snapshot ID
        snapshot = store.create_analysis_snapshot("v1.0")
        snapshot_id = snapshot["snapshot_id"]

        # Delete it
        result = store.delete_analysis_snapshot(snapshot_id)

        assert result["deleted"] is True

        # Verify it's gone
        history = store.get_analysis_history()
        assert history["count"] == 0


class TestThresholds:
    """Tests for change detection thresholds."""

    def test_default_thresholds(self, store):
        """Test default threshold configuration."""
        tester = RegressionTester(store)

        assert "entity_count" in tester._thresholds
        assert "confidence" in tester._thresholds
        assert "coverage" in tester._thresholds

    def test_custom_thresholds(self, store):
        """Test custom threshold configuration."""
        custom = {"entity_count": 0.2, "confidence": 0.1}
        tester = RegressionTester(store, thresholds=custom)

        assert tester._thresholds["entity_count"] == 0.2
        assert tester._thresholds["confidence"] == 0.1

    def test_significance_detection(self, store):
        """Test that significance is correctly determined."""
        tester = RegressionTester(store, thresholds={"entity_count": 0.1})

        # Test 20% change (significant with 10% threshold)
        diffs = tester._compare_counts(
            {"function": 100},
            {"function": 120},
            "entity",
        )
        assert diffs[0].significant is True

        # Test 5% change (not significant with 10% threshold)
        diffs = tester._compare_counts(
            {"function": 100},
            {"function": 105},
            "entity",
        )
        assert diffs[0].significant is False
