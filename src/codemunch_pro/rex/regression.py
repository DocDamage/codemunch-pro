"""Regression testing for analysis stability.

This module provides functionality to snapshot entity extraction results,
compare analysis between versions, track metrics over time, and detect
significant changes in the reverse-engineering data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore



@dataclass
class AnalysisSnapshot:
    """A snapshot of analysis results at a point in time.
    
    Captures entity counts by kind, reference coverage, confidence scores,
    and other metrics for tracking analysis stability over time.
    """
    
    snapshot_id: str
    created_at: datetime
    version_tag: str
    entity_counts: dict[str, int] = field(default_factory=dict)
    evidence_counts: dict[str, int] = field(default_factory=dict)
    edge_counts: dict[str, int] = field(default_factory=dict)
    confidence_scores: dict[str, float] = field(default_factory=dict)
    reference_coverage: dict[str, int] = field(default_factory=dict)
    artifact_stats: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert snapshot to dictionary representation."""
        return {
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at.isoformat(),
            "version_tag": self.version_tag,
            "entity_counts": self.entity_counts,
            "evidence_counts": self.evidence_counts,
            "edge_counts": self.edge_counts,
            "confidence_scores": self.confidence_scores,
            "reference_coverage": self.reference_coverage,
            "artifact_stats": self.artifact_stats,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisSnapshot":
        """Create a snapshot from dictionary representation."""
        return cls(
            snapshot_id=data["snapshot_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            version_tag=data["version_tag"],
            entity_counts=data.get("entity_counts", {}),
            evidence_counts=data.get("evidence_counts", {}),
            edge_counts=data.get("edge_counts", {}),
            confidence_scores=data.get("confidence_scores", {}),
            reference_coverage=data.get("reference_coverage", {}),
            artifact_stats=data.get("artifact_stats", {}),
            metadata=data.get("metadata", {}),
        )


@dataclass
class MetricDiff:
    """Difference in a single metric between two snapshots."""
    
    metric_name: str
    before: Any
    after: Any
    absolute_change: Any
    relative_change: float
    significant: bool
    severity: str  # "info", "warning", "critical"


@dataclass
class RegressionReport:
    """Report comparing two analysis snapshots.
    
    Contains detailed diffs of entity counts, confidence scores,
    reference coverage changes, and detected anomalies.
    """
    
    version_a: str
    version_b: str
    snapshot_a_id: str
    snapshot_b_id: str
    created_at: datetime
    entity_diffs: list[MetricDiff] = field(default_factory=list)
    evidence_diffs: list[MetricDiff] = field(default_factory=list)
    edge_diffs: list[MetricDiff] = field(default_factory=list)
    confidence_diffs: list[MetricDiff] = field(default_factory=list)
    coverage_diffs: list[MetricDiff] = field(default_factory=list)
    added_entities: list[str] = field(default_factory=list)
    removed_entities: list[str] = field(default_factory=list)
    changed_entities: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    significant_changes: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary representation."""
        return {
            "version_a": self.version_a,
            "version_b": self.version_b,
            "snapshot_a_id": self.snapshot_a_id,
            "snapshot_b_id": self.snapshot_b_id,
            "created_at": self.created_at.isoformat(),
            "entity_diffs": [
                {
                    "metric_name": d.metric_name,
                    "before": d.before,
                    "after": d.after,
                    "absolute_change": d.absolute_change,
                    "relative_change": d.relative_change,
                    "significant": d.significant,
                    "severity": d.severity,
                }
                for d in self.entity_diffs
            ],
            "evidence_diffs": [
                {
                    "metric_name": d.metric_name,
                    "before": d.before,
                    "after": d.after,
                    "absolute_change": d.absolute_change,
                    "relative_change": d.relative_change,
                    "significant": d.significant,
                    "severity": d.severity,
                }
                for d in self.evidence_diffs
            ],
            "edge_diffs": [
                {
                    "metric_name": d.metric_name,
                    "before": d.before,
                    "after": d.after,
                    "absolute_change": d.absolute_change,
                    "relative_change": d.relative_change,
                    "significant": d.significant,
                    "severity": d.severity,
                }
                for d in self.edge_diffs
            ],
            "confidence_diffs": [
                {
                    "metric_name": d.metric_name,
                    "before": d.before,
                    "after": d.after,
                    "absolute_change": d.absolute_change,
                    "relative_change": d.relative_change,
                    "significant": d.significant,
                    "severity": d.severity,
                }
                for d in self.confidence_diffs
            ],
            "coverage_diffs": [
                {
                    "metric_name": d.metric_name,
                    "before": d.before,
                    "after": d.after,
                    "absolute_change": d.absolute_change,
                    "relative_change": d.relative_change,
                    "significant": d.significant,
                    "severity": d.severity,
                }
                for d in self.coverage_diffs
            ],
            "added_entities": self.added_entities,
            "removed_entities": self.removed_entities,
            "changed_entities": self.changed_entities,
            "summary": self.summary,
            "significant_changes": self.significant_changes,
        }


class RegressionTester:
    """Regression tester for reverse-engineering analysis stability.
    
    Provides functionality to:
    - Create snapshots of entity extraction results
    - Compare analysis between versions
    - Track metrics over time (entity counts, reference coverage, confidence scores)
    - Detect significant changes
    """
    
    def __init__(
        self,
        store: ReverseEngineeringStore,
        thresholds: dict[str, float] | None = None,
    ):
        """Initialize the regression tester.
        
        Args:
            store: The ReverseEngineeringStore to analyze
            thresholds: Configuration for change detection thresholds.
                       Keys: "entity_count", "confidence", "coverage"
                       Default: entity_count=0.1 (10%), confidence=0.05 (5%), coverage=0.1 (10%)
        """
        self._store = store
        self._thresholds = thresholds or {
            "entity_count": 0.1,
            "confidence": 0.05,
            "coverage": 0.1,
        }
    
    def create_snapshot(
        self,
        version_tag: str,
        metadata: dict[str, Any] | None = None,
    ) -> AnalysisSnapshot:
        """Create a snapshot of the current analysis state.
        
        Args:
            version_tag: Identifier for this version (e.g., git commit hash)
            metadata: Optional additional metadata to store with the snapshot
            
        Returns:
            AnalysisSnapshot containing all metrics
        """
        snapshot_id = f"snapshot_{version_tag}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        # Get entity counts by kind
        entity_counts = self._get_entity_counts_by_kind()
        
        # Get evidence counts by kind
        evidence_counts = self._get_evidence_counts_by_kind()
        
        # Get edge counts by kind
        edge_counts = self._get_edge_counts_by_kind()
        
        # Get confidence score statistics
        confidence_scores = self._get_confidence_statistics()
        
        # Get reference coverage by address space
        reference_coverage = self._get_reference_coverage()
        
        # Get artifact statistics
        artifact_stats = self._store.stats()
        
        return AnalysisSnapshot(
            snapshot_id=snapshot_id,
            created_at=datetime.now(timezone.utc),
            version_tag=version_tag,
            entity_counts=entity_counts,
            evidence_counts=evidence_counts,
            edge_counts=edge_counts,
            confidence_scores=confidence_scores,
            reference_coverage=reference_coverage,
            artifact_stats=artifact_stats,
            metadata=metadata or {},
        )
    
    def compare_snapshots(
        self,
        snapshot_a: AnalysisSnapshot,
        snapshot_b: AnalysisSnapshot,
    ) -> RegressionReport:
        """Compare two snapshots and generate a regression report.
        
        Args:
            snapshot_a: The baseline snapshot
            snapshot_b: The new snapshot to compare against baseline
            
        Returns:
            RegressionReport with detailed diffs and change analysis
        """
        report = RegressionReport(
            version_a=snapshot_a.version_tag,
            version_b=snapshot_b.version_tag,
            snapshot_a_id=snapshot_a.snapshot_id,
            snapshot_b_id=snapshot_b.snapshot_id,
            created_at=datetime.now(timezone.utc),
        )
        
        # Compare entity counts
        report.entity_diffs = self._compare_counts(
            snapshot_a.entity_counts,
            snapshot_b.entity_counts,
            "entity",
        )
        
        # Compare evidence counts
        report.evidence_diffs = self._compare_counts(
            snapshot_a.evidence_counts,
            snapshot_b.evidence_counts,
            "evidence",
        )
        
        # Compare edge counts
        report.edge_diffs = self._compare_counts(
            snapshot_a.edge_counts,
            snapshot_b.edge_counts,
            "edge",
        )
        
        # Compare confidence scores
        report.confidence_diffs = self._compare_confidence_scores(
            snapshot_a.confidence_scores,
            snapshot_b.confidence_scores,
        )
        
        # Compare reference coverage
        report.coverage_diffs = self._compare_coverage(
            snapshot_a.reference_coverage,
            snapshot_b.reference_coverage,
        )
        
        # Compare individual entities
        (
            report.added_entities,
            report.removed_entities,
            report.changed_entities,
        ) = self._compare_entities(snapshot_a, snapshot_b)
        
        # Generate summary
        report.summary = self._generate_summary(report)
        
        # Identify significant changes
        report.significant_changes = self._identify_significant_changes(report)
        
        return report
    
    def detect_significant_change(
        self,
        report: RegressionReport,
        metric_type: str = "any",
    ) -> bool:
        """Detect if a report contains significant changes.
        
        Args:
            report: The regression report to analyze
            metric_type: Type of metric to check ("entity", "confidence", "coverage", "any")
            
        Returns:
            True if significant changes detected
        """
        if metric_type == "entity" or metric_type == "any":
            for diff in report.entity_diffs:
                if diff.significant:
                    return True
        
        if metric_type == "confidence" or metric_type == "any":
            for diff in report.confidence_diffs:
                if diff.significant:
                    return True
        
        if metric_type == "coverage" or metric_type == "any":
            for diff in report.coverage_diffs:
                if diff.significant:
                    return True
        
        return False
    
    def _get_entity_counts_by_kind(self) -> dict[str, int]:
        """Get entity counts grouped by kind."""
        cursor = self._store._conn.cursor()
        cursor.execute("SELECT kind, COUNT(*) FROM entities GROUP BY kind")
        return {row[0]: row[1] for row in cursor.fetchall()}
    
    def _get_evidence_counts_by_kind(self) -> dict[str, int]:
        """Get evidence counts grouped by kind."""
        cursor = self._store._conn.cursor()
        cursor.execute("SELECT kind, COUNT(*) FROM evidence GROUP BY kind")
        return {row[0]: row[1] for row in cursor.fetchall()}
    
    def _get_edge_counts_by_kind(self) -> dict[str, int]:
        """Get edge counts grouped by kind."""
        cursor = self._store._conn.cursor()
        cursor.execute("SELECT kind, COUNT(*) FROM edges GROUP BY kind")
        return {row[0]: row[1] for row in cursor.fetchall()}
    
    def _get_confidence_statistics(self) -> dict[str, float]:
        """Get confidence score statistics."""
        cursor = self._store._conn.cursor()
        
        # Evidence confidence
        cursor.execute("""
            SELECT 
                AVG(confidence),
                MIN(confidence),
                MAX(confidence),
                COUNT(*)
            FROM evidence 
            WHERE confidence IS NOT NULL
        """)
        row = cursor.fetchone()
        ev_stats = {
            "evidence_confidence_avg": row[0] if row[0] else 0.0,
            "evidence_confidence_min": row[1] if row[1] else 0.0,
            "evidence_confidence_max": row[2] if row[2] else 0.0,
            "evidence_with_confidence": row[3] if row[3] else 0,
        }
        
        # Edge confidence
        cursor.execute("""
            SELECT 
                AVG(confidence),
                MIN(confidence),
                MAX(confidence),
                COUNT(*)
            FROM edges 
            WHERE confidence IS NOT NULL
        """)
        row = cursor.fetchone()
        edge_stats = {
            "edge_confidence_avg": row[0] if row[0] else 0.0,
            "edge_confidence_min": row[1] if row[1] else 0.0,
            "edge_confidence_max": row[2] if row[2] else 0.0,
            "edge_with_confidence": row[3] if row[3] else 0,
        }
        
        return {**ev_stats, **edge_stats}
    
    def _get_reference_coverage(self) -> dict[str, int]:
        """Get reference coverage by address space."""
        cursor = self._store._conn.cursor()
        
        # Count entities with canonical_ref by address space
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN location_json IS NULL THEN 'unknown'
                    ELSE json_extract(location_json, '$.address_space')
                END as address_space,
                COUNT(*)
            FROM entities
            WHERE canonical_ref != ''
            GROUP BY address_space
        """)
        
        result = {}
        for row in cursor.fetchall():
            address_space = row[0] or "unknown"
            result[address_space] = row[1]
        
        # Also count total entities per address space
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN location_json IS NULL THEN 'unknown'
                    ELSE json_extract(location_json, '$.address_space')
                END as address_space,
                COUNT(*)
            FROM entities
            GROUP BY address_space
        """)
        
        for row in cursor.fetchall():
            address_space = row[0] or "unknown"
            total = row[1]
            covered = result.get(address_space, 0)
            result[f"{address_space}_coverage_pct"] = (
                (covered / total * 100) if total > 0 else 0.0
            )
        
        return result
    
    def _compare_counts(
        self,
        before: dict[str, int],
        after: dict[str, int],
        metric_prefix: str,
    ) -> list[MetricDiff]:
        """Compare two count dictionaries and return diffs."""
        diffs = []
        all_keys = set(before.keys()) | set(after.keys())
        
        for key in sorted(all_keys):
            before_val = before.get(key, 0)
            after_val = after.get(key, 0)
            absolute_change = after_val - before_val
            
            if before_val > 0:
                relative_change = absolute_change / before_val
            elif after_val > 0:
                relative_change = 1.0  # New category
            else:
                relative_change = 0.0
            
            # Determine significance
            threshold = self._thresholds.get("entity_count", 0.1)
            significant = abs(relative_change) >= threshold
            
            # Determine severity
            if abs(relative_change) >= threshold * 2:
                severity = "critical"
            elif significant:
                severity = "warning"
            else:
                severity = "info"
            
            diffs.append(MetricDiff(
                metric_name=f"{metric_prefix}_{key}",
                before=before_val,
                after=after_val,
                absolute_change=absolute_change,
                relative_change=relative_change,
                significant=significant,
                severity=severity,
            ))
        
        return diffs
    
    def _compare_confidence_scores(
        self,
        before: dict[str, float],
        after: dict[str, float],
    ) -> list[MetricDiff]:
        """Compare confidence score statistics."""
        diffs = []
        all_keys = set(before.keys()) | set(after.keys())
        threshold = self._thresholds.get("confidence", 0.05)
        
        for key in sorted(all_keys):
            before_val = before.get(key, 0.0)
            after_val = after.get(key, 0.0)
            absolute_change = after_val - before_val
            
            if before_val > 0:
                relative_change = absolute_change / before_val
            elif after_val > 0:
                relative_change = 1.0
            else:
                relative_change = 0.0
            
            # Confidence changes are significant if they exceed threshold
            significant = abs(absolute_change) >= threshold
            
            if abs(absolute_change) >= threshold * 2:
                severity = "critical"
            elif significant:
                severity = "warning"
            else:
                severity = "info"
            
            diffs.append(MetricDiff(
                metric_name=key,
                before=round(before_val, 4),
                after=round(after_val, 4),
                absolute_change=round(absolute_change, 4),
                relative_change=round(relative_change, 4),
                significant=significant,
                severity=severity,
            ))
        
        return diffs
    
    def _compare_coverage(
        self,
        before: dict[str, int],
        after: dict[str, int],
    ) -> list[MetricDiff]:
        """Compare reference coverage statistics."""
        diffs = []
        all_keys = set(before.keys()) | set(after.keys())
        threshold = self._thresholds.get("coverage", 0.1)
        
        for key in sorted(all_keys):
            before_val = before.get(key, 0)
            after_val = after.get(key, 0)
            absolute_change = after_val - before_val
            
            if "_coverage_pct" in key:
                # Coverage percentage comparison
                significant = abs(absolute_change) >= (threshold * 100)
                if abs(absolute_change) >= (threshold * 200):
                    severity = "critical"
                elif significant:
                    severity = "warning"
                else:
                    severity = "info"
            else:
                # Raw count comparison
                if before_val > 0:
                    relative_change = absolute_change / before_val
                elif after_val > 0:
                    relative_change = 1.0
                else:
                    relative_change = 0.0
                
                significant = abs(relative_change) >= threshold
                if abs(relative_change) >= threshold * 2:
                    severity = "critical"
                elif significant:
                    severity = "warning"
                else:
                    severity = "info"
            
            relative_change = (
                (absolute_change / before_val) if before_val > 0 else 
                (1.0 if after_val > 0 else 0.0)
            )
            
            diffs.append(MetricDiff(
                metric_name=key,
                before=before_val,
                after=after_val,
                absolute_change=absolute_change,
                relative_change=round(relative_change, 4),
                significant=significant,
                severity=severity,
            ))
        
        return diffs
    
    def _compare_entities(
        self,
        snapshot_a: AnalysisSnapshot,
        snapshot_b: AnalysisSnapshot,
    ) -> tuple[list[str], list[str], list[dict[str, Any]]]:
        """Compare individual entities between snapshots.
        
        Returns:
            Tuple of (added_entities, removed_entities, changed_entities)
        """
        # Get current entity IDs from store
        cursor = self._store._conn.cursor()
        cursor.execute("SELECT entity_id, kind, name, canonical_ref FROM entities")
        {row[0]: row for row in cursor.fetchall()}
        
        # Note: For full entity comparison, we'd need to store entity IDs in snapshot
        # For now, return empty lists - can be enhanced with full entity tracking
        return [], [], []
    
    def _generate_summary(self, report: RegressionReport) -> dict[str, Any]:
        """Generate a summary of the regression report."""
        total_entities_before = sum(
            d.before for d in report.entity_diffs if isinstance(d.before, int)
        )
        total_entities_after = sum(
            d.after for d in report.entity_diffs if isinstance(d.after, int)
        )
        
        total_evidence_before = sum(
            d.before for d in report.evidence_diffs if isinstance(d.before, int)
        )
        total_evidence_after = sum(
            d.after for d in report.evidence_diffs if isinstance(d.after, int)
        )
        
        significant_entity_changes = sum(
            1 for d in report.entity_diffs if d.significant
        )
        significant_confidence_changes = sum(
            1 for d in report.confidence_diffs if d.significant
        )
        
        return {
            "total_entities_before": total_entities_before,
            "total_entities_after": total_entities_after,
            "entity_change": total_entities_after - total_entities_before,
            "total_evidence_before": total_evidence_before,
            "total_evidence_after": total_evidence_after,
            "evidence_change": total_evidence_after - total_evidence_before,
            "significant_entity_changes": significant_entity_changes,
            "significant_confidence_changes": significant_confidence_changes,
            "entities_added": len(report.added_entities),
            "entities_removed": len(report.removed_entities),
            "entities_changed": len(report.changed_entities),
        }
    
    def _identify_significant_changes(self, report: RegressionReport) -> list[str]:
        """Identify and describe significant changes."""
        changes = []
        
        for diff in report.entity_diffs:
            if diff.significant:
                direction = "increased" if diff.absolute_change > 0 else "decreased"
                changes.append(
                    f"Entity count '{diff.metric_name}' {direction} by "
                    f"{abs(diff.absolute_change)} ({diff.relative_change*100:.1f}%)"
                )
        
        for diff in report.confidence_diffs:
            if diff.significant:
                direction = "increased" if diff.absolute_change > 0 else "decreased"
                changes.append(
                    f"Confidence '{diff.metric_name}' {direction} by "
                    f"{abs(diff.absolute_change):.3f}"
                )
        
        for diff in report.coverage_diffs:
            if diff.significant:
                direction = "increased" if diff.absolute_change > 0 else "decreased"
                changes.append(
                    f"Coverage '{diff.metric_name}' {direction} by "
                    f"{abs(diff.absolute_change):.1f}%"
                )
        
        return changes
