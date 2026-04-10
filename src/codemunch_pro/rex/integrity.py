"""Integrity checking for reverse-engineering projects.

This module provides comprehensive integrity validation for RE project data,
including detection of orphaned references, overlapping functions, invalid
address ranges, missing evidence, broken cross-references, and circular dependencies.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore


class Severity(Enum):
    """Issue severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class IssueType(Enum):
    """Types of integrity issues."""

    ORPHANED_REFERENCE = "orphaned_reference"
    OVERLAPPING_FUNCTION = "overlapping_function"
    INVALID_ADDRESS_RANGE = "invalid_address_range"
    MISSING_EVIDENCE = "missing_evidence"
    BROKEN_CROSS_REFERENCE = "broken_cross_reference"
    CIRCULAR_DEPENDENCY = "circular_dependency"
    INVALID_CONFIDENCE = "invalid_confidence"
    DUPLICATE_ENTITY_ID = "duplicate_entity_id"
    DUPLICATE_EDGE_ID = "duplicate_edge_id"
    STALE_ARTIFACT_REFERENCE = "stale_artifact_reference"


@dataclass
class IntegrityIssue:
    """A single integrity issue."""

    issue_type: IssueType
    severity: Severity
    message: str
    entity_id: str = ""
    artifact_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    auto_fixable: bool = False
    fix_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert issue to dictionary."""
        return {
            "issue_type": self.issue_type.value,
            "severity": self.severity.value,
            "message": self.message,
            "entity_id": self.entity_id,
            "artifact_id": self.artifact_id,
            "details": self.details,
            "auto_fixable": self.auto_fixable,
            "fix_action": self.fix_action,
        }


@dataclass
class IntegrityReport:
    """Report containing all integrity issues."""

    issues: list[IntegrityIssue] = field(default_factory=list)
    checked_at: str = ""
    stats: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.checked_at:
            from datetime import datetime, timezone

            self.checked_at = datetime.now(timezone.utc).isoformat()

    @property
    def error_count(self) -> int:
        """Count of error/critical issues."""
        return sum(
            1
            for i in self.issues
            if i.severity in (Severity.ERROR, Severity.CRITICAL)
        )

    @property
    def warning_count(self) -> int:
        """Count of warning issues."""
        return sum(1 for i in self.issues if i.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        """Count of info issues."""
        return sum(1 for i in self.issues if i.severity == Severity.INFO)

    @property
    def auto_fixable_count(self) -> int:
        """Count of auto-fixable issues."""
        return sum(1 for i in self.issues if i.auto_fixable)

    def get_by_severity(self, severity: Severity) -> list[IntegrityIssue]:
        """Get issues by severity."""
        return [i for i in self.issues if i.severity == severity]

    def get_by_type(self, issue_type: IssueType) -> list[IntegrityIssue]:
        """Get issues by type."""
        return [i for i in self.issues if i.issue_type == issue_type]

    def get_auto_fixable(self) -> list[IntegrityIssue]:
        """Get auto-fixable issues."""
        return [i for i in self.issues if i.auto_fixable]

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "checked_at": self.checked_at,
            "summary": {
                "total_issues": len(self.issues),
                "critical": len(self.get_by_severity(Severity.CRITICAL)),
                "errors": len(self.get_by_severity(Severity.ERROR)),
                "warnings": len(self.get_by_severity(Severity.WARNING)),
                "info": len(self.get_by_severity(Severity.INFO)),
                "auto_fixable": self.auto_fixable_count,
            },
            "stats": self.stats,
            "issues": [i.to_dict() for i in self.issues],
        }


class IntegrityChecker:
    """Integrity checker for reverse-engineering projects."""

    def __init__(self, store: ReverseEngineeringStore):
        self.store = store
        self.issues: list[IntegrityIssue] = []
        self._entity_cache: dict[str, Any] | None = None
        self._artifact_cache: set[str] | None = None
        self._evidence_cache: set[str] | None = None

    def _get_all_entity_ids(self) -> dict[str, Any]:
        """Cache all entity IDs."""
        if self._entity_cache is None:
            cursor = self.store._conn.cursor()
            cursor.execute("SELECT entity_id, artifact_id, kind FROM entities")
            self._entity_cache = {
                row["entity_id"]: {
                    "artifact_id": row["artifact_id"],
                    "kind": row["kind"],
                }
                for row in cursor.fetchall()
            }
        return self._entity_cache

    def _get_all_artifact_ids(self) -> set[str]:
        """Cache all artifact IDs."""
        if self._artifact_cache is None:
            cursor = self.store._conn.cursor()
            cursor.execute("SELECT artifact_id FROM artifacts")
            self._artifact_cache = {row["artifact_id"] for row in cursor.fetchall()}
        return self._artifact_cache

    def _get_all_evidence_ids(self) -> set[str]:
        """Cache all evidence IDs."""
        if self._evidence_cache is None:
            cursor = self.store._conn.cursor()
            cursor.execute("SELECT evidence_id FROM evidence")
            self._evidence_cache = {row["evidence_id"] for row in cursor.fetchall()}
        return self._evidence_cache

    def _clear_cache(self) -> None:
        """Clear internal caches."""
        self._entity_cache = None
        self._artifact_cache = None
        self._evidence_cache = None

    def check_all(self) -> IntegrityReport:
        """Run all integrity checks."""
        self.issues = []
        self._clear_cache()

        # Collect stats first
        stats = self.store.stats()

        # Run all checks
        self._check_orphaned_references()
        self._check_overlapping_functions()
        self._check_invalid_address_ranges()
        self._check_missing_evidence()
        self._check_broken_cross_references()
        self._check_circular_dependencies()
        self._check_invalid_confidence()
        self._check_duplicate_ids()
        self._check_stale_artifact_references()

        report = IntegrityReport(
            issues=self.issues,
            stats=stats,
        )

        self._clear_cache()
        return report

    def _check_orphaned_references(self) -> None:
        """Check for entities pointing to non-existent artifacts."""
        artifact_ids = self._get_all_artifact_ids()
        self._get_all_entity_ids()

        cursor = self.store._conn.cursor()
        cursor.execute(
            "SELECT entity_id, artifact_id, name FROM entities WHERE artifact_id IS NOT NULL"
        )

        for row in cursor.fetchall():
            artifact_id = row["artifact_id"]
            if artifact_id and artifact_id not in artifact_ids:
                self.issues.append(
                    IntegrityIssue(
                        issue_type=IssueType.ORPHANED_REFERENCE,
                        severity=Severity.ERROR,
                        message=f"Entity '{row['name']}' references non-existent artifact '{artifact_id}'",
                        entity_id=row["entity_id"],
                        artifact_id=artifact_id,
                        details={"referenced_artifact": artifact_id},
                        auto_fixable=True,
                        fix_action="remove_entity_or_update_artifact_id",
                    )
                )

    def _check_overlapping_functions(self) -> None:
        """Check for function address ranges that overlap."""
        from codemunch_pro.rex.model import AddressLocation

        cursor = self.store._conn.cursor()
        cursor.execute(
            """
            SELECT entity_id, name, location_json
            FROM entities
            WHERE kind = 'function' AND location_json IS NOT NULL
            """
        )

        # Group functions by address space
        functions_by_space: dict[str, list[tuple[str, str, AddressLocation]]] = []
        functions_by_space = defaultdict(list)

        for row in cursor.fetchall():
            location = self.store._json_to_location(row["location_json"])
            if location:
                functions_by_space[location.address_space].append(
                    (row["entity_id"], row["name"], location)
                )

        # Check for overlaps within each address space
        for address_space, functions in functions_by_space.items():
            # Sort by start address
            functions.sort(key=lambda x: x[2].start)

            for i, (eid1, name1, loc1) in enumerate(functions):
                for eid2, name2, loc2 in functions[i + 1 :]:
                    # Check for overlap: not (end1 < start2 or end2 < start1)
                    if not (loc1.end < loc2.start or loc2.end < loc1.start):
                        overlap_start = max(loc1.start, loc2.start)
                        overlap_end = min(loc1.end, loc2.end)
                        overlap_size = overlap_end - overlap_start + 1

                        self.issues.append(
                            IntegrityIssue(
                                issue_type=IssueType.OVERLAPPING_FUNCTION,
                                severity=Severity.WARNING,
                                message=(
                                    f"Functions overlap: '{name1}' (0x{loc1.start:04X}-0x{loc1.end:04X}) "
                                    f"and '{name2}' (0x{loc2.start:04X}-0x{loc2.end:04X})"
                                ),
                                entity_id=eid1,
                                details={
                                    "other_entity_id": eid2,
                                    "function1": name1,
                                    "function2": name2,
                                    "address_space": address_space,
                                    "overlap_start": overlap_start,
                                    "overlap_end": overlap_end,
                                    "overlap_size": overlap_size,
                                },
                                auto_fixable=False,
                            )
                        )

    def _check_invalid_address_ranges(self) -> None:
        """Check for invalid address ranges (start > end)."""
        cursor = self.store._conn.cursor()
        cursor.execute(
            """
            SELECT entity_id, name, location_json, kind
            FROM entities
            WHERE location_json IS NOT NULL
            """
        )

        for row in cursor.fetchall():
            location = self.store._json_to_location(row["location_json"])
            if location and location.start > location.end:
                self.issues.append(
                    IntegrityIssue(
                        issue_type=IssueType.INVALID_ADDRESS_RANGE,
                        severity=Severity.ERROR,
                        message=(
                            f"{row['kind']} '{row['name']}' has invalid address range: "
                            f"start (0x{location.start:04X}) > end (0x{location.end:04X})"
                        ),
                        entity_id=row["entity_id"],
                        details={
                            "start": location.start,
                            "end": location.end,
                            "address_space": location.address_space,
                        },
                        auto_fixable=False,
                    )
                )

    def _check_missing_evidence(self) -> None:
        """Check for entities without supporting evidence."""
        cursor = self.store._conn.cursor()
        cursor.execute(
            """
            SELECT e.entity_id, e.name, e.kind, e.artifact_id
            FROM entities e
            LEFT JOIN evidence ev ON ev.entity_ids_json LIKE '%"' || e.entity_id || '"%'
            WHERE ev.evidence_id IS NULL
            """
        )

        for row in cursor.fetchall():
            # Some entity kinds may not require evidence
            if row["kind"] in ("section", "document", "namespace"):
                continue

            self.issues.append(
                IntegrityIssue(
                    issue_type=IssueType.MISSING_EVIDENCE,
                    severity=Severity.INFO,
                    message=f"{row['kind']} '{row['name']}' has no supporting evidence",
                    entity_id=row["entity_id"],
                    artifact_id=row["artifact_id"] or "",
                    details={"entity_kind": row["kind"]},
                    auto_fixable=False,
                )
            )

    def _check_broken_cross_references(self) -> None:
        """Check for edges pointing to non-existent entities."""
        entity_ids = self._get_all_entity_ids()

        cursor = self.store._conn.cursor()
        cursor.execute(
            "SELECT edge_id, source_entity_id, target_entity_id, kind FROM edges"
        )

        for row in cursor.fetchall():
            source_id = row["source_entity_id"]
            target_id = row["target_entity_id"]

            if source_id not in entity_ids:
                self.issues.append(
                    IntegrityIssue(
                        issue_type=IssueType.BROKEN_CROSS_REFERENCE,
                        severity=Severity.ERROR,
                        message=f"Edge '{row['edge_id']}' references non-existent source entity '{source_id}'",
                        details={
                            "edge_id": row["edge_id"],
                            "source_entity_id": source_id,
                            "edge_kind": row["kind"],
                        },
                        auto_fixable=True,
                        fix_action="remove_edge",
                    )
                )

            if target_id not in entity_ids:
                self.issues.append(
                    IntegrityIssue(
                        issue_type=IssueType.BROKEN_CROSS_REFERENCE,
                        severity=Severity.ERROR,
                        message=f"Edge '{row['edge_id']}' references non-existent target entity '{target_id}'",
                        details={
                            "edge_id": row["edge_id"],
                            "target_entity_id": target_id,
                            "edge_kind": row["kind"],
                        },
                        auto_fixable=True,
                        fix_action="remove_edge",
                    )
                )

    def _check_circular_dependencies(self) -> None:
        """Check for circular dependencies in the entity graph."""
        # Build adjacency list for "depends_on" and "calls" edges
        cursor = self.store._conn.cursor()
        cursor.execute(
            """
            SELECT source_entity_id, target_entity_id
            FROM edges
            WHERE kind IN ('depends_on', 'calls', 'references', 'uses')
            """
        )

        graph: dict[str, set[str]] = defaultdict(set)
        for row in cursor.fetchall():
            graph[row["source_entity_id"]].add(row["target_entity_id"])

        # Find cycles using DFS
        visited: set[str] = set()
        rec_stack: set[str] = set()
        cycles: list[list[str]] = []

        def dfs(node: str, path: list[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor, path)
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    cycles.append(cycle)

            path.pop()
            rec_stack.remove(node)

        for node in list(graph.keys()):
            if node not in visited:
                dfs(node, [])

        # Report cycles
        for cycle in cycles:
            entity_names = []
            for eid in cycle[:-1]:  # Exclude the repeated last node
                entity = self.store.get_entity(eid)
                entity_names.append(entity.name if entity else eid)

            self.issues.append(
                IntegrityIssue(
                    issue_type=IssueType.CIRCULAR_DEPENDENCY,
                    severity=Severity.WARNING,
                    message=f"Circular dependency detected: {' -> '.join(entity_names)}",
                    entity_id=cycle[0],
                    details={
                        "cycle": cycle,
                        "entity_names": entity_names,
                    },
                    auto_fixable=False,
                )
            )

    def _check_invalid_confidence(self) -> None:
        """Check for invalid confidence values."""
        cursor = self.store._conn.cursor()

        # Check entities
        cursor.execute(
            """
            SELECT entity_id, name, attributes_json
            FROM entities
            WHERE attributes_json LIKE '%"confidence"%'
            """
        )

        for row in cursor.fetchall():
            import json

            attrs = json.loads(row["attributes_json"])
            confidence = attrs.get("confidence")
            if confidence is not None and not (0.0 <= confidence <= 1.0):
                self.issues.append(
                    IntegrityIssue(
                        issue_type=IssueType.INVALID_CONFIDENCE,
                        severity=Severity.WARNING,
                        message=f"Entity '{row['name']}' has invalid confidence value: {confidence}",
                        entity_id=row["entity_id"],
                        details={"confidence": confidence},
                        auto_fixable=True,
                        fix_action="clamp_confidence_to_valid_range",
                    )
                )

        # Check edges
        cursor.execute(
            """
            SELECT edge_id, confidence, attributes_json FROM edges
            """
        )

        for row in cursor.fetchall():
            confidence = row["confidence"]
            if confidence is not None and not (0.0 <= confidence <= 1.0):
                self.issues.append(
                    IntegrityIssue(
                        issue_type=IssueType.INVALID_CONFIDENCE,
                        severity=Severity.WARNING,
                        message=f"Edge '{row['edge_id']}' has invalid confidence value: {confidence}",
                        details={
                            "edge_id": row["edge_id"],
                            "confidence": confidence,
                        },
                        auto_fixable=True,
                        fix_action="clamp_confidence_to_valid_range",
                    )
                )

    def _check_duplicate_ids(self) -> None:
        """Check for duplicate entity or edge IDs."""
        cursor = self.store._conn.cursor()

        # Check for duplicate entity IDs (shouldn't happen with PK constraint, but check anyway)
        cursor.execute(
            """
            SELECT entity_id, COUNT(*) as cnt
            FROM entities
            GROUP BY entity_id
            HAVING cnt > 1
            """
        )

        for row in cursor.fetchall():
            self.issues.append(
                IntegrityIssue(
                    issue_type=IssueType.DUPLICATE_ENTITY_ID,
                    severity=Severity.CRITICAL,
                    message=f"Duplicate entity ID detected: '{row['entity_id']}'",
                    entity_id=row["entity_id"],
                    details={"count": row["cnt"]},
                    auto_fixable=False,
                )
            )

        # Check for duplicate edge IDs
        cursor.execute(
            """
            SELECT edge_id, COUNT(*) as cnt
            FROM edges
            GROUP BY edge_id
            HAVING cnt > 1
            """
        )

        for row in cursor.fetchall():
            self.issues.append(
                IntegrityIssue(
                    issue_type=IssueType.DUPLICATE_EDGE_ID,
                    severity=Severity.CRITICAL,
                    message=f"Duplicate edge ID detected: '{row['edge_id']}'",
                    details={"edge_id": row["edge_id"], "count": row["cnt"]},
                    auto_fixable=False,
                )
            )

    def _check_stale_artifact_references(self) -> None:
        """Check for evidence referencing non-existent entities."""
        import json

        entity_ids = self._get_all_entity_ids()

        cursor = self.store._conn.cursor()
        cursor.execute("SELECT evidence_id, entity_ids_json, artifact_id FROM evidence")

        for row in cursor.fetchall():
            try:
                entity_ids_list = json.loads(row["entity_ids_json"] or "[]")
                for entity_id in entity_ids_list:
                    if entity_id not in entity_ids:
                        self.issues.append(
                            IntegrityIssue(
                                issue_type=IssueType.STALE_ARTIFACT_REFERENCE,
                                severity=Severity.WARNING,
                                message=f"Evidence '{row['evidence_id']}' references non-existent entity '{entity_id}'",
                                artifact_id=row["artifact_id"],
                                details={
                                    "evidence_id": row["evidence_id"],
                                    "missing_entity_id": entity_id,
                                },
                                auto_fixable=True,
                                fix_action="remove_entity_reference_from_evidence",
                            )
                        )
            except json.JSONDecodeError:
                self.issues.append(
                    IntegrityIssue(
                        issue_type=IssueType.STALE_ARTIFACT_REFERENCE,
                        severity=Severity.ERROR,
                        message=f"Evidence '{row['evidence_id']}' has invalid entity_ids_json",
                        artifact_id=row["artifact_id"],
                        details={"entity_ids_json": row["entity_ids_json"]},
                        auto_fixable=False,
                    )
                )

    def fix_issues(self, issues: list[IntegrityIssue] | None = None) -> dict[str, Any]:
        """Auto-fix the specified issues or all auto-fixable issues.

        Args:
            issues: List of issues to fix. If None, fixes all auto-fixable issues.

        Returns:
            Dictionary with fix results.
        """
        if issues is None:
            issues = [i for i in self.issues if i.auto_fixable]

        fixed: list[str] = []
        failed: list[dict[str, Any]] = []

        for issue in issues:
            try:
                if self._fix_issue(issue):
                    fixed.append(issue.entity_id or issue.details.get("edge_id", ""))
                else:
                    failed.append({"issue": issue.to_dict(), "reason": "Fix not implemented"})
            except Exception as e:
                failed.append({"issue": issue.to_dict(), "reason": str(e)})

        return {
            "fixed_count": len(fixed),
            "failed_count": len(failed),
            "fixed": fixed,
            "failed": failed,
        }

    def _fix_issue(self, issue: IntegrityIssue) -> bool:
        """Apply a single fix."""
        import json

        cursor = self.store._conn.cursor()

        if issue.fix_action == "remove_edge":
            edge_id = issue.details.get("edge_id")
            if edge_id:
                cursor.execute("DELETE FROM edges WHERE edge_id = ?", (edge_id,))
                self.store._conn.commit()
                return True

        elif issue.fix_action == "remove_entity_or_update_artifact_id":
            # For orphaned references, remove the entity
            if issue.entity_id:
                cursor.execute(
                    "DELETE FROM entities WHERE entity_id = ?", (issue.entity_id,)
                )
                self.store._conn.commit()
                return True

        elif issue.fix_action == "clamp_confidence_to_valid_range":
            # Clamp confidence to [0.0, 1.0]
            if issue.entity_id:
                cursor.execute(
                    "SELECT attributes_json FROM entities WHERE entity_id = ?",
                    (issue.entity_id,),
                )
                row = cursor.fetchone()
                if row:
                    attrs = json.loads(row["attributes_json"])
                    confidence = attrs.get("confidence", 0.0)
                    attrs["confidence"] = max(0.0, min(1.0, confidence))
                    cursor.execute(
                        "UPDATE entities SET attributes_json = ? WHERE entity_id = ?",
                        (json.dumps(attrs), issue.entity_id),
                    )
                    self.store._conn.commit()
                    return True
            elif issue.details.get("edge_id"):
                edge_id = issue.details["edge_id"]
                confidence = issue.details.get("confidence", 0.0)
                clamped = max(0.0, min(1.0, confidence))
                cursor.execute(
                    "UPDATE edges SET confidence = ? WHERE edge_id = ?",
                    (clamped, edge_id),
                )
                self.store._conn.commit()
                return True

        elif issue.fix_action == "remove_entity_reference_from_evidence":
            evidence_id = issue.details.get("evidence_id")
            missing_entity_id = issue.details.get("missing_entity_id")
            if evidence_id and missing_entity_id:
                cursor.execute(
                    "SELECT entity_ids_json FROM evidence WHERE evidence_id = ?",
                    (evidence_id,),
                )
                row = cursor.fetchone()
                if row:
                    entity_ids = json.loads(row["entity_ids_json"] or "[]")
                    entity_ids = [eid for eid in entity_ids if eid != missing_entity_id]
                    cursor.execute(
                        "UPDATE evidence SET entity_ids_json = ? WHERE evidence_id = ?",
                        (json.dumps(entity_ids), evidence_id),
                    )
                    self.store._conn.commit()
                    return True

        return False
