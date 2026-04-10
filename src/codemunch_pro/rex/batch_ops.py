"""Batch operations for efficient bulk processing of reverse-engineering data.

This module provides the BatchProcessor class for performing bulk operations
on reverse-engineering data including indexing, labeling, exporting, and
search-and-replace operations with progress tracking and resume capability.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from codemunch_pro.rex.exporters import ExportOptions, get_exporter
from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EntityRecord,
    ReverseEngineeringBundle,
)

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore

logger = logging.getLogger(__name__)

# Type aliases
ProgressCallback = Callable[[str, int, int, dict[str, Any] | None], None]
OperationResult = dict[str, Any]


@dataclass
class BatchOperation:
    """Represents a single batch operation with state tracking."""

    operation_id: str
    operation_type: str
    status: str = "pending"  # pending, running, completed, failed, cancelled
    progress: int = 0
    total: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    completed_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize operation to dictionary."""
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "status": self.status,
            "progress": self.progress,
            "total": self.total,
            "errors": self.errors,
            "result": self.result,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "metadata": self.metadata,
        }


@dataclass
class Checkpoint:
    """Checkpoint data for resuming failed operations."""

    operation_id: str
    operation_type: str
    processed_items: list[str] = field(default_factory=list)
    failed_items: list[tuple[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize checkpoint to dictionary."""
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "processed_items": self.processed_items,
            "failed_items": self.failed_items,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Checkpoint:
        """Create checkpoint from dictionary."""
        return cls(
            operation_id=data["operation_id"],
            operation_type=data["operation_type"],
            processed_items=data.get("processed_items", []),
            failed_items=[tuple(item) for item in data.get("failed_items", [])],
            metadata=data.get("metadata", {}),
        )


class BatchProcessor:
    """Processor for batch operations on reverse-engineering data.

    Supports parallel processing, progress tracking, and resume on failure.

    Example:
        processor = BatchProcessor(store, max_workers=4)

        # Index an entire directory tree
        result = processor.index_directory(
            "/path/to/project",
            include_patterns=["**/*.asm"],
            progress_callback=lambda msg, prog, total, meta: print(f"{msg}: {prog}/{total}")
        )

        # Apply labels to address ranges
        processor.apply_labels(
            project_path="/path/to/project",
            labels=[
                {"address": 0x1000, "name": "start_function"},
                {"address": 0x2000, "name": "data_table"},
            ],
            address_space="rom"
        )

        # Export to multiple formats
        processor.export_multiple(
            project_path="/path/to/project",
            formats=["ida", "ghidra", "json"],
            output_dir="/path/to/exports"
        )
    """

    def __init__(
        self,
        store: ReverseEngineeringStore | None = None,
        max_workers: int = 4,
        checkpoint_dir: Path | str | None = None,
    ):
        """Initialize the batch processor.

        Args:
            store: Optional reverse-engineering store to use.
            max_workers: Maximum number of parallel workers.
            checkpoint_dir: Directory to store checkpoint files for resume.
        """
        self.store = store
        self.max_workers = max(1, max_workers)
        self.checkpoint_dir = (
            Path(checkpoint_dir) if checkpoint_dir else Path(".rex_checkpoints")
        )
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        # Operation tracking
        self._operations: dict[str, BatchOperation] = {}
        self._operations_lock = threading.Lock()
        self._cancelled: set[str] = set()

    def _generate_operation_id(self, operation_type: str) -> str:
        """Generate a unique operation ID."""
        timestamp = str(os.urandom(8).hex())
        return f"{operation_type}_{timestamp}"

    def _save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Save checkpoint to disk."""
        checkpoint_path = self.checkpoint_dir / f"{checkpoint.operation_id}.json"
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint.to_dict(), f, indent=2)

    def _load_checkpoint(self, operation_id: str) -> Checkpoint | None:
        """Load checkpoint from disk."""
        checkpoint_path = self.checkpoint_dir / f"{operation_id}.json"
        if not checkpoint_path.exists():
            return None
        with open(checkpoint_path, encoding="utf-8") as f:
            return Checkpoint.from_dict(json.load(f))

    def _delete_checkpoint(self, operation_id: str) -> None:
        """Delete checkpoint file."""
        checkpoint_path = self.checkpoint_dir / f"{operation_id}.json"
        if checkpoint_path.exists():
            checkpoint_path.unlink()

    def _update_progress(
        self,
        operation: BatchOperation,
        progress: int,
        message: str = "",
        callback: ProgressCallback | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Update operation progress and call callback if provided.

        Returns:
            False if operation was cancelled, True otherwise.
        """
        operation.progress = progress

        if callback:
            callback(message, progress, operation.total, metadata)

        return operation.operation_id not in self._cancelled

    def get_operation(self, operation_id: str) -> BatchOperation | None:
        """Get the status of a batch operation."""
        with self._operations_lock:
            return self._operations.get(operation_id)

    def cancel_operation(self, operation_id: str) -> bool:
        """Cancel a running batch operation."""
        with self._operations_lock:
            if operation_id in self._operations:
                self._cancelled.add(operation_id)
                return True
            return False

    def list_operations(
        self,
        status: str | None = None,
        operation_type: str | None = None,
    ) -> list[BatchOperation]:
        """List batch operations with optional filtering.

        Args:
            status: Filter by status (pending, running, completed, failed, cancelled).
            operation_type: Filter by operation type.

        Returns:
            List of matching operations.
        """
        with self._operations_lock:
            operations = list(self._operations.values())

        if status:
            operations = [op for op in operations if op.status == status]
        if operation_type:
            operations = [op for op in operations if op.operation_type == operation_type]

        return sorted(operations, key=lambda op: op.started_at, reverse=True)

    def index_directory(
        self,
        project_path: str,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        recursive: bool = True,
        parallel: bool = True,
        progress_callback: ProgressCallback | None = None,
        resume_from: str | None = None,
    ) -> OperationResult:
        """Index an entire directory tree of artifacts.

        Args:
            project_path: Root directory to index.
            include_patterns: Glob patterns for files to include.
            exclude_patterns: Glob patterns for files to exclude.
            recursive: Whether to recursively scan subdirectories.
            parallel: Whether to use parallel processing.
            progress_callback: Optional callback for progress updates.
            resume_from: Operation ID to resume from (if previous run failed).

        Returns:
            Dictionary with operation results and statistics.
        """
        import time

        from codemunch_pro.rex.adapter import AdapterRegistry
        from codemunch_pro.security import (
            DEFAULT_IGNORE_PATTERNS,
            is_binary_file,
            is_too_large,
        )

        operation_id = resume_from or self._generate_operation_id("index_directory")
        operation = BatchOperation(
            operation_id=operation_id,
            operation_type="index_directory",
            status="running",
            started_at=time.time(),
        )

        with self._operations_lock:
            self._operations[operation_id] = operation

        try:
            project_root = Path(project_path).resolve()
            if not project_root.is_dir():
                raise ValueError(f"Not a directory: {project_path}")

            # Load checkpoint if resuming
            checkpoint = None
            processed_paths: set[str] = set()
            if resume_from:
                checkpoint = self._load_checkpoint(operation_id)
                if checkpoint:
                    processed_paths = set(checkpoint.processed_items)
                    operation.metadata["resumed_from_checkpoint"] = True

            # Find all files to index
            registry = AdapterRegistry()
            files_to_index: list[Path] = []

            ignore_spec = None
            if exclude_patterns:
                import pathspec

                ignore_lines = list(DEFAULT_IGNORE_PATTERNS) + exclude_patterns
                ignore_spec = pathspec.PathSpec.from_lines("gitwildmatch", ignore_lines)

            include_spec = None
            if include_patterns:
                import pathspec

                include_spec = pathspec.PathSpec.from_lines(
                    "gitwildmatch", include_patterns
                )

            for root, dirs, files in os.walk(project_root):
                if not recursive and root != str(project_root):
                    break

                for filename in files:
                    file_path = Path(root) / filename
                    rel_path = file_path.relative_to(project_root).as_posix()

                    # Apply filters
                    if ignore_spec and ignore_spec.match_file(rel_path):
                        continue
                    if include_spec and not include_spec.match_file(rel_path):
                        continue
                    if is_binary_file(file_path) or is_too_large(file_path):
                        continue

                    # Check if already processed (resume)
                    if str(file_path) in processed_paths:
                        continue

                    files_to_index.append(file_path)

            operation.total = len(files_to_index)

            # Index files
            indexed_count = 0
            error_count = 0
            errors: list[dict[str, str]] = []

            def index_file(file_path: Path) -> tuple[str, bool, str]:
                """Index a single file. Returns (path, success, error_message)."""
                try:
                    importers = registry.find_importers(file_path)
                    if not importers:
                        return str(file_path), False, "No suitable importer"

                    bundle = importers[0].ingest(file_path)

                    if self.store:
                        self.store.replace_bundle(bundle)

                    return str(file_path), True, ""
                except Exception as e:
                    return str(file_path), False, str(e)

            if parallel and len(files_to_index) > 1:
                # Parallel processing
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {
                        executor.submit(index_file, fp): fp for fp in files_to_index
                    }

                    for future in as_completed(futures):
                        if operation_id in self._cancelled:
                            executor.shutdown(wait=False)
                            operation.status = "cancelled"
                            break

                        file_path, success, error = future.result()

                        if success:
                            indexed_count += 1
                            processed_paths.add(file_path)
                        else:
                            error_count += 1
                            errors.append({"path": file_path, "error": error})

                        # Save checkpoint periodically
                        if (indexed_count + error_count) % 10 == 0:
                            checkpoint = Checkpoint(
                                operation_id=operation_id,
                                operation_type="index_directory",
                                processed_items=list(processed_paths),
                                failed_items=[(e["path"], e["error"]) for e in errors],
                            )
                            self._save_checkpoint(checkpoint)

                        if not self._update_progress(
                            operation,
                            indexed_count + error_count,
                            f"Indexed {file_path}",
                            progress_callback,
                            {"current_file": file_path, "success": success},
                        ):
                            break
            else:
                # Sequential processing
                for file_path in files_to_index:
                    if operation_id in self._cancelled:
                        operation.status = "cancelled"
                        break

                    file_path_str, success, error = index_file(file_path)

                    if success:
                        indexed_count += 1
                        processed_paths.add(file_path_str)
                    else:
                        error_count += 1
                        errors.append({"path": file_path_str, "error": error})

                    if (indexed_count + error_count) % 10 == 0:
                        checkpoint = Checkpoint(
                            operation_id=operation_id,
                            operation_type="index_directory",
                            processed_items=list(processed_paths),
                            failed_items=[(e["path"], e["error"]) for e in errors],
                        )
                        self._save_checkpoint(checkpoint)

                    if not self._update_progress(
                        operation,
                        indexed_count + error_count,
                        f"Indexed {file_path}",
                        progress_callback,
                        {"current_file": str(file_path), "success": success},
                    ):
                        break

            # Finalize operation
            operation.completed_at = time.time()
            if operation.status != "cancelled":
                operation.status = "completed" if error_count == 0 else "completed_with_errors"

            # Clean up checkpoint on success
            if operation.status in ("completed", "completed_with_errors"):
                self._delete_checkpoint(operation_id)

            operation.result = {
                "indexed_count": indexed_count,
                "error_count": error_count,
                "total_files": len(files_to_index),
                "errors": errors[:100],  # Limit errors in result
            }

            return {
                "operation_id": operation_id,
                "status": operation.status,
                "indexed_count": indexed_count,
                "error_count": error_count,
                "total_files": len(files_to_index),
                "duration_seconds": operation.completed_at - operation.started_at,
            }

        except Exception as e:
            operation.status = "failed"
            operation.completed_at = time.time()
            operation.errors.append({"error": str(e)})

            # Save checkpoint for resume
            checkpoint = Checkpoint(
                operation_id=operation_id,
                operation_type="index_directory",
                processed_items=list(processed_paths) if "processed_paths" in dir() else [],
                failed_items=[(e["path"], e["error"]) for e in errors] if "errors" in dir() else [],
            )
            self._save_checkpoint(checkpoint)

            raise

    def apply_labels(
        self,
        project_path: str,
        labels: list[dict[str, Any]],
        address_space: str = "flat",
        artifact_id: str = "",
        parallel: bool = True,
        progress_callback: ProgressCallback | None = None,
    ) -> OperationResult:
        """Apply labels to address ranges in bulk.

        Args:
            project_path: Project path (for context).
            labels: List of label definitions with keys:
                - address: int - Start address
                - name: str - Label name
                - end_address: int (optional) - End address
                - kind: str (optional) - Entity kind (default: "reference")
                - comment: str (optional) - Comment/description
            address_space: Address space for the labels.
            artifact_id: Optional artifact ID to associate with.
            parallel: Whether to use parallel processing.
            progress_callback: Optional callback for progress updates.

        Returns:
            Dictionary with operation results.
        """
        import time

        operation_id = self._generate_operation_id("apply_labels")
        operation = BatchOperation(
            operation_id=operation_id,
            operation_type="apply_labels",
            status="running",
            total=len(labels),
            started_at=time.time(),
        )

        with self._operations_lock:
            self._operations[operation_id] = operation

        try:
            if not self.store:
                raise ValueError("Store required for apply_labels operation")

            applied_count = 0
            error_count = 0
            errors: list[dict[str, str]] = []

            def apply_single_label(label: dict[str, Any]) -> tuple[bool, str]:
                """Apply a single label. Returns (success, error_message)."""
                try:
                    address = label.get("address")
                    name = label.get("name")

                    if address is None or not name:
                        return False, "Missing address or name"

                    end_address = label.get("end_address", address)
                    kind = label.get("kind", "reference")
                    comment = label.get("comment", "")

                    # Create location
                    location = AddressLocation(
                        address_space=address_space,
                        start=address,
                        end=end_address,
                    )

                    # Create entity
                    entity_id = f"batch:{operation_id}:{address:08X}"
                    entity = EntityRecord(
                        entity_id=entity_id,
                        kind=kind,
                        name=name,
                        artifact_id=artifact_id or f"batch:{operation_id}",
                        canonical_ref=f"0x{address:08X}",
                        location=location,
                        summary=comment,
                        attributes={"batch_operation": operation_id},
                    )

                    # Create bundle and store
                    bundle = ReverseEngineeringBundle(
                        artifacts=[
                            ArtifactRecord(
                                artifact_id=artifact_id or f"batch:{operation_id}",
                                kind="batch_labels",
                                path=f"batch://{operation_id}",
                            )
                        ],
                        entities=[entity],
                    )

                    self.store.replace_bundle(bundle)

                    return True, ""
                except Exception as e:
                    return False, str(e)

            if parallel and len(labels) > 1:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {
                        executor.submit(apply_single_label, lbl): i
                        for i, lbl in enumerate(labels)
                    }

                    for future in as_completed(futures):
                        if operation_id in self._cancelled:
                            operation.status = "cancelled"
                            break

                        success, error = future.result()

                        if success:
                            applied_count += 1
                        else:
                            error_count += 1
                            errors.append({"error": error})

                        if not self._update_progress(
                            operation,
                            applied_count + error_count,
                            "Applying labels",
                            progress_callback,
                        ):
                            break
            else:
                for i, label in enumerate(labels):
                    if operation_id in self._cancelled:
                        operation.status = "cancelled"
                        break

                    success, error = apply_single_label(label)

                    if success:
                        applied_count += 1
                    else:
                        error_count += 1
                        errors.append({"index": i, "error": error})

                    if not self._update_progress(
                        operation,
                        applied_count + error_count,
                        "Applying labels",
                        progress_callback,
                    ):
                        break

            operation.completed_at = time.time()
            if operation.status != "cancelled":
                operation.status = "completed"

            operation.result = {
                "applied_count": applied_count,
                "error_count": error_count,
                "total_labels": len(labels),
            }

            return {
                "operation_id": operation_id,
                "status": operation.status,
                "applied_count": applied_count,
                "error_count": error_count,
                "total_labels": len(labels),
                "duration_seconds": operation.completed_at - operation.started_at,
            }

        except Exception as e:
            operation.status = "failed"
            operation.completed_at = time.time()
            operation.errors.append({"error": str(e)})
            raise

    def export_multiple(
        self,
        project_path: str,
        formats: list[str],
        output_dir: str,
        options: dict[str, Any] | None = None,
        parallel: bool = True,
        progress_callback: ProgressCallback | None = None,
    ) -> OperationResult:
        """Export to multiple formats in bulk.

        Args:
            project_path: Project path.
            formats: List of export formats ("ida", "ghidra", "binary_ninja", "json", "csv").
            output_dir: Directory for output files.
            options: Optional export options to apply to all formats.
            parallel: Whether to use parallel processing.
            progress_callback: Optional callback for progress updates.

        Returns:
            Dictionary with export results for each format.
        """
        import time

        operation_id = self._generate_operation_id("export_multiple")
        operation = BatchOperation(
            operation_id=operation_id,
            operation_type="export_multiple",
            status="running",
            total=len(formats),
            started_at=time.time(),
        )

        with self._operations_lock:
            self._operations[operation_id] = operation

        try:
            if not self.store:
                raise ValueError("Store required for export_multiple operation")

            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            export_options = ExportOptions()
            if options:
                for key, value in options.items():
                    if hasattr(export_options, key):
                        setattr(export_options, key, value)

            results: dict[str, Any] = {}
            completed_formats: list[str] = []
            failed_formats: list[dict[str, str]] = []

            def export_single_format(fmt: str) -> tuple[str, dict[str, Any] | None, str]:
                """Export to a single format. Returns (format, result, error)."""
                try:
                    fmt_lower = fmt.lower()
                    output_file = output_path / f"export_{fmt_lower}"

                    exporter = get_exporter(fmt_lower, self.store, export_options)
                    result = exporter.export(output_file)

                    return fmt, result, ""
                except Exception as e:
                    return fmt, None, str(e)

            if parallel and len(formats) > 1:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {
                        executor.submit(export_single_format, fmt): fmt for fmt in formats
                    }

                    for future in as_completed(futures):
                        if operation_id in self._cancelled:
                            operation.status = "cancelled"
                            break

                        fmt, result, error = future.result()

                        if error:
                            failed_formats.append({"format": fmt, "error": error})
                        else:
                            completed_formats.append(fmt)
                            results[fmt] = result

                        if not self._update_progress(
                            operation,
                            len(completed_formats) + len(failed_formats),
                            f"Exported to {fmt}",
                            progress_callback,
                        ):
                            break
            else:
                for fmt in formats:
                    if operation_id in self._cancelled:
                        operation.status = "cancelled"
                        break

                    fmt, result, error = export_single_format(fmt)

                    if error:
                        failed_formats.append({"format": fmt, "error": error})
                    else:
                        completed_formats.append(fmt)
                        results[fmt] = result

                    if not self._update_progress(
                        operation,
                        len(completed_formats) + len(failed_formats),
                        f"Exported to {fmt}",
                        progress_callback,
                    ):
                        break

            operation.completed_at = time.time()
            if operation.status != "cancelled":
                operation.status = "completed"

            operation.result = {
                "completed_formats": completed_formats,
                "failed_formats": failed_formats,
                "output_dir": str(output_path),
                "results": results,
            }

            return {
                "operation_id": operation_id,
                "status": operation.status,
                "completed_formats": completed_formats,
                "failed_count": len(failed_formats),
                "total_formats": len(formats),
                "output_dir": str(output_path),
                "duration_seconds": operation.completed_at - operation.started_at,
            }

        except Exception as e:
            operation.status = "failed"
            operation.completed_at = time.time()
            operation.errors.append({"error": str(e)})
            raise

    def search_and_replace(
        self,
        project_path: str,
        search_pattern: str,
        replacement: str,
        entity_kinds: list[str] | None = None,
        address_space: str | None = None,
        dry_run: bool = True,
        progress_callback: ProgressCallback | None = None,
    ) -> OperationResult:
        """Bulk rename/refactor entities using search and replace.

        Args:
            project_path: Project path (for context).
            search_pattern: Pattern to search for (supports wildcards with *).
            replacement: Replacement string (use * for match groups).
            entity_kinds: Optional list of entity kinds to filter.
            address_space: Optional address space filter.
            dry_run: If True, only preview changes without applying.
            progress_callback: Optional callback for progress updates.

        Returns:
            Dictionary with search/replace results.
        """
        import fnmatch
        import time

        operation_id = self._generate_operation_id("search_and_replace")
        operation = BatchOperation(
            operation_id=operation_id,
            operation_type="search_and_replace",
            status="running",
            started_at=time.time(),
        )

        with self._operations_lock:
            self._operations[operation_id] = operation

        try:
            if not self.store:
                raise ValueError("Store required for search_and_replace operation")

            # Get all entities
            cursor = self.store._conn.cursor()

            if entity_kinds:
                placeholders = ",".join("?" * len(entity_kinds))
                cursor.execute(
                    f"SELECT * FROM entities WHERE kind IN ({placeholders})",
                    entity_kinds,
                )
            else:
                cursor.execute("SELECT * FROM entities")

            rows = cursor.fetchall()

            operation.total = len(rows)

            matches: list[dict[str, Any]] = []
            replacements: list[dict[str, Any]] = []
            errors: list[dict[str, str]] = []

            for i, row in enumerate(rows):
                if operation_id in self._cancelled:
                    operation.status = "cancelled"
                    break

                entity_name = row["name"]

                # Check if name matches pattern
                if fnmatch.fnmatch(entity_name, search_pattern):
                    # Calculate replacement
                    new_name = entity_name
                    if "*" in search_pattern:
                        # Simple wildcard replacement
                        import re

                        pattern_escaped = re.escape(search_pattern).replace(r"\*", "(.*)")
                        match = re.match(pattern_escaped, entity_name)
                        if match:
                            new_name = replacement
                            for j, group in enumerate(match.groups(), 1):
                                new_name = new_name.replace(f"*{j}", group)
                    else:
                        new_name = replacement

                    match_info = {
                        "entity_id": row["entity_id"],
                        "old_name": entity_name,
                        "new_name": new_name,
                        "kind": row["kind"],
                    }
                    matches.append(match_info)

                    if not dry_run:
                        try:
                            cursor.execute(
                                "UPDATE entities SET name = ? WHERE entity_id = ?",
                                (new_name, row["entity_id"]),
                            )
                            replacements.append(match_info)
                        except Exception as e:
                            errors.append(
                                {"entity_id": row["entity_id"], "error": str(e)}
                            )

                if not self._update_progress(operation, i + 1, "Searching entities", progress_callback):
                    break

            if not dry_run:
                self.store._conn.commit()

            operation.completed_at = time.time()
            if operation.status != "cancelled":
                operation.status = "completed"

            operation.result = {
                "match_count": len(matches),
                "replacement_count": len(replacements),
                "error_count": len(errors),
                "dry_run": dry_run,
                "matches": matches[:100],  # Limit in result
            }

            return {
                "operation_id": operation_id,
                "status": operation.status,
                "match_count": len(matches),
                "replacement_count": len(replacements),
                "error_count": len(errors),
                "dry_run": dry_run,
                "duration_seconds": operation.completed_at - operation.started_at,
            }

        except Exception as e:
            operation.status = "failed"
            operation.completed_at = time.time()
            operation.errors.append({"error": str(e)})
            raise

    def generate_reports(
        self,
        project_path: str,
        report_types: list[str],
        output_dir: str,
        progress_callback: ProgressCallback | None = None,
    ) -> OperationResult:
        """Generate analysis reports for the project.

        Args:
            project_path: Project path (for context).
            report_types: List of report types to generate:
                - "statistics": General project statistics
                - "coverage": Address space coverage analysis
                - "entities": Entity inventory
                - "cross_refs": Cross-reference analysis
                - "similarity": Function similarity report
            output_dir: Directory for output reports.
            progress_callback: Optional callback for progress updates.

        Returns:
            Dictionary with report generation results.
        """
        import json
        import time

        operation_id = self._generate_operation_id("generate_reports")
        operation = BatchOperation(
            operation_id=operation_id,
            operation_type="generate_reports",
            status="running",
            total=len(report_types),
            started_at=time.time(),
        )

        with self._operations_lock:
            self._operations[operation_id] = operation

        try:
            if not self.store:
                raise ValueError("Store required for generate_reports operation")

            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            generated_reports: list[dict[str, Any]] = []
            errors: list[dict[str, str]] = []

            for report_type in report_types:
                if operation_id in self._cancelled:
                    operation.status = "cancelled"
                    break

                try:
                    report_data: dict[str, Any] = {}
                    report_file = output_path / f"report_{report_type}.json"

                    if report_type == "statistics":
                        report_data = self._generate_statistics_report()
                    elif report_type == "coverage":
                        report_data = self._generate_coverage_report()
                    elif report_type == "entities":
                        report_data = self._generate_entities_report()
                    elif report_type == "cross_refs":
                        report_data = self._generate_cross_refs_report()
                    elif report_type == "similarity":
                        report_data = self._generate_similarity_report()
                    else:
                        errors.append(
                            {"report_type": report_type, "error": "Unknown report type"}
                        )
                        continue

                    # Write report
                    with open(report_file, "w", encoding="utf-8") as f:
                        json.dump(report_data, f, indent=2, default=str)

                    generated_reports.append(
                        {
                            "report_type": report_type,
                            "file": str(report_file),
                            "size_bytes": report_file.stat().st_size,
                        }
                    )

                except Exception as e:
                    errors.append({"report_type": report_type, "error": str(e)})

                if not self._update_progress(
                    operation,
                    len(generated_reports) + len(errors),
                    f"Generated {report_type} report",
                    progress_callback,
                ):
                    break

            operation.completed_at = time.time()
            if operation.status != "cancelled":
                operation.status = "completed"

            operation.result = {
                "generated_reports": generated_reports,
                "errors": errors,
                "output_dir": str(output_path),
            }

            return {
                "operation_id": operation_id,
                "status": operation.status,
                "generated_count": len(generated_reports),
                "error_count": len(errors),
                "reports": generated_reports,
                "output_dir": str(output_path),
                "duration_seconds": operation.completed_at - operation.started_at,
            }

        except Exception as e:
            operation.status = "failed"
            operation.completed_at = time.time()
            operation.errors.append({"error": str(e)})
            raise

    def _generate_statistics_report(self) -> dict[str, Any]:
        """Generate general project statistics report."""
        if not self.store:
            return {}

        cursor = self.store._conn.cursor()

        # Entity counts by kind
        cursor.execute("SELECT kind, COUNT(*) as count FROM entities GROUP BY kind")
        entity_counts = {row["kind"]: row["count"] for row in cursor.fetchall()}

        # Evidence counts by kind
        cursor.execute("SELECT kind, COUNT(*) as count FROM evidence GROUP BY kind")
        evidence_counts = {row["kind"]: row["count"] for row in cursor.fetchall()}

        # Edge counts by kind
        cursor.execute("SELECT kind, COUNT(*) as count FROM edges GROUP BY kind")
        edge_counts = {row["kind"]: row["count"] for row in cursor.fetchall()}

        # Artifact counts by kind
        cursor.execute("SELECT kind, COUNT(*) as count FROM artifacts GROUP BY kind")
        artifact_counts = {row["kind"]: row["count"] for row in cursor.fetchall()}

        return {
            "report_type": "statistics",
            "generated_at": time.time(),
            "entity_counts": entity_counts,
            "evidence_counts": evidence_counts,
            "edge_counts": edge_counts,
            "artifact_counts": artifact_counts,
            "total_entities": sum(entity_counts.values()),
            "total_evidence": sum(evidence_counts.values()),
            "total_edges": sum(edge_counts.values()),
            "total_artifacts": sum(artifact_counts.values()),
        }

    def _generate_coverage_report(self) -> dict[str, Any]:
        """Generate address space coverage report."""
        if not self.store:
            return {}

        cursor = self.store._conn.cursor()
        cursor.execute("SELECT location_json FROM entities WHERE location_json IS NOT NULL")

        address_spaces: dict[str, dict[str, Any]] = {}

        for row in cursor.fetchall():
            try:
                location = json.loads(row["location_json"])
                space = location.get("address_space", "unknown")

                if space not in address_spaces:
                    address_spaces[space] = {
                        "regions": [],
                        "min_address": float("inf"),
                        "max_address": 0,
                    }

                start = location.get("start", 0)
                end = location.get("end", start)

                address_spaces[space]["regions"].append({"start": start, "end": end})
                address_spaces[space]["min_address"] = min(
                    address_spaces[space]["min_address"], start
                )
                address_spaces[space]["max_address"] = max(
                    address_spaces[space]["max_address"], end
                )
            except (json.JSONDecodeError, KeyError):
                continue

        # Calculate coverage statistics per address space
        for space, data in address_spaces.items():
            regions = data["regions"]
            if not regions:
                continue

            # Sort and merge overlapping regions
            regions.sort(key=lambda r: r["start"])
            merged = [regions[0]]

            for region in regions[1:]:
                last = merged[-1]
                if region["start"] <= last["end"] + 1:
                    last["end"] = max(last["end"], region["end"])
                else:
                    merged.append(region)

            total_covered = sum(r["end"] - r["start"] + 1 for r in merged)
            total_range = data["max_address"] - data["min_address"] + 1

            data["merged_regions"] = len(merged)
            data["total_covered_bytes"] = total_covered
            data["total_range_bytes"] = total_range
            data["coverage_percent"] = (total_covered / total_range * 100) if total_range > 0 else 0

        return {
            "report_type": "coverage",
            "generated_at": time.time(),
            "address_spaces": address_spaces,
        }

    def _generate_entities_report(self) -> dict[str, Any]:
        """Generate entity inventory report."""
        if not self.store:
            return {}

        entities = self.store.list_entities(limit=10000)

        return {
            "report_type": "entities",
            "generated_at": time.time(),
            "entity_count": len(entities),
            "entities": [
                {
                    "entity_id": e.entity_id,
                    "kind": e.kind,
                    "name": e.name,
                    "canonical_ref": e.canonical_ref,
                    "artifact_id": e.artifact_id,
                }
                for e in entities
            ],
        }

    def _generate_cross_refs_report(self) -> dict[str, Any]:
        """Generate cross-reference analysis report."""
        if not self.store:
            return {}

        cursor = self.store._conn.cursor()
        cursor.execute("SELECT kind, COUNT(*) as count FROM edges GROUP BY kind")
        edge_counts = {row["kind"]: row["count"] for row in cursor.fetchall()}

        # Find entities with most references
        cursor.execute("""
            SELECT target_entity_id, COUNT(*) as ref_count
            FROM edges
            GROUP BY target_entity_id
            ORDER BY ref_count DESC
            LIMIT 100
        """)
        top_referenced = [
            {"entity_id": row["target_entity_id"], "reference_count": row["ref_count"]}
            for row in cursor.fetchall()
        ]

        return {
            "report_type": "cross_refs",
            "generated_at": time.time(),
            "edge_counts_by_kind": edge_counts,
            "top_referenced_entities": top_referenced,
        }

    def _generate_similarity_report(self) -> dict[str, Any]:
        """Generate function similarity report."""
        if not self.store:
            return {}

        # Build similarity index
        try:
            index = self.store.build_similarity_index(algorithm="fuzzy_hash")

            return {
                "report_type": "similarity",
                "generated_at": time.time(),
                "index_size": len(index),
                "algorithm": "fuzzy_hash",
                "note": "Use find_similar_functions() for detailed similarity analysis",
            }
        except Exception as e:
            return {
                "report_type": "similarity",
                "generated_at": time.time(),
                "error": str(e),
            }
