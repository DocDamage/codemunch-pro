"""Tests for batch operations module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from codemunch_pro.rex.batch_ops import (
    BatchOperation,
    BatchProcessor,
    Checkpoint,
)


class TestCheckpoint:
    """Tests for Checkpoint dataclass."""

    def test_checkpoint_creation(self):
        """Test creating a checkpoint."""
        checkpoint = Checkpoint(
            operation_id="test_op_123",
            operation_type="index_directory",
            processed_items=["/path/to/file1", "/path/to/file2"],
            failed_items=[("/path/to/failed", "error message")],
            metadata={"key": "value"},
        )

        assert checkpoint.operation_id == "test_op_123"
        assert checkpoint.operation_type == "index_directory"
        assert len(checkpoint.processed_items) == 2
        assert len(checkpoint.failed_items) == 1
        assert checkpoint.metadata["key"] == "value"

    def test_checkpoint_serialization(self):
        """Test checkpoint serialization/deserialization."""
        checkpoint = Checkpoint(
            operation_id="test_op_123",
            operation_type="index_directory",
            processed_items=["/path/to/file1"],
            failed_items=[("/path/to/failed", "error")],
        )

        data = checkpoint.to_dict()
        assert data["operation_id"] == "test_op_123"
        assert data["operation_type"] == "index_directory"

        restored = Checkpoint.from_dict(data)
        assert restored.operation_id == checkpoint.operation_id
        assert restored.processed_items == checkpoint.processed_items
        assert restored.failed_items == checkpoint.failed_items


class TestBatchOperation:
    """Tests for BatchOperation dataclass."""

    def test_operation_creation(self):
        """Test creating a batch operation."""
        operation = BatchOperation(
            operation_id="test_op_123",
            operation_type="index_directory",
            status="running",
            progress=50,
            total=100,
        )

        assert operation.operation_id == "test_op_123"
        assert operation.operation_type == "index_directory"
        assert operation.status == "running"
        assert operation.progress == 50
        assert operation.total == 100

    def test_operation_serialization(self):
        """Test operation serialization."""
        operation = BatchOperation(
            operation_id="test_op_123",
            operation_type="index_directory",
            status="completed",
            result={"indexed_count": 50},
            errors=[{"error": "test error"}],
        )

        data = operation.to_dict()
        assert data["operation_id"] == "test_op_123"
        assert data["status"] == "completed"
        assert data["result"]["indexed_count"] == 50
        assert len(data["errors"]) == 1


class TestBatchProcessor:
    """Tests for BatchProcessor class."""

    @pytest.fixture
    def mock_store(self):
        """Create a mock store for testing."""
        store = MagicMock()
        store._conn = MagicMock()
        store._conn.cursor.return_value = MagicMock()
        return store

    @pytest.fixture
    def processor(self, mock_store, tmp_path):
        """Create a BatchProcessor with mock store."""
        checkpoint_dir = tmp_path / "checkpoints"
        return BatchProcessor(
            store=mock_store,
            max_workers=2,
            checkpoint_dir=checkpoint_dir,
        )

    def test_processor_initialization(self, processor, tmp_path):
        """Test processor initialization."""
        assert processor.max_workers == 2
        assert processor.store is not None
        assert processor.checkpoint_dir.exists()

    def test_generate_operation_id(self, processor):
        """Test operation ID generation."""
        op_id1 = processor._generate_operation_id("index_directory")
        op_id2 = processor._generate_operation_id("index_directory")

        assert op_id1.startswith("index_directory_")
        assert op_id2.startswith("index_directory_")
        assert op_id1 != op_id2  # IDs should be unique

    def test_save_and_load_checkpoint(self, processor):
        """Test checkpoint saving and loading."""
        checkpoint = Checkpoint(
            operation_id="test_op_123",
            operation_type="index_directory",
            processed_items=["/path/to/file1"],
            failed_items=[],
        )

        processor._save_checkpoint(checkpoint)

        loaded = processor._load_checkpoint("test_op_123")
        assert loaded is not None
        assert loaded.operation_id == "test_op_123"
        assert loaded.processed_items == ["/path/to/file1"]

    def test_delete_checkpoint(self, processor):
        """Test checkpoint deletion."""
        checkpoint = Checkpoint(
            operation_id="test_op_delete",
            operation_type="test",
        )

        processor._save_checkpoint(checkpoint)
        assert processor._load_checkpoint("test_op_delete") is not None

        processor._delete_checkpoint("test_op_delete")
        assert processor._load_checkpoint("test_op_delete") is None

    def test_get_and_list_operations(self, processor):
        """Test operation retrieval and listing."""
        # Create an operation manually
        operation = BatchOperation(
            operation_id="test_op_123",
            operation_type="index_directory",
            status="running",
        )

        with processor._operations_lock:
            processor._operations["test_op_123"] = operation

        # Test get_operation
        retrieved = processor.get_operation("test_op_123")
        assert retrieved is not None
        assert retrieved.operation_id == "test_op_123"

        # Test list_operations
        operations = processor.list_operations()
        assert len(operations) == 1
        assert operations[0].operation_id == "test_op_123"

        # Test filtering
        filtered = processor.list_operations(status="running")
        assert len(filtered) == 1

        filtered = processor.list_operations(status="completed")
        assert len(filtered) == 0

    def test_cancel_operation(self, processor):
        """Test operation cancellation."""
        operation = BatchOperation(
            operation_id="test_op_cancel",
            operation_type="index_directory",
            status="running",
        )

        with processor._operations_lock:
            processor._operations["test_op_cancel"] = operation

        assert processor.cancel_operation("test_op_cancel") is True
        assert "test_op_cancel" in processor._cancelled

        assert processor.cancel_operation("nonexistent") is False


class TestBatchProcessorApplyLabels:
    """Tests for the apply_labels method."""

    @pytest.fixture
    def mock_store(self):
        """Create a mock store for testing."""
        store = MagicMock()
        store._conn = MagicMock()
        return store

    @pytest.fixture
    def processor(self, mock_store, tmp_path):
        """Create a BatchProcessor with mock store."""
        checkpoint_dir = tmp_path / "checkpoints"
        return BatchProcessor(
            store=mock_store,
            max_workers=2,
            checkpoint_dir=checkpoint_dir,
        )

    def test_apply_labels_basic(self, processor, tmp_path):
        """Test basic label application."""
        labels = [
            {"address": 0x1000, "name": "function_1"},
            {"address": 0x2000, "name": "data_table"},
        ]

        result = processor.apply_labels(
            project_path=str(tmp_path),
            labels=labels,
            address_space="rom",
            parallel=False,
        )

        assert result["status"] == "completed"
        assert result["applied_count"] == 2
        assert result["total_labels"] == 2
        assert "operation_id" in result
        assert "duration_seconds" in result

    def test_apply_labels_with_kinds(self, processor, tmp_path):
        """Test label application with different kinds."""
        labels = [
            {"address": 0x1000, "name": "start", "kind": "function"},
            {"address": 0x2000, "name": "table", "kind": "data", "comment": "Lookup table"},
        ]

        result = processor.apply_labels(
            project_path=str(tmp_path),
            labels=labels,
            address_space="rom",
            parallel=False,
        )

        assert result["applied_count"] == 2

    def test_apply_labels_empty_list(self, processor, tmp_path):
        """Test label application with empty list."""
        result = processor.apply_labels(
            project_path=str(tmp_path),
            labels=[],
            parallel=False,
        )

        assert result["status"] == "completed"
        assert result["applied_count"] == 0
        assert result["total_labels"] == 0


class TestBatchProcessorExportMultiple:
    """Tests for the export_multiple method."""

    @pytest.fixture
    def mock_store(self):
        """Create a mock store for testing."""
        store = MagicMock()
        store._conn = MagicMock()
        return store

    @pytest.fixture
    def processor(self, mock_store, tmp_path):
        """Create a BatchProcessor with mock store."""
        checkpoint_dir = tmp_path / "checkpoints"
        return BatchProcessor(
            store=mock_store,
            max_workers=2,
            checkpoint_dir=checkpoint_dir,
        )

    @patch("codemunch_pro.rex.batch_ops.get_exporter")
    def test_export_multiple_formats(self, mock_get_exporter, processor, tmp_path):
        """Test exporting to multiple formats."""
        # Setup mock exporter
        mock_exporter = MagicMock()
        mock_exporter.export.return_value = {
            "format": "test",
            "path": "/path/to/export",
            "functions": 10,
        }
        mock_get_exporter.return_value = mock_exporter

        output_dir = tmp_path / "exports"
        formats = ["json", "csv"]

        result = processor.export_multiple(
            project_path=str(tmp_path),
            formats=formats,
            output_dir=str(output_dir),
            parallel=False,
        )

        assert result["status"] == "completed"
        assert result["completed_formats"] == ["json", "csv"]
        assert result["failed_count"] == 0
        assert result["total_formats"] == 2
        assert Path(result["output_dir"]).exists()

    @patch("codemunch_pro.rex.batch_ops.get_exporter")
    def test_export_with_options(self, mock_get_exporter, processor, tmp_path):
        """Test export with custom options."""
        mock_exporter = MagicMock()
        mock_exporter.export.return_value = {"format": "test"}
        mock_get_exporter.return_value = mock_exporter

        options = {
            "include_functions": False,
            "include_comments": False,
        }

        result = processor.export_multiple(
            project_path=str(tmp_path),
            formats=["json"],
            output_dir=str(tmp_path / "exports"),
            options=options,
            parallel=False,
        )

        assert result["status"] == "completed"


class TestBatchProcessorSearchAndReplace:
    """Tests for the search_and_replace method."""

    @pytest.fixture
    def mock_store(self):
        """Create a mock store for testing."""
        store = MagicMock()
        store._conn = MagicMock()
        cursor = MagicMock()
        cursor.fetchall.return_value = [
            {"entity_id": "e1", "name": "old_function_name", "kind": "function"},
            {"entity_id": "e2", "name": "another_old_name", "kind": "function"},
            {"entity_id": "e3", "name": "unrelated", "kind": "data"},
        ]
        store._conn.cursor.return_value = cursor
        return store

    @pytest.fixture
    def processor(self, mock_store, tmp_path):
        """Create a BatchProcessor with mock store."""
        checkpoint_dir = tmp_path / "checkpoints"
        return BatchProcessor(
            store=mock_store,
            max_workers=2,
            checkpoint_dir=checkpoint_dir,
        )

    def test_search_and_replace_dry_run(self, processor, tmp_path):
        """Test search and replace in dry-run mode."""
        result = processor.search_and_replace(
            project_path=str(tmp_path),
            search_pattern="*old*",
            replacement="new_*",
            dry_run=True,
        )

        assert result["status"] == "completed"
        assert result["dry_run"] is True
        assert result["match_count"] >= 1  # At least one name matches "*old*"

    def test_search_and_replace_actual(self, processor, tmp_path):
        """Test actual search and replace (not dry run)."""
        result = processor.search_and_replace(
            project_path=str(tmp_path),
            search_pattern="*old*",
            replacement="new_*",
            dry_run=False,
        )

        assert result["status"] == "completed"
        assert result["dry_run"] is False
        assert result["match_count"] >= 1

    def test_search_and_replace_with_filter(self, processor, tmp_path):
        """Test search and replace with entity kind filter."""
        result = processor.search_and_replace(
            project_path=str(tmp_path),
            search_pattern="*old*",
            replacement="new_*",
            entity_kinds=["function"],
            dry_run=True,
        )

        assert result["status"] == "completed"


class TestBatchProcessorGenerateReports:
    """Tests for the generate_reports method."""

    @pytest.fixture
    def mock_store(self):
        """Create a mock store for testing."""
        store = MagicMock()
        store._conn = MagicMock()
        cursor = MagicMock()
        cursor.fetchall.return_value = []
        store._conn.cursor.return_value = cursor
        store.list_entities.return_value = []
        return store

    @pytest.fixture
    def processor(self, mock_store, tmp_path):
        """Create a BatchProcessor with mock store."""
        checkpoint_dir = tmp_path / "checkpoints"
        return BatchProcessor(
            store=mock_store,
            max_workers=2,
            checkpoint_dir=checkpoint_dir,
        )

    def test_generate_statistics_report(self, processor, tmp_path):
        """Test generating statistics report."""
        output_dir = tmp_path / "reports"

        result = processor.generate_reports(
            project_path=str(tmp_path),
            report_types=["statistics"],
            output_dir=str(output_dir),
        )

        assert result["status"] == "completed"
        # Report generation may fail due to mocking, but status should be completed
        assert Path(result["output_dir"]).exists()

    def test_generate_multiple_reports(self, processor, tmp_path):
        """Test generating multiple report types."""
        output_dir = tmp_path / "reports"
        report_types = ["statistics", "entities", "cross_refs"]

        result = processor.generate_reports(
            project_path=str(tmp_path),
            report_types=report_types,
            output_dir=str(output_dir),
        )

        assert result["status"] == "completed"
        # Report generation may fail due to mocking, but status should be completed
        assert result["generated_count"] + result["error_count"] == 3

    def test_generate_unknown_report_type(self, processor, tmp_path):
        """Test handling of unknown report type."""
        output_dir = tmp_path / "reports"

        result = processor.generate_reports(
            project_path=str(tmp_path),
            report_types=["unknown_type"],
            output_dir=str(output_dir),
        )

        assert result["status"] == "completed"
        assert result["generated_count"] == 0
        assert result["error_count"] == 1


class TestBatchProcessorIntegration:
    """Integration tests for BatchProcessor."""

    def test_checkpoint_resume_flow(self, tmp_path):
        """Test the full checkpoint and resume flow."""
        store = MagicMock()
        store._conn = MagicMock()

        processor = BatchProcessor(
            store=store,
            max_workers=2,
            checkpoint_dir=tmp_path / "checkpoints",
        )

        # Create a checkpoint
        checkpoint = Checkpoint(
            operation_id="test_resume_op",
            operation_type="index_directory",
            processed_items=["/path/to/file1.asm"],
            failed_items=[],
        )

        processor._save_checkpoint(checkpoint)

        # Load it back
        loaded = processor._load_checkpoint("test_resume_op")
        assert loaded is not None
        assert loaded.processed_items == ["/path/to/file1.asm"]

        # Delete it
        processor._delete_checkpoint("test_resume_op")
        assert processor._load_checkpoint("test_resume_op") is None
