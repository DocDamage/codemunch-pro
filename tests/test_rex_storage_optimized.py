"""Tests for optimized REX storage with performance enhancements."""

import asyncio
import gc
import os
import tempfile
from pathlib import Path

import pytest

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)
from codemunch_pro.rex.storage import (
    ReverseEngineeringStore,
    ConnectionPool,
    StatementCache,
)

try:
    from codemunch_pro.rex.async_storage import AsyncReverseEngineeringStore, HAS_AIOSQLITE
except ImportError:
    AsyncReverseEngineeringStore = None  # type: ignore
    HAS_AIOSQLITE = False


@pytest.fixture
def temp_db_path():
    """Create a temporary database path with proper cleanup."""
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "test.db"
    yield db_path
    
    # Cleanup
    gc.collect()  # Force garbage collection to close any dangling references
    try:
        if db_path.exists():
            os.unlink(db_path)
        os.rmdir(tmpdir)
    except (PermissionError, OSError):
        pass  # Ignore cleanup errors on Windows


@pytest.fixture
def store(temp_db_path):
    """Create a test store with optimizations enabled."""
    store = ReverseEngineeringStore(
        db_path=temp_db_path,
        use_connection_pool=True,
        pool_size=3,
        use_statement_cache=True,
    )
    yield store
    store.close()
    gc.collect()


@pytest.fixture
def sample_bundle():
    """Create a sample bundle for testing."""
    artifact = ArtifactRecord(
        artifact_id="test:artifact:1",
        kind="test",
        path="/test/path",
        title="Test Artifact",
    )
    
    entity = EntityRecord(
        entity_id="test:entity:1",
        kind="function",
        name="test_function",
        artifact_id="test:artifact:1",
        canonical_ref="0x1234",
        location=AddressLocation(
            address_space="test",
            start=0x1000,
            end=0x1100,
        ),
    )
    
    evidence = EvidenceRecord(
        evidence_id="test:evidence:1",
        kind="disassembly",
        artifact_id="test:artifact:1",
        entity_ids=("test:entity:1",),
        excerpt="LD A, #0x00",
        confidence=0.95,
    )
    
    edge = EdgeRecord(
        edge_id="test:edge:1",
        kind="calls",
        source_entity_id="test:entity:1",
        target_entity_id="test:entity:2",
        confidence=0.9,
    )
    
    return ReverseEngineeringBundle(
        artifacts=[artifact],
        entities=[entity],
        evidence=[evidence],
        edges=[edge],
    )


class TestConnectionPool:
    """Tests for ConnectionPool class."""
    
    def test_pool_creation(self, temp_db_path):
        """Test connection pool initialization."""
        pool = ConnectionPool(temp_db_path, pool_size=3)
        assert len(pool._pool) == 3
        pool.close_all()
        gc.collect()
    
    def test_get_connection(self, temp_db_path):
        """Test getting connections from pool."""
        pool = ConnectionPool(temp_db_path, pool_size=2)
        conn1 = pool.get_connection()
        conn2 = pool.get_connection()
        
        assert conn1 is not None
        assert conn2 is not None
        
        pool.release_connection(conn1)
        pool.release_connection(conn2)
        pool.close_all()
        gc.collect()
    
    def test_connection_optimization_settings(self, temp_db_path):
        """Test that connections have performance optimizations."""
        pool = ConnectionPool(temp_db_path, pool_size=1)
        conn = pool.get_connection()
        
        # Check WAL mode
        cursor = conn.execute("PRAGMA journal_mode")
        mode = cursor.fetchone()[0]
        assert mode == "wal"
        
        pool.close_all()
        gc.collect()


class TestStatementCache:
    """Tests for StatementCache class."""
    
    def test_cache_set_get(self):
        """Test caching statements."""
        cache = StatementCache(cache_size=10)
        cache.set("key1", "statement1")
        
        assert cache.get("key1") == "statement1"
        assert cache.get("nonexistent") is None
    
    def test_cache_size_limit(self):
        """Test cache eviction at size limit."""
        cache = StatementCache(cache_size=2)
        cache.set("key1", "statement1")
        cache.set("key2", "statement2")
        cache.set("key3", "statement3")  # Should evict key1
        
        assert cache.get("key1") is None
        assert cache.get("key2") == "statement2"
        assert cache.get("key3") == "statement3"


class TestLazyEntity:
    """Tests for LazyEntity class."""
    
    def test_lazy_loading(self, store, sample_bundle):
        """Test that entities are loaded lazily."""
        store.upsert_bundle(sample_bundle)
        
        # Create lazy wrapper
        lazy = store.get_entity_lazy("test:entity:1")
        
        # Access should trigger load
        assert lazy.entity_id == "test:entity:1"
        assert lazy.name == "test_function"
        assert lazy.kind == "function"
        assert lazy._loaded is True


class TestBulkOperations:
    """Tests for bulk insert operations."""
    
    def test_bulk_insert_artifacts(self, store):
        """Test bulk artifact insertion."""
        artifacts = [
            ArtifactRecord(
                artifact_id=f"artifact:{i}",
                kind="test",
                path=f"/test/{i}",
            )
            for i in range(100)
        ]
        
        store.bulk_insert_artifacts(artifacts)
        
        stats = store.stats()
        assert stats["artifacts"] == 100
    
    def test_bulk_insert_entities(self, store):
        """Test bulk entity insertion."""
        entities = [
            EntityRecord(
                entity_id=f"entity:{i}",
                kind="function",
                name=f"func_{i}",
            )
            for i in range(100)
        ]
        
        store.bulk_insert_entities(entities)
        
        stats = store.stats()
        assert stats["entities"] == 100
    
    def test_bulk_insert_evidence(self, store):
        """Test bulk evidence insertion."""
        evidence_list = [
            EvidenceRecord(
                evidence_id=f"evidence:{i}",
                kind="disassembly",
                artifact_id="test",
                excerpt=f"instruction {i}",
            )
            for i in range(100)
        ]
        
        store.bulk_insert_evidence(evidence_list)
        
        stats = store.stats()
        assert stats["evidence"] == 100
    
    def test_bulk_insert_edges(self, store):
        """Test bulk edge insertion."""
        edges = [
            EdgeRecord(
                edge_id=f"edge:{i}",
                kind="calls",
                source_entity_id=f"src:{i}",
                target_entity_id=f"dst:{i}",
            )
            for i in range(100)
        ]
        
        store.bulk_insert_edges(edges)
        
        stats = store.stats()
        assert stats["edges"] == 100
    
    def test_bulk_insert_performance(self, store):
        """Test that bulk insert is faster than individual inserts."""
        import time
        
        # Bulk insert timing
        artifacts = [
            ArtifactRecord(
                artifact_id=f"perf:artifact:{i}",
                kind="test",
                path=f"/test/{i}",
            )
            for i in range(100)
        ]
        
        start = time.time()
        store.bulk_insert_artifacts(artifacts)
        bulk_time = time.time() - start
        
        # Bulk should be reasonably fast
        assert bulk_time < 5.0  # Should complete in under 5 seconds


class TestCaching:
    """Tests for LRU caching."""
    
    def test_get_artifact_cached(self, store, sample_bundle):
        """Test artifact caching."""
        store.upsert_bundle(sample_bundle)
        store.clear_caches()
        
        # First call should miss
        store.get_artifact("test:artifact:1")
        info1 = store.get_cache_info()["get_artifact"]
        assert info1["misses"] == 1
        
        # Second call should hit
        store.get_artifact("test:artifact:1")
        info2 = store.get_cache_info()["get_artifact"]
        assert info2["hits"] == 1
    
    def test_get_entity_cached(self, store, sample_bundle):
        """Test entity caching."""
        store.upsert_bundle(sample_bundle)
        store.clear_caches()
        
        store.get_entity("test:entity:1")
        info1 = store.get_cache_info()["get_entity"]
        assert info1["misses"] == 1
        
        store.get_entity("test:entity:1")
        info2 = store.get_cache_info()["get_entity"]
        assert info2["hits"] == 1
    
    def test_search_entities_cached(self, store, sample_bundle):
        """Test search caching."""
        store.upsert_bundle(sample_bundle)
        store.clear_caches()
        
        store.search_entities("test")
        info1 = store.get_cache_info()["search_entities"]
        assert info1["misses"] == 1
        
        store.search_entities("test")
        info2 = store.get_cache_info()["search_entities"]
        assert info2["hits"] == 1
    
    def test_cache_clear(self, store, sample_bundle):
        """Test clearing caches."""
        store.upsert_bundle(sample_bundle)
        store.get_artifact("test:artifact:1")
        
        info_before = store.get_cache_info()["get_artifact"]
        assert info_before["currsize"] == 1
        
        store.clear_caches()
        
        info_after = store.get_cache_info()["get_artifact"]
        assert info_after["currsize"] == 0


class TestAdditionalIndexes:
    """Tests for additional database indexes."""
    
    def test_indexes_created(self, store):
        """Test that all indexes are created."""
        conn = store._conn
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        )
        indexes = [row[0] for row in cursor.fetchall()]
        
        expected_indexes = [
            "idx_entities_artifact",
            "idx_entities_kind",
            "idx_entities_canonical_ref",
            "idx_evidence_artifact",
            "idx_evidence_kind",
            "idx_edges_source",
            "idx_edges_target",
            "idx_entities_artifact_kind",
            "idx_entities_name",
            "idx_edges_kind",
            "idx_edges_source_kind",
            "idx_edges_target_kind",
        ]
        
        for idx in expected_indexes:
            assert idx in indexes, f"Missing index: {idx}"


@pytest.mark.skipif(AsyncReverseEngineeringStore is None, reason="Async storage not available")
class TestAsyncStorage:
    """Tests for AsyncReverseEngineeringStore."""
    
    def test_async_initialization(self, temp_db_path):
        """Test async store initialization."""
        async def test():
            async with AsyncReverseEngineeringStore(temp_db_path) as store:
                stats = await store.stats()
                assert stats["artifacts"] == 0
                assert stats["entities"] == 0
        
        asyncio.run(test())
        gc.collect()
    
    def test_async_bulk_insert(self, temp_db_path):
        """Test async bulk insert."""
        async def test():
            async with AsyncReverseEngineeringStore(temp_db_path) as store:
                artifacts = [
                    ArtifactRecord(
                        artifact_id=f"async:artifact:{i}",
                        kind="test",
                        path=f"/test/{i}",
                    )
                    for i in range(50)
                ]
                
                await store.bulk_insert_artifacts(artifacts)
                
                stats = await store.stats()
                assert stats["artifacts"] == 50
        
        asyncio.run(test())
        gc.collect()
    
    def test_async_entity_operations(self, temp_db_path):
        """Test async entity CRUD operations."""
        async def test():
            async with AsyncReverseEngineeringStore(temp_db_path) as store:
                entities = [
                    EntityRecord(
                        entity_id=f"async:entity:{i}",
                        kind="function",
                        name=f"func_{i}",
                    )
                    for i in range(10)
                ]
                
                await store.bulk_insert_entities(entities)
                
                # Test get
                entity = await store.get_entity("async:entity:5")
                assert entity is not None
                assert entity.name == "func_5"
                
                # Test list
                all_entities = await store.list_entities(kind="function", limit=100)
                assert len(all_entities) == 10
        
        asyncio.run(test())
        gc.collect()
    
    def test_async_search(self, temp_db_path):
        """Test async search operations."""
        async def test():
            async with AsyncReverseEngineeringStore(temp_db_path) as store:
                entities = [
                    EntityRecord(
                        entity_id=f"search:entity:{i}",
                        kind="function",
                        name=f"searchable_func_{i}",
                    )
                    for i in range(10)
                ]
                
                await store.bulk_insert_entities(entities)
                
                results = await store.search_entities("searchable")
                assert len(results) == 10
        
        asyncio.run(test())
        gc.collect()
    
    def test_async_graph_traversal(self, temp_db_path):
        """Test async graph traversal."""
        async def test():
            async with AsyncReverseEngineeringStore(temp_db_path) as store:
                # Create a chain: A -> B -> C
                edges = [
                    EdgeRecord(
                        edge_id="edge:ab",
                        kind="calls",
                        source_entity_id="entity:a",
                        target_entity_id="entity:b",
                    ),
                    EdgeRecord(
                        edge_id="edge:bc",
                        kind="calls",
                        source_entity_id="entity:b",
                        target_entity_id="entity:c",
                    ),
                ]
                
                await store.bulk_insert_edges(edges)
                
                result = await store.traverse_entity_graph(
                    entity_ids=["entity:a"],
                    depth=2,
                    edge_limit=10
                )
                
                assert len(result["edges"]) == 2
        
        asyncio.run(test())
        gc.collect()
    
    def test_async_provenance(self, temp_db_path):
        """Test async provenance operations."""
        async def test():
            async with AsyncReverseEngineeringStore(temp_db_path) as store:
                artifacts = [
                    ArtifactRecord(
                        artifact_id=f"prov:artifact:{i}",
                        kind="test",
                        path=f"/test/{i}",
                    )
                    for i in range(2)
                ]
                
                entities = [
                    EntityRecord(
                        entity_id=f"prov:entity:{i}",
                        kind="reference",
                        name=f"ref_{i}",
                        artifact_id=f"prov:artifact:{i % 2}",
                        canonical_ref="shared:ref",
                    )
                    for i in range(4)
                ]
                
                await store.bulk_insert_artifacts(artifacts)
                await store.bulk_insert_entities(entities)
                
                summaries = await store.summarize_ref_provenance("shared:ref")
                assert len(summaries) == 2  # Two artifacts
                
                comparison = await store.compare_ref_provenance("shared:ref")
                assert comparison["artifact_count"] == 2
        
        asyncio.run(test())
        gc.collect()
    
    def test_async_import_from_sync(self, temp_db_path):
        """Test importing data from sync store."""
        async def test():
            # Create sync store with data
            sync_db = temp_db_path.parent / "sync.db"
            sync_store = ReverseEngineeringStore(sync_db)
            
            artifacts = [
                ArtifactRecord(
                    artifact_id=f"import:artifact:{i}",
                    kind="test",
                    path=f"/test/{i}",
                )
                for i in range(10)
            ]
            sync_store.bulk_insert_artifacts(artifacts)
            
            # Import to async store
            async_db = temp_db_path.parent / "async_import.db"
            async with AsyncReverseEngineeringStore(async_db) as async_store:
                counts = await async_store.import_bundle_from_sync_store(sync_store)
                
                assert counts["artifacts"] == 10
                
                stats = await async_store.stats()
                assert stats["artifacts"] == 10
            
            sync_store.close()
        
        asyncio.run(test())
        gc.collect()
    
    def test_async_without_aiosqlite(self, temp_db_path):
        """Test that async store works without aiosqlite (using executor)."""
        async def test():
            # Use a different database path to avoid conflicts
            executor_db = temp_db_path.parent / "executor.db"
            # Force use of executor
            store = AsyncReverseEngineeringStore(executor_db, use_executor=True)
            await store.initialize()
            
            try:
                artifacts = [
                    ArtifactRecord(
                        artifact_id=f"executor:artifact:{i}",
                        kind="test",
                        path=f"/test/{i}",
                    )
                    for i in range(5)
                ]
                
                await store.bulk_insert_artifacts(artifacts)
                
                stats = await store.stats()
                assert stats["artifacts"] == 5
            finally:
                await store.close()
        
        asyncio.run(test())
        gc.collect()


class TestLargeProjectPerformance:
    """Performance tests simulating large projects."""
    
    def test_large_entity_count(self, store):
        """Test handling many entities."""
        # Simulate a large project with 1000 entities
        entities = [
            EntityRecord(
                entity_id=f"large:entity:{i}",
                kind="function" if i % 3 == 0 else "data",
                name=f"symbol_{i}",
                artifact_id="large:artifact",
                canonical_ref=f"ref:{i % 100}",  # Create some duplicates
                location=AddressLocation(
                    address_space="rom",
                    start=i * 0x100,
                    end=i * 0x100 + 0x50,
                ) if i % 2 == 0 else None,
            )
            for i in range(1000)
        ]
        
        store.bulk_insert_entities(entities)
        
        stats = store.stats()
        assert stats["entities"] == 1000
        
        # Test query performance
        import time
        start = time.time()
        results = store.list_entities(kind="function", limit=500)  # Get more than 100
        query_time = time.time() - start
        
        # Count function entities (those where i % 3 == 0)
        expected_functions = sum(1 for i in range(1000) if i % 3 == 0)
        assert len(results) == min(expected_functions, 500)  # Limited by limit parameter
        assert query_time < 1.0  # Should be fast with indexes
    
    def test_large_evidence_count(self, store):
        """Test handling many evidence records."""
        # Create 5000 evidence records
        evidence_list = [
            EvidenceRecord(
                evidence_id=f"large:evidence:{i}",
                kind="disassembly" if i % 2 == 0 else "comment",
                artifact_id="large:artifact",
                entity_ids=(f"large:entity:{i % 1000}",),
                excerpt=f"Instruction at {i}",
                confidence=0.5 + (i % 50) / 100,
            )
            for i in range(5000)
        ]
        
        store.bulk_insert_evidence(evidence_list)
        
        stats = store.stats()
        assert stats["evidence"] == 5000
    
    def test_large_edge_graph(self, store):
        """Test handling large edge graphs."""
        # Create a dense graph with 2000 edges
        edges = []
        for i in range(100):
            for j in range(20):
                edges.append(EdgeRecord(
                    edge_id=f"large:edge:{i}:{j}",
                    kind="calls",
                    source_entity_id=f"node:{i}",
                    target_entity_id=f"node:{(i + j) % 100}",
                ))
        
        store.bulk_insert_edges(edges)
        
        stats = store.stats()
        assert stats["edges"] == 2000
        
        # Test graph traversal performance
        import time
        start = time.time()
        store.traverse_entity_graph(
            entity_ids=["node:0"],
            depth=3,
            edge_limit=100
        )
        traverse_time = time.time() - start
        
        assert traverse_time < 2.0  # Should complete quickly with indexes


class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_empty_bulk_insert(self, store):
        """Test bulk insert with empty lists."""
        store.bulk_insert_artifacts([])
        store.bulk_insert_entities([])
        store.bulk_insert_evidence([])
        store.bulk_insert_edges([])
        
        stats = store.stats()
        assert all(v == 0 for v in stats.values())
    
    def test_entity_not_found(self, store):
        """Test getting non-existent entity."""
        entity = store.get_entity("nonexistent:entity")
        assert entity is None
    
    def test_artifact_not_found(self, store):
        """Test getting non-existent artifact."""
        artifact = store.get_artifact("nonexistent:artifact")
        assert artifact is None
    
    def test_lazy_entity_not_found(self, store):
        """Test lazy loading of non-existent entity."""
        lazy = store.get_entity_lazy("nonexistent:entity")
        assert lazy.entity_id == "nonexistent:entity"
        assert lazy.name == ""  # Should return empty, not raise
    
    def test_search_no_results(self, store):
        """Test search returning no results."""
        results = store.search_entities("xyznonexistent")
        assert results == []
    
    def test_upsert_bundle_empty(self, store):
        """Test upserting empty bundle."""
        bundle = ReverseEngineeringBundle()
        store.upsert_bundle(bundle)
        
        stats = store.stats()
        assert all(v == 0 for v in stats.values())
