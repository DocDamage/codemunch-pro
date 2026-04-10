"""Storage backend for reverse-engineering data with performance optimizations."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.similarity import (
        SimilarityIndex,
    )

from codemunch_pro.rex.entropy import EntropyAnalyzer
from codemunch_pro.rex.exporters import ExportOptions, get_exporter
from codemunch_pro.rex.memory_map import MemoryMap, MemoryRegion, RegionType
from codemunch_pro.rex.pattern_matcher import BytePattern, PatternMatcher
from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)
from codemunch_pro.rex.cfg import ControlFlowGraph, BasicBlock

DEFAULT_REX_DB_DIR = Path(".rex_db")
DEFAULT_CONNECTION_POOL_SIZE = 5
DEFAULT_STATEMENT_CACHE_SIZE = 100


class LazyEntity:
    """Lazy loading wrapper for EntityRecord."""
    
    def __init__(self, store: ReverseEngineeringStore, entity_id: str):
        self._store = store
        self._entity_id = entity_id
        self._loaded = False
        self._entity: EntityRecord | None = None
    
    def _load(self) -> EntityRecord | None:
        if not self._loaded:
            self._entity = self._store.get_entity(self._entity_id)
            self._loaded = True
        return self._entity
    
    @property
    def entity_id(self) -> str:
        return self._entity_id
    
    @property
    def kind(self) -> str:
        entity = self._load()
        return entity.kind if entity else ""
    
    @property
    def name(self) -> str:
        entity = self._load()
        return entity.name if entity else ""
    
    @property
    def artifact_id(self) -> str:
        entity = self._load()
        return entity.artifact_id if entity else ""
    
    @property
    def canonical_ref(self) -> str:
        entity = self._load()
        return entity.canonical_ref if entity else ""
    
    @property
    def location(self) -> AddressLocation | None:
        entity = self._load()
        return entity.location if entity else None
    
    @property
    def summary(self) -> str:
        entity = self._load()
        return entity.summary if entity else ""
    
    @property
    def aliases(self) -> tuple[str, ...]:
        entity = self._load()
        return entity.aliases if entity else ()
    
    @property
    def attributes(self) -> dict[str, Any]:
        entity = self._load()
        return entity.attributes if entity else {}
    
    def to_dict(self) -> dict[str, Any]:
        entity = self._load()
        return entity.to_dict() if entity else {}


class ConnectionPool:
    """Thread-safe SQLite connection pool."""
    
    def __init__(self, db_path: Path, pool_size: int = DEFAULT_CONNECTION_POOL_SIZE):
        self._db_path = db_path
        self._pool_size = pool_size
        self._pool: list[sqlite3.Connection] = []
        self._all_connections: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._local = threading.local()
        
        # Create initial connections
        for _ in range(pool_size):
            conn = self._create_connection()
            self._pool.append(conn)
    
    def _create_connection(self) -> sqlite3.Connection:
        """Create a new database connection with optimized settings."""
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        
        # Performance optimizations
        conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for better concurrency
        conn.execute("PRAGMA synchronous=NORMAL")  # Balance safety and speed
        conn.execute("PRAGMA cache_size=10000")  # Increase cache size (pages)
        conn.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in memory
        conn.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O

        self._all_connections.append(conn)
        return conn
    
    def get_connection(self) -> sqlite3.Connection:
        """Get a connection from the pool."""
        # Check thread-local connection first
        if hasattr(self._local, 'conn') and self._local.conn:
            return self._local.conn
        
        with self._lock:
            if self._pool:
                conn = self._pool.pop()
                self._local.conn = conn
                return conn
        
        # Create new connection if pool is exhausted
        conn = self._create_connection()
        self._local.conn = conn
        return conn
    
    def release_connection(self, conn: sqlite3.Connection) -> None:
        """Release a connection back to the pool."""
        with self._lock:
            if len(self._pool) < self._pool_size:
                self._pool.append(conn)
            else:
                conn.close()
    
    def close_all(self) -> None:
        """Close all connections in the pool."""
        with self._lock:
            local_conn = getattr(self._local, "conn", None)
            connections = list(self._all_connections)
            if local_conn is not None and local_conn not in connections:
                connections.append(local_conn)

            for conn in connections:
                try:
                    conn.close()
                except sqlite3.Error:
                    continue
            self._pool.clear()
            self._all_connections.clear()
            self._local.conn = None


class StatementCache:
    """Cache for prepared SQLite statements."""
    
    def __init__(self, cache_size: int = DEFAULT_STATEMENT_CACHE_SIZE):
        self._cache: dict[str, sqlite3.Statement] = {}
        self._cache_size = cache_size
        self._lock = threading.Lock()
    
    def get(self, key: str) -> sqlite3.Statement | None:
        """Get a cached statement."""
        with self._lock:
            return self._cache.get(key)
    
    def set(self, key: str, statement: sqlite3.Statement) -> None:
        """Cache a prepared statement."""
        with self._lock:
            if len(self._cache) >= self._cache_size:
                # Simple LRU eviction - remove first item
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[key] = statement
    
    def clear(self) -> None:
        """Clear the statement cache."""
        with self._lock:
            self._cache.clear()


class ReverseEngineeringStore:
    """SQLite-backed store for reverse-engineering data with performance optimizations."""

    def __init__(
        self, 
        db_path: Path | str = DEFAULT_REX_DB_DIR / "rex.db",
        use_connection_pool: bool = True,
        pool_size: int = DEFAULT_CONNECTION_POOL_SIZE,
        use_statement_cache: bool = True,
    ):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._use_connection_pool = use_connection_pool
        self._use_statement_cache = use_statement_cache
        
        # Initialize connection pool or single connection
        if use_connection_pool:
            self._pool = ConnectionPool(self._db_path, pool_size)
            self._conn = self._pool.get_connection()
        else:
            self._conn = sqlite3.connect(self._db_path)
            self._conn.row_factory = sqlite3.Row
            self._pool = None
        
        # Statement cache
        self._statement_cache = StatementCache() if use_statement_cache else None
        
        self._init_db()
        self._create_additional_indexes()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get current connection (from pool or single)."""
        if self._pool:
            return self._pool.get_connection()
        return self._conn
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        cursor = self._conn.cursor()
        
        # Artifacts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT DEFAULT '',
                title TEXT DEFAULT '',
                media_type TEXT DEFAULT '',
                metadata_json TEXT DEFAULT '{}',
                indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Entities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                entity_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                artifact_id TEXT,
                canonical_ref TEXT DEFAULT '',
                summary TEXT DEFAULT '',
                aliases_json TEXT DEFAULT '[]',
                location_json TEXT,
                attributes_json TEXT DEFAULT '{}',
                FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE
            )
        """)
        
        # Evidence table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                entity_ids_json TEXT DEFAULT '[]',
                location_json TEXT,
                excerpt TEXT DEFAULT '',
                confidence REAL,
                attributes_json TEXT DEFAULT '{}',
                FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE
            )
        """)
        
        # Edges table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS edges (
                edge_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                source_entity_id TEXT NOT NULL,
                target_entity_id TEXT NOT NULL,
                evidence_id TEXT DEFAULT '',
                confidence REAL,
                attributes_json TEXT DEFAULT '{}',
                FOREIGN KEY (source_entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE,
                FOREIGN KEY (target_entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for common queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_artifact ON entities(artifact_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_canonical_ref ON entities(canonical_ref)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_artifact ON evidence(artifact_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence(kind)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_entity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_entity_id)")
        
        self._conn.commit()
    
    def _create_additional_indexes(self) -> None:
        """Create additional indexes for performance optimization."""
        cursor = self._conn.cursor()
        
        # Composite index for entity lookups by artifact and kind
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_entities_artifact_kind 
            ON entities(artifact_id, kind)
        """)
        
        # Index for entity name searches
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_entities_name 
            ON entities(name COLLATE NOCASE)
        """)
        
        # Index for edge lookups by kind
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_edges_kind 
            ON edges(kind)
        """)
        
        # Composite index for edges (source, kind)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_edges_source_kind 
            ON edges(source_entity_id, kind)
        """)
        
        # Composite index for edges (target, kind)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_edges_target_kind 
            ON edges(target_entity_id, kind)
        """)
        
        # Index for evidence confidence filtering
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_confidence 
            ON evidence(confidence) WHERE confidence IS NOT NULL
        """)
        
        self._conn.commit()
    
    def close(self) -> None:
        """Close the database connection."""
        if self._statement_cache:
            self._statement_cache.clear()
        
        if self._pool:
            self._pool.close_all()
        else:
            self._conn.close()
    
    def _location_to_json(self, location: AddressLocation | None) -> str | None:
        """Serialize AddressLocation to JSON string."""
        if location is None:
            return None
        return json.dumps(location.to_dict())
    
    def _json_to_location(self, json_str: str | None) -> AddressLocation | None:
        """Deserialize JSON string to AddressLocation."""
        if json_str is None:
            return None
        data = json.loads(json_str)
        return AddressLocation(
            address_space=data["address_space"],
            start=data["start"],
            end=data["end"],
            unit=data.get("unit", "byte"),
            display=data.get("display", ""),
            segment=data.get("segment", ""),
            attributes=data.get("attributes", {}),
        )
    
    def _prepare_statement(self, sql: str) -> Any:
        """Get or prepare a cached statement."""
        if not self._use_statement_cache or self._statement_cache is None:
            return sql
        
        cached = self._statement_cache.get(sql)
        if cached:
            return cached
        
        # SQLite doesn't expose prepared statements directly, so we cache the SQL
        return sql
    
    # Bulk insert operations
    
    def bulk_insert_artifacts(self, artifacts: list[ArtifactRecord]) -> None:
        """Bulk insert artifacts for better performance."""
        if not artifacts:
            return
        
        cursor = self._conn.cursor()
        cursor.executemany(
            """
            INSERT INTO artifacts (artifact_id, kind, path, sha256, title, media_type, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                kind = excluded.kind,
                path = excluded.path,
                sha256 = excluded.sha256,
                title = excluded.title,
                media_type = excluded.media_type,
                metadata_json = excluded.metadata_json,
                indexed_at = CURRENT_TIMESTAMP
            """,
            [
                (
                    a.artifact_id,
                    a.kind,
                    a.path,
                    a.sha256,
                    a.title,
                    a.media_type,
                    json.dumps(a.metadata),
                )
                for a in artifacts
            ],
        )
        self._conn.commit()
        self.clear_caches()
    
    def bulk_insert_entities(self, entities: list[EntityRecord]) -> None:
        """Bulk insert entities for better performance."""
        if not entities:
            return
        
        cursor = self._conn.cursor()
        cursor.executemany(
            """
            INSERT INTO entities (entity_id, kind, name, artifact_id, canonical_ref, summary, aliases_json, location_json, attributes_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id) DO UPDATE SET
                kind = excluded.kind,
                name = excluded.name,
                artifact_id = excluded.artifact_id,
                canonical_ref = excluded.canonical_ref,
                summary = excluded.summary,
                aliases_json = excluded.aliases_json,
                location_json = excluded.location_json,
                attributes_json = excluded.attributes_json
            """,
            [
                (
                    e.entity_id,
                    e.kind,
                    e.name,
                    e.artifact_id,
                    e.canonical_ref,
                    e.summary,
                    json.dumps(list(e.aliases)),
                    self._location_to_json(e.location),
                    json.dumps(e.attributes),
                )
                for e in entities
            ],
        )
        self._conn.commit()
        self.clear_caches()
    
    def bulk_insert_evidence(self, evidence_list: list[EvidenceRecord]) -> None:
        """Bulk insert evidence for better performance."""
        if not evidence_list:
            return
        
        cursor = self._conn.cursor()
        cursor.executemany(
            """
            INSERT INTO evidence (evidence_id, kind, artifact_id, entity_ids_json, location_json, excerpt, confidence, attributes_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(evidence_id) DO UPDATE SET
                kind = excluded.kind,
                artifact_id = excluded.artifact_id,
                entity_ids_json = excluded.entity_ids_json,
                location_json = excluded.location_json,
                excerpt = excluded.excerpt,
                confidence = excluded.confidence,
                attributes_json = excluded.attributes_json
            """,
            [
                (
                    ev.evidence_id,
                    ev.kind,
                    ev.artifact_id,
                    json.dumps(list(ev.entity_ids)),
                    self._location_to_json(ev.location),
                    ev.excerpt,
                    ev.confidence,
                    json.dumps(ev.attributes),
                )
                for ev in evidence_list
            ],
        )
        self._conn.commit()
        self.clear_caches()
    
    def bulk_insert_edges(self, edges: list[EdgeRecord]) -> None:
        """Bulk insert edges for better performance."""
        if not edges:
            return
        
        cursor = self._conn.cursor()
        cursor.executemany(
            """
            INSERT INTO edges (edge_id, kind, source_entity_id, target_entity_id, evidence_id, confidence, attributes_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(edge_id) DO UPDATE SET
                kind = excluded.kind,
                source_entity_id = excluded.source_entity_id,
                target_entity_id = excluded.target_entity_id,
                evidence_id = excluded.evidence_id,
                confidence = excluded.confidence,
                attributes_json = excluded.attributes_json
            """,
            [
                (
                    e.edge_id,
                    e.kind,
                    e.source_entity_id,
                    e.target_entity_id,
                    e.evidence_id,
                    e.confidence,
                    json.dumps(e.attributes),
                )
                for e in edges
            ],
        )
        self._conn.commit()
        self.clear_caches()
    
    def upsert_bundle(self, bundle: ReverseEngineeringBundle) -> None:
        """Upsert a bundle into the store using bulk operations."""
        self.bulk_insert_artifacts(bundle.artifacts)
        self.bulk_insert_entities(bundle.entities)
        self.bulk_insert_evidence(bundle.evidence)
        self.bulk_insert_edges(bundle.edges)
    
    def replace_bundle(self, bundle: ReverseEngineeringBundle) -> None:
        """Replace a bundle in the store (delete old data for these artifacts, then insert)."""
        cursor = self._conn.cursor()
        
        # Collect all artifact IDs from the bundle
        artifact_ids = [a.artifact_id for a in bundle.artifacts]
        
        # Delete existing data for these artifacts
        for artifact_id in artifact_ids:
            # Delete edges for entities of this artifact
            cursor.execute(
                """
                DELETE FROM edges WHERE source_entity_id IN 
                (SELECT entity_id FROM entities WHERE artifact_id = ?)
                OR target_entity_id IN 
                (SELECT entity_id FROM entities WHERE artifact_id = ?)
                """,
                (artifact_id, artifact_id),
            )
            # Delete evidence for this artifact
            cursor.execute("DELETE FROM evidence WHERE artifact_id = ?", (artifact_id,))
            # Delete entities for this artifact
            cursor.execute("DELETE FROM entities WHERE artifact_id = ?", (artifact_id,))
            # Delete the artifact itself
            cursor.execute("DELETE FROM artifacts WHERE artifact_id = ?", (artifact_id,))
        
        self._conn.commit()
        
        # Now insert the new bundle data
        self.upsert_bundle(bundle)
    
    def stats(self) -> dict[str, int]:
        """Return statistics about the store."""
        cursor = self._conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM artifacts")
        artifacts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM entities")
        entities = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM evidence")
        evidence = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM edges")
        edges = cursor.fetchone()[0]
        
        return {
            "artifacts": artifacts,
            "entities": entities,
            "evidence": evidence,
            "edges": edges,
        }
    
    def _row_to_artifact(self, row: sqlite3.Row) -> ArtifactRecord:
        """Convert a database row to an ArtifactRecord."""
        return ArtifactRecord(
            artifact_id=row["artifact_id"],
            kind=row["kind"],
            path=row["path"],
            sha256=row["sha256"],
            title=row["title"],
            media_type=row["media_type"],
            metadata=json.loads(row["metadata_json"] or "{}"),
        )
    
    def _row_to_entity(self, row: sqlite3.Row) -> EntityRecord:
        """Convert a database row to an EntityRecord."""
        return EntityRecord(
            entity_id=row["entity_id"],
            kind=row["kind"],
            name=row["name"],
            artifact_id=row["artifact_id"] or "",
            canonical_ref=row["canonical_ref"] or "",
            location=self._json_to_location(row["location_json"]),
            summary=row["summary"] or "",
            aliases=tuple(json.loads(row["aliases_json"] or "[]")),
            attributes=json.loads(row["attributes_json"] or "{}"),
        )
    
    def _row_to_evidence(self, row: sqlite3.Row) -> EvidenceRecord:
        """Convert a database row to an EvidenceRecord."""
        return EvidenceRecord(
            evidence_id=row["evidence_id"],
            kind=row["kind"],
            artifact_id=row["artifact_id"],
            entity_ids=tuple(json.loads(row["entity_ids_json"] or "[]")),
            location=self._json_to_location(row["location_json"]),
            excerpt=row["excerpt"] or "",
            confidence=row["confidence"],
            attributes=json.loads(row["attributes_json"] or "{}"),
        )
    
    def _row_to_edge(self, row: sqlite3.Row) -> EdgeRecord:
        """Convert a database row to an EdgeRecord."""
        return EdgeRecord(
            edge_id=row["edge_id"],
            kind=row["kind"],
            source_entity_id=row["source_entity_id"],
            target_entity_id=row["target_entity_id"],
            evidence_id=row["evidence_id"] or "",
            confidence=row["confidence"],
            attributes=json.loads(row["attributes_json"] or "{}"),
        )
    
    @lru_cache(maxsize=128)
    def get_artifact(self, artifact_id: str) -> ArtifactRecord | None:
        """Get an artifact by ID (cached)."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_artifact(row)
    
    @lru_cache(maxsize=256)
    def get_entity(self, entity_id: str) -> EntityRecord | None:
        """Get an entity by ID (cached)."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM entities WHERE entity_id = ?", (entity_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_entity(row)
    
    def get_entity_lazy(self, entity_id: str) -> LazyEntity:
        """Get a lazy-loading wrapper for an entity."""
        return LazyEntity(self, entity_id)
    
    @lru_cache(maxsize=64)
    def search_evidence(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Search for evidence by excerpt content (case-insensitive, cached)."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT * FROM evidence 
            WHERE excerpt LIKE ? 
            ORDER BY evidence_id
            LIMIT ?
            """,
            (f"%{query}%", limit),
        )
        rows = cursor.fetchall()
        return [dict(self._row_to_evidence(row).to_dict()) for row in rows]
    
    @lru_cache(maxsize=64)
    def search_entities(self, query: str, kind: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Search for entities by name or canonical_ref (case-insensitive, cached)."""
        cursor = self._conn.cursor()
        
        sql = """
            SELECT * FROM entities 
            WHERE (name LIKE ? OR canonical_ref LIKE ? OR entity_id LIKE ?)
        """
        params = [f"%{query}%", f"%{query}%", f"%{query}%"]
        
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        
        sql += " ORDER BY entity_id LIMIT ?"
        params.append(limit)
        
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(self._row_to_entity(row).to_dict()) for row in rows]
    
    def list_artifacts(self, kind: str = "", limit: int = 100) -> list[ArtifactRecord]:
        """List all artifacts."""
        cursor = self._conn.cursor()
        
        if kind:
            cursor.execute(
                "SELECT * FROM artifacts WHERE kind = ? ORDER BY artifact_id LIMIT ?",
                (kind, limit),
            )
        else:
            cursor.execute(
                "SELECT * FROM artifacts ORDER BY artifact_id LIMIT ?",
                (limit,),
            )
        
        rows = cursor.fetchall()
        return [self._row_to_artifact(row) for row in rows]
    
    def get_entities_for_artifact(self, artifact_id: str, kind: str | None = None, limit: int = 100) -> list[EntityRecord]:
        """Get entities for an artifact."""
        cursor = self._conn.cursor()
        
        if kind:
            cursor.execute(
                """
                SELECT * FROM entities 
                WHERE artifact_id = ? AND kind = ?
                ORDER BY entity_id LIMIT ?
                """,
                (artifact_id, kind, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM entities 
                WHERE artifact_id = ?
                ORDER BY entity_id LIMIT ?
                """,
                (artifact_id, limit),
            )
        
        rows = cursor.fetchall()
        return [self._row_to_entity(row) for row in rows]
    
    def get_evidence_for_artifact(self, artifact_id: str, kind: str | None = None, limit: int = 100) -> list[EvidenceRecord]:
        """Get evidence for an artifact."""
        cursor = self._conn.cursor()
        
        if kind:
            cursor.execute(
                """
                SELECT * FROM evidence 
                WHERE artifact_id = ? AND kind = ?
                ORDER BY evidence_id LIMIT ?
                """,
                (artifact_id, kind, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM evidence 
                WHERE artifact_id = ?
                ORDER BY evidence_id LIMIT ?
                """,
                (artifact_id, limit),
            )
        
        rows = cursor.fetchall()
        return [self._row_to_evidence(row) for row in rows]
    
    @lru_cache(maxsize=128)
    def find_entities_by_canonical_ref(self, ref: str, kind: str | None = None, limit: int = 100) -> list[EntityRecord]:
        """Find entities by canonical reference (cached)."""
        cursor = self._conn.cursor()
        
        if kind:
            cursor.execute(
                """
                SELECT * FROM entities 
                WHERE canonical_ref = ? AND kind = ?
                ORDER BY entity_id LIMIT ?
                """,
                (ref, kind, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM entities 
                WHERE canonical_ref = ?
                ORDER BY entity_id LIMIT ?
                """,
                (ref, limit),
            )
        
        rows = cursor.fetchall()
        return [self._row_to_entity(row) for row in rows]
    
    def list_entities(self, kind: str | None = None, address_space: str | None = None, limit: int = 100) -> list[EntityRecord]:
        """List entities with optional kind and address-space filters."""
        cursor = self._conn.cursor()
        
        sql = "SELECT * FROM entities WHERE 1=1"
        params: list[Any] = []
        
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        
        if address_space:
            # Filter by address_space in the location_json
            sql += " AND location_json LIKE ?"
            params.append(f'%"address_space": "{address_space}"%')
        
        sql += " ORDER BY entity_id LIMIT ?"
        params.append(limit)
        
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [self._row_to_entity(row) for row in rows]
    
    def get_evidence_for_entity(self, entity_id: str, limit: int = 100) -> list[EvidenceRecord]:
        """Get evidence for an entity (evidence that mentions this entity)."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT * FROM evidence 
            WHERE entity_ids_json LIKE ?
            ORDER BY evidence_id LIMIT ?
            """,
            (f'%"{entity_id}"%', limit),
        )
        rows = cursor.fetchall()
        return [self._row_to_evidence(row) for row in rows]
    
    def get_neighbors(self, entity_id: str, limit: int = 100) -> list[EdgeRecord]:
        """Get neighbors for an entity (both incoming and outgoing edges)."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT * FROM edges 
            WHERE source_entity_id = ? OR target_entity_id = ?
            ORDER BY edge_id LIMIT ?
            """,
            (entity_id, entity_id, limit),
        )
        rows = cursor.fetchall()
        return [self._row_to_edge(row) for row in rows]
    
    def get_evidence_for_entities(self, entity_ids: list[str], limit: int = 100) -> list[EvidenceRecord]:
        """Get evidence for multiple entities."""
        if not entity_ids:
            return []
        
        self._conn.cursor()
        evidence_list = []
        
        for entity_id in entity_ids[:limit]:
            evidence_list.extend(self.get_evidence_for_entity(entity_id, limit=limit))
        
        # Deduplicate by evidence_id
        seen = set()
        result = []
        for ev in evidence_list:
            if ev.evidence_id not in seen:
                seen.add(ev.evidence_id)
                result.append(ev)
                if len(result) >= limit:
                    break
        
        return result
    
    def get_neighbors_for_entities(self, entity_ids: list[str], limit: int = 100) -> list[EdgeRecord]:
        """Get neighbors for multiple entities."""
        if not entity_ids:
            return []
        
        cursor = self._conn.cursor()
        placeholders = ",".join("?" * len(entity_ids))
        cursor.execute(
            f"""
            SELECT * FROM edges 
            WHERE source_entity_id IN ({placeholders}) OR target_entity_id IN ({placeholders})
            ORDER BY edge_id LIMIT ?
            """,
            entity_ids + entity_ids + [limit],
        )
        rows = cursor.fetchall()
        return [self._row_to_edge(row) for row in rows]
    
    def traverse_entity_graph(
        self, entity_ids: list[str], depth: int = 2, edge_limit: int = 20
    ) -> dict[str, Any]:
        """Traverse the entity graph using BFS."""
        if not entity_ids:
            return {"entities": [], "edges": [], "depths": {}, "root_entity_ids": []}
        
        visited_entities: set[str] = set()
        visited_edges: set[str] = set()
        depths: dict[str, int] = {}
        
        # Initialize with root entities
        queue: list[tuple[str, int]] = []
        for entity_id in entity_ids:
            queue.append((entity_id, 0))
            visited_entities.add(entity_id)
            depths[entity_id] = 0
        
        result_entities: list[EntityRecord] = []
        result_edges: list[EdgeRecord] = []
        
        while queue and len(visited_edges) < edge_limit:
            current_id, current_depth = queue.pop(0)
            
            # Get the entity
            entity = self.get_entity(current_id)
            if entity:
                result_entities.append(entity)
            
            if current_depth >= depth:
                continue
            
            # Get neighbors
            neighbors = self.get_neighbors(current_id, limit=edge_limit)
            for edge in neighbors:
                if edge.edge_id not in visited_edges and len(visited_edges) < edge_limit:
                    visited_edges.add(edge.edge_id)
                    result_edges.append(edge)
                
                # Add connected entities to queue
                other_id = edge.target_entity_id if edge.source_entity_id == current_id else edge.source_entity_id
                if other_id not in visited_entities:
                    visited_entities.add(other_id)
                    depths[other_id] = current_depth + 1
                    queue.append((other_id, current_depth + 1))
        
        return {
            "entities": result_entities,
            "edges": result_edges,
            "depths": depths,
            "root_entity_ids": entity_ids,
        }
    
    def trace_entity_paths(
        self, entity_ids: list[str], depth: int = 2, edge_limit: int = 20
    ) -> dict[str, Any]:
        """Trace entity paths from root entities using BFS."""
        if not entity_ids:
            return {"entities": [], "edges": [], "paths": [], "root_entity_ids": []}
        
        # Collect all entities and edges in the traversal
        visited_entities: dict[str, EntityRecord] = {}
        visited_edges: dict[str, EdgeRecord] = {}
        
        # BFS from each root
        for root_id in entity_ids:
            if root_id in visited_entities:
                continue
            
            queue: list[tuple[str, int]] = [(root_id, 0)]
            visited_entities[root_id] = self.get_entity(root_id)  # type: ignore
            
            while queue and len(visited_edges) < edge_limit:
                current_id, current_depth = queue.pop(0)
                
                if current_depth >= depth:
                    continue
                
                # Get all edges for this entity (both incoming and outgoing)
                edges = self.get_neighbors(current_id, limit=edge_limit)
                
                for edge in edges:
                    if edge.edge_id in visited_edges:
                        continue
                    if len(visited_edges) >= edge_limit:
                        break
                    
                    visited_edges[edge.edge_id] = edge
                    
                    # Get the connected entity
                    other_id = edge.target_entity_id if edge.source_entity_id == current_id else edge.source_entity_id
                    
                    if other_id not in visited_entities:
                        entity = self.get_entity(other_id)
                        if entity:
                            visited_entities[other_id] = entity
                            queue.append((other_id, current_depth + 1))
        
        # Build paths from roots to all reachable entities
        paths: list[dict[str, Any]] = []
        
        for root_id in entity_ids:
            # BFS to find shortest paths to all reachable entities
            visited: set[str] = {root_id}
            queue: list[tuple[str, list[str], list[str]]] = [(root_id, [], [])]
            
            while queue:
                current_id, edge_ids, entity_ids_path = queue.pop(0)
                
                # Find all edges connected to current entity
                for edge in visited_edges.values():
                    if edge.source_entity_id == current_id:
                        next_id = edge.target_entity_id
                    elif edge.target_entity_id == current_id:
                        next_id = edge.source_entity_id
                    else:
                        continue
                    
                    if next_id in visited:
                        continue
                    
                    visited.add(next_id)
                    new_edge_ids = edge_ids + [edge.edge_id]
                    new_entity_ids = entity_ids_path + [next_id]
                    
                    # Add path to this entity
                    paths.append({
                        "root_entity_id": root_id,
                        "target_entity_id": next_id,
                        "depth": len(new_edge_ids),
                        "edge_ids": new_edge_ids,
                        "entity_ids": [root_id] + new_entity_ids,
                    })
                    
                    # Continue BFS if within depth
                    if len(new_edge_ids) < depth:
                        queue.append((next_id, new_edge_ids, new_entity_ids))
        
        return {
            "entities": list(visited_entities.values()),
            "edges": list(visited_edges.values()),
            "paths": paths,
            "root_entity_ids": entity_ids,
        }
    
    def summarize_ref_provenance(
        self, ref: str, kind: str = "reference", limit_artifacts: int = 100, limit_anchors: int = 25
    ) -> list[dict[str, Any]]:
        """Summarize reference provenance grouped by artifact."""
        entities = self.find_entities_by_canonical_ref(ref, kind=kind, limit=limit_artifacts * 10)
        
        # Group by artifact
        by_artifact: dict[str, list[EntityRecord]] = defaultdict(list)
        for entity in entities:
            by_artifact[entity.artifact_id].append(entity)
        
        summaries = []
        for artifact_id, artifact_entities in list(by_artifact.items())[:limit_artifacts]:
            artifact = self.get_artifact(artifact_id)
            if not artifact:
                continue
            
            # Get evidence for these entities
            evidence_counts: dict[str, int] = defaultdict(int)
            anchor_kinds: dict[str, int] = defaultdict(int)
            
            # Collect all related entities (including document and sections)
            all_related_entity_ids: set[str] = set()
            for entity in artifact_entities[:limit_anchors]:
                all_related_entity_ids.add(entity.entity_id)
                # Add connected entities via edges
                edges = self.get_neighbors(entity.entity_id, limit=limit_anchors)
                for edge in edges:
                    all_related_entity_ids.add(edge.source_entity_id)
                    all_related_entity_ids.add(edge.target_entity_id)
            
            # Count kinds for all related entities
            for entity_id in all_related_entity_ids:
                entity = self.get_entity(entity_id)
                if entity and entity.artifact_id == artifact_id:
                    anchor_kinds[entity.kind] += 1
            
            # Count evidence
            for entity in artifact_entities[:limit_anchors]:
                evidence = self.get_evidence_for_entity(entity.entity_id)
                for ev in evidence:
                    evidence_counts[ev.kind] += 1
            
            summaries.append({
                "artifact": artifact.to_dict(),
                "reference_entity_count": len(artifact_entities),
                "evidence_kind_counts": dict(evidence_counts),
                "anchor_kind_counts": dict(anchor_kinds),
            })
        
        return summaries
    
    def compare_ref_provenance(
        self, ref: str, kind: str = "reference", limit_artifacts: int = 100, limit_anchors: int = 25
    ) -> dict[str, Any]:
        """Compare reference provenance across artifacts."""
        summaries = self.summarize_ref_provenance(ref, kind, limit_artifacts, limit_anchors)
        
        # Collect common and unique evidence kinds and anchor kinds
        all_evidence_kinds: set[str] = set()
        all_anchor_kinds: set[str] = set()
        
        for summary in summaries:
            all_evidence_kinds.update(summary["evidence_kind_counts"].keys())
            all_anchor_kinds.update(summary["anchor_kind_counts"].keys())
        
        # Find common kinds (present in all artifacts)
        common_evidence_kinds = all_evidence_kinds.copy()
        common_anchor_kinds = all_anchor_kinds.copy()
        
        for summary in summaries:
            common_evidence_kinds &= set(summary["evidence_kind_counts"].keys())
            common_anchor_kinds &= set(summary["anchor_kind_counts"].keys())
        
        # Find unique anchor signatures per artifact
        unique_signatures: dict[str, list[str]] = defaultdict(list)
        shared_signatures: list[str] = []
        
        # Build anchor signatures
        artifact_signatures: dict[str, set[str]] = defaultdict(set)
        for summary in summaries:
            artifact_id = summary["artifact"]["artifact_id"]
            for anchor_kind in summary["anchor_kind_counts"].keys():
                signature = f"{anchor_kind}|{artifact_id}"
                artifact_signatures[artifact_id].add(signature)
        
        # Find shared signatures
        if len(artifact_signatures) > 1:
            all_sigs = list(artifact_signatures.values())
            shared = all_sigs[0].copy()
            for sigs in all_sigs[1:]:
                shared &= sigs
            shared_signatures = list(shared)
        
        # Find unique signatures (present in only one artifact)
        list(artifact_signatures.values())
        for artifact_id, sigs in artifact_signatures.items():
            # A signature is unique if it's not in any other artifact
            other_sigs = set()
            for other_id, other in artifact_signatures.items():
                if other_id != artifact_id:
                    other_sigs.update(other)
            unique = sigs - other_sigs
            unique_signatures[artifact_id] = list(unique)
        
        # Find disagreements
        disagreements: dict[str, Any] = {
            "artifacts_with_exclusive_anchor_kind": defaultdict(list),
            "artifacts_missing_anchor_kind": defaultdict(list),
            "per_artifact": {},
        }
        
        for summary in summaries:
            artifact_id = summary["artifact"]["artifact_id"]
            artifact_kinds = set(summary["anchor_kind_counts"].keys())
            
            # Exclusive: kinds in this artifact but not in ALL other artifacts
            # Missing: kinds not in this artifact but present in at least one other
            other_kinds = set()
            for other_summary in summaries:
                if other_summary["artifact"]["artifact_id"] != artifact_id:
                    other_kinds.update(other_summary["anchor_kind_counts"].keys())
            
            exclusive = artifact_kinds - other_kinds  # Only in this artifact
            missing = other_kinds - artifact_kinds    # In others but not here
            
            for kind in exclusive:
                disagreements["artifacts_with_exclusive_anchor_kind"][kind].append(artifact_id)
            for kind in missing:
                disagreements["artifacts_missing_anchor_kind"][kind].append(artifact_id)
            
            disagreements["per_artifact"][artifact_id] = {
                "exclusive_anchor_kinds": list(exclusive),
                "missing_anchor_kinds": list(missing),
            }
        
        return {
            "artifact_count": len(summaries),
            "comparison": {
                "common_evidence_kinds": sorted(common_evidence_kinds),
                "common_anchor_kinds": sorted(common_anchor_kinds),
                "all_anchor_kinds": sorted(all_anchor_kinds),
                "unique_anchor_signatures": dict(unique_signatures),
                "shared_anchor_signatures": shared_signatures,
                "disagreements": disagreements,
            },
            "artifacts": summaries,
        }
    
    def list_shared_canonical_refs(
        self,
        kind: str = "reference",
        min_artifacts: int = 2,
        limit: int = 10,
        address_space: str | None = None,
        limit_artifacts: int = 25,
        limit_anchors: int = 10,
    ) -> list[dict[str, Any]]:
        """List shared canonical references across multiple artifacts."""
        cursor = self._conn.cursor()
        
        # Build query to find refs appearing in multiple artifacts
        sql = """
            SELECT canonical_ref, COUNT(DISTINCT artifact_id) as artifact_count
            FROM entities
            WHERE kind = ? AND canonical_ref != ''
        """
        params = [kind]
        
        if address_space:
            sql += " AND location_json LIKE ?"
            params.append(f'%"address_space": "{address_space}"%')
        
        sql += """
            GROUP BY canonical_ref
            HAVING artifact_count >= ?
            ORDER BY artifact_count DESC
            LIMIT ?
        """
        params.extend([min_artifacts, limit])
        
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            ref = row["canonical_ref"]
            artifact_count = row["artifact_count"]
            
            # Get entities for this ref
            entities = self.find_entities_by_canonical_ref(ref, kind=kind, limit=limit_artifacts)
            
            # Get unique artifact IDs
            artifact_ids = list(set(e.artifact_id for e in entities))[:limit_artifacts]
            artifact_id_set = set(artifact_ids)
            anchor_entities = entities[:limit_anchors]
            anchor_entity_ids = [entity.entity_id for entity in anchor_entities]
            anchor_entity_id_set = set(anchor_entity_ids)
            
            # Batch-load neighbors for all anchors to avoid per-anchor query loops.
            anchor_edges: dict[str, list[EdgeRecord]] = {entity_id: [] for entity_id in anchor_entity_ids}
            if anchor_entity_ids:
                placeholders = ",".join(["?"] * len(anchor_entity_ids))
                cursor.execute(
                    f"""
                    SELECT * FROM edges
                    WHERE source_entity_id IN ({placeholders}) OR target_entity_id IN ({placeholders})
                    ORDER BY edge_id
                    """,
                    tuple(anchor_entity_ids) + tuple(anchor_entity_ids),
                )
                edge_rows = cursor.fetchall()
                for edge_row in edge_rows:
                    edge = self._row_to_edge(edge_row)
                    if edge.source_entity_id in anchor_entity_id_set:
                        anchor_edges[edge.source_entity_id].append(edge)
                    if edge.target_entity_id in anchor_entity_id_set and edge.target_entity_id != edge.source_entity_id:
                        anchor_edges[edge.target_entity_id].append(edge)

            # Batch-load related entities referenced by those neighbor edges.
            related_entity_ids: set[str] = set()
            for anchor_id in anchor_entity_ids:
                for edge in anchor_edges.get(anchor_id, [])[:limit_anchors]:
                    if edge.source_entity_id == anchor_id:
                        related_entity_ids.add(edge.target_entity_id)
                    else:
                        related_entity_ids.add(edge.source_entity_id)

            entity_by_id = {entity.entity_id: entity for entity in anchor_entities}
            if related_entity_ids:
                placeholders = ",".join(["?"] * len(related_entity_ids))
                cursor.execute(
                    f"SELECT * FROM entities WHERE entity_id IN ({placeholders})",
                    tuple(related_entity_ids),
                )
                for entity_row in cursor.fetchall():
                    loaded_entity = self._row_to_entity(entity_row)
                    entity_by_id[loaded_entity.entity_id] = loaded_entity

            # Get unique anchor kinds across all related entities (including connected ones).
            all_related_kinds: set[str] = set()
            all_anchor_entities: set[str] = set()
            section_count = 0
            for entity in anchor_entities:
                all_related_kinds.add(entity.kind)
                all_anchor_entities.add(entity.entity_id)
                # Add connected entity kinds with preloaded edge/entity data.
                for edge in anchor_edges.get(entity.entity_id, [])[:limit_anchors]:
                    if edge.source_entity_id == entity.entity_id:
                        other_id = edge.target_entity_id
                    else:
                        other_id = edge.source_entity_id
                    other = entity_by_id.get(other_id)
                    if other and other.artifact_id in artifact_id_set:
                        all_related_kinds.add(other.kind)
                        all_anchor_entities.add(other.entity_id)
                        if other.kind == "section":
                            section_count += 1

            anchor_kinds = list(all_related_kinds)[:limit_anchors]

            # Calculate ranking score with higher weight for anchor diversity and section contexts
            ranking_score = artifact_count * 10 + len(anchor_kinds) * 5 + section_count * 2
            
            results.append({
                "canonical_ref": ref,
                "artifact_count": artifact_count,
                "artifacts": artifact_ids,
                "anchor_kinds": anchor_kinds,
                "ranking_score": ranking_score,
                "ranking_breakdown": {
                    "artifact_count": artifact_count,
                    "shared_anchor_kind_count": len(all_anchor_entities),
                },
            })
        
        # Sort by ranking score descending
        results.sort(key=lambda x: x["ranking_score"], reverse=True)
        
        return results
    
    def get_evidence_in_range(
        self, address_space: str, start: int, end: int, artifact_id: str | None = None
    ) -> list[EvidenceRecord]:
        """Get evidence whose location overlaps with the given address range."""
        cursor = self._conn.cursor()
        
        # Get all evidence and filter by location
        if artifact_id:
            cursor.execute(
                "SELECT * FROM evidence WHERE artifact_id = ?",
                (artifact_id,),
            )
        else:
            cursor.execute("SELECT * FROM evidence")
        
        rows = cursor.fetchall()
        result = []
        
        for row in rows:
            location = self._json_to_location(row["location_json"])
            if location is None:
                continue
            if location.address_space != address_space:
                continue
            # Check for overlap: not (end < loc.start or loc.end < start)
            if not (end < location.start or location.end < start):
                result.append(self._row_to_evidence(row))
        
        return result
    
    def get_entities_in_range(
        self, address_space: str, start: int, end: int, kind: str | None = None
    ) -> list[EntityRecord]:
        """Get entities whose location overlaps with the given address range."""
        cursor = self._conn.cursor()
        
        # Get all entities with locations and filter
        if kind:
            cursor.execute(
                "SELECT * FROM entities WHERE kind = ? AND location_json IS NOT NULL",
                (kind,),
            )
        else:
            cursor.execute("SELECT * FROM entities WHERE location_json IS NOT NULL")
        
        rows = cursor.fetchall()
        result = []
        
        for row in rows:
            location = self._json_to_location(row["location_json"])
            if location is None:
                continue
            if location.address_space != address_space:
                continue
            # Check for overlap: not (end < loc.start or loc.end < start)
            if not (end < location.start or location.end < start):
                result.append(self._row_to_entity(row))
        
        return result
    
    def get_edges_for_artifact(self, artifact_id: str, limit: int = 10000) -> list[EdgeRecord]:
        """Get edges for entities belonging to a specific artifact."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT e.* FROM edges e
            WHERE e.source_entity_id IN (
                SELECT entity_id FROM entities WHERE artifact_id = ?
            )
            OR e.target_entity_id IN (
                SELECT entity_id FROM entities WHERE artifact_id = ?
            )
            ORDER BY e.edge_id
            LIMIT ?
            """,
            (artifact_id, artifact_id, limit),
        )
        rows = cursor.fetchall()
        return [self._row_to_edge(row) for row in rows]
    
    def generate_cfg(
        self,
        function_address: int,
        format: str = "json",
        depth: int = 1,
        address_space: str = "",
    ) -> dict[str, Any]:
        """Generate a Control Flow Graph for a function.
        
        Args:
            function_address: The address of the function to analyze
            format: Output format - "json", "dot", or "graphml"
            depth: Traversal depth (1 = single function, 2 = with callees)
            address_space: Optional address space filter
            
        Returns:
            Dictionary containing the CFG in the requested format
        """
        # Find the function entity by address
        cursor = self._conn.cursor()
        
        if address_space:
            cursor.execute(
                """
                SELECT * FROM entities 
                WHERE kind = 'function' 
                AND location_json LIKE ?
                AND location_json LIKE ?
                LIMIT 1
                """,
                (f'"address_space": "{address_space}"%', f'"start": {function_address}%'),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM entities 
                WHERE kind = 'function' 
                AND location_json LIKE ?
                LIMIT 1
                """,
                (f'"start": {function_address}%',),
            )
        
        row = cursor.fetchone()
        if row is None:
            return {
                "error": f"Function not found at address 0x{function_address:04X}",
                "function_address": function_address,
            }
        
        entity = self._row_to_entity(row)
        
        # Build the CFG
        cfg = ControlFlowGraph.from_entity(entity, store=self)
        
        # Get evidence (disassembly) for this function
        if entity.location:
            evidence = self.get_evidence_in_range(
                address_space=entity.location.address_space,
                start=entity.location.start,
                end=entity.location.end,
            )
            
            # Build basic blocks from evidence
            for ev in evidence:
                if ev.location and ev.location.start not in cfg.blocks:
                    block = BasicBlock(start_addr=ev.location.start)
                    block.attributes["evidence_id"] = ev.evidence_id
                    cfg.add_block(block)
        
        # Get related edges for control flow
        neighbors = self.get_neighbors(entity.entity_id, limit=100)
        for edge in neighbors:
            if edge.kind in ("calls", "jumps_to", "falls_through", "branches_to"):
                target_entity = self.get_entity(edge.target_entity_id)
                if target_entity and target_entity.location:
                    target_addr = target_entity.location.start
                    if target_addr not in cfg.blocks:
                        cfg.add_block(BasicBlock(start_addr=target_addr))
                    # Add edge from function entry to target
                    cfg.add_edge(
                        cfg.entry_addr, 
                        target_addr, 
                        edge_type=edge.kind,
                    )
        
        # Apply depth-limited traversal
        if depth > 1:
            cfg = cfg.traverse(depth=depth)
        
        # Generate output in requested format
        result: dict[str, Any] = {
            "function_address": function_address,
            "function_name": entity.name,
            "entity_id": entity.entity_id,
            "depth": depth,
            "format": format,
            "statistics": cfg.get_statistics(),
        }
        
        if format == "json":
            result["cfg"] = cfg.to_dict()
            result["output"] = cfg.to_json()
        elif format == "dot":
            result["output"] = cfg.to_dot()
        elif format == "graphml":
            result["output"] = cfg.to_graphml()
        else:
            result["error"] = f"Unknown format: {format}"
        
        return result
    
    def analyze_entropy(
        self,
        address_space: str,
        data: bytes,
        window_size: int = 256,
        base_address: int = 0,
    ) -> dict[str, Any]:
        """Analyze entropy of an address space.

        Args:
            address_space: Name of the address space being analyzed.
            data: Byte data to analyze.
            window_size: Size of the sliding window in bytes.
            base_address: Base address for display purposes.

        Returns:
            Dictionary with entropy analysis results.
        """
        analyzer = EntropyAnalyzer(window_size=window_size)
        analysis = analyzer.analyze_address_space(data, base_address=base_address)
        stats = analyzer.get_statistics(data)

        return {
            "address_space": address_space,
            "base_address": f"0x{base_address:08X}",
            "data_size": len(data),
            "window_size": window_size,
            "statistics": stats,
            "windows": analysis["windows"],
            "packed_regions": analysis["packed_regions"],
            "packed_region_count": len(analysis["packed_regions"]),
        }
    
    def detect_packed_regions(
        self,
        address_space: str,
        data: bytes,
        threshold: float = 7.2,
        min_region_size: int = 512,
        window_size: int = 256,
        base_address: int = 0,
    ) -> dict[str, Any]:
        """Detect packed/encrypted regions in an address space.

        Args:
            address_space: Name of the address space being analyzed.
            data: Byte data to analyze.
            threshold: Entropy threshold for high-entropy detection.
            min_region_size: Minimum size for a region to be reported.
            window_size: Size of the sliding window in bytes.
            base_address: Base address for display purposes.

        Returns:
            Dictionary with detected packed regions.
        """
        analyzer = EntropyAnalyzer(window_size=window_size)
        regions = analyzer.detect_packed_regions(
            data, threshold=threshold, min_region_size=min_region_size
        )
        stats = analyzer.get_statistics(data)

        region_list: list[dict[str, Any]] = []
        for region in regions:
            region_list.append({
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
            "address_space": address_space,
            "base_address": f"0x{base_address:08X}",
            "data_size": len(data),
            "threshold": threshold,
            "min_region_size": min_region_size,
            "statistics": stats,
            "regions": region_list,
            "region_count": len(region_list),
        }
    
    def build_similarity_index(
        self,
        algorithm: str = "fuzzy_hash",
        threshold: float = 0.7,
    ) -> SimilarityIndex:
        """Build a similarity index for all function entities.

        Args:
            algorithm: Algorithm to use - "fuzzy_hash", "ngram", "cfg", or "combined"
            threshold: Default similarity threshold (0.0-1.0)

        Returns:
            A SimilarityIndex populated with function fingerprints
        """
        # Import here to avoid circular imports
        from codemunch_pro.rex.similarity import (
            SimilarityAlgorithm,
            SimilarityIndex,
            create_fingerprint_from_entity,
        )

        # Map string to enum
        algo_map = {
            "fuzzy_hash": SimilarityAlgorithm.FUZZY_HASH,
            "ngram": SimilarityAlgorithm.NGRAM,
            "cfg": SimilarityAlgorithm.CFG,
            "combined": SimilarityAlgorithm.FUZZY_HASH,  # Combined uses all
        }
        algo = algo_map.get(algorithm, SimilarityAlgorithm.FUZZY_HASH)

        index = SimilarityIndex(algorithm=algo, threshold=threshold)

        # Get all function entities
        functions = self.list_entities(kind="function", limit=10000)

        for entity in functions:
            # Try to get instruction sequence from evidence
            instruction_sequence = None
            block_count = 0

            # Get evidence for this function to extract instructions
            if entity.location:
                evidence = self.get_evidence_for_entity(entity.entity_id, limit=100)
                if evidence:
                    instructions = []
                    for ev in evidence:
                        # Extract instruction mnemonics from evidence excerpt
                        # Format is typically: "ADDR: MNEMONIC operands"
                        excerpt = ev.excerpt.strip()
                        if ":" in excerpt:
                            parts = excerpt.split(":", 1)
                            if len(parts) == 2:
                                mnemonic = parts[1].strip().split()[0] if parts[1].strip() else ""
                                if mnemonic:
                                    instructions.append(mnemonic.upper())
                    if instructions:
                        instruction_sequence = instructions

            # Get block count from attributes or estimate
            block_count = entity.attributes.get("block_count", 0) or 0

            # Create fingerprint
            fingerprint = create_fingerprint_from_entity(
                entity=entity,
                instruction_sequence=instruction_sequence,
                block_count=block_count,
            )
            index.add_fingerprint(fingerprint)

        return index
    
    def find_similar_functions(
        self,
        function_address: int,
        threshold: float = 0.7,
        top_k: int = 10,
        algorithm: str = "fuzzy_hash",
    ) -> dict[str, Any]:
        """Find functions similar to the function at the given address.

        Uses fuzzy hashing and other similarity algorithms to detect
        code clones and similar functions.

        Args:
            function_address: The address of the function to compare against
            threshold: Minimum similarity score (0.0-1.0)
            top_k: Maximum number of similar functions to return
            algorithm: Algorithm to use - "fuzzy_hash", "ngram", "cfg", or "combined"

        Returns:
            Dictionary with similarity search results
        """
        from codemunch_pro.rex.similarity import (
            create_fingerprint_from_entity,
        )

        # Build the similarity index
        index = self.build_similarity_index(algorithm=algorithm, threshold=threshold)

        # Find the source function entity by address
        functions = self.list_entities(kind="function", limit=10000)
        source_entity = None
        for entity in functions:
            if entity.location and entity.location.start == function_address:
                source_entity = entity
                break

        if source_entity is None:
            return {
                "error": f"Function not found at address 0x{function_address:04X}",
                "function_address": function_address,
                "similar_functions": [],
            }

        # Build similarity index
        index = self.build_similarity_index(algorithm=algorithm, threshold=threshold)

        # Get the fingerprint for the source function
        source_fp = index.get_fingerprint(source_entity.entity_id)
        if source_fp is None:
            # Create fingerprint if not in index
            source_fp = create_fingerprint_from_entity(source_entity)

        # Find similar functions
        similar_results = index.find_similar(
            query_fp=source_fp,
            top_k=top_k,
            threshold=threshold,
        )

        return {
            "function_address": function_address,
            "function_name": source_entity.name,
            "entity_id": source_entity.entity_id,
            "algorithm": algorithm,
            "threshold": threshold,
            "index_size": len(index),
            "similar_functions": [r.to_dict() for r in similar_results],
            "count": len(similar_results),
        }
    
    def search_byte_pattern(
        self,
        pattern: str | BytePattern,
        address_space: str | None = None,
        mask: int | None = None,
        data: bytes | None = None,
        context_bytes: int = 16,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """Search for a byte pattern in binary data.

        Searches binary data for a pattern with support for wildcards (?),
        bit masks, and character classes. Can search either provided data
        or data associated with entities in the specified address space.

        Args:
            pattern: Pattern string (e.g., "A9 ?? 8D 00 21") or BytePattern
            address_space: Optional address space to search (searches all if None)
            mask: Optional bit mask to apply to matched bytes
            data: Optional binary data to search (if None, searches stored entities)
            context_bytes: Number of context bytes to include before/after match
            max_results: Maximum number of results to return

        Returns:
            List of match dictionaries with offset, matched_bytes, and context

        Example:
            # Search for LDA #$xx followed by STA $2100
            matches = store.search_byte_pattern("A9 ?? 8D 00 21")

            # Search with bit mask (match any byte with high nibble 0x8)
            matches = store.search_byte_pattern("8? ??", mask=0xF0)
        """
        # Parse pattern if string
        if isinstance(pattern, str):
            byte_pattern = BytePattern.parse(pattern)
        else:
            byte_pattern = pattern

        results: list[dict[str, Any]] = []

        # If no data provided, we need to collect it from entities
        if data is None:
            # Get entities with location data
            cursor = self._conn.cursor()
            if address_space:
                cursor.execute(
                    """
                    SELECT * FROM entities 
                    WHERE location_json LIKE ?
                    LIMIT ?
                    """,
                    (f'"address_space": "{address_space}"%', max_results * 10),
                )
            else:
                cursor.execute(
                    "SELECT * FROM entities WHERE location_json IS NOT NULL LIMIT ?",
                    (max_results * 10,),
                )

            rows = cursor.fetchall()

            for row in rows:
                location = self._json_to_location(row["location_json"])
                if location is None:
                    continue

                # Check address space filter
                if address_space and location.address_space != address_space:
                    continue

                # Get evidence for this entity to extract bytes
                evidence_list = self.get_evidence_for_entity(row["entity_id"], limit=10)

                for ev in evidence_list:
                    if not ev.excerpt:
                        continue

                    # Try to extract hex bytes from evidence excerpt
                    # This is a simplified approach - real implementation might
                    # store actual binary data
                    try:
                        # Look for hex bytes in the excerpt
                        hex_matches = re.findall(r'[0-9A-Fa-f]{2}', ev.excerpt)
                        if len(hex_matches) >= len(byte_pattern):
                            evidence_bytes = bytes(int(h, 16) for h in hex_matches)

                            # Search in this evidence
                            matcher = PatternMatcher(context_size=context_bytes)
                            matches = matcher.search(evidence_bytes, byte_pattern)

                            for match in matches:
                                if len(results) >= max_results:
                                    return results

                                result = {
                                    "entity_id": row["entity_id"],
                                    "entity_name": row["name"],
                                    "entity_kind": row["kind"],
                                    "address_space": location.address_space,
                                    "address": location.start + match.offset,
                                    "offset_in_evidence": match.offset,
                                    "pattern": byte_pattern.raw_pattern,
                                    "matched_bytes": match.matched_bytes.hex(),
                                    "context_before": match.context_before.hex() if match.context_before else "",
                                    "context_after": match.context_after.hex() if match.context_after else "",
                                    "evidence_id": ev.evidence_id,
                                }

                                # Apply mask if provided
                                if mask is not None:
                                    masked_bytes = bytes(b & mask for b in match.matched_bytes)
                                    result["masked_bytes"] = masked_bytes.hex()

                                results.append(result)
                    except (ValueError, re.error):
                        continue

            return results

        # Search provided data directly
        matcher = PatternMatcher(context_size=context_bytes)
        matches = matcher.search(data, byte_pattern)

        for match in matches[:max_results]:
            result = {
                "offset": match.offset,
                "pattern": byte_pattern.raw_pattern,
                "matched_bytes": match.matched_bytes.hex(),
                "context_before": match.context_before.hex() if match.context_before else "",
                "context_after": match.context_after.hex() if match.context_after else "",
            }

            # Apply mask if provided
            if mask is not None:
                masked_bytes = bytes(b & mask for b in match.matched_bytes)
                result["masked_bytes"] = masked_bytes.hex()

            results.append(result)

        return results
    
    def extract_strings(
        self,
        data: bytes,
        base_address: int = 0,
        min_length: int = 4,
        encoding: str | None = None,
        find_xrefs: bool = True,
        pointer_size: int = 4,
        address_space: str = "flat",
    ) -> dict[str, Any]:
        """Extract strings from binary data with optional XREF tracking.

        Args:
            data: Binary data to analyze
            base_address: Base address for the data
            min_length: Minimum string length to extract
            encoding: Encoding filter (e.g., "ascii", "utf-8", "shift_jis", 
                     "utf-16-le", "utf-16-be"). If None, tries all encodings.
            find_xrefs: Whether to find cross-references to strings
            pointer_size: Pointer size in bytes (4 for 32-bit, 8 for 64-bit)
            address_space: Name of the address space

        Returns:
            Dictionary with extracted strings and cross-references
        """
        from codemunch_pro.rex.string_extraction import (
            StringEncoding,
            StringExtractor,
        )

        # Map encoding string to enum
        encodings: list[StringEncoding] | None = None
        if encoding:
            try:
                encodings = [StringEncoding(encoding.lower())]
            except ValueError:
                # Try alternative names
                encoding_map = {
                    "shift-jis": StringEncoding.SHIFT_JIS,
                    "shiftjis": StringEncoding.SHIFT_JIS,
                    "sjis": StringEncoding.SHIFT_JIS,
                    "utf16le": StringEncoding.UTF16_LE,
                    "utf16": StringEncoding.UTF16_LE,
                    "utf16be": StringEncoding.UTF16_BE,
                }
                if encoding.lower() in encoding_map:
                    encodings = [encoding_map[encoding.lower()]]
                else:
                    return {"error": f"Unknown encoding: {encoding}"}

        extractor = StringExtractor(min_length=min_length, encodings=encodings)
        strings = extractor.extract_strings(data, base_address)

        result: dict[str, Any] = {
            "string_count": len(strings),
            "min_length": min_length,
            "base_address": f"0x{base_address:08X}",
            "address_space": address_space,
            "strings": [
                {
                    "address": s.address,
                    "text": s.text,
                    "encoding": s.encoding.value,
                    "type": s.string_type.name.lower(),
                    "length": s.length,
                }
                for s in strings
            ],
        }

        if find_xrefs:
            xrefs = extractor.find_xrefs(data, strings, base_address, pointer_size)
            result["xref_count"] = len(xrefs)
            result["xrefs"] = [x.to_dict() for x in xrefs]

        return result
    
    def get_string_xrefs(
        self,
        string_address: int,
        kind: str = "references_string",
    ) -> list[dict[str, Any]]:
        """Get cross-references to a string at the given address.

        Args:
            string_address: Address of the string
            kind: Edge kind to filter (default: "references_string")

        Returns:
            List of cross-reference edges
        """
        cursor = self._conn.cursor()

        # Find string entities with matching address in canonical_ref or location
        cursor.execute(
            """
            SELECT entity_id FROM entities
            WHERE kind = 'string'
            AND (canonical_ref = ? OR location_json LIKE ?)
            """,
            (
                f"0x{string_address:08X}",
                f'"start": {string_address}%',
            ),
        )

        string_entities = [row["entity_id"] for row in cursor.fetchall()]

        if not string_entities:
            return []

        # Find edges that reference these string entities
        xrefs: list[dict[str, Any]] = []
        for string_entity_id in string_entities:
            cursor.execute(
                """
                SELECT * FROM edges
                WHERE target_entity_id = ?
                AND kind = ?
                """,
                (string_entity_id, kind),
            )

            for row in cursor.fetchall():
                edge = self._row_to_edge(row)
                source_entity = self.get_entity(edge.source_entity_id)
                target_entity = self.get_entity(edge.target_entity_id)

                xref = {
                    "edge_id": edge.edge_id,
                    "edge_kind": edge.kind,
                    "source_entity_id": edge.source_entity_id,
                    "target_entity_id": edge.target_entity_id,
                    "xref_type": edge.attributes.get("xref_type", "unknown"),
                    "code_address": edge.attributes.get("code_address"),
                    "string_address": edge.attributes.get("string_address"),
                }

                if source_entity:
                    xref["source_name"] = source_entity.name
                    if source_entity.location:
                        xref["code_address"] = source_entity.location.start

                if target_entity:
                    xref["string_text"] = target_entity.attributes.get("full_text", "")
                    if target_entity.location:
                        xref["string_address"] = target_entity.location.start

                xrefs.append(xref)

        return xrefs
    
    def export_to_format(
        self,
        format_type: str,
        output_path: Path | str,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Export reverse-engineering data to various formats.

        Args:
            format_type: Export format - "ida", "ghidra", "binary_ninja", "json", "csv"
            output_path: Path for the output file(s)
            options: Optional export options including:
                - include_functions: bool = True
                - include_data_labels: bool = True
                - include_comments: bool = True
                - include_structures: bool = True
                - include_xrefs: bool = True
                - min_confidence: float | None = None
                - address_space_filter: str | None = None
                - artifact_filter: str | None = None

        Returns:
            Dictionary with export results including path and counts

        Example:
            store.export_to_format("ida", "/path/to/output.py")
            store.export_to_format("json", "/path/to/export.json", {"include_xrefs": False})
        """
        output_path = Path(output_path)

        # Build export options
        export_opts = ExportOptions()
        if options:
            if "include_functions" in options:
                export_opts.include_functions = options["include_functions"]
            if "include_data_labels" in options:
                export_opts.include_data_labels = options["include_data_labels"]
            if "include_comments" in options:
                export_opts.include_comments = options["include_comments"]
            if "include_structures" in options:
                export_opts.include_structures = options["include_structures"]
            if "include_xrefs" in options:
                export_opts.include_xrefs = options["include_xrefs"]
            if "min_confidence" in options:
                export_opts.min_confidence = options["min_confidence"]
            if "address_space_filter" in options:
                export_opts.address_space_filter = options["address_space_filter"]
            if "artifact_filter" in options:
                export_opts.artifact_filter = options["artifact_filter"]

        # Get exporter and run export
        exporter = get_exporter(format_type, self, export_opts)
        result = exporter.export(output_path)

        return {
            "success": True,
            "format": format_type,
            **result,
        }
    def store_execution_trace(
        self,
        capture_id: str,
        entries: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Store an execution trace capture in the database.

        Creates a trace artifact with entities and evidence for each
        trace entry, enabling correlation with static analysis data.

        Args:
            capture_id: Unique identifier for this trace capture
            entries: List of trace entry dictionaries
            metadata: Optional metadata about the capture

        Returns:
            Dictionary with stored entity and evidence counts
        """
        cursor = self._conn.cursor()

        # Create trace artifact
        artifact_id = f"trace_capture:{capture_id}"
        artifact = ArtifactRecord(
            artifact_id=artifact_id,
            kind="execution_trace",
            path=f"trace://{capture_id}",
            title=f"Execution Trace: {capture_id}",
            metadata=metadata or {},
        )

        # Store artifact
        cursor.execute(
            """
            INSERT OR REPLACE INTO artifacts 
            (artifact_id, kind, path, sha256, title, media_type, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.artifact_id,
                artifact.kind,
                artifact.path,
                "",
                artifact.title,
                "application/json",
                json.dumps(artifact.metadata),
            ),
        )

        entities: list[EntityRecord] = []
        evidence_records: list[EvidenceRecord] = []
        edges: list[EdgeRecord] = []

        # Process trace entries
        for i, entry in enumerate(entries):
            address = entry.get("address", 0)
            disassembly = entry.get("disassembly", "")
            instruction_bytes = entry.get("instruction_bytes", "")

            # Create entity for each unique address
            entity_id = f"trace:{capture_id}:addr:{address:08X}:{i}"
            addr_hex = f"0x{address:08X}"

            location = AddressLocation(
                address_space="execution",
                start=address,
                end=address + len(bytes.fromhex(instruction_bytes)) if instruction_bytes else address,
            )

            entity = EntityRecord(
                entity_id=entity_id,
                kind="trace_entry",
                name=f"Trace@{addr_hex}",
                artifact_id=artifact_id,
                canonical_ref=addr_hex,
                location=location,
                attributes={
                    "disassembly": disassembly,
                    "instruction_bytes": instruction_bytes,
                    "entry_index": i,
                    "timestamp": entry.get("timestamp", 0),
                },
            )
            entities.append(entity)

            # Create evidence for the trace entry
            evidence_id = f"trace:{capture_id}:entry:{i}"
            evidence = EvidenceRecord(
                evidence_id=evidence_id,
                kind="execution_trace",
                artifact_id=artifact_id,
                entity_ids=(entity_id,),
                location=location,
                excerpt=disassembly,
                attributes=entry,
            )
            evidence_records.append(evidence)

        # Insert entities
        for entity in entities:
            cursor.execute(
                """
                INSERT OR REPLACE INTO entities
                (entity_id, kind, name, artifact_id, canonical_ref, summary, aliases_json, location_json, attributes_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entity.entity_id,
                    entity.kind,
                    entity.name,
                    entity.artifact_id,
                    entity.canonical_ref,
                    entity.summary,
                    json.dumps(list(entity.aliases)),
                    self._location_to_json(entity.location),
                    json.dumps(entity.attributes),
                ),
            )

        # Insert evidence
        for ev in evidence_records:
            cursor.execute(
                """
                INSERT OR REPLACE INTO evidence
                (evidence_id, kind, artifact_id, entity_ids_json, location_json, excerpt, confidence, attributes_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev.evidence_id,
                    ev.kind,
                    ev.artifact_id,
                    json.dumps(list(ev.entity_ids)),
                    self._location_to_json(ev.location),
                    ev.excerpt,
                    ev.confidence,
                    json.dumps(ev.attributes),
                ),
            )

        self._conn.commit()

        return {
            "artifact_id": artifact_id,
            "capture_id": capture_id,
            "entity_count": len(entities),
            "evidence_count": len(evidence_records),
            "edge_count": len(edges),
        }

    def get_execution_trace(self, capture_id: str) -> dict[str, Any] | None:
        """Retrieve a stored execution trace.

        Args:
            capture_id: The trace capture ID

        Returns:
            Dictionary with trace data or None if not found
        """
        artifact_id = f"trace_capture:{capture_id}"
        artifact = self.get_artifact(artifact_id)

        if artifact is None:
            return None

        entities = self.get_entities_for_artifact(artifact_id, limit=10000)
        evidence = self.get_evidence_for_artifact(artifact_id, limit=10000)

        # Sort entries by index in attributes
        sorted_evidence = sorted(
            evidence,
            key=lambda e: e.attributes.get("entry_index", 0),
        )

        return {
            "capture_id": capture_id,
            "artifact": artifact.to_dict(),
            "entries": [ev.to_dict() for ev in sorted_evidence],
            "entry_count": len(sorted_evidence),
            "entity_count": len(entities),
        }

    def list_execution_traces(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all stored execution traces.

        Args:
            limit: Maximum number of traces to return

        Returns:
            List of trace metadata dictionaries
        """
        artifacts = self.list_artifacts(kind="execution_trace", limit=limit)
        return [
            {
                "capture_id": a.artifact_id.replace("trace_capture:", ""),
                "artifact_id": a.artifact_id,
                "title": a.title,
                "metadata": a.metadata,
                "indexed_at": a.metadata.get("indexed_at", ""),
            }
            for a in artifacts
        ]

    def correlate_trace_with_static(
        self,
        capture_id: str,
        address_space: str = "",
        tolerance: int = 0,
    ) -> dict[str, Any]:
        """Correlate a dynamic execution trace with static analysis data.

        Finds static analysis entities that correspond to addresses
        visited during dynamic execution.

        Args:
            capture_id: The trace capture to correlate
            address_space: Optional address space filter
            tolerance: Address matching tolerance in bytes

        Returns:
            Dictionary with correlation results
        """
        trace = self.get_execution_trace(capture_id)
        if trace is None:
            return {"error": f"Trace not found: {capture_id}"}

        entries = trace.get("entries", [])
        correlations: list[dict[str, Any]] = []

        for entry in entries:
            entry_attrs = entry.get("attributes", {})
            address = entry_attrs.get("address", 0)

            # Find static entities at or near this address
            range_start = address - tolerance
            range_end = address + tolerance

            if address_space:
                entities = self.get_entities_in_range(
                    address_space=address_space,
                    start=range_start,
                    end=range_end,
                )
            else:
                # Search all address spaces
                cursor = self._conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM entities 
                    WHERE location_json IS NOT NULL
                    AND kind != 'trace_entry'
                    """
                )
                all_entities = [self._row_to_entity(row) for row in cursor.fetchall()]
                entities = [
                    e for e in all_entities
                    if e.location and range_start <= e.location.start <= range_end
                ]

            if entities:
                correlations.append({
                    "trace_address": address,
                    "trace_disassembly": entry_attrs.get("disassembly", ""),
                    "correlated_entities": [
                        {
                            "entity_id": e.entity_id,
                            "name": e.name,
                            "kind": e.kind,
                            "canonical_ref": e.canonical_ref,
                            "address": e.location.start if e.location else None,
                        }
                        for e in entities[:5]  # Limit to top 5
                    ],
                })

        return {
            "capture_id": capture_id,
            "address_space": address_space,
            "tolerance": tolerance,
            "trace_entry_count": len(entries),
            "correlated_entry_count": len(correlations),
            "correlations": correlations,
        }

    def delete_execution_trace(self, capture_id: str) -> bool:
        """Delete a stored execution trace and all associated data.

        Args:
            capture_id: The trace capture ID to delete

        Returns:
            True if the trace existed and was deleted
        """
        artifact_id = f"trace_capture:{capture_id}"
        
        # Check if the artifact exists first (using direct query to avoid cache)
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT 1 FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        if cursor.fetchone() is None:
            return False
        
        # Delete edges for entities of this artifact
        cursor.execute(
            """
            DELETE FROM edges WHERE source_entity_id IN 
            (SELECT entity_id FROM entities WHERE artifact_id = ?)
            OR target_entity_id IN 
            (SELECT entity_id FROM entities WHERE artifact_id = ?)
            """,
            (artifact_id, artifact_id),
        )

        # Delete evidence for this artifact
        cursor.execute(
            "DELETE FROM evidence WHERE artifact_id = ?",
            (artifact_id,),
        )

        # Delete entities for this artifact
        cursor.execute(
            "DELETE FROM entities WHERE artifact_id = ?",
            (artifact_id,),
        )

        # Delete the artifact
        cursor.execute(
            "DELETE FROM artifacts WHERE artifact_id = ?",
            (artifact_id,),
        )

        self._conn.commit()
        
        # Clear caches since we deleted data
        self.clear_caches()
        
        return True


    def infer_structures(
        self,
        address: int,
        data: bytes | None = None,
        max_size: int = 256,
        heuristic: str = "balanced",
        pointer_size: int = 4,
        address_space: str = "flat",
    ) -> dict[str, Any]:
        """Infer data structure layout from access patterns.

        Uses heuristics to detect pointers, arrays, strings, and nested
        structures based on memory access patterns and value analysis.

        Args:
            address: Starting address of the structure to analyze
            data: Optional binary data to analyze. If None, attempts to
                  reconstruct data from stored evidence
            max_size: Maximum size to analyze in bytes (default 256)
            heuristic: Heuristic strategy - "conservative", "balanced",
                      or "aggressive" (default: "balanced")
            pointer_size: Size of pointers in bytes - 4 for 32-bit,
                         8 for 64-bit (default: 4)
            address_space: Address space identifier (default: "flat")

        Returns:
            Dictionary with inferred structure information including:
            - name: Structure identifier
            - address: Starting address
            - size: Detected structure size
            - fields: List of inferred fields with types, offsets, confidence
            - confidence: Overall confidence score
            - alignment: Detected alignment requirement
        """
        from codemunch_pro.rex.structure_recovery import (
            StructureRecovery,
            HeuristicStrategy,
        )

        # Initialize structure recovery
        recovery = StructureRecovery(store=self)

        # Set strategy
        try:
            strategy = HeuristicStrategy(heuristic.lower())
        except ValueError:
            strategy = HeuristicStrategy.BALANCED
        recovery.set_strategy(strategy)

        # If no data provided, try to get from stored evidence
        if data is None:
            # Get evidence in range
            evidence = self.get_evidence_in_range(
                address_space=address_space,
                start=address,
                end=address + max_size,
            )

            # Reconstruct data from evidence
            if evidence:
                # Create a buffer from evidence
                data = bytearray(max_size)
                for ev in evidence:
                    if ev.location:
                        # Try to extract hex bytes from evidence excerpt
                        hex_matches = re.findall(r'[0-9A-Fa-f]{2}', ev.excerpt)
                        if hex_matches:
                            ev_data = bytes(int(h, 16) for h in hex_matches)
                            ev_offset = ev.location.start - address
                            if 0 <= ev_offset < max_size:
                                end_pos = min(ev_offset + len(ev_data), max_size)
                                data[ev_offset:end_pos] = ev_data[:end_pos - ev_offset]
                data = bytes(data)
            else:
                # No evidence available, use zero-filled buffer
                data = bytes(max_size)

        # Perform structure inference
        structure = recovery.infer_structure(
            address=address,
            data=data,
            max_size=max_size,
            address_space=address_space,
            pointer_size=pointer_size,
            base_address=address,
        )

        return structure.to_dict()

    def generate_heat_map(
        self,
        heat_source: str,
        address_space: str,
        resolution: int = 256,
        color_scheme: str = "viridis",
        start_address: int | None = None,
        end_address: int | None = None,
        threshold: float = 0.0,
        output_format: str = "json",
    ) -> dict[str, Any]:
        """Generate a heat map for visualizing data over an address space.

        Creates a heat map visualization showing the distribution of various
        metrics across an address space, such as code coverage, reference
        counts, call frequency, or entropy values.

        Args:
            heat_source: Type of data to visualize - "coverage", "reference_count",
                        "call_frequency", or "entropy".
            address_space: The address space to visualize (e.g., "flat", "snes-lorom").
            resolution: Number of cells in the heat map (default 256, max 4096).
            color_scheme: Color scheme for visualization - "viridis", "plasma",
                         "inferno", "magma", "hot", "cool", "jet", "greyscale",
                         "red_green", "blue_yellow" (default: "viridis").
            start_address: Optional start address for the range (inclusive).
            end_address: Optional end address for the range (inclusive).
            threshold: Minimum value threshold for region detection (0.0-1.0).
            output_format: Output format - "json", "ascii", or "png".

        Returns:
            Dictionary containing the heat map result with cells, regions,
            and metadata. For "ascii" format, includes "ascii_art" field.
            For "png" format, includes "png_base64" field.

        Example:
            # Generate coverage heat map
            result = store.generate_heat_map(
                heat_source="coverage",
                address_space="rom",
                resolution=512,
                color_scheme="hot",
            )

            # Generate with ASCII output for terminal
            result = store.generate_heat_map(
                heat_source="reference_count",
                address_space="flat",
                output_format="ascii",
            )
        """
        from codemunch_pro.rex.heat_map import generate_heat_map

        return generate_heat_map(
            store=self,
            heat_source=heat_source,
            address_space=address_space,
            resolution=resolution,
            color_scheme=color_scheme,
            start_address=start_address,
            end_address=end_address,
            threshold=threshold,
            output_format=output_format,
        )

    def detect_anomalies(
        self,
        address_space: str,
        min_severity: str = "info",
    ) -> dict[str, Any]:
        """Detect anomalies and unusual code patterns in an address space.

        Uses statistical analysis to identify:
        - Anti-debugging patterns (RDTSC, debugger detection)
        - High entropy regions (packed/encrypted data)
        - Unreachable code (dead code, obfuscation)
        - Potential bugs (null pointer dereferences, buffer overflows)
        - Rare/unusual instructions

        Args:
            address_space: The address space to analyze.
            min_severity: Minimum severity to report - "info", "warning", or "critical".

        Returns:
            Dictionary with anomaly detection results.
        """
        from codemunch_pro.rex.anomaly_detection import (
            AnomalyDetector,
            SeverityLevel,
        )

        # Map severity string to enum
        severity_map = {
            SeverityLevel.INFO.label: SeverityLevel.INFO,
            SeverityLevel.WARNING.label: SeverityLevel.WARNING,
            SeverityLevel.CRITICAL.label: SeverityLevel.CRITICAL,
        }
        min_sev = severity_map.get(min_severity.lower(), SeverityLevel.INFO)

        detector = AnomalyDetector()
        result = detector.detect_anomalies(
            store=self,
            address_space=address_space,
            min_severity=min_sev,
        )

        return result.to_dict()

    def auto_document_function(
        self,
        function_address: int,
        context_hint: str = "",
        address_space: str = "",
        output_format: str = "markdown",
        store_as_evidence: bool = True,
    ) -> dict[str, Any]:
        """Generate auto-documentation for a function using LLM patterns.

        Analyzes function context including called functions, calling functions,
        string references, and data access patterns to generate comprehensive
        documentation.

        Args:
            function_address: The address of the function to document.
            context_hint: Optional hint about the function's purpose.
            address_space: Optional address space filter.
            output_format: Output format - "markdown" or "plain_text" (default: "markdown").
            store_as_evidence: Whether to store the generated documentation as evidence.

        Returns:
            Dictionary containing:
            - function_address: The documented function address
            - function_name: The function name
            - documentation: The formatted documentation string
            - template: The documentation template data
            - evidence_id: The evidence ID if stored (or empty string)
            - confidence: The confidence score of the documentation
        """
        from codemunch_pro.rex.auto_document import (
            FunctionDocumenter,
            OutputFormat,
        )

        # Create documenter and generate documentation
        documenter = FunctionDocumenter(self)

        fmt = OutputFormat.MARKDOWN if output_format.lower() == "markdown" else OutputFormat.PLAIN_TEXT
        doc = documenter.generate_documentation(
            function_address=function_address,
            context_hint=context_hint,
            address_space=address_space,
            output_format=fmt,
        )

        # Format output
        formatted_doc = documenter.format_output(doc, fmt)

        result = {
            "function_address": function_address,
            "function_name": doc.function_name,
            "documentation": formatted_doc,
            "template": doc.to_dict(),
            "evidence_id": "",
            "confidence": doc.confidence,
        }

        # Store as evidence if requested
        if store_as_evidence:
            # Find the function entity
            entity = None
            entities = self.list_entities(kind="function", limit=10000)
            for e in entities:
                if e.location and e.location.start == function_address:
                    if not address_space or e.location.address_space == address_space:
                        entity = e
                        break

            if entity:
                from codemunch_pro.rex.model import EvidenceRecord, AddressLocation
                import uuid

                evidence_id = f"auto_doc:{entity.entity_id}:{uuid.uuid4().hex[:8]}"

                location = entity.location or AddressLocation(
                    address_space=address_space or "flat",
                    start=function_address,
                    end=function_address,
                )

                evidence = EvidenceRecord(
                    evidence_id=evidence_id,
                    kind="auto_documentation",
                    artifact_id=entity.artifact_id or "auto_generated",
                    entity_ids=(entity.entity_id,),
                    location=location,
                    excerpt=formatted_doc[:500],  # First 500 chars as excerpt
                    confidence=doc.confidence,
                    attributes={
                        "function_address": function_address,
                        "function_name": doc.function_name,
                        "full_documentation": formatted_doc,
                        "template": doc.to_dict(),
                        "context_hint": context_hint,
                        "output_format": output_format,
                        "generated_by": "FunctionDocumenter",
                    },
                )

                # Store the evidence
                cursor = self._conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO evidence
                    (evidence_id, kind, artifact_id, entity_ids_json, location_json, excerpt, confidence, attributes_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence.evidence_id,
                        evidence.kind,
                        evidence.artifact_id,
                        json.dumps(list(evidence.entity_ids)),
                        self._location_to_json(evidence.location),
                        evidence.excerpt,
                        evidence.confidence,
                        json.dumps(evidence.attributes),
                    ),
                )
                self._conn.commit()

                result["evidence_id"] = evidence_id

        return result


    def get_memory_map(self, address_space: str) -> MemoryMap:
        """Generate a memory map visualization for the given address space.

        Analyzes entities in the database with the specified address space
        and constructs a MemoryMap with detected regions.

        Args:
            address_space: The address space to analyze (e.g., "snes-lorom", "flat").

        Returns:
            MemoryMap containing detected memory regions based on entities.
        """
        memory_map = MemoryMap(
            name=f"Memory Map - {address_space}",
            address_space=address_space,
        )

        cursor = self._conn.cursor()

        # Get all entities with locations in this address space
        cursor.execute(
            """
            SELECT * FROM entities
            WHERE location_json LIKE ?
            ORDER BY location_json
            """,
            (f'"address_space": "{address_space}"%',),
        )

        rows = cursor.fetchall()

        # Track regions by entity kind
        kind_to_region_type: dict[str, RegionType] = {
            "function": RegionType.ROM,
            "data": RegionType.RAM,
            "string": RegionType.ROM,
            "reference": RegionType.ROM,
            "section": RegionType.ROM,
            "variable": RegionType.RAM,
            "io_port": RegionType.IO,
            "vram": RegionType.VRAM,
            "oam": RegionType.VRAM,
            "cgram": RegionType.VRAM,
            "system_vector": RegionType.SYSTEM_ROM,
            "interrupt_vector": RegionType.SYSTEM_ROM,
        }

        for row in rows:
            location = self._json_to_location(row["location_json"])
            if location is None:
                continue

            entity_kind = row["kind"]
            entity_name = row["name"]

            # Determine region type based on entity kind
            region_type = kind_to_region_type.get(entity_kind, RegionType.ROM)

            # Create a memory region for this entity
            region = MemoryRegion(
                name=entity_name,
                start=location.start,
                end=location.end,
                region_type=region_type,
                description=f"{entity_kind} entity from {row.get('artifact_id', 'unknown')}",
            )

            memory_map.add_region(region)

        # If no regions found, add some default regions based on common patterns
        if not memory_map.regions:
            # Add placeholder regions indicating empty address space
            memory_map.add_region(MemoryRegion(
                name="Empty Address Space",
                start=0x00000000,
                end=0x00FFFFFF,
                region_type=RegionType.ROM,
                description=f"No entities found in address space: {address_space}",
            ))

        return memory_map

    def suggest_rename(self, entity_id: str, platform: str = "generic") -> dict[str, Any]:
        """Suggest new names for an entity using smart rename heuristics.

        Uses multiple heuristics to suggest better names for functions and data:
        - String references analysis
        - Called function patterns
        - Known library signatures
        - Pattern recognition (getter/setter, init, cleanup, etc.)

        Args:
            entity_id: The entity ID to analyze
            platform: Target platform naming convention (windows, linux, macos, generic)

        Returns:
            Dictionary with rename suggestions and metadata
        """
        from codemunch_pro.rex.smart_rename import RenameSuggester

        suggester = RenameSuggester(platform=platform)
        entity = self.get_entity(entity_id)

        if entity is None:
            return {
                "success": False,
                "entity_id": entity_id,
                "error": "Entity not found",
                "suggestions": [],
            }

        if entity.kind == "function":
            result = suggester.suggest_function_name(entity_id, self)
        else:
            result = suggester.suggest_data_label(entity_id, self)

        # Convert to dictionary format
        suggestions_dict = [
            {
                "suggested_name": s.suggested_name,
                "confidence": s.confidence,
                "heuristic": s.heuristic,
                "reasoning": s.reasoning,
                "platform": s.platform,
            }
            for s in result.suggestions
        ]

        best = result.best_suggestion
        return {
            "success": True,
            "entity_id": entity_id,
            "current_name": result.current_name,
            "entity_kind": entity.kind if entity else "unknown",
            "platform": platform,
            "best_suggestion": {
                "suggested_name": best.suggested_name,
                "confidence": best.confidence,
                "heuristic": best.heuristic,
                "reasoning": best.reasoning,
            } if best else None,
            "suggestions": suggestions_dict,
            "suggestion_count": len(suggestions_dict),
            "metadata": result.metadata,
        }
    
    # Cache management methods
    
    def clear_caches(self) -> None:
        """Clear all LRU caches."""
        self.get_artifact.cache_clear()
        self.get_entity.cache_clear()
        self.search_evidence.cache_clear()
        self.search_entities.cache_clear()
        self.find_entities_by_canonical_ref.cache_clear()
    
    def get_cache_info(self) -> dict[str, dict[str, Any]]:
        """Get cache statistics."""
        return {
            "get_artifact": {
                "hits": self.get_artifact.cache_info().hits,
                "misses": self.get_artifact.cache_info().misses,
                "maxsize": self.get_artifact.cache_info().maxsize,
                "currsize": self.get_artifact.cache_info().currsize,
            },
            "get_entity": {
                "hits": self.get_entity.cache_info().hits,
                "misses": self.get_entity.cache_info().misses,
                "maxsize": self.get_entity.cache_info().maxsize,
                "currsize": self.get_entity.cache_info().currsize,
            },
            "search_evidence": {
                "hits": self.search_evidence.cache_info().hits,
                "misses": self.search_evidence.cache_info().misses,
                "maxsize": self.search_evidence.cache_info().maxsize,
                "currsize": self.search_evidence.cache_info().currsize,
            },
            "search_entities": {
                "hits": self.search_entities.cache_info().hits,
                "misses": self.search_entities.cache_info().misses,
                "maxsize": self.search_entities.cache_info().maxsize,
                "currsize": self.search_entities.cache_info().currsize,
            },
            "find_entities_by_canonical_ref": {
                "hits": self.find_entities_by_canonical_ref.cache_info().hits,
                "misses": self.find_entities_by_canonical_ref.cache_info().misses,
                "maxsize": self.find_entities_by_canonical_ref.cache_info().maxsize,
                "currsize": self.find_entities_by_canonical_ref.cache_info().currsize,
            },
        }

    # ========================================================================
    # Regression Testing Methods
    # ========================================================================

    def create_analysis_snapshot(
        self,
        version_tag: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a snapshot of the current analysis state for regression testing.

        Captures entity counts by kind, reference coverage, confidence scores,
        and other metrics for tracking analysis stability over time.

        Args:
            version_tag: Identifier for this version (e.g., git commit hash)
            metadata: Optional additional metadata to store with the snapshot

        Returns:
            Dictionary containing the snapshot data
        """
        from codemunch_pro.rex.regression import RegressionTester

        tester = RegressionTester(self)
        snapshot = tester.create_snapshot(version_tag, metadata)

        # Store snapshot in database for history tracking
        cursor = self._conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version_tag TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            )
        """)

        cursor.execute("""
            INSERT INTO analysis_snapshots (snapshot_id, created_at, version_tag, snapshot_json)
            VALUES (?, ?, ?, ?)
        """, (
            snapshot.snapshot_id,
            snapshot.created_at.isoformat(),
            snapshot.version_tag,
            json.dumps(snapshot.to_dict()),
        ))
        self._conn.commit()

        return snapshot.to_dict()

    def compare_analysis_versions(
        self,
        version_a: str,
        version_b: str,
    ) -> dict[str, Any]:
        """Compare analysis between two versions and generate a regression report.

        Args:
            version_a: The baseline version tag or snapshot ID
            version_b: The new version tag or snapshot ID to compare

        Returns:
            Dictionary containing the regression report with diffs and analysis
        """
        from codemunch_pro.rex.regression import RegressionTester, AnalysisSnapshot

        # Try to load snapshots from database
        cursor = self._conn.cursor()

        # Ensure table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version_tag TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            )
        """)

        # Check if inputs are snapshot IDs or version tags
        try:
            cursor.execute("""
                SELECT snapshot_json FROM analysis_snapshots
                WHERE snapshot_id = ? OR version_tag = ?
                ORDER BY created_at DESC LIMIT 1
            """, (version_a, version_a))
            row_a = cursor.fetchone()
        except sqlite3.OperationalError:
            row_a = None

        try:
            cursor.execute("""
                SELECT snapshot_json FROM analysis_snapshots
                WHERE snapshot_id = ? OR version_tag = ?
                ORDER BY created_at DESC LIMIT 1
            """, (version_b, version_b))
            row_b = cursor.fetchone()
        except sqlite3.OperationalError:
            row_b = None

        if row_a is None:
            return {
                "error": f"Version/snapshot not found: {version_a}",
                "version_a": version_a,
                "version_b": version_b,
            }

        if row_b is None:
            return {
                "error": f"Version/snapshot not found: {version_b}",
                "version_a": version_a,
                "version_b": version_b,
            }

        snapshot_a = AnalysisSnapshot.from_dict(json.loads(row_a[0]))
        snapshot_b = AnalysisSnapshot.from_dict(json.loads(row_b[0]))

        tester = RegressionTester(self)
        report = tester.compare_snapshots(snapshot_a, snapshot_b)

        # Store comparison report
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_comparisons (
                comparison_id TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version_a TEXT NOT NULL,
                version_b TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
        """)

        comparison_id = f"comparison_{version_a}_to_{version_b}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        cursor.execute("""
            INSERT INTO analysis_comparisons (comparison_id, version_a, version_b, report_json)
            VALUES (?, ?, ?, ?)
        """, (
            comparison_id,
            version_a,
            version_b,
            json.dumps(report.to_dict()),
        ))
        self._conn.commit()

        result = report.to_dict()
        result["comparison_id"] = comparison_id
        return result

    def get_analysis_history(
        self,
        limit: int = 10,
        version_filter: str = "",
    ) -> dict[str, Any]:
        """Get the history of analysis snapshots.

        Args:
            limit: Maximum number of snapshots to return
            version_filter: Optional version tag filter (substring match)

        Returns:
            Dictionary with list of snapshots and metadata
        """
        cursor = self._conn.cursor()

        # Ensure table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version_tag TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            )
        """)

        if version_filter:
            cursor.execute("""
                SELECT snapshot_id, created_at, version_tag, snapshot_json
                FROM analysis_snapshots
                WHERE version_tag LIKE ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (f"%{version_filter}%", limit))
        else:
            cursor.execute("""
                SELECT snapshot_id, created_at, version_tag, snapshot_json
                FROM analysis_snapshots
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))

        rows = cursor.fetchall()

        snapshots = []
        for row in rows:
            snapshot_data = json.loads(row[3])
            snapshots.append({
                "snapshot_id": row[0],
                "created_at": row[1],
                "version_tag": row[2],
                "summary": {
                    "entity_counts": snapshot_data.get("entity_counts", {}),
                    "evidence_counts": snapshot_data.get("evidence_counts", {}),
                    "edge_counts": snapshot_data.get("edge_counts", {}),
                    "artifact_stats": snapshot_data.get("artifact_stats", {}),
                },
            })

        return {
            "snapshots": snapshots,
            "count": len(snapshots),
            "limit": limit,
            "version_filter": version_filter,
        }

    def delete_analysis_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        """Delete an analysis snapshot.

        Args:
            snapshot_id: The snapshot ID to delete

        Returns:
            Dictionary with deletion status
        """
        cursor = self._conn.cursor()

        cursor.execute("""
            DELETE FROM analysis_snapshots WHERE snapshot_id = ?
        """, (snapshot_id,))

        deleted = cursor.rowcount > 0
        self._conn.commit()

        return {
            "snapshot_id": snapshot_id,
            "deleted": deleted,
            "message": "Snapshot deleted" if deleted else "Snapshot not found",
        }

    def check_integrity(self) -> dict[str, Any]:
        """Check the integrity of the reverse-engineering database.
        
        Returns:
            Dictionary with integrity report
        """
        from codemunch_pro.rex.integrity import IntegrityChecker
        
        checker = IntegrityChecker(self)
        report = checker.check_all()
        return report.to_dict()

    def fix_integrity_issues(self, auto_fix: bool = False) -> dict[str, Any]:
        """Fix integrity issues in the database.
        
        Args:
            auto_fix: If True, automatically fix safe issues
            
        Returns:
            Dictionary with fix report
        """
        from codemunch_pro.rex.integrity import IntegrityChecker
        
        checker = IntegrityChecker(self)
        report = checker.check_all()
        auto_fixable = report.get_auto_fixable()
        
        if auto_fix:
            fixed = checker.fix_issues(auto_fixable)
            return {
                "auto_fix": True,
                "fixed_count": fixed["fixed_count"],
                "failed_count": fixed["failed_count"],
                "fixed": fixed["fixed"],
                "failed": fixed["failed"],
                "issues": [issue.to_dict() for issue in auto_fixable],
                "report": report.to_dict(),
                "message": f"Fixed {fixed['fixed_count']} issues",
            }
        
        return {
            "auto_fix": False,
            "would_fix_count": len(auto_fixable),
            "issues": [issue.to_dict() for issue in auto_fixable],
            "report": report.to_dict(),
            "message": f"Found {len(auto_fixable)} auto-fixable issues. Set auto_fix=True to fix.",
        }
