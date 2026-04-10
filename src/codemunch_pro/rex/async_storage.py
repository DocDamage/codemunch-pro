"""Async storage backend for reverse-engineering data.

This module provides asynchronous versions of all ReverseEngineeringStore
methods using asyncio and aiosqlite for non-blocking database operations.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.similarity import (
        SimilarityIndex,
    )

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)

# Try to import aiosqlite for true async support
try:
    import aiosqlite
    HAS_AIOSQLITE = True
except ImportError:
    HAS_AIOSQLITE = False

DEFAULT_REX_DB_DIR = Path(".rex_db")


class AsyncReverseEngineeringStore:
    """Async SQLite-backed store for reverse-engineering data.
    
    This class provides asynchronous versions of all methods from
    ReverseEngineeringStore. When aiosqlite is available, it uses
    true async database operations. Otherwise, it falls back to
    running synchronous operations in an executor.
    """

    def __init__(
        self,
        db_path: Path | str = DEFAULT_REX_DB_DIR / "rex.db",
        use_executor: bool = False,
    ):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._use_executor = use_executor or not HAS_AIOSQLITE
        self._conn: aiosqlite.Connection | sqlite3.Connection | None = None
        self._lock = asyncio.Lock()
    
    async def _get_connection(self) -> aiosqlite.Connection | sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            if HAS_AIOSQLITE and not self._use_executor:
                self._conn = await aiosqlite.connect(self._db_path)
                self._conn.row_factory = aiosqlite.Row
                await self._conn.execute("PRAGMA journal_mode=WAL")
                await self._conn.execute("PRAGMA synchronous=NORMAL")
                await self._conn.execute("PRAGMA cache_size=10000")
                await self._conn.execute("PRAGMA temp_store=MEMORY")
            else:
                # Fall back to sync connection in executor
                # Use check_same_thread=False since connection may be created
                # in one thread but accessed from another via executor
                loop = asyncio.get_event_loop()
                self._conn = await loop.run_in_executor(
                    None, partial(sqlite3.connect, self._db_path, check_same_thread=False)
                )
                self._conn.row_factory = sqlite3.Row  # type: ignore
        return self._conn
    
    async def _execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> Any:
        """Execute SQL asynchronously."""
        conn = await self._get_connection()
        if HAS_AIOSQLITE and not self._use_executor:
            return await conn.execute(sql, parameters)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, conn.execute, sql, parameters)
    
    async def _executemany(self, sql: str, parameters: list[tuple[Any, ...]]) -> Any:
        """Execute SQL with many parameters asynchronously."""
        conn = await self._get_connection()
        if HAS_AIOSQLITE and not self._use_executor:
            return await conn.executemany(sql, parameters)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, conn.executemany, sql, parameters)
    
    async def _commit(self) -> None:
        """Commit transaction asynchronously."""
        conn = await self._get_connection()
        if HAS_AIOSQLITE and not self._use_executor:
            await conn.commit()
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, conn.commit)
    
    async def initialize(self) -> None:
        """Initialize database schema."""
        async with self._lock:
            # Artifacts table
            await self._execute("""
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
            await self._execute("""
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
            await self._execute("""
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
            await self._execute("""
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
            
            # Create indexes
            await self._execute("CREATE INDEX IF NOT EXISTS idx_entities_artifact ON entities(artifact_id)")
            await self._execute("CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind)")
            await self._execute("CREATE INDEX IF NOT EXISTS idx_entities_canonical_ref ON entities(canonical_ref)")
            await self._execute("CREATE INDEX IF NOT EXISTS idx_evidence_artifact ON evidence(artifact_id)")
            await self._execute("CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence(kind)")
            await self._execute("CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_entity_id)")
            await self._execute("CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_entity_id)")
            
            # Additional performance indexes
            await self._execute("""
                CREATE INDEX IF NOT EXISTS idx_entities_artifact_kind 
                ON entities(artifact_id, kind)
            """)
            await self._execute("""
                CREATE INDEX IF NOT EXISTS idx_entities_name 
                ON entities(name COLLATE NOCASE)
            """)
            await self._execute("""
                CREATE INDEX IF NOT EXISTS idx_edges_kind 
                ON edges(kind)
            """)
            await self._execute("""
                CREATE INDEX IF NOT EXISTS idx_edges_source_kind 
                ON edges(source_entity_id, kind)
            """)
            await self._execute("""
                CREATE INDEX IF NOT EXISTS idx_edges_target_kind 
                ON edges(target_entity_id, kind)
            """)
            
            await self._commit()
    
    async def close(self) -> None:
        """Close the database connection."""
        async with self._lock:
            if self._conn:
                if HAS_AIOSQLITE and not self._use_executor:
                    await self._conn.close()
                else:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, self._conn.close)
                self._conn = None
    
    async def __aenter__(self) -> AsyncReverseEngineeringStore:
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()
    
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
    
    def _row_to_artifact(self, row: Any) -> ArtifactRecord:
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
    
    def _row_to_entity(self, row: Any) -> EntityRecord:
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
    
    def _row_to_evidence(self, row: Any) -> EvidenceRecord:
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
    
    def _row_to_edge(self, row: Any) -> EdgeRecord:
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
    
    # Bulk insert operations
    
    async def bulk_insert_artifacts(self, artifacts: list[ArtifactRecord]) -> None:
        """Bulk insert artifacts asynchronously."""
        if not artifacts:
            return
        
        params = [
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
        ]
        
        await self._executemany(
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
            params,
        )
        await self._commit()
    
    async def bulk_insert_entities(self, entities: list[EntityRecord]) -> None:
        """Bulk insert entities asynchronously."""
        if not entities:
            return
        
        params = [
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
        ]
        
        await self._executemany(
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
            params,
        )
        await self._commit()
    
    async def bulk_insert_evidence(self, evidence_list: list[EvidenceRecord]) -> None:
        """Bulk insert evidence asynchronously."""
        if not evidence_list:
            return
        
        params = [
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
        ]
        
        await self._executemany(
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
            params,
        )
        await self._commit()
    
    async def bulk_insert_edges(self, edges: list[EdgeRecord]) -> None:
        """Bulk insert edges asynchronously."""
        if not edges:
            return
        
        params = [
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
        ]
        
        await self._executemany(
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
            params,
        )
        await self._commit()
    
    async def upsert_bundle(self, bundle: ReverseEngineeringBundle) -> None:
        """Upsert a bundle into the store asynchronously."""
        await self.bulk_insert_artifacts(bundle.artifacts)
        await self.bulk_insert_entities(bundle.entities)
        await self.bulk_insert_evidence(bundle.evidence)
        await self.bulk_insert_edges(bundle.edges)
    
    # Query operations
    
    async def get_artifact(self, artifact_id: str) -> ArtifactRecord | None:
        """Get an artifact by ID asynchronously."""
        cursor = await self._execute(
            "SELECT * FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        row = await self._fetchone(cursor)
        if row is None:
            return None
        return self._row_to_artifact(row)
    
    async def get_entity(self, entity_id: str) -> EntityRecord | None:
        """Get an entity by ID asynchronously."""
        cursor = await self._execute(
            "SELECT * FROM entities WHERE entity_id = ?",
            (entity_id,)
        )
        row = await self._fetchone(cursor)
        if row is None:
            return None
        return self._row_to_entity(row)
    
    async def list_artifacts(self, kind: str = "", limit: int = 100) -> list[ArtifactRecord]:
        """List all artifacts asynchronously."""
        if kind:
            cursor = await self._execute(
                "SELECT * FROM artifacts WHERE kind = ? ORDER BY artifact_id LIMIT ?",
                (kind, limit)
            )
        else:
            cursor = await self._execute(
                "SELECT * FROM artifacts ORDER BY artifact_id LIMIT ?",
                (limit,)
            )
        
        rows = await self._fetchall(cursor)
        return [self._row_to_artifact(row) for row in rows]
    
    async def list_entities(
        self, kind: str | None = None, address_space: str | None = None, limit: int = 100
    ) -> list[EntityRecord]:
        """List entities asynchronously."""
        sql = "SELECT * FROM entities WHERE 1=1"
        params: list[Any] = []
        
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        
        if address_space:
            sql += " AND location_json LIKE ?"
            params.append(f'"address_space": "{address_space}"%')
        
        sql += " ORDER BY entity_id LIMIT ?"
        params.append(limit)
        
        cursor = await self._execute(sql, tuple(params))
        rows = await self._fetchall(cursor)
        return [self._row_to_entity(row) for row in rows]
    
    async def get_entities_for_artifact(
        self, artifact_id: str, kind: str | None = None, limit: int = 100
    ) -> list[EntityRecord]:
        """Get entities for an artifact asynchronously."""
        if kind:
            cursor = await self._execute(
                """
                SELECT * FROM entities 
                WHERE artifact_id = ? AND kind = ?
                ORDER BY entity_id LIMIT ?
                """,
                (artifact_id, kind, limit)
            )
        else:
            cursor = await self._execute(
                """
                SELECT * FROM entities 
                WHERE artifact_id = ?
                ORDER BY entity_id LIMIT ?
                """,
                (artifact_id, limit)
            )
        
        rows = await self._fetchall(cursor)
        return [self._row_to_entity(row) for row in rows]
    
    async def get_evidence_for_artifact(
        self, artifact_id: str, kind: str | None = None, limit: int = 100
    ) -> list[EvidenceRecord]:
        """Get evidence for an artifact asynchronously."""
        if kind:
            cursor = await self._execute(
                """
                SELECT * FROM evidence 
                WHERE artifact_id = ? AND kind = ?
                ORDER BY evidence_id LIMIT ?
                """,
                (artifact_id, kind, limit)
            )
        else:
            cursor = await self._execute(
                """
                SELECT * FROM evidence 
                WHERE artifact_id = ?
                ORDER BY evidence_id LIMIT ?
                """,
                (artifact_id, limit)
            )
        
        rows = await self._fetchall(cursor)
        return [self._row_to_evidence(row) for row in rows]
    
    async def find_entities_by_canonical_ref(
        self, ref: str, kind: str | None = None, limit: int = 100
    ) -> list[EntityRecord]:
        """Find entities by canonical reference asynchronously."""
        if kind:
            cursor = await self._execute(
                """
                SELECT * FROM entities 
                WHERE canonical_ref = ? AND kind = ?
                ORDER BY entity_id LIMIT ?
                """,
                (ref, kind, limit)
            )
        else:
            cursor = await self._execute(
                """
                SELECT * FROM entities 
                WHERE canonical_ref = ?
                ORDER BY entity_id LIMIT ?
                """,
                (ref, limit)
            )
        
        rows = await self._fetchall(cursor)
        return [self._row_to_entity(row) for row in rows]
    
    async def search_entities(
        self, query: str, kind: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Search for entities asynchronously."""
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
        
        cursor = await self._execute(sql, tuple(params))
        rows = await self._fetchall(cursor)
        return [dict(self._row_to_entity(row).to_dict()) for row in rows]
    
    async def search_evidence(
        self, query: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Search for evidence asynchronously."""
        cursor = await self._execute(
            """
            SELECT * FROM evidence 
            WHERE excerpt LIKE ? 
            ORDER BY evidence_id
            LIMIT ?
            """,
            (f"%{query}%", limit)
        )
        rows = await self._fetchall(cursor)
        return [dict(self._row_to_evidence(row).to_dict()) for row in rows]
    
    async def get_neighbors(self, entity_id: str, limit: int = 100) -> list[EdgeRecord]:
        """Get neighbors for an entity asynchronously."""
        cursor = await self._execute(
            """
            SELECT * FROM edges 
            WHERE source_entity_id = ? OR target_entity_id = ?
            ORDER BY edge_id LIMIT ?
            """,
            (entity_id, entity_id, limit)
        )
        rows = await self._fetchall(cursor)
        return [self._row_to_edge(row) for row in rows]
    
    async def get_evidence_for_entity(
        self, entity_id: str, limit: int = 100
    ) -> list[EvidenceRecord]:
        """Get evidence for an entity asynchronously."""
        cursor = await self._execute(
            """
            SELECT * FROM evidence 
            WHERE entity_ids_json LIKE ?
            ORDER BY evidence_id LIMIT ?
            """,
            (f'%"{entity_id}"%', limit)
        )
        rows = await self._fetchall(cursor)
        return [self._row_to_evidence(row) for row in rows]
    
    async def _fetchone(self, cursor: Any) -> Any:
        """Fetch one row from cursor (handles both sync and async)."""
        if HAS_AIOSQLITE and not self._use_executor:
            return await cursor.fetchone()
        else:
            # For executor mode, cursor is already the result
            return cursor.fetchone()
    
    async def _fetchall(self, cursor: Any) -> list[Any]:
        """Fetch all rows from cursor (handles both sync and async)."""
        if HAS_AIOSQLITE and not self._use_executor:
            return await cursor.fetchall()
        else:
            return cursor.fetchall()
    
    async def stats(self) -> dict[str, int]:
        """Return statistics about the store asynchronously."""
        artifacts_cursor = await self._execute("SELECT COUNT(*) FROM artifacts")
        artifacts_row = await self._fetchone(artifacts_cursor)
        
        entities_cursor = await self._execute("SELECT COUNT(*) FROM entities")
        entities_row = await self._fetchone(entities_cursor)
        
        evidence_cursor = await self._execute("SELECT COUNT(*) FROM evidence")
        evidence_row = await self._fetchone(evidence_cursor)
        
        edges_cursor = await self._execute("SELECT COUNT(*) FROM edges")
        edges_row = await self._fetchone(edges_cursor)
        
        return {
            "artifacts": artifacts_row[0],
            "entities": entities_row[0],
            "evidence": evidence_row[0],
            "edges": edges_row[0],
        }
    
    async def traverse_entity_graph(
        self, entity_ids: list[str], depth: int = 2, edge_limit: int = 20
    ) -> dict[str, Any]:
        """Traverse the entity graph using BFS asynchronously."""
        if not entity_ids:
            return {"entities": [], "edges": [], "depths": {}, "root_entity_ids": []}
        
        visited_entities: set[str] = set()
        visited_edges: set[str] = set()
        depths: dict[str, int] = {}
        
        queue: list[tuple[str, int]] = []
        for entity_id in entity_ids:
            queue.append((entity_id, 0))
            visited_entities.add(entity_id)
            depths[entity_id] = 0
        
        result_entities: list[EntityRecord] = []
        result_edges: list[EdgeRecord] = []
        
        while queue and len(visited_edges) < edge_limit:
            current_id, current_depth = queue.pop(0)
            
            entity = await self.get_entity(current_id)
            if entity:
                result_entities.append(entity)
            
            if current_depth >= depth:
                continue
            
            neighbors = await self.get_neighbors(current_id, limit=edge_limit)
            for edge in neighbors:
                if edge.edge_id not in visited_edges and len(visited_edges) < edge_limit:
                    visited_edges.add(edge.edge_id)
                    result_edges.append(edge)
                
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
    
    async def get_entities_in_range(
        self, address_space: str, start: int, end: int, kind: str | None = None
    ) -> list[EntityRecord]:
        """Get entities in an address range asynchronously."""
        if kind:
            cursor = await self._execute(
                "SELECT * FROM entities WHERE kind = ? AND location_json IS NOT NULL",
                (kind,)
            )
        else:
            cursor = await self._execute(
                "SELECT * FROM entities WHERE location_json IS NOT NULL"
            )
        
        rows = await self._fetchall(cursor)
        result = []
        
        for row in rows:
            location = self._json_to_location(row["location_json"])
            if location is None:
                continue
            if location.address_space != address_space:
                continue
            if not (end < location.start or location.end < start):
                result.append(self._row_to_entity(row))
        
        return result
    
    async def get_evidence_in_range(
        self, address_space: str, start: int, end: int, artifact_id: str | None = None
    ) -> list[EvidenceRecord]:
        """Get evidence in an address range asynchronously."""
        if artifact_id:
            cursor = await self._execute(
                "SELECT * FROM evidence WHERE artifact_id = ?",
                (artifact_id,)
            )
        else:
            cursor = await self._execute("SELECT * FROM evidence")
        
        rows = await self._fetchall(cursor)
        result = []
        
        for row in rows:
            location = self._json_to_location(row["location_json"])
            if location is None:
                continue
            if location.address_space != address_space:
                continue
            if not (end < location.start or location.end < start):
                result.append(self._row_to_evidence(row))
        
        return result
    
    # High-level operations
    
    async def summarize_ref_provenance(
        self, ref: str, kind: str = "reference", limit_artifacts: int = 100, limit_anchors: int = 25
    ) -> list[dict[str, Any]]:
        """Summarize reference provenance asynchronously."""
        entities = await self.find_entities_by_canonical_ref(ref, kind=kind, limit=limit_artifacts * 10)
        
        by_artifact: dict[str, list[EntityRecord]] = defaultdict(list)
        for entity in entities:
            by_artifact[entity.artifact_id].append(entity)
        
        summaries = []
        for artifact_id, artifact_entities in list(by_artifact.items())[:limit_artifacts]:
            artifact = await self.get_artifact(artifact_id)
            if not artifact:
                continue
            
            evidence_counts: dict[str, int] = defaultdict(int)
            anchor_kinds: dict[str, int] = defaultdict(int)
            
            all_related_entity_ids: set[str] = set()
            for entity in artifact_entities[:limit_anchors]:
                all_related_entity_ids.add(entity.entity_id)
                edges = await self.get_neighbors(entity.entity_id, limit=limit_anchors)
                for edge in edges:
                    all_related_entity_ids.add(edge.source_entity_id)
                    all_related_entity_ids.add(edge.target_entity_id)
            
            for entity_id in all_related_entity_ids:
                entity = await self.get_entity(entity_id)
                if entity and entity.artifact_id == artifact_id:
                    anchor_kinds[entity.kind] += 1
            
            for entity in artifact_entities[:limit_anchors]:
                evidence = await self.get_evidence_for_entity(entity.entity_id)
                for ev in evidence:
                    evidence_counts[ev.kind] += 1
            
            summaries.append({
                "artifact": artifact.to_dict(),
                "reference_entity_count": len(artifact_entities),
                "evidence_kind_counts": dict(evidence_counts),
                "anchor_kind_counts": dict(anchor_kinds),
            })
        
        return summaries
    
    async def compare_ref_provenance(
        self, ref: str, kind: str = "reference", limit_artifacts: int = 100, limit_anchors: int = 25
    ) -> dict[str, Any]:
        """Compare reference provenance asynchronously."""
        summaries = await self.summarize_ref_provenance(ref, kind, limit_artifacts, limit_anchors)
        
        all_evidence_kinds: set[str] = set()
        all_anchor_kinds: set[str] = set()
        
        for summary in summaries:
            all_evidence_kinds.update(summary["evidence_kind_counts"].keys())
            all_anchor_kinds.update(summary["anchor_kind_counts"].keys())
        
        common_evidence_kinds = all_evidence_kinds.copy()
        common_anchor_kinds = all_anchor_kinds.copy()
        
        for summary in summaries:
            common_evidence_kinds &= set(summary["evidence_kind_counts"].keys())
            common_anchor_kinds &= set(summary["anchor_kind_counts"].keys())
        
        unique_signatures: dict[str, list[str]] = defaultdict(list)
        shared_signatures: list[str] = []
        
        artifact_signatures: dict[str, set[str]] = defaultdict(set)
        for summary in summaries:
            artifact_id = summary["artifact"]["artifact_id"]
            for anchor_kind in summary["anchor_kind_counts"].keys():
                signature = f"{anchor_kind}|{artifact_id}"
                artifact_signatures[artifact_id].add(signature)
        
        if len(artifact_signatures) > 1:
            all_sigs = list(artifact_signatures.values())
            shared = all_sigs[0].copy()
            for sigs in all_sigs[1:]:
                shared &= sigs
            shared_signatures = list(shared)
        
        for artifact_id, sigs in artifact_signatures.items():
            other_sigs = set()
            for other_id, other in artifact_signatures.items():
                if other_id != artifact_id:
                    other_sigs.update(other)
            unique = sigs - other_sigs
            unique_signatures[artifact_id] = list(unique)
        
        disagreements: dict[str, Any] = {
            "artifacts_with_exclusive_anchor_kind": defaultdict(list),
            "artifacts_missing_anchor_kind": defaultdict(list),
            "per_artifact": {},
        }
        
        for summary in summaries:
            artifact_id = summary["artifact"]["artifact_id"]
            artifact_kinds = set(summary["anchor_kind_counts"].keys())
            
            other_kinds = set()
            for other_summary in summaries:
                if other_summary["artifact"]["artifact_id"] != artifact_id:
                    other_kinds.update(other_summary["anchor_kind_counts"].keys())
            
            exclusive = artifact_kinds - other_kinds
            missing = other_kinds - artifact_kinds
            
            for k in exclusive:
                disagreements["artifacts_with_exclusive_anchor_kind"][k].append(artifact_id)
            for k in missing:
                disagreements["artifacts_missing_anchor_kind"][k].append(artifact_id)
            
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
    
    async def list_shared_canonical_refs(
        self,
        kind: str = "reference",
        min_artifacts: int = 2,
        limit: int = 10,
        address_space: str | None = None,
        limit_artifacts: int = 25,
        limit_anchors: int = 10,
    ) -> list[dict[str, Any]]:
        """List shared canonical references asynchronously."""
        sql = """
            SELECT canonical_ref, COUNT(DISTINCT artifact_id) as artifact_count
            FROM entities
            WHERE kind = ? AND canonical_ref != ''
        """
        params = [kind]
        
        if address_space:
            sql += " AND location_json LIKE ?"
            params.append(f'"address_space": "{address_space}"%')
        
        sql += """
            GROUP BY canonical_ref
            HAVING artifact_count >= ?
            ORDER BY artifact_count DESC
            LIMIT ?
        """
        params.extend([min_artifacts, limit])
        
        cursor = await self._execute(sql, tuple(params))
        rows = await self._fetchall(cursor)
        
        results = []
        for row in rows:
            ref = row["canonical_ref"]
            artifact_count = row["artifact_count"]
            
            entities = await self.find_entities_by_canonical_ref(ref, kind=kind, limit=limit_artifacts)
            artifact_ids = list(set(e.artifact_id for e in entities))[:limit_artifacts]
            
            all_related_kinds: set[str] = set()
            all_anchor_entities: set[str] = set()
            for entity in entities[:limit_anchors]:
                all_related_kinds.add(entity.kind)
                all_anchor_entities.add(entity.entity_id)
                edges = await self.get_neighbors(entity.entity_id, limit=limit_anchors)
                for edge in edges:
                    for eid in [edge.source_entity_id, edge.target_entity_id]:
                        e = await self.get_entity(eid)
                        if e and e.artifact_id in artifact_ids:
                            all_related_kinds.add(e.kind)
                            all_anchor_entities.add(e.entity_id)
            
            anchor_kinds = list(all_related_kinds)[:limit_anchors]
            
            section_count = 0
            for e in entities[:limit_anchors]:
                edges = await self.get_neighbors(e.entity_id, limit=limit_anchors)
                for edge in edges:
                    other_id = edge.target_entity_id if edge.source_entity_id == e.entity_id else edge.source_entity_id
                    other = await self.get_entity(other_id)
                    if other and other.kind == "section":
                        section_count += 1
            
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
        
        results.sort(key=lambda x: x["ranking_score"], reverse=True)
        return results
    
    # Import/Export helpers
    
    async def import_bundle_from_sync_store(
        self, sync_store: Any, artifact_ids: list[str] | None = None
    ) -> dict[str, int]:
        """Import data from a synchronous ReverseEngineeringStore.
        
        This is useful for migrating data or batch imports from sync code.
        
        Args:
            sync_store: A ReverseEngineeringStore instance
            artifact_ids: Optional list of artifact IDs to import (imports all if None)
            
        Returns:
            Dictionary with import counts
        """
        loop = asyncio.get_event_loop()
        
        if artifact_ids is None:
            artifacts = await loop.run_in_executor(None, sync_store.list_artifacts, "", 10000)
            artifact_ids = [a.artifact_id for a in artifacts]
        
        total_artifacts = 0
        total_entities = 0
        total_evidence = 0
        total_edges = 0
        
        for artifact_id in artifact_ids:
            artifact = await loop.run_in_executor(None, sync_store.get_artifact, artifact_id)
            if artifact:
                await self.bulk_insert_artifacts([artifact])
                total_artifacts += 1
            
            entities = await loop.run_in_executor(
                None, sync_store.get_entities_for_artifact, artifact_id, None, 10000
            )
            if entities:
                await self.bulk_insert_entities(entities)
                total_entities += len(entities)
            
            evidence = await loop.run_in_executor(
                None, sync_store.get_evidence_for_artifact, artifact_id, None, 10000
            )
            if evidence:
                await self.bulk_insert_evidence(evidence)
                total_evidence += len(evidence)
            
            edges = await loop.run_in_executor(
                None, sync_store.get_edges_for_artifact, artifact_id, 10000
            )
            if edges:
                await self.bulk_insert_edges(edges)
                total_edges += len(edges)
        
        return {
            "artifacts": total_artifacts,
            "entities": total_entities,
            "evidence": total_evidence,
            "edges": total_edges,
        }
