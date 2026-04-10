"""SQLite storage with FTS5 full-text search and sqlite-vec vector search."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from pathlib import Path

import sqlite_vec

from codemunch_pro.parser.symbols import Symbol

logger = logging.getLogger(__name__)

DEFAULT_DB_DIR = Path.home() / '.codemunch-pro'

SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Metadata
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Indexed files with content hash for incremental updates
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    path TEXT UNIQUE NOT NULL,
    sha256 TEXT NOT NULL,
    language TEXT,
    size_bytes INTEGER,
    indexed_at TEXT DEFAULT (datetime('now'))
);

-- Extracted symbols
CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY,
    file_id INTEGER REFERENCES files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    language TEXT NOT NULL,
    signature TEXT,
    docstring TEXT,
    decorators TEXT,
    parent_name TEXT,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL,
    byte_length INTEGER NOT NULL
);

-- Call graph edges
CREATE TABLE IF NOT EXISTS call_edges (
    id INTEGER PRIMARY KEY,
    caller_id INTEGER REFERENCES symbols(id) ON DELETE CASCADE,
    callee_name TEXT NOT NULL,
    callee_id INTEGER REFERENCES symbols(id) ON DELETE SET NULL,
    line INTEGER
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_qualified ON symbols(qualified_name);
CREATE INDEX IF NOT EXISTS idx_symbols_kind ON symbols(kind);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_id);
CREATE INDEX IF NOT EXISTS idx_call_callee ON call_edges(callee_name);
CREATE INDEX IF NOT EXISTS idx_call_caller ON call_edges(caller_id);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
"""

FTS_SQL = """
-- FTS5 for symbol search
CREATE VIRTUAL TABLE IF NOT EXISTS symbols_fts USING fts5(
    name, qualified_name, signature, docstring,
    content=symbols, content_rowid=id
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS symbols_ai AFTER INSERT ON symbols BEGIN
    INSERT INTO symbols_fts(rowid, name, qualified_name, signature, docstring)
    VALUES (new.id, new.name, new.qualified_name, new.signature, new.docstring);
END;

CREATE TRIGGER IF NOT EXISTS symbols_ad AFTER DELETE ON symbols BEGIN
    INSERT INTO symbols_fts(symbols_fts, rowid, name, qualified_name, signature, docstring)
    VALUES ('delete', old.id, old.name, old.qualified_name, old.signature, old.docstring);
END;

CREATE TRIGGER IF NOT EXISTS symbols_au AFTER UPDATE ON symbols BEGIN
    INSERT INTO symbols_fts(symbols_fts, rowid, name, qualified_name, signature, docstring)
    VALUES ('delete', old.id, old.name, old.qualified_name, old.signature, old.docstring);
    INSERT INTO symbols_fts(rowid, name, qualified_name, signature, docstring)
    VALUES (new.id, new.name, new.qualified_name, new.signature, new.docstring);
END;

-- FTS5 for file content search
CREATE VIRTUAL TABLE IF NOT EXISTS file_content_fts USING fts5(
    path, content
);
"""

VEC_SQL = """
-- sqlite-vec for semantic vector search (384-dim, FastEmbed bge-small-en-v1.5)
CREATE VIRTUAL TABLE IF NOT EXISTS symbols_vec USING vec0(
    embedding float[384]
);
"""


def _normalize_rel_path(path: str) -> str:
    """Normalize repository-relative paths to POSIX separators."""
    return path.replace("\\", "/")


class Database:
    """Per-repo SQLite database with FTS5 and vector search."""

    def __init__(self, repo_path: str, db_dir: Path | None = None):
        self.repo_path = str(Path(repo_path).resolve())
        self.db_dir = db_dir or DEFAULT_DB_DIR
        self.db_dir.mkdir(parents=True, exist_ok=True)

        # Create a stable DB name from repo path
        repo_hash = hashlib.sha256(self.repo_path.encode()).hexdigest()[:12]
        repo_name = Path(self.repo_path).name
        self.db_path = self.db_dir / f'{repo_name}_{repo_hash}.db'

        self.conn = self._connect()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        """Create and configure SQLite connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA synchronous=NORMAL')

        # Load sqlite-vec extension
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)

        return conn

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        cur = self.conn.cursor()

        # Create core tables
        cur.executescript(SCHEMA_SQL)

        # Check if FTS tables exist
        tables = {
            row[0]
            for row in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        if 'symbols_fts' not in tables:
            cur.executescript(FTS_SQL)

        if 'symbols_vec' not in tables:
            cur.execute(VEC_SQL)

        # Store metadata
        cur.execute(
            'INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)',
            ('schema_version', str(SCHEMA_VERSION)),
        )
        cur.execute(
            'INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)',
            ('repo_path', self.repo_path),
        )
        self.conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()

    # --- File operations ---

    def get_file_hash(self, path: str) -> str | None:
        """Get the stored SHA-256 hash for a file path."""
        path = _normalize_rel_path(path)
        row = self.conn.execute(
            'SELECT sha256 FROM files WHERE path = ?', (path,)
        ).fetchone()
        return row['sha256'] if row else None

    def upsert_file(
        self,
        path: str,
        sha256: str,
        language: str | None,
        size_bytes: int,
        symbols: list[Symbol],
        file_content: str = '',
    ) -> int:
        """Insert or update a file and its symbols.

        Returns the file ID.
        """
        path = _normalize_rel_path(path)
        cur = self.conn.cursor()

        # Check if file exists
        existing = cur.execute(
            'SELECT id FROM files WHERE path = ?', (path,)
        ).fetchone()

        if existing:
            file_id = existing['id']
            # Delete old symbols (cascades to call_edges)
            cur.execute('DELETE FROM symbols WHERE file_id = ?', (file_id,))
            # Delete old FTS content
            cur.execute(
                "DELETE FROM file_content_fts WHERE path = ?", (path,)
            )
            # Delete old vectors
            cur.execute(
                'DELETE FROM symbols_vec WHERE rowid IN '
                '(SELECT id FROM symbols WHERE file_id = ?)',
                (file_id,),
            )
            # Update file record
            cur.execute(
                'UPDATE files SET sha256 = ?, language = ?, size_bytes = ?, '
                'indexed_at = datetime("now") WHERE id = ?',
                (sha256, language, size_bytes, file_id),
            )
        else:
            cur.execute(
                'INSERT INTO files (path, sha256, language, size_bytes) '
                'VALUES (?, ?, ?, ?)',
                (path, sha256, language, size_bytes),
            )
            file_id = cur.lastrowid

        # Insert symbols
        symbol_id_map: dict[str, int] = {}  # qualified_name -> id
        for sym in symbols:
            cur.execute(
                'INSERT INTO symbols '
                '(file_id, name, qualified_name, kind, language, signature, '
                'docstring, decorators, parent_name, line, end_line, '
                'byte_offset, byte_length) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    file_id, sym.name, sym.qualified_name, sym.kind,
                    sym.language, sym.signature, sym.docstring,
                    json.dumps(sym.decorators) if sym.decorators else None,
                    sym.parent_name, sym.line, sym.end_line,
                    sym.byte_offset, sym.byte_length,
                ),
            )
            symbol_row_id = cur.lastrowid
            if symbol_row_id is None:
                raise RuntimeError(f'Failed to insert symbol row for {sym.qualified_name}')
            symbol_id_map[sym.qualified_name] = int(symbol_row_id)

        # Insert call edges
        for sym in symbols:
            caller_id = symbol_id_map.get(sym.qualified_name)
            if caller_id and sym.calls:
                for call in sym.calls:
                    callee_id = symbol_id_map.get(call.callee_name)
                    cur.execute(
                        'INSERT INTO call_edges (caller_id, callee_name, callee_id, line) '
                        'VALUES (?, ?, ?, ?)',
                        (caller_id, call.callee_name, callee_id, call.line),
                    )

        # Insert file content for FTS
        if file_content:
            cur.execute(
                'INSERT INTO file_content_fts (path, content) VALUES (?, ?)',
                (path, file_content),
            )

        self.conn.commit()
        return file_id

    def delete_file(self, path: str) -> None:
        """Delete a file and all its symbols."""
        path = _normalize_rel_path(path)
        cur = self.conn.cursor()
        file_row = cur.execute(
            'SELECT id FROM files WHERE path = ?', (path,)
        ).fetchone()

        if file_row:
            file_id = file_row['id']
            # Delete vectors for this file's symbols
            cur.execute(
                'DELETE FROM symbols_vec WHERE rowid IN '
                '(SELECT id FROM symbols WHERE file_id = ?)',
                (file_id,),
            )
            # Cascading delete handles symbols and call_edges
            cur.execute('DELETE FROM files WHERE id = ?', (file_id,))
            cur.execute(
                "DELETE FROM file_content_fts WHERE path = ?", (path,)
            )
            self.conn.commit()

    def get_all_file_hashes(self) -> dict[str, str]:
        """Get {path: sha256} for all indexed files."""
        rows = self.conn.execute('SELECT path, sha256 FROM files').fetchall()
        return {row['path']: row['sha256'] for row in rows}

    # --- Symbol queries ---

    def get_symbol(self, qualified_name: str) -> dict | None:
        """Get a symbol by qualified name."""
        row = self.conn.execute(
            'SELECT s.*, f.path as file_path FROM symbols s '
            'JOIN files f ON s.file_id = f.id '
            'WHERE s.qualified_name = ?',
            (qualified_name,),
        ).fetchone()
        return dict(row) if row else None

    def get_symbols_batch(self, qualified_names: list[str]) -> list[dict]:
        """Get multiple symbols by qualified names."""
        if not qualified_names:
            return []
        placeholders = ','.join('?' for _ in qualified_names)
        rows = self.conn.execute(
            f'SELECT s.*, f.path as file_path FROM symbols s '
            f'JOIN files f ON s.file_id = f.id '
            f'WHERE s.qualified_name IN ({placeholders})',
            qualified_names,
        ).fetchall()
        return [dict(row) for row in rows]

    def get_file_symbols(self, file_path: str) -> list[dict]:
        """Get all symbols in a file, ordered by line number."""
        file_path = _normalize_rel_path(file_path)
        rows = self.conn.execute(
            'SELECT s.*, f.path as file_path FROM symbols s '
            'JOIN files f ON s.file_id = f.id '
            'WHERE f.path = ? ORDER BY s.line',
            (file_path,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_all_symbols(
        self,
        kind_filter: str = '',
        limit: int = 500,
    ) -> list[dict]:
        """Get all symbols in the repo, optionally filtered by kind."""
        query = (
            'SELECT s.name, s.qualified_name, s.kind, s.language, '
            's.line, s.signature, f.path as file_path '
            'FROM symbols s JOIN files f ON s.file_id = f.id'
        )
        params: list = []
        if kind_filter:
            query += ' WHERE s.kind = ?'
            params.append(kind_filter)
        query += ' ORDER BY f.path, s.line LIMIT ?'
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # --- Search ---

    def search_fts(self, query: str, limit: int = 20) -> list[dict]:
        """Full-text search across symbol names, signatures, docstrings."""
        # Escape FTS5 special characters
        safe_query = query.replace('"', '""')
        rows = self.conn.execute(
            'SELECT s.*, f.path as file_path, rank '
            'FROM symbols_fts fts '
            'JOIN symbols s ON fts.rowid = s.id '
            'JOIN files f ON s.file_id = f.id '
            'WHERE symbols_fts MATCH ? '
            'ORDER BY rank LIMIT ?',
            (f'"{safe_query}"', limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def search_text(
        self, query: str, glob: str = '', limit: int = 20,
    ) -> list[dict]:
        """Full-text search in file contents."""
        safe_query = query.replace('"', '""')
        if glob:
            rows = self.conn.execute(
                'SELECT path, snippet(file_content_fts, 1, ">>>", "<<<", "...", 40) as snippet, rank '
                'FROM file_content_fts '
                'WHERE file_content_fts MATCH ? AND path GLOB ? '
                'ORDER BY rank LIMIT ?',
                (f'"{safe_query}"', glob, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                'SELECT path, snippet(file_content_fts, 1, ">>>", "<<<", "...", 40) as snippet, rank '
                'FROM file_content_fts '
                'WHERE file_content_fts MATCH ? '
                'ORDER BY rank LIMIT ?',
                (f'"{safe_query}"', limit),
            ).fetchall()
        return [dict(row) for row in rows]

    # --- Vector search ---

    def store_embedding(self, symbol_id: int, embedding: list[float]) -> None:
        """Store a vector embedding for a symbol."""
        from sqlite_vec import serialize_float32
        self.conn.execute(
            'INSERT OR REPLACE INTO symbols_vec (rowid, embedding) VALUES (?, ?)',
            (symbol_id, serialize_float32(embedding)),
        )

    def store_embeddings_batch(
        self, items: list[tuple[int, list[float]]],
    ) -> None:
        """Batch store vector embeddings."""
        from sqlite_vec import serialize_float32
        for symbol_id, embedding in items:
            self.conn.execute(
                'INSERT OR REPLACE INTO symbols_vec (rowid, embedding) VALUES (?, ?)',
                (symbol_id, serialize_float32(embedding)),
            )
        self.conn.commit()

    def search_vec(
        self, query_embedding: list[float], limit: int = 20,
    ) -> list[dict]:
        """Vector similarity search."""
        from sqlite_vec import serialize_float32
        rows = self.conn.execute(
            'SELECT v.rowid, v.distance, s.*, f.path as file_path '
            'FROM symbols_vec v '
            'JOIN symbols s ON v.rowid = s.id '
            'JOIN files f ON s.file_id = f.id '
            'WHERE v.embedding MATCH ? '
            'ORDER BY v.distance LIMIT ?',
            (serialize_float32(query_embedding), limit),
        ).fetchall()
        return [dict(row) for row in rows]

    # --- Call graph ---

    def get_callees(
        self, qualified_name: str, depth: int = 1,
    ) -> list[dict]:
        """Get what a function calls (outgoing edges), with depth traversal."""
        visited: set[str] = set()
        results: list[dict] = []
        self._traverse_callees(qualified_name, depth, 0, visited, results)
        return results

    def _traverse_callees(
        self,
        qualified_name: str,
        max_depth: int,
        current_depth: int,
        visited: set[str],
        results: list[dict],
    ) -> None:
        if current_depth >= max_depth or qualified_name in visited:
            return
        visited.add(qualified_name)

        sym = self.get_symbol(qualified_name)
        if not sym:
            return

        rows = self.conn.execute(
            'SELECT ce.callee_name, ce.callee_id, ce.line, '
            's.qualified_name as resolved_name, s.kind, s.line as def_line, '
            'f.path as def_file '
            'FROM call_edges ce '
            'JOIN symbols caller ON ce.caller_id = caller.id '
            'LEFT JOIN symbols s ON ce.callee_id = s.id '
            'LEFT JOIN files f ON s.file_id = f.id '
            'WHERE caller.qualified_name = ?',
            (qualified_name,),
        ).fetchall()

        for row in rows:
            d = dict(row)
            d['depth'] = current_depth + 1
            results.append(d)

            # Recurse if resolved
            resolved = d.get('resolved_name')
            if resolved and resolved not in visited:
                self._traverse_callees(
                    resolved, max_depth, current_depth + 1, visited, results,
                )

    def get_callers(
        self, qualified_name: str, depth: int = 1,
    ) -> list[dict]:
        """Get who calls a function (incoming edges), with depth traversal."""
        visited: set[str] = set()
        results: list[dict] = []
        self._traverse_callers(qualified_name, depth, 0, visited, results)
        return results

    def _traverse_callers(
        self,
        qualified_name: str,
        max_depth: int,
        current_depth: int,
        visited: set[str],
        results: list[dict],
    ) -> None:
        if current_depth >= max_depth or qualified_name in visited:
            return
        visited.add(qualified_name)

        # Find by callee_name or by resolved callee_id
        rows = self.conn.execute(
            'SELECT ce.line, s.qualified_name as caller_name, s.kind, '
            's.line as caller_line, f.path as caller_file '
            'FROM call_edges ce '
            'JOIN symbols s ON ce.caller_id = s.id '
            'JOIN files f ON s.file_id = f.id '
            'WHERE ce.callee_name = ? OR ce.callee_name LIKE ?',
            (qualified_name, f'%.{qualified_name.split(".")[-1]}'),
        ).fetchall()

        for row in rows:
            d = dict(row)
            d['depth'] = current_depth + 1
            results.append(d)

            caller = d.get('caller_name')
            if caller and caller not in visited:
                self._traverse_callers(
                    caller, max_depth, current_depth + 1, visited, results,
                )

    def resolve_call_edges(self) -> int:
        """Post-indexing: resolve callee_name → callee_id for all unresolved edges."""
        cur = self.conn.cursor()
        updated = cur.execute(
            'UPDATE call_edges SET callee_id = ('
            '  SELECT s.id FROM symbols s '
            '  WHERE s.name = call_edges.callee_name '
            '  OR s.qualified_name = call_edges.callee_name '
            '  LIMIT 1'
            ') WHERE callee_id IS NULL',
        ).rowcount
        self.conn.commit()
        return updated

    # --- File tree ---

    def get_file_tree(
        self, path_prefix: str = '', depth: int = 3,
    ) -> list[dict]:
        """Get directory tree with file counts and symbol counts."""
        rows = self.conn.execute(
            'SELECT f.path, f.language, f.size_bytes, '
            '(SELECT COUNT(*) FROM symbols s WHERE s.file_id = f.id) as symbol_count '
            'FROM files f WHERE f.path LIKE ? '
            'ORDER BY f.path',
            (f'{path_prefix}%',),
        ).fetchall()
        return [dict(row) for row in rows]

    # --- Stats ---

    def get_stats(self) -> dict:
        """Get database statistics."""
        files = self.conn.execute('SELECT COUNT(*) as c FROM files').fetchone()['c']
        symbols = self.conn.execute('SELECT COUNT(*) as c FROM symbols').fetchone()['c']
        edges = self.conn.execute('SELECT COUNT(*) as c FROM call_edges').fetchone()['c']
        resolved = self.conn.execute(
            'SELECT COUNT(*) as c FROM call_edges WHERE callee_id IS NOT NULL'
        ).fetchone()['c']

        langs = self.conn.execute(
            'SELECT language, COUNT(*) as c FROM files '
            'WHERE language IS NOT NULL GROUP BY language'
        ).fetchall()

        kinds = self.conn.execute(
            'SELECT kind, COUNT(*) as c FROM symbols GROUP BY kind'
        ).fetchall()

        return {
            'repo_path': self.repo_path,
            'db_path': str(self.db_path),
            'files': files,
            'symbols': symbols,
            'call_edges': edges,
            'resolved_edges': resolved,
            'languages': {row['language']: row['c'] for row in langs},
            'symbol_kinds': {row['kind']: row['c'] for row in kinds},
        }
