"""CodeMunch Pro MCP Server with code indexing and reverse-engineering tools.

Supports both stdio and streamable-http transports.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

import pathspec

from mcp.server.fastmcp import FastMCP

from codemunch_pro.embedder.embed import Embedder
from codemunch_pro.parser.extractor import extract_symbols
from codemunch_pro.parser.languages import get_language_for_file
from codemunch_pro.rex import (
    AdapterRegistry,
    BytePattern,
    DEFAULT_REX_DB_DIR,
    FlatAddressCodec,
    GenericDocumentImporter,
    GitError,
    REProjectRepo,
    ReverseEngineeringStore,
    SegmentedHexAddressCodec,
)
from codemunch_pro.security import (
    DEFAULT_IGNORE_PATTERNS,
    is_binary_file,
    is_too_large,
    validate_path,
)
from codemunch_pro.storage.database import Database

logger = logging.getLogger(__name__)

# Global state
_databases: dict[str, Database] = {}
_rex_stores: dict[str, ReverseEngineeringStore] = {}
_rex_registry: AdapterRegistry | None = None
_embedder: Embedder | None = None


def _get_embedder() -> Embedder:
    global _embedder
    if _embedder is None:
        _embedder = Embedder()
    return _embedder


def _get_db(repo_path: str) -> Database:
    """Get or create a Database for a repo path."""
    resolved = str(Path(repo_path).resolve())
    if resolved not in _databases:
        _databases[resolved] = Database(resolved)
    return _databases[resolved]


def _get_rex_registry() -> AdapterRegistry:
    """Get or create the reverse-engineering importer registry."""
    global _rex_registry
    if _rex_registry is None:
        registry = AdapterRegistry()
        registry.register_codec(SegmentedHexAddressCodec())
        registry.register_codec(FlatAddressCodec())
        registry.register_importer(GenericDocumentImporter())
        _rex_registry = registry
    return _rex_registry


def _get_rex_store(project_path: str) -> ReverseEngineeringStore:
    """Get or create a reverse-engineering store for a project path."""
    resolved = str(Path(project_path).resolve())
    if resolved not in _rex_stores:
        root = Path(resolved)
        root_hash = hashlib.sha256(resolved.encode()).hexdigest()[:12]
        db_path = DEFAULT_REX_DB_DIR / f"{root.name}_{root_hash}.db"
        _rex_stores[resolved] = ReverseEngineeringStore(db_path)
    return _rex_stores[resolved]


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def _load_gitignore(root: Path) -> pathspec.PathSpec | None:
    """Load .gitignore patterns from a directory."""
    gitignore = root / '.gitignore'
    if gitignore.is_file():
        patterns = gitignore.read_text(errors='replace').splitlines()
        return pathspec.PathSpec.from_lines('gitwildmatch', patterns)
    return None


def _walk_source_files(
    root: Path,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> list[Path]:
    """Walk directory tree and return source files to index."""
    files: list[Path] = []

    # Build ignore spec
    ignore_lines = list(DEFAULT_IGNORE_PATTERNS)
    if exclude_patterns:
        ignore_lines.extend(exclude_patterns)
    ignore_spec = pathspec.PathSpec.from_lines('gitwildmatch', ignore_lines)

    # Load .gitignore
    gitignore_spec = _load_gitignore(root)

    # Build include spec
    include_spec = None
    if include_patterns:
        include_spec = pathspec.PathSpec.from_lines(
            'gitwildmatch', include_patterns,
        )

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)

        # Filter directories
        dirnames[:] = [
            d for d in dirnames
            if not ignore_spec.match_file(os.path.join(rel_dir, d) + '/')
            and not (gitignore_spec and gitignore_spec.match_file(os.path.join(rel_dir, d) + '/'))
            and not d.startswith('.')
        ]

        for fname in filenames:
            rel_path = os.path.join(rel_dir, fname)
            full_path = Path(dirpath) / fname

            # Skip ignored files
            if ignore_spec.match_file(rel_path):
                continue
            if gitignore_spec and gitignore_spec.match_file(rel_path):
                continue

            # Apply include filter
            if include_spec and not include_spec.match_file(rel_path):
                continue

            # Must be a recognized language
            if get_language_for_file(full_path) is None:
                continue

            # Skip binary/large files
            if is_binary_file(full_path) or is_too_large(full_path):
                continue

            files.append(full_path)

    return files


def _walk_rex_artifacts(
    root: Path,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> list[Path]:
    """Walk a directory tree and return importer-supported artifacts."""
    files: list[Path] = []
    registry = _get_rex_registry()

    ignore_lines = list(DEFAULT_IGNORE_PATTERNS)
    if exclude_patterns:
        ignore_lines.extend(exclude_patterns)
    ignore_spec = pathspec.PathSpec.from_lines("gitwildmatch", ignore_lines)
    gitignore_spec = _load_gitignore(root)

    include_spec = None
    if include_patterns:
        include_spec = pathspec.PathSpec.from_lines("gitwildmatch", include_patterns)

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)

        dirnames[:] = [
            d
            for d in dirnames
            if not ignore_spec.match_file(os.path.join(rel_dir, d) + "/")
            and not (gitignore_spec and gitignore_spec.match_file(os.path.join(rel_dir, d) + "/"))
            and not d.startswith(".")
        ]

        for fname in filenames:
            rel_path = os.path.join(rel_dir, fname)
            full_path = Path(dirpath) / fname

            if ignore_spec.match_file(rel_path):
                continue
            if gitignore_spec and gitignore_spec.match_file(rel_path):
                continue
            if include_spec and not include_spec.match_file(rel_path):
                continue
            if is_binary_file(full_path) or is_too_large(full_path):
                continue
            if not registry.find_importers(full_path):
                continue

            files.append(full_path)

    return files


def _resolve_project_artifact(project_path: str, artifact_path: str) -> Path:
    """Resolve an artifact path relative to the project when needed."""
    project_root = Path(project_path).resolve()
    candidate = Path(artifact_path)
    if not candidate.is_absolute():
        candidate = project_root / candidate
    resolved = candidate.resolve()
    return resolved


def _index_artifact_path(project_path: str, artifact_path: str) -> dict[str, Any]:
    """Index a single reverse-engineering artifact into the rex store."""
    project_root = Path(project_path).resolve()
    if not project_root.is_dir():
        return {"error": f"Not a directory: {project_path}"}

    artifact = _resolve_project_artifact(project_path, artifact_path)
    if not artifact.is_file():
        return {"error": f"Not a file: {artifact_path}"}

    registry = _get_rex_registry()
    importers = registry.find_importers(artifact)
    if not importers:
        return {"error": f"No reverse-engineering importer for: {artifact.name}"}

    bundle = importers[0].ingest(artifact)
    store = _get_rex_store(str(project_root))
    store.replace_bundle(bundle)

    return {
        "project": str(project_root),
        "artifact": artifact.as_posix(),
        "importer": importers[0].name,
        "artifacts": len(bundle.artifacts),
        "entities": len(bundle.entities),
        "evidence": len(bundle.evidence),
        "edges": len(bundle.edges),
    }


def _index_artifact_folder(
    project_path: str,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """Index all importer-supported artifacts in a folder."""
    project_root = Path(project_path).resolve()
    if not project_root.is_dir():
        return {"error": f"Not a directory: {project_path}"}

    store = _get_rex_store(str(project_root))
    artifacts = _walk_rex_artifacts(project_root, include_patterns, exclude_patterns)

    stats = {
        "project": str(project_root),
        "artifacts_indexed": 0,
        "bundle_artifacts": 0,
        "entities": 0,
        "evidence": 0,
        "edges": 0,
    }

    registry = _get_rex_registry()
    for artifact in artifacts:
        importers = registry.find_importers(artifact)
        if not importers:
            continue
        bundle = importers[0].ingest(artifact)
        stats["artifacts_indexed"] += 1
        stats["bundle_artifacts"] += len(bundle.artifacts)
        stats["entities"] += len(bundle.entities)
        stats["evidence"] += len(bundle.evidence)
        stats["edges"] += len(bundle.edges)
        store.replace_bundle(bundle)
    return stats


def _search_rex_entities(
    project_path: str,
    query: str,
    kind: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """Search reverse-engineering entities in a project store."""
    store = _get_rex_store(project_path)
    limit = max(1, min(limit, 100))
    results = store.search_entities(query, kind=kind, limit=limit)
    return {
        "project": str(Path(project_path).resolve()),
        "query": query,
        "kind": kind,
        "results": results,
        "count": len(results),
    }


def _get_rex_artifact(
    project_path: str,
    artifact_path: str,
    entity_kind: str = "",
    evidence_kind: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """Fetch an indexed artifact together with its entities and evidence."""
    store = _get_rex_store(project_path)
    limit = max(1, min(limit, 500))
    resolved = _resolve_project_artifact(project_path, artifact_path)
    artifact_id = resolved.as_posix()

    artifact = store.get_artifact(artifact_id)
    if artifact is None:
        return {"error": f"Artifact not found: {artifact_path}"}

    entities = store.get_entities_for_artifact(artifact_id, kind=entity_kind, limit=limit)
    evidence = store.get_evidence_for_artifact(artifact_id, kind=evidence_kind, limit=limit)
    return {
        "project": str(Path(project_path).resolve()),
        "artifact": artifact.to_dict(),
        "entities": [item.to_dict() for item in entities],
        "evidence": [item.to_dict() for item in evidence],
        "entity_count": len(entities),
        "evidence_count": len(evidence),
        "entity_kind": entity_kind,
        "evidence_kind": evidence_kind,
    }


def _list_rex_artifacts(
    project_path: str,
    kind: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """List indexed reverse-engineering artifacts for a project."""
    store = _get_rex_store(project_path)
    limit = max(1, min(limit, 500))
    artifacts = store.list_artifacts(kind=kind, limit=limit)
    return {
        "project": str(Path(project_path).resolve()),
        "kind": kind,
        "artifacts": [item.to_dict() for item in artifacts],
        "count": len(artifacts),
    }


def _find_rex_entities_by_ref(
    project_path: str,
    canonical_ref: str,
    kind: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """Find reverse-engineering entities by exact canonical reference."""
    store = _get_rex_store(project_path)
    limit = max(1, min(limit, 500))
    entities = store.find_entities_by_canonical_ref(canonical_ref, kind=kind, limit=limit)
    return {
        "project": str(Path(project_path).resolve()),
        "canonical_ref": canonical_ref,
        "kind": kind,
        "entities": [item.to_dict() for item in entities],
        "count": len(entities),
    }


def _list_rex_entities(
    project_path: str,
    kind: str = "",
    address_space: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """List reverse-engineering entities with optional kind and address-space filters."""
    store = _get_rex_store(project_path)
    limit = max(1, min(limit, 500))
    entities = store.list_entities(kind=kind, address_space=address_space, limit=limit)
    return {
        "project": str(Path(project_path).resolve()),
        "kind": kind,
        "address_space": address_space,
        "entities": [item.to_dict() for item in entities],
        "count": len(entities),
    }


def _search_rex_evidence_range(
    project_path: str,
    address_space: str,
    start: int,
    end: int,
    artifact_id: str = "",
) -> dict[str, Any]:
    """Search evidence by address range overlap."""
    store = _get_rex_store(project_path)
    evidence = store.get_evidence_in_range(
        address_space=address_space,
        start=start,
        end=end,
        artifact_id=artifact_id if artifact_id else None,
    )
    return {
        "project": str(Path(project_path).resolve()),
        "address_space": address_space,
        "start": start,
        "end": end,
        "artifact_id": artifact_id,
        "evidence": [item.to_dict() for item in evidence],
        "count": len(evidence),
    }


def _search_rex_entities_range(
    project_path: str,
    address_space: str,
    start: int,
    end: int,
    kind: str = "",
) -> dict[str, Any]:
    """Search entities by address range overlap."""
    store = _get_rex_store(project_path)
    entities = store.get_entities_in_range(
        address_space=address_space,
        start=start,
        end=end,
        kind=kind if kind else None,
    )
    return {
        "project": str(Path(project_path).resolve()),
        "address_space": address_space,
        "start": start,
        "end": end,
        "kind": kind,
        "entities": [item.to_dict() for item in entities],
        "count": len(entities),
    }


def _get_rex_ref_context(
    project_path: str,
    canonical_ref: str,
    kind: str = "",
    evidence_limit: int = 100,
    edge_limit: int = 100,
) -> dict[str, Any]:
    """Fetch entities, evidence, and edges linked to an exact canonical reference."""
    store = _get_rex_store(project_path)
    evidence_limit = max(1, min(evidence_limit, 500))
    edge_limit = max(1, min(edge_limit, 500))
    entities = store.find_entities_by_canonical_ref(canonical_ref, kind=kind, limit=500)
    entity_ids = [entity.entity_id for entity in entities]
    evidence = store.get_evidence_for_entities(entity_ids, limit=evidence_limit)
    edges = store.get_neighbors_for_entities(entity_ids, limit=edge_limit)
    return {
        "project": str(Path(project_path).resolve()),
        "canonical_ref": canonical_ref,
        "kind": kind,
        "entities": [item.to_dict() for item in entities],
        "evidence": [item.to_dict() for item in evidence],
        "neighbors": [item.to_dict() for item in edges],
        "entity_count": len(entities),
        "evidence_count": len(evidence),
        "neighbor_count": len(edges),
    }


def _get_rex_ref_graph(
    project_path: str,
    canonical_ref: str,
    kind: str = "",
    depth: int = 2,
    edge_limit: int = 200,
) -> dict[str, Any]:
    """Traverse the reverse-engineering graph outward from an exact canonical reference."""
    store = _get_rex_store(project_path)
    depth = max(0, min(depth, 5))
    edge_limit = max(1, min(edge_limit, 1000))
    roots = store.find_entities_by_canonical_ref(canonical_ref, kind=kind, limit=500)
    traversal = store.traverse_entity_graph(
        [entity.entity_id for entity in roots],
        depth=depth,
        edge_limit=edge_limit,
    )

    node_depths: dict[str, int] = traversal["depths"]  # type: ignore[assignment]
    entities = traversal["entities"]  # type: ignore[assignment]
    edges = traversal["edges"]  # type: ignore[assignment]

    return {
        "project": str(Path(project_path).resolve()),
        "canonical_ref": canonical_ref,
        "kind": kind,
        "depth": depth,
        "root_entity_ids": traversal["root_entity_ids"],
        "entities": [
            {
                **entity.to_dict(),
                "traversal_depth": node_depths.get(entity.entity_id, 0),
            }
            for entity in entities
        ],
        "edges": [edge.to_dict() for edge in edges],
        "entity_count": len(entities),
        "edge_count": len(edges),
    }


def _get_rex_ref_paths(
    project_path: str,
    canonical_ref: str,
    kind: str = "",
    target_kind: str = "",
    depth: int = 3,
    edge_limit: int = 200,
    max_paths: int = 100,
    dedupe: bool = True,
) -> dict[str, Any]:
    """Return shortest-path style expansions from an exact canonical reference."""
    store = _get_rex_store(project_path)
    depth = max(0, min(depth, 5))
    edge_limit = max(1, min(edge_limit, 1000))
    max_paths = max(1, min(max_paths, 500))
    roots = store.find_entities_by_canonical_ref(canonical_ref, kind=kind, limit=500)
    traced = store.trace_entity_paths(
        [entity.entity_id for entity in roots],
        depth=depth,
        edge_limit=edge_limit,
    )

    entities = traced["entities"]  # type: ignore[assignment]
    edges = traced["edges"]  # type: ignore[assignment]
    paths = traced["paths"]  # type: ignore[assignment]
    entity_lookup = {entity.entity_id: entity for entity in entities}
    edge_lookup = {edge.edge_id: edge for edge in edges}

    def path_signature(path: dict[str, Any], target_entity: Any) -> str:
        artifact_id = target_entity.artifact_id or ""
        canonical = target_entity.canonical_ref or ""
        edge_kinds = ",".join(
            edge_lookup[edge_id].kind
            for edge_id in path["edge_ids"]
            if edge_id in edge_lookup
        )
        return "|".join(
            [
                target_entity.kind,
                artifact_id,
                canonical,
                target_entity.name,
                edge_kinds,
            ]
        )

    def path_sort_key(path: dict[str, Any], target_entity: Any) -> tuple[int, int, int, str, str]:
        kind_priority = {
            "section": 0,
            "document": 1,
            "field": 2,
            "reference": 3,
        }.get(target_entity.kind, 4)
        return (
            kind_priority,
            path["depth"],
            len(path["edge_ids"]),
            target_entity.artifact_id or "",
            target_entity.entity_id,
        )

    candidate_paths = []
    for path in paths:
        target_entity = entity_lookup.get(path["target_entity_id"])
        if target_entity is None:
            continue
        if target_kind and target_entity.kind != target_kind:
            continue
        candidate_paths.append(
            {
                "root_entity_id": path["root_entity_id"],
                "target_entity_id": path["target_entity_id"],
                "target_kind": target_entity.kind,
                "target_artifact_id": target_entity.artifact_id,
                "depth": path["depth"],
                "path_signature": path_signature(path, target_entity),
                "sort_key": path_sort_key(path, target_entity),
                "entities": [entity_lookup[entity_id].to_dict() for entity_id in path["entity_ids"] if entity_id in entity_lookup],
                "edges": [edge_lookup[edge_id].to_dict() for edge_id in path["edge_ids"] if edge_id in edge_lookup],
            }
        )

    candidate_paths.sort(key=lambda item: item["sort_key"])
    raw_path_count = len(candidate_paths)

    filtered_paths = []
    seen_signatures: set[str] = set()
    for path in candidate_paths:
        signature = path["path_signature"]
        if dedupe and signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        filtered_paths.append(
            {
                "rank": len(filtered_paths) + 1,
                "root_entity_id": path["root_entity_id"],
                "target_entity_id": path["target_entity_id"],
                "target_kind": path["target_kind"],
                "target_artifact_id": path["target_artifact_id"],
                "depth": path["depth"],
                "path_signature": signature,
                "entities": path["entities"],
                "edges": path["edges"],
            }
        )
        if len(filtered_paths) >= max_paths:
            break

    return {
        "project": str(Path(project_path).resolve()),
        "canonical_ref": canonical_ref,
        "kind": kind,
        "target_kind": target_kind,
        "depth": depth,
        "dedupe": dedupe,
        "dedupe_applied": dedupe and raw_path_count != len(filtered_paths),
        "root_entity_ids": traced["root_entity_ids"],
        "raw_path_count": raw_path_count,
        "paths": filtered_paths,
        "path_count": len(filtered_paths),
    }


def _get_rex_ref_provenance(
    project_path: str,
    canonical_ref: str,
    kind: str = "",
    limit_artifacts: int = 100,
    limit_anchors: int = 25,
) -> dict[str, Any]:
    """Summarize exact-reference provenance per artifact."""
    store = _get_rex_store(project_path)
    limit_artifacts = max(1, min(limit_artifacts, 500))
    limit_anchors = max(1, min(limit_anchors, 100))
    summaries = store.summarize_ref_provenance(
        canonical_ref,
        kind=kind,
        limit_artifacts=limit_artifacts,
        limit_anchors=limit_anchors,
    )
    return {
        "project": str(Path(project_path).resolve()),
        "canonical_ref": canonical_ref,
        "kind": kind,
        "artifacts": summaries,
        "artifact_count": len(summaries),
    }


def _compare_rex_ref_provenance(
    project_path: str,
    canonical_ref: str,
    kind: str = "",
    limit_artifacts: int = 100,
    limit_anchors: int = 25,
) -> dict[str, Any]:
    """Compare exact-reference provenance across artifacts."""
    store = _get_rex_store(project_path)
    limit_artifacts = max(1, min(limit_artifacts, 500))
    limit_anchors = max(1, min(limit_anchors, 100))
    comparison = store.compare_ref_provenance(
        canonical_ref,
        kind=kind,
        limit_artifacts=limit_artifacts,
        limit_anchors=limit_anchors,
    )
    return {
        "project": str(Path(project_path).resolve()),
        **comparison,
    }


def _list_rex_shared_refs(
    project_path: str,
    kind: str = "reference",
    address_space: str = "",
    min_artifacts: int = 2,
    limit: int = 100,
    limit_artifacts: int = 25,
    limit_anchors: int = 10,
) -> dict[str, Any]:
    """List canonical references shared across multiple artifacts."""
    store = _get_rex_store(project_path)
    limit = max(1, min(limit, 500))
    limit_artifacts = max(1, min(limit_artifacts, 100))
    limit_anchors = max(1, min(limit_anchors, 50))
    min_artifacts = max(1, min(min_artifacts, 100))
    results = store.list_shared_canonical_refs(
        kind=kind,
        address_space=address_space,
        min_artifacts=min_artifacts,
        limit=limit,
        limit_artifacts=limit_artifacts,
        limit_anchors=limit_anchors,
    )
    return {
        "project": str(Path(project_path).resolve()),
        "kind": kind,
        "address_space": address_space,
        "min_artifacts": min_artifacts,
        "results": results,
        "count": len(results),
    }


def _diff_rex_records(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    key: str,
) -> dict[str, Any]:
    before_map = {item[key]: item for item in before}
    after_map = {item[key]: item for item in after}

    before_keys = set(before_map)
    after_keys = set(after_map)
    added_keys = sorted(after_keys - before_keys)
    removed_keys = sorted(before_keys - after_keys)
    common_keys = sorted(before_keys & after_keys)
    changed_keys = [item_key for item_key in common_keys if before_map[item_key] != after_map[item_key]]

    return {
        "added": [after_map[item_key] for item_key in added_keys],
        "removed": [before_map[item_key] for item_key in removed_keys],
        "changed": [
            {
                key: item_key,
                "before": before_map[item_key],
                "after": after_map[item_key],
            }
            for item_key in changed_keys
        ],
        "summary": {
            "added": len(added_keys),
            "removed": len(removed_keys),
            "changed": len(changed_keys),
        },
    }


def _diff_rex_artifact(
    project_path: str,
    artifact_path: str,
    apply: bool = False,
) -> dict[str, Any]:
    """Compare the stored artifact graph against the current importer output."""
    project_root = Path(project_path).resolve()
    if not project_root.is_dir():
        return {"error": f"Not a directory: {project_path}"}

    artifact = _resolve_project_artifact(project_path, artifact_path)
    if not artifact.is_file():
        return {"error": f"Not a file: {artifact_path}"}

    registry = _get_rex_registry()
    importers = registry.find_importers(artifact)
    if not importers:
        return {"error": f"No reverse-engineering importer for: {artifact.name}"}

    importer = importers[0]
    new_bundle = importer.ingest(artifact)
    store = _get_rex_store(str(project_root))
    artifact_id = artifact.as_posix()

    stored_artifact = store.get_artifact(artifact_id)
    old_artifacts = [stored_artifact.to_dict()] if stored_artifact is not None else []
    old_entities = [item.to_dict() for item in store.get_entities_for_artifact(artifact_id, limit=10000)]
    old_evidence = [item.to_dict() for item in store.get_evidence_for_artifact(artifact_id, limit=10000)]
    old_edges = [item.to_dict() for item in store.get_edges_for_artifact(artifact_id, limit=10000)]

    new_artifacts = [item.to_dict() for item in new_bundle.artifacts]
    new_entities = [item.to_dict() for item in new_bundle.entities]
    new_evidence = [item.to_dict() for item in new_bundle.evidence]
    new_edges = [item.to_dict() for item in new_bundle.edges]

    artifact_diff = _diff_rex_records(old_artifacts, new_artifacts, "artifact_id")
    entity_diff = _diff_rex_records(old_entities, new_entities, "entity_id")
    evidence_diff = _diff_rex_records(old_evidence, new_evidence, "evidence_id")
    edge_diff = _diff_rex_records(old_edges, new_edges, "edge_id")

    if apply:
        store.replace_bundle(new_bundle)

    return {
        "project": str(project_root),
        "artifact": artifact_id,
        "importer": importer.name,
        "applied": apply,
        "artifact_diff": artifact_diff,
        "entity_diff": entity_diff,
        "evidence_diff": evidence_diff,
        "edge_diff": edge_diff,
        "stored_previously": stored_artifact is not None,
        "summary": {
            "artifacts_added": artifact_diff["summary"]["added"],
            "artifacts_removed": artifact_diff["summary"]["removed"],
            "artifacts_changed": artifact_diff["summary"]["changed"],
            "entities_added": entity_diff["summary"]["added"],
            "entities_removed": entity_diff["summary"]["removed"],
            "entities_changed": entity_diff["summary"]["changed"],
            "evidence_added": evidence_diff["summary"]["added"],
            "evidence_removed": evidence_diff["summary"]["removed"],
            "evidence_changed": evidence_diff["summary"]["changed"],
            "edges_added": edge_diff["summary"]["added"],
            "edges_removed": edge_diff["summary"]["removed"],
            "edges_changed": edge_diff["summary"]["changed"],
        },
    }


def _index_directory(
    repo_path: str,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    embed: bool = True,
) -> dict[str, Any]:
    """Core indexing logic used by index_folder and index_repo tools."""
    root = Path(repo_path).resolve()
    if not root.is_dir():
        return {'error': f'Not a directory: {repo_path}'}

    db = _get_db(str(root))
    existing_hashes = db.get_all_file_hashes()
    source_files = _walk_source_files(root, include_patterns, exclude_patterns)

    stats = {
        'total_files': len(source_files),
        'indexed': 0,
        'skipped_unchanged': 0,
        'deleted': 0,
        'symbols_extracted': 0,
        'errors': 0,
    }

    # Track current file paths
    current_paths: set[str] = set()

    # Batch embeddings
    embed_queue: list[tuple[int, str]] = []  # (symbol_id, text)

    for file_path in source_files:
        rel_path = file_path.relative_to(root).as_posix()
        current_paths.add(rel_path)

        # Incremental: skip unchanged files
        file_hash = _sha256_file(file_path)
        if existing_hashes.get(rel_path) == file_hash:
            stats['skipped_unchanged'] += 1
            continue

        try:
            symbols = extract_symbols(file_path)
            language = get_language_for_file(file_path)
            content = file_path.read_text(errors='replace')
            size = file_path.stat().st_size

            db.upsert_file(
                path=rel_path,
                sha256=file_hash,
                language=language,
                size_bytes=size,
                symbols=symbols,
                file_content=content,
            )

            stats['indexed'] += 1
            stats['symbols_extracted'] += len(symbols)

            # Queue symbols for embedding
            if embed:
                embedder = _get_embedder()
                for sym in symbols:
                    text = embedder.format_symbol_text(
                        name=sym.name,
                        kind=sym.kind,
                        signature=sym.signature,
                        docstring=sym.docstring,
                        language=sym.language,
                    )
                    # We need the symbol ID from the DB
                    sym_row = db.get_symbol(sym.qualified_name)
                    if sym_row:
                        embed_queue.append((sym_row['id'], text))

        except Exception as e:
            logger.warning('Error indexing %s: %s', file_path, e)
            stats['errors'] += 1

    # Remove deleted files
    for old_path in existing_hashes:
        if old_path not in current_paths:
            db.delete_file(old_path)
            stats['deleted'] += 1

    # Resolve call graph edges
    resolved = db.resolve_call_edges()
    stats['call_edges_resolved'] = resolved

    # Batch embed
    if embed and embed_queue:
        try:
            embedder = _get_embedder()
            texts = [text for _, text in embed_queue]
            vectors = embedder.embed(texts)
            items = [
                (sym_id, vec)
                for (sym_id, _), vec in zip(embed_queue, vectors)
            ]
            db.store_embeddings_batch(items)
            stats['embeddings_stored'] = len(items)
        except Exception as e:
            logger.warning('Embedding error: %s', e)
            stats['embedding_error'] = str(e)

    return stats


def _search_byte_pattern(
    project_path: str,
    pattern: str,
    address_space: str = "",
    mask: int | None = None,
    context_bytes: int = 16,
    max_results: int = 100,
) -> dict[str, Any]:
    """Search for a byte pattern in the reverse-engineering store.

    Args:
        project_path: Root path used to scope the reverse-engineering store.
        pattern: Pattern string with wildcards (e.g., "A9 ?? 8D 00 21").
        address_space: Optional address space to filter by.
        mask: Optional bit mask to apply to matched bytes.
        context_bytes: Number of context bytes to include (default 16).
        max_results: Maximum number of results (default 100).

    Returns:
        Dictionary with matches and metadata.
    """
    store = _get_rex_store(project_path)

    # Parse and validate the pattern
    try:
        byte_pattern = BytePattern.parse(pattern)
    except ValueError as e:
        return {
            "error": f"Invalid pattern: {e}",
            "pattern": pattern,
        }

    # Perform the search
    results = store.search_byte_pattern(
        pattern=byte_pattern,
        address_space=address_space if address_space else None,
        mask=mask,
        data=None,  # Search stored entities
        context_bytes=context_bytes,
        max_results=max_results,
    )

    return {
        "project": str(Path(project_path).resolve()),
        "pattern": pattern,
        "parsed_pattern": byte_pattern.raw_pattern,
        "pattern_length": len(byte_pattern),
        "address_space": address_space,
        "mask": f"0x{mask:02X}" if mask is not None else None,
        "results": results,
        "count": len(results),
        "max_results": max_results,
    }


def _extract_strings(
    project_path: str,
    binary_path: str,
    base_address: int = 0,
    min_length: int = 4,
    encoding: str = "",
    find_xrefs: bool = True,
    pointer_size: int = 4,
    address_space: str = "flat",
) -> dict[str, Any]:
    """Extract strings from a binary file with cross-reference tracking.
    
    Args:
        project_path: Root path used to scope the reverse-engineering store.
        binary_path: Path to the binary file.
        base_address: Base address for the binary data.
        min_length: Minimum string length to extract.
        encoding: Encoding filter (empty for all).
        find_xrefs: Whether to find cross-references.
        pointer_size: Pointer size in bytes.
        address_space: Name of the address space.
        
    Returns:
        Dictionary with extracted strings and cross-references.
    """
    from pathlib import Path
    from codemunch_pro.rex.string_extraction import (
        BinaryStringImporter,
        StringEncoding,
    )
    
    project_root = Path(project_path).resolve()
    binary_file = Path(binary_path)
    
    if not binary_file.is_absolute():
        binary_file = project_root / binary_file
    
    binary_file = binary_file.resolve()
    
    if not binary_file.is_file():
        return {"error": f"Binary file not found: {binary_path}"}
    
    try:
        binary_file.read_bytes()
    except (IOError, OSError) as e:
        return {"error": f"Failed to read binary file: {e}"}
    
    # Determine encodings to use
    encodings = None
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
    
    # Create importer and extract strings
    importer = BinaryStringImporter(
        min_length=min_length,
        encodings=encodings,
        find_xrefs=find_xrefs,
        pointer_size=pointer_size,
    )
    
    try:
        bundle = importer.ingest(
            path=binary_file,
            base_address=base_address,
            address_space=address_space,
        )
    except Exception as e:
        return {"error": f"Failed to extract strings: {e}"}
    
    # Store the bundle in the rex store
    store = _get_rex_store(project_path)
    store.replace_bundle(bundle)
    
    # Build result
    strings = [
        {
            "address": entity.location.start if entity.location else 0,
            "text": entity.attributes.get("full_text", entity.name),
            "encoding": entity.attributes.get("encoding", "unknown"),
            "type": entity.attributes.get("string_type", "unknown"),
            "length": entity.attributes.get("length", 0),
        }
        for entity in bundle.entities
        if entity.kind == "string"
    ]
    
    xrefs = [
        {
            "code_address": edge.attributes.get("code_address"),
            "string_address": edge.attributes.get("string_address"),
            "xref_type": edge.attributes.get("xref_type", "unknown"),
        }
        for edge in bundle.edges
        if edge.kind == "references_string"
    ]
    
    return {
        "project": str(project_root),
        "binary_path": str(binary_file),
        "base_address": f"0x{base_address:08X}",
        "address_space": address_space,
        "min_length": min_length,
        "encoding": encoding or "all",
        "pointer_size": pointer_size,
        "strings": strings,
        "string_count": len(strings),
        "xrefs": xrefs,
        "xref_count": len(xrefs),
    }


def _get_string_xrefs(
    project_path: str,
    string_address: int,
) -> dict[str, Any]:
    """Get cross-references to a string at the given address.
    
    Args:
        project_path: Root path used to scope the reverse-engineering store.
        string_address: Address of the string.
        
    Returns:
        Dictionary with cross-references.
    """
    store = _get_rex_store(project_path)
    xrefs = store.get_string_xrefs(string_address)
    
    return {
        "project": str(Path(project_path).resolve()),
        "string_address": f"0x{string_address:08X}",
        "xrefs": xrefs,
        "count": len(xrefs),
    }


def create_server(
    transport: str = 'stdio',
    port: int = 5002,
) -> FastMCP:
    """Create and configure the MCP server."""

    kwargs: dict[str, Any] = {
        'name': 'CodeMunch Pro',
    }
    if transport == 'streamable-http':
        kwargs.update({
            'host': '0.0.0.0',
            'port': port,
            'streamable_http_path': '/mcp',
            'stateless_http': True,
            'json_response': True,
        })

    mcp = FastMCP(**kwargs)
    _register_server_tools(mcp)
    return mcp


def _register_server_tools(mcp: FastMCP) -> None:
    _register_code_index_tools(mcp)
    _register_rex_analysis_tools(mcp)
    _register_runtime_tools(mcp)


def _register_code_index_tools(mcp: FastMCP) -> None:
    # --- Tool 1: index_folder ---
    @mcp.tool()
    def index_folder(
        path: str,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        embed: bool = True,
    ) -> dict[str, Any]:
        """Index a local directory. Extracts symbols from source files using tree-sitter AST parsing.

        Supports 10 languages: Python, JavaScript, TypeScript, Go, Rust, Java, C, C++, C#, Ruby.
        Uses incremental indexing — only re-parses files that changed (SHA-256 comparison).
        Generates vector embeddings for semantic search.

        Args:
            path: Absolute path to the directory to index.
            include_patterns: Optional glob patterns to include (e.g. ["src/**/*.py"]).
            exclude_patterns: Optional glob patterns to exclude (e.g. ["tests/**"]).
            embed: Whether to generate vector embeddings (default True, set False for faster indexing).
        """
        try:
            validated = validate_path(path)
            if not validated.is_dir():
                return {'error': f'Not a directory: {path}'}
        except ValueError as e:
            return {'error': str(e)}

        return _index_directory(
            str(validated), include_patterns, exclude_patterns, embed,
        )

    # --- Tool 2: index_repo ---
    @mcp.tool()
    def index_repo(
        url: str,
        branch: str = '',
        token: str = '',
        sparse_paths: list[str] | None = None,
        embed: bool = True,
    ) -> dict[str, Any]:
        """Index a GitHub or GitLab repository by downloading its tarball.

        No git binary needed. Downloads the repo archive, extracts, and indexes.
        Subsequent calls use a cache — only re-downloads if new commits exist.

        Args:
            url: Repository URL (e.g. "https://github.com/owner/repo").
            branch: Branch to index (default: repo's default branch).
            token: Optional auth token for private repos (GitHub PAT or GitLab token).
            sparse_paths: Optional list of paths to index (e.g. ["src/", "lib/"]).
            embed: Whether to generate vector embeddings (default True).
        """
        from codemunch_pro.remote import fetch_repo

        try:
            fetch_result = fetch_repo(
                url=url,
                branch=branch,
                token=token,
                sparse_paths=sparse_paths,
            )
        except Exception as e:
            return {'error': f'Failed to fetch repo: {e}'}

        if 'error' in fetch_result:
            return fetch_result

        local_path = fetch_result['local_path']

        # Index the downloaded repo
        index_stats = _index_directory(
            local_path,
            embed=embed,
        )

        return {
            **index_stats,
            'repo_url': url,
            'branch': fetch_result['branch'],
            'sha': fetch_result['sha'],
            'cached': fetch_result['cached'],
            'local_path': local_path,
        }

    # --- Tool 3: list_repos ---
    @mcp.tool()
    def list_repos() -> dict[str, Any]:
        """List all indexed repositories with stats.

        Returns repository paths, file counts, symbol counts, and languages.
        """
        repos = []
        for path, db in _databases.items():
            stats = db.get_stats()
            repos.append(stats)

        # Also check for DB files on disk
        from codemunch_pro.storage.database import DEFAULT_DB_DIR
        if DEFAULT_DB_DIR.exists():
            for db_file in DEFAULT_DB_DIR.glob('*.db'):
                # Open and check if not already loaded
                try:
                    with sqlite3.connect(str(db_file)) as conn:
                        conn.row_factory = sqlite3.Row
                        row = conn.execute(
                            "SELECT value FROM meta WHERE key = 'repo_path'"
                        ).fetchone()
                        if row and row["value"] not in _databases:
                            db = _get_db(row["value"])
                            repos.append(db.get_stats())
                except (sqlite3.Error, OSError, ValueError) as exc:
                    logger.debug("Skipping DB file %s during repo scan: %s", db_file, exc)

        return {'repos': repos, 'count': len(repos)}

    # --- Tool 4: invalidate_cache ---
    @mcp.tool()
    def invalidate_cache(repo_path: str) -> dict[str, Any]:
        """Force re-index a repository by clearing its cache.

        Deletes the stored hashes so all files are re-parsed on next index.

        Args:
            repo_path: Path to the repository to invalidate.
        """
        db = _get_db(repo_path)
        cur = db.conn.cursor()
        cur.execute('DELETE FROM files')
        cur.execute('DELETE FROM symbols')
        cur.execute('DELETE FROM call_edges')
        cur.execute('DELETE FROM symbols_vec')
        cur.execute("DELETE FROM file_content_fts")
        db.conn.commit()
        return {'status': 'cache_cleared', 'repo': repo_path}

    # --- Tool 5: file_tree ---
    @mcp.tool()
    def file_tree(
        repo_path: str,
        path_prefix: str = '',
        depth: int = 3,
    ) -> dict[str, Any]:
        """Get the directory tree of an indexed repository.

        Shows files with their language, size, and symbol count.

        Args:
            repo_path: Path to the indexed repository.
            path_prefix: Optional path prefix to filter (e.g. "src/").
            depth: Maximum directory depth to show (default 3).
        """
        db = _get_db(repo_path)
        files = db.get_file_tree(path_prefix, depth)

        # Build tree structure
        tree: dict[str, Any] = {}
        for f in files:
            parts = f['path'].split('/')
            # Limit depth
            if len(parts) > depth + 1:
                continue
            node = tree
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = {
                'language': f['language'],
                'size': f['size_bytes'],
                'symbols': f['symbol_count'],
            }

        return {
            'tree': tree,
            'total_files': len(files),
            'repo': repo_path,
        }

    # --- Tool 6: file_outline ---
    @mcp.tool()
    def file_outline(
        repo_path: str,
        file_path: str,
    ) -> dict[str, Any]:
        """List all symbols in a single file, ordered by line number.

        Shows functions, classes, methods, types, and interfaces with their signatures.

        Args:
            repo_path: Path to the indexed repository.
            file_path: Relative path to the file within the repo (e.g. "src/main.py").
        """
        db = _get_db(repo_path)
        symbols = db.get_file_symbols(file_path)
        return {
            'file': file_path,
            'symbols': [
                {
                    'name': s['name'],
                    'qualified_name': s['qualified_name'],
                    'kind': s['kind'],
                    'line': s['line'],
                    'end_line': s['end_line'],
                    'signature': s['signature'],
                    'docstring': (s.get('docstring') or '')[:100],
                }
                for s in symbols
            ],
            'count': len(symbols),
        }

    # --- Tool 7: repo_outline ---
    @mcp.tool()
    def repo_outline(
        repo_path: str,
        kind_filter: str = '',
        limit: int = 200,
    ) -> dict[str, Any]:
        """List all symbols in the repository (summary view).

        Returns a compact list of all functions, classes, methods, etc.
        Use kind_filter to show only specific types.

        Args:
            repo_path: Path to the indexed repository.
            kind_filter: Optional filter: "function", "class", "method", "type", "interface".
            limit: Maximum symbols to return (default 200, max 500).
        """
        db = _get_db(repo_path)
        limit = max(1, min(limit, 500))
        symbols = db.get_all_symbols(kind_filter, limit)
        return {
            'symbols': [
                {
                    'qualified_name': s['qualified_name'],
                    'kind': s['kind'],
                    'file': s['file_path'],
                    'line': s['line'],
                    'signature': s['signature'],
                }
                for s in symbols
            ],
            'count': len(symbols),
            'repo': repo_path,
        }

    # --- Tool 8: get_symbol ---
    @mcp.tool()
    def get_symbol(
        repo_path: str,
        qualified_name: str,
    ) -> dict[str, Any]:
        """Get the full source code of a specific symbol using O(1) byte-offset seek.

        Retrieves the exact bytes of a function, class, or method without reading the entire file.
        This is the key token-saving feature — get exactly what you need.

        Args:
            repo_path: Path to the indexed repository.
            qualified_name: Fully qualified name (e.g. "MyClass.my_method" or "my_function").
        """
        db = _get_db(repo_path)
        sym = db.get_symbol(qualified_name)
        if not sym:
            return {'error': f'Symbol not found: {qualified_name}'}

        # O(1) byte seek to extract source
        file_path = Path(repo_path) / sym['file_path']
        try:
            with open(file_path, 'rb') as f:
                f.seek(sym['byte_offset'])
                source = f.read(sym['byte_length']).decode('utf-8', errors='replace')
        except (OSError, ValueError) as e:
            return {'error': f'Cannot read source: {e}', 'symbol': dict(sym)}

        return {
            'qualified_name': sym['qualified_name'],
            'kind': sym['kind'],
            'language': sym['language'],
            'file': sym['file_path'],
            'line': sym['line'],
            'end_line': sym['end_line'],
            'signature': sym['signature'],
            'docstring': sym.get('docstring', ''),
            'source': source,
            'byte_length': sym['byte_length'],
        }

    # --- Tool 9: get_symbols ---
    @mcp.tool()
    def get_symbols(
        repo_path: str,
        qualified_names: list[str],
    ) -> dict[str, Any]:
        """Batch get source code for multiple symbols at once.

        More efficient than calling get_symbol repeatedly. Returns all requested symbols
        with their full source code.

        Args:
            repo_path: Path to the indexed repository.
            qualified_names: List of fully qualified names to retrieve.
        """
        results = []
        for qname in qualified_names[:50]:  # Cap at 50
            result = get_symbol(repo_path=repo_path, qualified_name=qname)
            results.append(result)

        return {
            'symbols': results,
            'count': len(results),
            'requested': len(qualified_names),
        }

    # --- Tool 10: search_symbols ---
    @mcp.tool()
    def search_symbols(
        repo_path: str,
        query: str,
        kind: str = '',
        limit: int = 20,
    ) -> dict[str, Any]:
        """Hybrid search across all symbols using FTS5 + vector similarity.

        Combines keyword matching (BM25) with semantic similarity (embeddings)
        using Reciprocal Rank Fusion for best results.

        Args:
            repo_path: Path to the indexed repository.
            query: Search query (natural language or code terms).
            kind: Optional filter: "function", "class", "method", "type", "interface".
            limit: Maximum results (default 20).
        """
        db = _get_db(repo_path)
        limit = max(1, min(limit, 50))

        # FTS5 search
        fts_results = db.search_fts(query, limit * 2)

        # Vector search
        vec_results = []
        try:
            embedder = _get_embedder()
            query_vec = embedder.embed_one(query)
            if query_vec:
                vec_results = db.search_vec(query_vec, limit * 2)
        except Exception as e:
            logger.warning('Vector search failed: %s', e)

        # Reciprocal Rank Fusion (k=60)
        scores: dict[str, float] = {}
        symbol_data: dict[str, dict] = {}
        K = 60

        for rank, r in enumerate(fts_results):
            qn = r['qualified_name']
            scores[qn] = scores.get(qn, 0) + 1 / (K + rank)
            symbol_data[qn] = r

        for rank, r in enumerate(vec_results):
            qn = r['qualified_name']
            scores[qn] = scores.get(qn, 0) + 1 / (K + rank)
            if qn not in symbol_data:
                symbol_data[qn] = r

        # Sort by fused score
        ranked = sorted(scores.items(), key=lambda x: -x[1])

        # Apply kind filter
        results = []
        for qn, score in ranked:
            if kind and symbol_data[qn].get('kind') != kind:
                continue
            sym = symbol_data[qn]
            results.append({
                'qualified_name': sym['qualified_name'],
                'kind': sym['kind'],
                'file': sym.get('file_path', ''),
                'line': sym['line'],
                'signature': sym.get('signature', ''),
                'docstring': (sym.get('docstring') or '')[:100],
                'score': round(score, 4),
            })
            if len(results) >= limit:
                break

        return {
            'results': results,
            'count': len(results),
            'query': query,
            'search_type': 'hybrid' if vec_results else 'fts_only',
        }

    # --- Tool 11: search_text ---
    @mcp.tool()
    def search_text(
        repo_path: str,
        query: str,
        glob: str = '',
        limit: int = 20,
    ) -> dict[str, Any]:
        """Full-text search in file contents (strings, comments, config values).

        Searches the raw text of all indexed files, not just symbol names.
        Useful for finding string literals, TODO comments, config values, error messages.

        Args:
            repo_path: Path to the indexed repository.
            query: Text to search for.
            glob: Optional file glob pattern (e.g. "*.py", "src/**/*.ts").
            limit: Maximum results (default 20).
        """
        db = _get_db(repo_path)
        limit = max(1, min(limit, 50))
        results = db.search_text(query, glob, limit)
        return {
            'results': results,
            'count': len(results),
            'query': query,
        }

    # --- Tool 12: get_callees ---
    @mcp.tool()
    def get_callees(
        repo_path: str,
        qualified_name: str,
        depth: int = 1,
    ) -> dict[str, Any]:
        """Get what a function calls (outgoing call graph edges).

        Traces the call graph from a function to see what it invokes.
        Use depth > 1 for transitive callees.

        Args:
            repo_path: Path to the indexed repository.
            qualified_name: Fully qualified name of the function to trace from.
            depth: How deep to traverse (1 = direct calls, 2 = calls of calls, etc).
        """
        db = _get_db(repo_path)
        depth = max(1, min(depth, 5))
        callees = db.get_callees(qualified_name, depth)
        return {
            'function': qualified_name,
            'callees': callees,
            'count': len(callees),
            'depth': depth,
        }

    # --- Tool 13: get_callers ---
    @mcp.tool()
    def get_callers(
        repo_path: str,
        qualified_name: str,
        depth: int = 1,
    ) -> dict[str, Any]:
        """Get who calls a function (incoming call graph edges).

        Traces the call graph backwards to find all callers of a function.
        Use depth > 1 for transitive callers.

        Args:
            repo_path: Path to the indexed repository.
            qualified_name: Fully qualified name of the function to trace.
            depth: How deep to traverse (1 = direct callers, 2 = callers of callers, etc).
        """
        db = _get_db(repo_path)
        depth = max(1, min(depth, 5))
        callers = db.get_callers(qualified_name, depth)
        return {
            'function': qualified_name,
            'callers': callers,
            'count': len(callers),
            'depth': depth,
        }

    # --- Tool 14: diff_symbols ---
    @mcp.tool()
    def diff_symbols(
        repo_path: str,
    ) -> dict[str, Any]:
        """Re-index a repository and show what symbols changed since last index.

        Compares the current state of files against the stored index to find:
        - New symbols (added since last index)
        - Removed symbols (deleted since last index)
        - Modified symbols (same name but different content hash)

        Useful for code review, PR analysis, and understanding what changed.

        Args:
            repo_path: Path to an already-indexed repository.
        """
        root = Path(repo_path).resolve()
        if not root.is_dir():
            return {'error': f'Not a directory: {repo_path}'}

        db = _get_db(str(root))

        # Snapshot current symbols
        old_symbols: dict[str, dict] = {}
        for sym in db.get_all_symbols(limit=10000):
            qn = sym['qualified_name']
            old_symbols[qn] = {
                'kind': sym['kind'],
                'file': sym.get('file_path', ''),
                'line': sym['line'],
                'signature': sym.get('signature', ''),
            }

        # Snapshot current file hashes
        old_hashes = db.get_all_file_hashes()

        # Find changed files
        source_files = _walk_source_files(root)
        changed_files: list[str] = []
        new_files: list[str] = []
        for file_path in source_files:
            rel_path = str(file_path.relative_to(root))
            file_hash = _sha256_file(file_path)
            if rel_path not in old_hashes:
                new_files.append(rel_path)
                changed_files.append(rel_path)
            elif old_hashes[rel_path] != file_hash:
                changed_files.append(rel_path)

        # Deleted files
        current_paths = {str(f.relative_to(root)) for f in source_files}
        deleted_files = [p for p in old_hashes if p not in current_paths]

        # Re-extract symbols from changed files only
        new_symbols: dict[str, dict] = {}
        for file_path in source_files:
            rel_path = str(file_path.relative_to(root))
            if rel_path in changed_files or rel_path in new_files:
                try:
                    symbols = extract_symbols(file_path)
                    for sym in symbols:
                        new_symbols[sym.qualified_name] = {
                            'kind': sym.kind,
                            'file': rel_path,
                            'line': sym.line,
                            'signature': sym.signature,
                        }
                except Exception as exc:
                    logger.debug("Failed to extract symbols for %s during diff: %s", rel_path, exc)
            else:
                # Unchanged — carry forward old symbols for this file
                for qn, data in old_symbols.items():
                    if data['file'] == rel_path:
                        new_symbols[qn] = data

        # Compute diff
        old_names = set(old_symbols.keys())
        new_names = set(new_symbols.keys())

        added = []
        for qn in sorted(new_names - old_names):
            s = new_symbols[qn]
            added.append({
                'qualified_name': qn,
                'kind': s['kind'],
                'file': s['file'],
                'line': s['line'],
                'signature': s['signature'],
            })

        removed = []
        for qn in sorted(old_names - new_names):
            s = old_symbols[qn]
            removed.append({
                'qualified_name': qn,
                'kind': s['kind'],
                'file': s['file'],
                'line': s['line'],
            })

        modified = []
        for qn in sorted(old_names & new_names):
            old = old_symbols[qn]
            new = new_symbols[qn]
            if old.get('signature') != new.get('signature') or old.get('line') != new.get('line'):
                modified.append({
                    'qualified_name': qn,
                    'kind': new['kind'],
                    'file': new['file'],
                    'old_line': old['line'],
                    'new_line': new['line'],
                    'old_signature': old.get('signature', ''),
                    'new_signature': new.get('signature', ''),
                })

        return {
            'added': added,
            'removed': removed,
            'modified': modified,
            'summary': {
                'added_count': len(added),
                'removed_count': len(removed),
                'modified_count': len(modified),
                'changed_files': len(changed_files),
                'new_files': len(new_files),
                'deleted_files': len(deleted_files),
            },
        }

    # --- Tool 15: dependency_map ---
    @mcp.tool()
    def dependency_map(
        repo_path: str,
        file_path: str,
    ) -> dict[str, Any]:
        """Show what a file depends on and what depends on it.

        Maps import/call relationships at the file level. Useful for understanding
        how a file fits in the codebase before modifying it.

        Args:
            repo_path: Path to the indexed repository.
            file_path: Relative path to the file (e.g. "src/main.py").
        """
        db = _get_db(repo_path)

        # Get all symbols in this file
        file_symbols = db.get_file_symbols(file_path)
        if not file_symbols:
            return {'error': f'File not found in index: {file_path}'}

        file_symbol_names = {s['qualified_name'] for s in file_symbols}
        file_symbol_names.update(s['name'] for s in file_symbols)

        # Find outgoing dependencies (what this file's symbols call)
        depends_on: dict[str, list[str]] = {}  # file -> [symbol names called]
        for sym in file_symbols:
            callees = db.get_callees(sym['qualified_name'], depth=1)
            for callee in callees:
                callee_file = callee.get('def_file', '')
                if callee_file and callee_file != file_path:
                    depends_on.setdefault(callee_file, [])
                    name = callee.get('resolved_name') or callee.get('callee_name', '')
                    if name and name not in depends_on[callee_file]:
                        depends_on[callee_file].append(name)

        # Find incoming dependencies (what calls symbols in this file)
        depended_by: dict[str, list[str]] = {}  # file -> [symbol names that call us]
        for sym in file_symbols:
            callers = db.get_callers(sym['qualified_name'], depth=1)
            for caller in callers:
                caller_file = caller.get('caller_file', '')
                if caller_file and caller_file != file_path:
                    depended_by.setdefault(caller_file, [])
                    name = caller.get('caller_name', '')
                    if name and name not in depended_by[caller_file]:
                        depended_by[caller_file].append(name)

        return {
            'file': file_path,
            'symbols_count': len(file_symbols),
            'depends_on': {k: v for k, v in sorted(depends_on.items())},
            'depended_by': {k: v for k, v in sorted(depended_by.items())},
            'depends_on_files': len(depends_on),
            'depended_by_files': len(depended_by),
        }



def _register_rex_analysis_tools(mcp: FastMCP) -> None:
    # --- Tool 16: index_artifact ---
    @mcp.tool()
    def index_artifact(
        project_path: str,
        artifact_path: str,
    ) -> dict[str, Any]:
        """Index a single reverse-engineering artifact into the rex store.

        Supports generic document-style artifacts such as markdown notes, JSON
        reports, YAML manifests, text files, and asm-like sources.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            artifact_path: Absolute path or project-relative path to the artifact.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}
        return _index_artifact_path(project_path, artifact_path)

    # --- Tool 17: index_artifact_folder ---
    @mcp.tool()
    def index_artifact_folder(
        project_path: str,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> dict[str, Any]:
        """Index all importer-supported reverse-engineering artifacts in a folder.

        Args:
            project_path: Root directory to scan.
            include_patterns: Optional glob filters (e.g. ["reports/**/*.md"]).
            exclude_patterns: Optional glob exclusions.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}
        return _index_artifact_folder(project_path, include_patterns, exclude_patterns)

    # --- Tool 18: search_evidence ---
    @mcp.tool()
    def search_evidence(
        project_path: str,
        query: str,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Search reverse-engineering evidence excerpts within a project store."""
        store = _get_rex_store(project_path)
        limit = max(1, min(limit, 100))
        results = store.search_evidence(query, limit)
        return {
            'project': str(Path(project_path).resolve()),
            'query': query,
            'results': results,
            'count': len(results),
        }

    # --- Tool 19: get_rex_entity ---
    @mcp.tool()
    def get_rex_entity(
        project_path: str,
        entity_id: str,
    ) -> dict[str, Any]:
        """Fetch a reverse-engineering entity and its linked evidence."""
        store = _get_rex_store(project_path)
        entity = store.get_entity(entity_id)
        if entity is None:
            return {'error': f'Entity not found: {entity_id}'}
        evidence = store.get_evidence_for_entity(entity_id)
        return {
            'project': str(Path(project_path).resolve()),
            'entity': entity.to_dict(),
            'evidence': [item.to_dict() for item in evidence],
            'evidence_count': len(evidence),
        }

    # --- Tool 20: get_rex_neighbors ---
    @mcp.tool()
    def get_rex_neighbors(
        project_path: str,
        entity_id: str,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Get neighboring reverse-engineering edges for an entity."""
        store = _get_rex_store(project_path)
        limit = max(1, min(limit, 200))
        neighbors = store.get_neighbors(entity_id, limit)
        return {
            'project': str(Path(project_path).resolve()),
            'entity_id': entity_id,
            'neighbors': [edge.to_dict() for edge in neighbors],
            'count': len(neighbors),
        }

    # --- Tool 21: search_rex_entities ---
    @mcp.tool()
    def search_rex_entities(
        project_path: str,
        query: str,
        kind: str = '',
        limit: int = 20,
    ) -> dict[str, Any]:
        """Search reverse-engineering entities by name, summary, or canonical reference."""
        return _search_rex_entities(project_path, query, kind, limit)

    # --- Tool 22: get_rex_artifact ---
    @mcp.tool()
    def get_rex_artifact(
        project_path: str,
        artifact_path: str,
        entity_kind: str = '',
        evidence_kind: str = '',
        limit: int = 100,
    ) -> dict[str, Any]:
        """Fetch an indexed reverse-engineering artifact with linked entities and evidence."""
        return _get_rex_artifact(project_path, artifact_path, entity_kind, evidence_kind, limit)

    # --- Tool 23: list_rex_artifacts ---
    @mcp.tool()
    def list_rex_artifacts(
        project_path: str,
        kind: str = '',
        limit: int = 100,
    ) -> dict[str, Any]:
        """List indexed reverse-engineering artifacts for a project."""
        return _list_rex_artifacts(project_path, kind, limit)

    # --- Tool 24: diff_rex_artifact ---
    @mcp.tool()
    def diff_rex_artifact(
        project_path: str,
        artifact_path: str,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Diff stored reverse-engineering records for an artifact against current importer output."""
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}
        return _diff_rex_artifact(project_path, artifact_path, apply)

    # --- Tool 25: find_rex_entities_by_ref ---
    @mcp.tool()
    def find_rex_entities_by_ref(
        project_path: str,
        canonical_ref: str,
        kind: str = '',
        limit: int = 100,
    ) -> dict[str, Any]:
        """Find reverse-engineering entities by exact canonical reference."""
        return _find_rex_entities_by_ref(project_path, canonical_ref, kind, limit)

    # --- Tool 26: list_rex_entities ---
    @mcp.tool()
    def list_rex_entities(
        project_path: str,
        kind: str = '',
        address_space: str = '',
        limit: int = 100,
    ) -> dict[str, Any]:
        """List reverse-engineering entities with optional kind and address-space filters."""
        return _list_rex_entities(project_path, kind, address_space, limit)

    # --- Tool 27: search_rex_evidence_range ---
    @mcp.tool()
    def search_rex_evidence_range(
        project_path: str,
        address_space: str,
        start: int,
        end: int,
        artifact_id: str = '',
    ) -> dict[str, Any]:
        """Search reverse-engineering evidence by address range overlap.

        Returns all evidence records whose location overlaps with the given range.
        Useful for finding all evidence within a specific memory region or address range.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            address_space: Address space name (e.g., "segmented-hex", "flat").
            start: Start address of the range (inclusive).
            end: End address of the range (inclusive).
            artifact_id: Optional artifact ID to filter by specific artifact.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}
        return _search_rex_evidence_range(
            project_path,
            address_space,
            start,
            end,
            artifact_id,
        )

    # --- Tool 28: search_rex_entities_range ---
    @mcp.tool()
    def search_rex_entities_range(
        project_path: str,
        address_space: str,
        start: int,
        end: int,
        kind: str = '',
    ) -> dict[str, Any]:
        """Search reverse-engineering entities by address range overlap.

        Returns all entity records whose location overlaps with the given range.
        Useful for finding all entities (functions, data, references) within a
        specific memory region or address range.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            address_space: Address space name (e.g., "segmented-hex", "flat").
            start: Start address of the range (inclusive).
            end: End address of the range (inclusive).
            kind: Optional entity kind filter (e.g., "reference", "function").
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}
        return _search_rex_entities_range(
            project_path,
            address_space,
            start,
            end,
            kind,
        )

    # --- Tool 29: get_rex_ref_context ---
    @mcp.tool()
    def get_rex_ref_context(
        project_path: str,
        canonical_ref: str,
        kind: str = '',
        evidence_limit: int = 100,
        edge_limit: int = 100,
    ) -> dict[str, Any]:
        """Fetch entities, evidence, and graph edges linked to an exact canonical reference."""
        return _get_rex_ref_context(project_path, canonical_ref, kind, evidence_limit, edge_limit)

    # --- Tool 30: get_rex_ref_graph ---
    @mcp.tool()
    def get_rex_ref_graph(
        project_path: str,
        canonical_ref: str,
        kind: str = '',
        depth: int = 2,
        edge_limit: int = 200,
    ) -> dict[str, Any]:
        """Traverse the reverse-engineering graph outward from an exact canonical reference."""
        return _get_rex_ref_graph(project_path, canonical_ref, kind, depth, edge_limit)

    # --- Tool 31: get_rex_ref_paths ---
    @mcp.tool()
    def get_rex_ref_paths(
        project_path: str,
        canonical_ref: str,
        kind: str = '',
        target_kind: str = '',
        depth: int = 3,
        edge_limit: int = 200,
        max_paths: int = 100,
        dedupe: bool = True,
    ) -> dict[str, Any]:
        """Return shortest-path style expansions from an exact canonical reference."""
        return _get_rex_ref_paths(project_path, canonical_ref, kind, target_kind, depth, edge_limit, max_paths, dedupe)

    # --- Tool 32: get_rex_ref_provenance ---
    @mcp.tool()
    def get_rex_ref_provenance(
        project_path: str,
        canonical_ref: str,
        kind: str = '',
        limit_artifacts: int = 100,
        limit_anchors: int = 25,
    ) -> dict[str, Any]:
        """Summarize exact-reference provenance per artifact."""
        return _get_rex_ref_provenance(project_path, canonical_ref, kind, limit_artifacts, limit_anchors)

    # --- Tool 33: compare_rex_ref_provenance ---
    @mcp.tool()
    def compare_rex_ref_provenance(
        project_path: str,
        canonical_ref: str,
        kind: str = '',
        limit_artifacts: int = 100,
        limit_anchors: int = 25,
    ) -> dict[str, Any]:
        """Compare exact-reference provenance across artifacts."""
        return _compare_rex_ref_provenance(project_path, canonical_ref, kind, limit_artifacts, limit_anchors)

    # --- Tool 34: list_rex_shared_refs ---
    @mcp.tool()
    def list_rex_shared_refs(
        project_path: str,
        kind: str = 'reference',
        address_space: str = '',
        min_artifacts: int = 2,
        limit: int = 100,
        limit_artifacts: int = 25,
        limit_anchors: int = 10,
    ) -> dict[str, Any]:
        """List canonical references shared across multiple artifacts."""
        return _list_rex_shared_refs(
            project_path,
            kind,
            address_space,
            min_artifacts,
            limit,
            limit_artifacts,
            limit_anchors,
        )

    # --- Tool 35: search_byte_pattern ---
    @mcp.tool()
    def search_byte_pattern(
        project_path: str,
        pattern: str,
        address_space: str = '',
        mask: int | None = None,
        context_bytes: int = 16,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Search for a byte pattern with wildcards in reverse-engineering data.

        Searches indexed binary artifacts for byte sequences with support for
        wildcards (?), bit masks, and character classes. Useful for finding
        instruction sequences, magic numbers, or data signatures.

        Pattern syntax:
        - "A9 8D 00 21" - exact byte sequence
        - "A9 ?? 8D 00 21" - wildcard for single byte
        - "A9 ?D 00 21" - wildcard on nibble (matches A0-AD, B0-BD, etc.)
        - "A9 [0-9] 00 21" - character class (digits 0-9)
        - "A9 [01] 00 21" - bit mask (matches 0 or 1)

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            pattern: Byte pattern with hex bytes and wildcards (e.g., "A9 ?? 8D 00 21").
            address_space: Optional address space filter (e.g., "snes-lorom").
            mask: Optional bit mask to apply to matched bytes (0-255).
            context_bytes: Context bytes to include before/after match (default 16).
            max_results: Maximum number of matches to return (default 100, max 500).

        Returns:
            Dictionary with matches containing offset, matched_bytes, and context.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}

        max_results = max(1, min(max_results, 500))
        context_bytes = max(0, min(context_bytes, 64))

        return _search_byte_pattern(
            project_path,
            pattern,
            address_space,
            mask,
            context_bytes,
            max_results,
        )

    @mcp.tool()
    def extract_strings(
        project_path: str,
        binary_path: str,
        base_address: int = 0,
        min_length: int = 4,
        encoding: str = "",
        find_xrefs: bool = True,
        pointer_size: int = 4,
        address_space: str = "flat",
    ) -> dict[str, Any]:
        """Extract strings from a binary file with cross-reference tracking.

        Extracts readable strings from binary files using multiple encodings
        (ASCII, UTF-8, Shift-JIS, UTF-16LE/BE). Supports null-terminated strings,
        length-prefixed strings, and raw sequences. Optionally finds code
        references to each string and stores them in the edges table as
        "references_string" relationships.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            binary_path: Path to the binary file (relative to project_path or absolute).
            base_address: Base address for the binary data (default 0).
            min_length: Minimum string length to extract (default 4).
            encoding: Encoding to use - "ascii", "utf-8", "shift_jis", "utf-16-le",
                     "utf-16-be", or empty string for all encodings (default).
            find_xrefs: Whether to find cross-references to strings (default True).
            pointer_size: Pointer size in bytes - 4 for 32-bit, 8 for 64-bit (default 4).
            address_space: Name of the address space (default "flat").

        Returns:
            Dictionary with extracted strings, cross-references, and metadata.
            Strings include address, text, encoding, type, and length.
            Cross-references include code address, string address, and xref type.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}

        return _extract_strings(
            project_path,
            binary_path,
            base_address,
            min_length,
            encoding,
            find_xrefs,
            pointer_size,
            address_space,
        )

    @mcp.tool()
    def get_string_xrefs(
        project_path: str,
        string_address: int,
    ) -> dict[str, Any]:
        """Get cross-references to a string at the given address.

        Returns all code references to a specific string, showing where in the
        code the string is referenced. Useful for finding string usage in
        functions, pointer tables, and data structures.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            string_address: Address of the string to find references for.

        Returns:
            Dictionary with the string address and a list of cross-references.
            Each xref includes the code address, xref type (direct, pointer_table),
            and source information.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}

        return _get_string_xrefs(project_path, string_address)

    @mcp.tool()
    def find_similar_functions(
        project_path: str,
        function_address: int,
        threshold: float = 0.7,
        top_k: int = 10,
        algorithm: str = "fuzzy_hash",
    ) -> dict[str, Any]:
        """Find functions similar to the function at the given address.

        Uses fuzzy hashing and other similarity algorithms to detect
        code clones and similar functions in the reverse-engineering data.

        Supported algorithms:
        - "fuzzy_hash": Rolling hash based similarity (default, resilient to small changes)
        - "ngram": N-gram based similarity (good for instruction sequences)
        - "cfg": Control flow graph structure similarity
        - "combined": Weighted combination of all algorithms

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            function_address: The address of the function to find similar functions for.
            threshold: Minimum similarity score (0.0-1.0, default 0.7).
            top_k: Maximum number of similar functions to return (default 10, max 100).
            algorithm: Algorithm to use - "fuzzy_hash", "ngram", "cfg", or "combined".

        Returns:
            Dictionary with source function info and list of similar functions
            with their similarity scores and comparison details.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}

        return _find_similar_functions(
            project_path,
            function_address,
            threshold,
            top_k,
            algorithm,
        )

    # --- Graph Visualization Tools ---

    @mcp.tool()
    def export_call_graph_dot(
        repo_path: str,
        symbol_name: str,
        depth: int = 3,
    ) -> dict[str, Any]:
        """Export call graph to Graphviz DOT format.

        Generates a directed graph showing function call relationships starting
        from the specified symbol. Nodes are color-coded by type (functions=blue,
        classes=orange, methods=purple).

        Args:
            repo_path: Path to the indexed repository.
            symbol_name: Fully qualified name of the starting symbol.
            depth: How deep to traverse the call graph (1-5, default 3).
        """
        return _export_call_graph_dot(repo_path, symbol_name, depth)

    @mcp.tool()
    def export_reference_graph_dot(
        project_path: str,
        address: str,
        depth: int = 2,
    ) -> dict[str, Any]:
        """Export reference graph to Graphviz DOT format.

        Generates a directed graph showing reverse-engineering entity relationships
        starting from a canonical reference (e.g., "C3:2B00" or "0x4204").
        Nodes are color-coded by entity kind.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            address: Canonical reference address (e.g., "C3:2B00", "0x4204").
            depth: How deep to traverse the graph (1-5, default 2).
        """
        return _export_reference_graph_dot(project_path, address, depth)

    @mcp.tool()
    def export_data_flow_dot(
        project_path: str,
        symbol_name: str,
    ) -> dict[str, Any]:
        """Export data flow graph to Graphviz DOT format.

        Generates a graph showing data flow relationships for a symbol.
        Includes variable reads/writes and data dependencies. For code symbols,
        this shows callers and callees with data flow edges.

        Args:
            project_path: Path to the indexed repository or project.
            symbol_name: Name of the symbol to analyze.
        """
        return _export_data_flow_dot(project_path, symbol_name)

    @mcp.tool()
    def get_graph_statistics(project_path: str) -> dict[str, Any]:
        """Get graph statistics for a project.

        Returns statistics about the code graph including node counts by type,
        edge counts, graph density, and connectivity metrics.

        Args:
            project_path: Path to the indexed repository or project.
        """
        return _get_graph_statistics(project_path)

    @mcp.tool()
    def analyze_entropy(
        project_path: str,
        file_path: str,
        address_space: str = 'rom',
        window_size: int = 256,
        base_address: int = 0,
    ) -> dict[str, Any]:
        """Analyze entropy of a binary file to detect packed/encrypted regions.

        Uses Shannon entropy with a sliding window approach to identify regions
        of high entropy that typically indicate compressed or encrypted data.
        Returns entropy measurements per window and overall statistics.

        Args:
            project_path: Root path of the project.
            file_path: Path to the binary file (relative to project or absolute).
            address_space: Name of the address space (e.g., 'rom', 'ram').
            window_size: Size of the sliding window in bytes (default 256).
            base_address: Base address for display purposes (default 0).
        """
        return _analyze_entropy_file(
            project_path, file_path, address_space, window_size, base_address
        )

    @mcp.tool()
    def detect_packed_regions(
        project_path: str,
        file_path: str,
        address_space: str = 'rom',
        threshold: float = 7.2,
        min_region_size: int = 512,
        window_size: int = 256,
        base_address: int = 0,
    ) -> dict[str, Any]:
        """Detect packed/encrypted regions in a binary file using entropy analysis.

        Identifies contiguous regions with high entropy that are likely to be
        compressed, encrypted, or packed. Returns detected regions with
        confidence scores and entropy metrics.

        Args:
            project_path: Root path of the project.
            file_path: Path to the binary file (relative to project or absolute).
            address_space: Name of the address space (e.g., 'rom', 'ram').
            threshold: Entropy threshold for detection (default 7.2, range 0-8).
            min_region_size: Minimum region size in bytes (default 512).
            window_size: Size of the sliding window in bytes (default 256).
            base_address: Base address for display purposes (default 0).
        """
        return _detect_packed_regions_file(
            project_path,
            file_path,
            address_space,
            threshold,
            min_region_size,
            window_size,
            base_address,
        )

    @mcp.tool()
    def generate_cfg(
        project_path: str,
        function_address: int,
        format: str = "json",
        depth: int = 1,
        address_space: str = "",
    ) -> dict[str, Any]:
        """Generate a Control Flow Graph for a function.

        Creates a CFG showing basic blocks and control flow edges for the
        specified function. Supports multiple export formats.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            function_address: The address of the function to analyze.
            format: Output format - "json", "dot", or "graphml" (default: "json").
            depth: Traversal depth - 1 for single function, 2+ to include callees.
            address_space: Optional address space filter (e.g., "segmented-hex").

        Returns:
            Dictionary containing the CFG in the requested format, including
            statistics (block count, edge count, cyclomatic complexity).
        """
        store = _get_rex_store(project_path)
        depth = max(1, min(depth, 5))
        
        result = store.generate_cfg(
            function_address=function_address,
            format=format,
            depth=depth,
            address_space=address_space,
        )
        
        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    @mcp.tool()
    def get_memory_map(
        project_path: str,
        address_space: str,
        format: str = "json",
    ) -> dict[str, Any]:
        """Generate memory map visualization data for an address space.

        Creates a visual representation of the memory layout showing regions
        like ROM, RAM, VRAM, I/O registers, and System ROM. Supports multiple
        output formats including JSON data, SVG graphics, HTML page, and ASCII art.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            address_space: Address space name (e.g., "snes-lorom", "flat", "nes-prg").
            format: Output format - "json" (default), "svg", "html", "text".

        Returns:
            Dictionary containing memory map data or formatted output.
            For "json": Returns structured region data with bounds and overlaps.
            For "svg": Returns SVG vector graphics string.
            For "html": Returns complete HTML page with interactive table.
            For "text": Returns ASCII art representation.

        Example:
            get_memory_map("/path/to/project", "snes-lorom", "html")
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        memory_map = store.get_memory_map(address_space)

        if format == "json":
            return {
                "project": str(Path(project_path).resolve()),
                "address_space": address_space,
                "format": "json",
                **memory_map.to_dict(),
            }
        elif format == "svg":
            return {
                "project": str(Path(project_path).resolve()),
                "address_space": address_space,
                "format": "svg",
                "svg": memory_map.to_svg(),
            }
        elif format == "html":
            return {
                "project": str(Path(project_path).resolve()),
                "address_space": address_space,
                "format": "html",
                "html": memory_map.to_html(),
            }
        elif format == "text":
            return {
                "project": str(Path(project_path).resolve()),
                "address_space": address_space,
                "format": "text",
                "text": memory_map.to_text(),
            }
        else:
            return {
                "error": f"Unknown format: {format}. Use 'json', 'svg', 'html', or 'text'.",
                "project": str(Path(project_path).resolve()),
                "address_space": address_space,
            }

    @mcp.tool()
    def export_rex_project(
        project_path: str,
        format_type: str,
        output_path: str,
        include_functions: bool = True,
        include_data_labels: bool = True,
        include_comments: bool = True,
        include_structures: bool = True,
        include_xrefs: bool = True,
        address_space_filter: str = "",
    ) -> dict[str, Any]:
        """Export reverse-engineering project to various formats.

        Exports functions, data labels, comments, structures, and cross-references
        to formats compatible with other reverse-engineering tools.

        Supported formats:
        - "ida" or "ida_python": IDA Pro Python script (.py)
        - "ghidra" or "ghidra_xml": Ghidra XML import format (.xml)
        - "binary_ninja" or "binja": Binary Ninja Python script (.py)
        - "json": Generic JSON format for external tools (.json)
        - "csv": CSV files for spreadsheets (creates a directory with multiple CSVs)

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            format_type: Export format (ida, ghidra, binary_ninja, json, csv).
            output_path: Path for the output file or directory.
            include_functions: Include function definitions (default True).
            include_data_labels: Include data labels (default True).
            include_comments: Include comments (default True).
            include_structures: Include structures/types (default True).
            include_xrefs: Include cross-references (default True).
            address_space_filter: Optional filter by address space (e.g., "snes-lorom").

        Returns:
            Dictionary with export results including output path and item counts.

        Example:
            export_rex_project("/path/to/project", "ida", "/path/to/output.py")
            export_rex_project("/path/to/project", "json", "/path/to/export.json")
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}

        options = {
            'include_functions': include_functions,
            'include_data_labels': include_data_labels,
            'include_comments': include_comments,
            'include_structures': include_structures,
            'include_xrefs': include_xrefs,
        }

        if address_space_filter:
            options['address_space_filter'] = address_space_filter

        return _export_rex_project(project_path, format_type, output_path, options)

    # --- Git Integration Tools ---

    @mcp.tool()
    def diff_rex_project(
        project_path: str,
        commit_a: str,
        commit_b: str,
        artifact_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Compare RE artifacts between two git commits.

        Shows changes to manifests, labels, notes, and symbols between commits
        with human-readable diffs for tracking RE project evolution.

        Args:
            project_path: Root path of the git repository.
            commit_a: First commit hash or ref (e.g., "HEAD~5").
            commit_b: Second commit hash or ref (e.g., "HEAD").
            artifact_types: Optional filter - ["manifest", "label", "note", "symbol"].

        Returns:
            Dictionary with added, modified, deleted artifacts grouped by type.
        """
        try:
            repo = REProjectRepo(project_path)
        except GitError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Failed to open repository: {e}"}

        try:
            return repo.diff_rex_project(commit_a, commit_b, artifact_types)
        except Exception as e:
            return {"error": f"Failed to diff project: {e}"}

    @mcp.tool()
    def blame_artifact(
        project_path: str,
        artifact_path: str,
        line_start: int | None = None,
        line_end: int | None = None,
    ) -> dict[str, Any]:
        """Show who last modified each line of an RE artifact.

        Uses git blame to track authorship of lines in manifests, labels,
        notes, and symbol files. Useful for understanding the history of
        specific analysis or annotations.

        Args:
            project_path: Root path of the git repository.
            artifact_path: Path to the artifact (relative to project root).
            line_start: Optional starting line number for partial blame.
            line_end: Optional ending line number for partial blame.

        Returns:
            Dictionary with per-line blame information and author statistics.
        """
        try:
            repo = REProjectRepo(project_path)
        except GitError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Failed to open repository: {e}"}

        try:
            return repo.blame_artifact(artifact_path, line_start, line_end)
        except Exception as e:
            return {"error": f"Failed to blame artifact: {e}"}

    @mcp.tool()
    def log_entity(
        project_path: str,
        entity_id: str,
        artifact_pattern: str = "*",
        max_commits: int = 50,
    ) -> dict[str, Any]:
        """Get the commit history for a reverse-engineering entity.

        Searches git history for commits mentioning an entity ID in either
        commit messages or file changes. Useful for tracking the evolution
        of functions, data structures, or addresses through analysis history.

        Args:
            project_path: Root path of the git repository.
            entity_id: The entity ID to search for (e.g., function address).
            artifact_pattern: Glob pattern for artifacts to search (default "*").
            max_commits: Maximum number of commits to return (default 50).

        Returns:
            Dictionary with commit history, authors, and files changed.
        """
        try:
            repo = REProjectRepo(project_path)
        except GitError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Failed to open repository: {e}"}

        try:
            return repo.log_entity(entity_id, artifact_pattern, max_commits)
        except Exception as e:
            return {"error": f"Failed to get entity log: {e}"}

    @mcp.tool()
    def infer_structures(
        project_path: str,
        address: int,
        max_size: int = 256,
        heuristic: str = "balanced",
        pointer_size: int = 4,
        address_space: str = "flat",
    ) -> dict[str, Any]:
        """Infer data structure layout from binary access patterns.

        Uses heuristics to detect pointers, arrays, strings, integers, booleans,
        and nested structures based on memory access patterns and value analysis.
        Supports multiple heuristic strategies from conservative (high confidence only)
        to aggressive (include speculative guesses).

        Detection heuristics:
        - Pointer detection: Identifies aligned addresses pointing to valid memory
        - Array detection: Recognizes repeating patterns at regular intervals
        - String detection: Finds null-terminated or length-prefixed strings
        - Integer detection: Fills gaps with appropriately sized integers
        - Boolean detection: Single-byte fields with values 0 or 1
        - Nested structure detection: Identifies sub-structures by field clustering

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            address: Starting address of the structure to analyze (e.g., 0x1000).
            max_size: Maximum size to analyze in bytes (default 256, max 4096).
            heuristic: Detection strategy - "conservative" (high confidence),
                      "balanced" (moderate, default), or "aggressive" (speculative).
            pointer_size: Size of pointers in bytes - 4 for 32-bit, 8 for 64-bit (default 4).
            address_space: Address space identifier (default "flat").

        Returns:
            Dictionary with inferred structure containing:
            - name: Structure identifier (e.g., "struct_0x00001000")
            - address: Starting address
            - size: Detected structure size in bytes
            - fields: List of inferred fields with:
                - offset: Byte offset within structure
                - field_type: Type (pointer, array, string, integer, bool, struct)
                - size: Field size in bytes
                - name: Generated field name
                - confidence: Confidence score (0.0-1.0)
                - element_count: For arrays, number of elements
                - element_size: For arrays, size of each element
                - target_address: For pointers, the pointed-to address
                - string_encoding: For strings, detected encoding
                - nested_fields: For nested structures, child fields
            - field_count: Total number of detected fields
            - confidence: Overall structure confidence score
            - alignment: Detected alignment requirement (1, 2, 4, or 8)

        Example:
            infer_structures("/path/to/project", 0x1000, 64, "balanced", 4, "flat")
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {'error': str(e)}

        # Validate and clamp parameters
        max_size = max(1, min(max_size, 4096))
        if heuristic not in ("conservative", "balanced", "aggressive"):
            heuristic = "balanced"
        pointer_size = 4 if pointer_size == 4 else 8

        store = _get_rex_store(project_path)

        return store.infer_structures(
            address=address,
            data=None,  # Will fetch from stored evidence
            max_size=max_size,
            heuristic=heuristic,
            pointer_size=pointer_size,
            address_space=address_space,
        )



def _register_runtime_tools(mcp: FastMCP) -> None:
    # --- Debugger Tools ---

    @mcp.tool()
    def debugger_attach(
        project_path: str,
        session_id: str,
        session_type: str,
        target: str,
        emulator_type: str = "",
        rpc_url: str = "",
    ) -> dict[str, Any]:
        """Attach to a debugger or emulator for dynamic analysis.

        Creates a debugger session (GDB, LLDB, or emulator) and connects
        to the target process or device.

        Args:
            project_path: Project path for context and trace storage.
            session_id: Unique identifier for this debugger session.
            session_type: Type of debugger - "gdb", "lldb", or "emulator".
            target: Target to attach to (PID, host:port, executable path).
            emulator_type: For emulator sessions: "mgba", "mesen", "bizhawk", etc.
            rpc_url: Optional RPC URL for emulator connections.

        Returns:
            Dictionary with session status and connection info.
        """
        from codemunch_pro.rex.debugger import create_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        kwargs = {}
        if emulator_type:
            kwargs["emulator_type"] = emulator_type
        if rpc_url:
            kwargs["rpc_url"] = rpc_url

        session = create_session(session_type, session_id, **kwargs)
        if session is None:
            return {
                "error": f"Failed to create session of type: {session_type}",
                "valid_types": ["gdb", "lldb", "emulator"],
            }

        success = session.attach(target, **kwargs)

        return {
            "session_id": session_id,
            "session_type": session_type,
            "target": target,
            "connected": success,
            "state": session.state.value,
            "error": session.error_message if not success else "",
        }

    @mcp.tool()
    def debugger_detach(
        project_path: str,
        session_id: str,
    ) -> dict[str, Any]:
        """Detach from a debugger session.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID to detach.

        Returns:
            Dictionary with detach status.
        """
        from codemunch_pro.rex.debugger import get_session, remove_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        success = session.detach()
        remove_session(session_id)

        return {
            "session_id": session_id,
            "detached": success,
            "state": session.state.value,
        }

    @mcp.tool()
    def debugger_read_memory(
        project_path: str,
        session_id: str,
        address: int,
        size: int,
    ) -> dict[str, Any]:
        """Read memory from a debugger target.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID.
            address: Memory address to read from.
            size: Number of bytes to read.

        Returns:
            Dictionary with memory data in hex format.
        """
        from codemunch_pro.rex.debugger import get_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        if not session.is_connected:
            return {"error": "Session not connected"}

        result = session.read_memory(address, size)

        return {
            "session_id": session_id,
            "address": f"0x{address:08X}",
            "size": size,
            "success": result.success,
            "data": result.data.hex() if result.data else "",
            "error": result.error,
        }

    @mcp.tool()
    def debugger_write_memory(
        project_path: str,
        session_id: str,
        address: int,
        data_hex: str,
    ) -> dict[str, Any]:
        """Write memory to a debugger target.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID.
            address: Memory address to write to.
            data_hex: Hex-encoded data to write.

        Returns:
            Dictionary with write status.
        """
        from codemunch_pro.rex.debugger import get_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        if not session.is_connected:
            return {"error": "Session not connected"}

        try:
            data = bytes.fromhex(data_hex)
        except ValueError as e:
            return {"error": f"Invalid hex data: {e}"}

        success = session.write_memory(address, data)

        return {
            "session_id": session_id,
            "address": f"0x{address:08X}",
            "size": len(data),
            "success": success,
            "error": session.error_message if not success else "",
        }

    @mcp.tool()
    def debugger_set_breakpoint(
        project_path: str,
        session_id: str,
        address: int,
        condition: str = "",
    ) -> dict[str, Any]:
        """Set a breakpoint in a debugger session.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID.
            address: Address to set breakpoint at.
            condition: Optional breakpoint condition expression.

        Returns:
            Dictionary with breakpoint ID and status.
        """
        from codemunch_pro.rex.debugger import get_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        if not session.is_connected:
            return {"error": "Session not connected"}

        bp = session.set_breakpoint(address, condition=condition)

        if bp is None:
            return {"error": "Failed to set breakpoint"}

        return {
            "session_id": session_id,
            "breakpoint_id": bp.id,
            "address": f"0x{address:08X}",
            "enabled": bp.enabled,
            "condition": bp.condition,
        }

    @mcp.tool()
    def debugger_remove_breakpoint(
        project_path: str,
        session_id: str,
        breakpoint_id: str,
    ) -> dict[str, Any]:
        """Remove a breakpoint from a debugger session.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID.
            breakpoint_id: The breakpoint ID to remove.

        Returns:
            Dictionary with removal status.
        """
        from codemunch_pro.rex.debugger import get_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        success = session.remove_breakpoint(breakpoint_id)

        return {
            "session_id": session_id,
            "breakpoint_id": breakpoint_id,
            "removed": success,
        }

    @mcp.tool()
    def debugger_continue(
        project_path: str,
        session_id: str,
    ) -> dict[str, Any]:
        """Continue execution in a debugger session.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID.

        Returns:
            Dictionary with execution status.
        """
        from codemunch_pro.rex.debugger import get_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        success = session.continue_execution()

        return {
            "session_id": session_id,
            "continued": success,
            "state": session.state.value,
        }

    @mcp.tool()
    def debugger_step(
        project_path: str,
        session_id: str,
        into: bool = True,
    ) -> dict[str, Any]:
        """Step execution in a debugger session.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID.
            into: If True, step into function calls; else step over.

        Returns:
            Dictionary with step status and current state.
        """
        from codemunch_pro.rex.debugger import get_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        success = session.step(into=into)
        registers = session.get_registers()

        return {
            "session_id": session_id,
            "stepped": success,
            "state": session.state.value,
            "registers": registers.to_dict() if registers else None,
        }

    @mcp.tool()
    def debugger_get_registers(
        project_path: str,
        session_id: str,
    ) -> dict[str, Any]:
        """Get CPU registers from a debugger session.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID.

        Returns:
            Dictionary with register values.
        """
        from codemunch_pro.rex.debugger import get_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        if not session.is_connected:
            return {"error": "Session not connected"}

        registers = session.get_registers()

        if registers is None:
            return {"error": "Failed to get registers"}

        return {
            "session_id": session_id,
            "registers": registers.to_dict(),
        }

    @mcp.tool()
    def debugger_get_backtrace(
        project_path: str,
        session_id: str,
        max_frames: int = 50,
    ) -> dict[str, Any]:
        """Get call stack backtrace from a debugger session.

        Args:
            project_path: Project path for context.
            session_id: The debugger session ID.
            max_frames: Maximum number of stack frames to retrieve.

        Returns:
            Dictionary with stack frames.
        """
        from codemunch_pro.rex.debugger import get_session

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        session = get_session(session_id)
        if session is None:
            return {"error": f"Session not found: {session_id}"}

        if not session.is_connected:
            return {"error": "Session not connected"}

        frames = session.get_backtrace(max_frames=max_frames)

        return {
            "session_id": session_id,
            "frame_count": len(frames),
            "frames": [f.to_dict() for f in frames],
        }

    @mcp.tool()
    def debugger_list_sessions(
        project_path: str,
    ) -> dict[str, Any]:
        """List active debugger sessions.

        Args:
            project_path: Project path for context.

        Returns:
            Dictionary with list of active sessions.
        """
        from codemunch_pro.rex.debugger import list_sessions

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        sessions = list_sessions()

        return {
            "project": str(Path(project_path).resolve()),
            "session_count": len(sessions),
            "sessions": [
                {
                    "session_id": sid,
                    "name": session.name,
                    "state": session.state.value,
                    "connected": session.is_connected,
                }
                for sid, session in sessions
            ],
        }

    @mcp.tool()
    def debugger_store_trace(
        project_path: str,
        capture_id: str,
        entries: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Store an execution trace in the reverse-engineering database.

        Args:
            project_path: Project path for context and storage.
            capture_id: Unique identifier for this trace capture.
            entries: List of trace entries with address, disassembly, etc.
            metadata: Optional metadata about the trace.

        Returns:
            Dictionary with storage results.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        result = store.store_execution_trace(capture_id, entries, metadata)

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    @mcp.tool()
    def debugger_correlate_trace(
        project_path: str,
        capture_id: str,
        address_space: str = "",
        tolerance: int = 0,
    ) -> dict[str, Any]:
        """Correlate a stored execution trace with static analysis data.

        Args:
            project_path: Project path for context.
            capture_id: The trace capture ID to correlate.
            address_space: Optional address space filter.
            tolerance: Address matching tolerance in bytes.

        Returns:
            Dictionary with correlation results.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        result = store.correlate_trace_with_static(capture_id, address_space, tolerance)

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    @mcp.tool()
    def debugger_get_trace(
        project_path: str,
        capture_id: str,
    ) -> dict[str, Any]:
        """Retrieve a stored execution trace.

        Args:
            project_path: Project path for context.
            capture_id: The trace capture ID to retrieve.

        Returns:
            Dictionary with trace data.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        result = store.get_execution_trace(capture_id)

        if result is None:
            return {"error": f"Trace not found: {capture_id}"}

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    @mcp.tool()
    def debugger_list_traces(
        project_path: str,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List stored execution traces.

        Args:
            project_path: Project path for context.
            limit: Maximum number of traces to return.

        Returns:
            Dictionary with list of traces.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        traces = store.list_execution_traces(limit=limit)

        return {
            "project": str(Path(project_path).resolve()),
            "trace_count": len(traces),
            "traces": traces,
        }

    # --- Auto-Documentation Tool ---

    @mcp.tool()
    def auto_document_function(
        project_path: str,
        function_address: int,
        context_hint: str = "",
        address_space: str = "",
        output_format: str = "markdown",
        store_as_evidence: bool = True,
    ) -> dict[str, Any]:
        """Generate auto-documentation for a function using LLM patterns.

        Analyzes function context including called functions, calling functions,
        string references, and data access patterns to generate comprehensive
        documentation. The documentation includes:

        - Function purpose and behavior analysis
        - Input parameters (inferred from code patterns)
        - Return values (inferred from register usage)
        - Side effects (memory/register modifications)
        - Related functions (callers and callees)

        The generated documentation is stored as evidence in the reverse-engineering
        database for future reference.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            function_address: The address of the function to document (e.g., 0x1234).
            context_hint: Optional hint about the function's purpose (e.g., "handles player input").
            address_space: Optional address space filter (e.g., "rom", "ram", "snes-lorom").
            output_format: Output format - "markdown" or "plain_text" (default: "markdown").
            store_as_evidence: Whether to store the generated documentation as evidence.

        Returns:
            Dictionary containing:
            - function_address: The documented function address
            - function_name: The function name
            - documentation: The formatted documentation string
            - template: The structured documentation data
            - evidence_id: The evidence ID if stored
            - confidence: Confidence score (0.0-1.0) of the documentation

        Example:
            auto_document_function(
                "/path/to/project",
                0x1234,
                "handles player movement",
                "rom",
                "markdown"
            )
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)

        result = store.auto_document_function(
            function_address=function_address,
            context_hint=context_hint,
            address_space=address_space,
            output_format=output_format,
            store_as_evidence=store_as_evidence,
        )

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    @mcp.tool()
    def detect_anomalies(
        project_path: str,
        address_space: str,
        min_severity: str = "info",
    ) -> dict[str, Any]:
        """Detect anomalies and unusual code patterns in an address space.

        Uses statistical analysis to identify suspicious patterns including:
        - Anti-debugging techniques (RDTSC, INT3, debugger detection)
        - VM detection patterns (CPUID, SIDT, SGDT)
        - High entropy regions (packed/encrypted data)
        - Unreachable code (dead code, obfuscation)
        - Potential bugs (null pointer dereferences, unchecked returns)
        - Rare/unusual instructions

        Each anomaly includes a severity level (info, warning, critical) and
        confidence score to help prioritize analysis.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            address_space: The address space to analyze (e.g., "rom", "ram", "flat").
            min_severity: Minimum severity to report - "info", "warning", or "critical".

        Returns:
            Dictionary with anomaly detection results including:
            - total_anomalies: Total number of anomalies found
            - by_severity: Breakdown by severity level
            - anomalies: List of detailed anomaly reports with addresses,
              descriptions, confidence scores, and related details.

        Example:
            detect_anomalies("/path/to/project", "rom", "warning")
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        # Validate severity
        valid_severities = ["info", "warning", "critical"]
        if min_severity.lower() not in valid_severities:
            return {
                "error": f"Invalid severity: {min_severity}. Must be one of: {valid_severities}",
            }

        store = _get_rex_store(project_path)

        try:
            result = store.detect_anomalies(
                address_space=address_space,
                min_severity=min_severity,
            )
            return {
                "project": str(Path(project_path).resolve()),
                "address_space": address_space,
                "min_severity": min_severity,
                **result,
            }
        except Exception as e:
            return {
                "error": f"Anomaly detection failed: {e}",
                "project": str(Path(project_path).resolve()),
                "address_space": address_space,
            }

    # --- Heat Map Tool ---

    @mcp.tool()
    def generate_heat_map(
        project_path: str,
        heat_source: str,
        address_space: str,
        resolution: int = 256,
        color_scheme: str = "viridis",
        start_address: int = 0,
        end_address: int = 0,
        threshold: float = 0.0,
        output_format: str = "json",
    ) -> dict[str, Any]:
        """Generate a heat map for visualizing data over an address space.

        Creates a heat map visualization showing the distribution of various
        metrics across an address space. Useful for identifying hotspots in
        code coverage, frequently referenced functions, or high-entropy regions.

        Heat Sources:
        - "coverage": Code coverage from execution traces (requires stored traces)
        - "reference_count": Number of references to each address
        - "call_frequency": Function call frequency
        - "entropy": Entropy values (if pre-computed in entity attributes)

        Color Schemes:
        - "viridis", "plasma", "inferno", "magma": Perceptually uniform gradients
        - "hot", "cool", "jet": Classic heat map colors
        - "greyscale": Black and white
        - "red_green", "blue_yellow": Diverging schemes

        Output Formats:
        - "json": Returns cell data with addresses, values, and colors
        - "ascii": Returns ASCII art visualization for terminal display
        - "png": Returns base64-encoded PNG image (requires matplotlib)

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            heat_source: Type of data to visualize - "coverage", "reference_count",
                        "call_frequency", or "entropy".
            address_space: The address space to visualize (e.g., "flat", "rom", "ram").
            resolution: Number of cells in the heat map (default 256, range 16-4096).
            color_scheme: Color scheme name (default "viridis").
            start_address: Optional start address (0 = auto-detect from data).
            end_address: Optional end address (0 = auto-detect from data).
            threshold: Minimum value threshold for region detection (0.0-1.0).
            output_format: Output format - "json", "ascii", or "png".

        Returns:
            Dictionary containing:
            - heat_source: The heat source type used
            - address_space: The address space visualized
            - resolution: Number of cells generated
            - total_cells: Total number of data cells
            - min_value/max_value: Value range
            - color_scheme: Color scheme used
            - region_count: Number of high-heat regions detected
            - regions: List of high-heat regions (top 10)
            - format: Output format
            - cells: List of cell data (for "json" format)
            - ascii_art: ASCII visualization (for "ascii" format)
            - png_base64: Base64 PNG data (for "png" format)
            - mime_type: "image/png" (for "png" format)

        Example:
            # Generate coverage heat map as JSON
            generate_heat_map(
                "/path/to/project",
                "coverage",
                "rom",
                512,
                "hot",
            )

            # Generate reference count heat map as ASCII art
            generate_heat_map(
                "/path/to/project",
                "reference_count",
                "flat",
                output_format="ascii",
            )
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)

        # Handle optional address range
        start = start_address if start_address > 0 else None
        end = end_address if end_address > 0 else None

        # Clamp resolution
        resolution = max(16, min(resolution, 4096))

        result = store.generate_heat_map(
            heat_source=heat_source,
            address_space=address_space,
            resolution=resolution,
            color_scheme=color_scheme,
            start_address=start,
            end_address=end,
            threshold=threshold,
            output_format=output_format,
        )

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }


    @mcp.tool()
    def suggest_rename(
        project_path: str,
        entity_id: str,
        platform: str = "generic",
    ) -> dict[str, Any]:
        """Suggest new names for functions and data using smart heuristics.

        Analyzes entity context including string references, called functions,
        known library signatures, and naming patterns to generate intelligent
        rename suggestions with confidence scores.

        Supported platforms:
        - "generic": Standard C naming conventions
        - "windows": Windows API naming (CreateFile, CloseHandle, etc.)
        - "linux": Linux/Unix conventions
        - "macos": macOS/iOS conventions

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            entity_id: The entity ID to analyze (e.g., "func:0x1234").
            platform: Target platform naming convention (default: "generic").

        Returns:
            Dictionary with rename suggestions including:
            - current_name: The entity's current name
            - best_suggestion: Highest confidence suggestion
            - suggestions: List of all suggestions sorted by confidence
            - metadata: Analysis metadata
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        result = store.suggest_rename(entity_id, platform=platform)

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    # --- Integrity Checking Tool ---

    @mcp.tool()
    def check_integrity(
        project_path: str,
        auto_fix: bool = False,
    ) -> dict[str, Any]:
        """Check and optionally fix integrity issues in a reverse-engineering project.

        Validates the consistency of indexed reverse-engineering data and identifies
        potential issues that could affect analysis accuracy. Can optionally auto-fix
        safe issues.

        Checks performed:
        - Orphaned references: Entities pointing to non-existent artifacts
        - Overlapping functions: Address ranges that collide with each other
        - Invalid address ranges: Start address greater than end address
        - Missing evidence: Entities without supporting evidence records
        - Broken cross-references: Edges pointing to non-existent entities
        - Circular dependencies: Dependency cycles in entity relationships
        - Invalid confidence values: Out-of-range confidence scores
        - Duplicate IDs: Duplicate entity or edge identifiers
        - Stale artifact references: Evidence referencing non-existent entities

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            auto_fix: If True, automatically fix all safe-to-fix issues.
                     If False, only report issues without making changes.

        Returns:
            Dictionary with integrity check results including:
            - summary: Counts of issues by severity (critical, errors, warnings, info)
            - stats: Database statistics (artifacts, entities, evidence, edges)
            - issues: Detailed list of all detected issues with severity and fixability
            - fixed_count: Number of issues fixed (only if auto_fix=True)
            - checked_at: ISO timestamp of when the check was performed

        Example:
            # Check integrity without fixing
            check_integrity("/path/to/project")

            # Check and auto-fix issues
            check_integrity("/path/to/project", auto_fix=True)
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)

        # Run integrity check
        report = store.check_integrity()

        result = {
            "project": str(Path(project_path).resolve()),
            "checked_at": report.get("checked_at", ""),
            "summary": report.get("summary", {}),
            "stats": report.get("stats", {}),
            "issues": report.get("issues", []),
            "auto_fix": auto_fix,
        }

        # Apply fixes if requested
        if auto_fix:
            fix_result = store.fix_integrity_issues(auto_fix=True)
            result["fixed_count"] = fix_result.get("fixed_count", 0)
            result["failed_count"] = fix_result.get("failed_count", 0)
            result["fixed"] = fix_result.get("fixed", [])
            result["failed"] = fix_result.get("failed", [])

        return result

    # --- Regression Testing Tools ---

    @mcp.tool()
    def create_analysis_snapshot(
        project_path: str,
        version_tag: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a snapshot of the current analysis state for regression testing.

        Captures entity counts by kind, reference coverage, confidence scores,
        and other metrics for tracking analysis stability over time. Snapshots
        are stored in the project database and can be compared later.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            version_tag: Identifier for this version (e.g., git commit hash).
            metadata: Optional additional metadata to store with the snapshot.

        Returns:
            Dictionary containing the snapshot data including:
            - snapshot_id: Unique identifier for this snapshot
            - created_at: Timestamp when snapshot was created
            - version_tag: The version identifier
            - entity_counts: Counts of entities by kind
            - evidence_counts: Counts of evidence by kind
            - edge_counts: Counts of edges by kind
            - confidence_scores: Confidence score statistics
            - reference_coverage: Reference coverage metrics by address space
            - artifact_stats: Overall artifact statistics
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        return _create_analysis_snapshot(
            project_path=project_path,
            version_tag=version_tag,
            metadata=metadata,
        )

    @mcp.tool()
    def compare_analysis_versions(
        project_path: str,
        version_a: str,
        version_b: str,
    ) -> dict[str, Any]:
        """Compare analysis between two versions and generate a regression report.

        Compares entity counts, confidence scores, reference coverage, and
        other metrics between two snapshots to detect significant changes.
        Useful for detecting regressions in analysis quality after updates.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            version_a: The baseline version tag or snapshot ID.
            version_b: The new version tag or snapshot ID to compare.

        Returns:
            Dictionary containing the regression report with:
            - version_a, version_b: The compared versions
            - snapshot_a_id, snapshot_b_id: The snapshot identifiers
            - entity_diffs: Changes in entity counts by kind
            - evidence_diffs: Changes in evidence counts by kind
            - edge_diffs: Changes in edge counts by kind
            - confidence_diffs: Changes in confidence scores
            - coverage_diffs: Changes in reference coverage
            - summary: Overall summary of changes
            - significant_changes: List of detected significant changes
            - comparison_id: Unique identifier for this comparison
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        return _compare_analysis_versions(
            project_path=project_path,
            version_a=version_a,
            version_b=version_b,
        )

    @mcp.tool()
    def get_analysis_history(
        project_path: str,
        limit: int = 10,
        version_filter: str = "",
    ) -> dict[str, Any]:
        """Get the history of analysis snapshots for a project.

        Lists all stored snapshots with their summaries, useful for tracking
        analysis evolution over time and selecting versions for comparison.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            limit: Maximum number of snapshots to return (default 10, max 100).
            version_filter: Optional version tag filter (substring match).

        Returns:
            Dictionary with:
            - snapshots: List of snapshot summaries
            - count: Number of snapshots returned
            - limit: The requested limit
            - version_filter: The applied filter (if any)
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        limit = max(1, min(limit, 100))

        return _get_analysis_history(
            project_path=project_path,
            limit=limit,
            version_filter=version_filter,
        )

    @mcp.tool()
    def delete_analysis_snapshot(
        project_path: str,
        snapshot_id: str,
    ) -> dict[str, Any]:
        """Delete an analysis snapshot.

        Removes a previously created snapshot from the project database.

        Args:
            project_path: Root path used to scope the reverse-engineering store.
            snapshot_id: The snapshot ID to delete.

        Returns:
            Dictionary with deletion status.
        """
        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        return _delete_analysis_snapshot(
            project_path=project_path,
            snapshot_id=snapshot_id,
        )

    # --- Batch Operations Tools ---

    @mcp.tool()
    def batch_index_directory(
        project_path: str,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        recursive: bool = True,
        parallel: bool = True,
    ) -> dict[str, Any]:
        """Batch index an entire directory tree of artifacts.

        Efficiently indexes all importer-supported artifacts in a directory tree
        with progress tracking and resume capability on failure.

        Args:
            project_path: Root directory to index.
            include_patterns: Optional glob patterns for files to include.
            exclude_patterns: Optional glob patterns for files to exclude.
            recursive: Whether to recursively scan subdirectories (default True).
            parallel: Whether to use parallel processing (default True).

        Returns:
            Dictionary with operation results including:
            - operation_id: Unique ID for tracking this batch operation
            - status: Operation status (completed, failed, etc.)
            - indexed_count: Number of files successfully indexed
            - error_count: Number of files that failed to index
            - total_files: Total number of files processed
            - duration_seconds: Time taken for the operation
        """
        from codemunch_pro.rex import BatchProcessor

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        processor = BatchProcessor(store=store, max_workers=4)

        result = processor.index_directory(
            project_path=project_path,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            recursive=recursive,
            parallel=parallel,
        )

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    @mcp.tool()
    def batch_apply_labels(
        project_path: str,
        labels: list[dict[str, Any]],
        address_space: str = "flat",
        artifact_id: str = "",
        parallel: bool = True,
    ) -> dict[str, Any]:
        """Apply labels to address ranges in bulk.

        Efficiently applies multiple labels to addresses in a single operation,
        useful for importing symbol tables or naming conventions from external tools.

        Args:
            project_path: Project path for context.
            labels: List of label definitions, each containing:
                - address: int - Start address (required)
                - name: str - Label name (required)
                - end_address: int (optional) - End address (defaults to start)
                - kind: str (optional) - Entity kind (default "reference")
                - comment: str (optional) - Description/comment
            address_space: Address space for the labels (default "flat").
            artifact_id: Optional artifact ID to associate with labels.
            parallel: Whether to use parallel processing (default True).

        Returns:
            Dictionary with operation results including:
            - operation_id: Unique ID for tracking this batch operation
            - status: Operation status
            - applied_count: Number of labels successfully applied
            - error_count: Number of labels that failed
            - total_labels: Total number of labels processed
            - duration_seconds: Time taken for the operation
        """
        from codemunch_pro.rex import BatchProcessor

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        processor = BatchProcessor(store=store, max_workers=4)

        result = processor.apply_labels(
            project_path=project_path,
            labels=labels,
            address_space=address_space,
            artifact_id=artifact_id,
            parallel=parallel,
        )

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    @mcp.tool()
    def batch_export(
        project_path: str,
        formats: list[str],
        output_dir: str,
        include_functions: bool = True,
        include_data_labels: bool = True,
        include_comments: bool = True,
        include_structures: bool = True,
        include_xrefs: bool = True,
        address_space_filter: str = "",
        parallel: bool = True,
    ) -> dict[str, Any]:
        """Export reverse-engineering data to multiple formats in bulk.

        Exports all indexed data to multiple formats simultaneously, useful for
        generating outputs for different reverse-engineering tools at once.

        Supported formats:
        - "ida" or "ida_python": IDA Pro Python script
        - "ghidra" or "ghidra_xml": Ghidra XML import format
        - "binary_ninja" or "binja": Binary Ninja Python script
        - "json": Generic JSON format
        - "csv": CSV files for spreadsheets

        Args:
            project_path: Project path.
            formats: List of export formats to generate.
            output_dir: Directory for output files (created if needed).
            include_functions: Include function definitions (default True).
            include_data_labels: Include data labels (default True).
            include_comments: Include comments (default True).
            include_structures: Include structures/types (default True).
            include_xrefs: Include cross-references (default True).
            address_space_filter: Optional filter by address space.
            parallel: Whether to use parallel processing (default True).

        Returns:
            Dictionary with export results including:
            - operation_id: Unique ID for tracking this batch operation
            - status: Operation status
            - completed_formats: List of successfully exported formats
            - failed_count: Number of formats that failed
            - total_formats: Total number of formats requested
            - output_dir: Path to the output directory
            - duration_seconds: Time taken for the operation
        """
        from codemunch_pro.rex import BatchProcessor

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        processor = BatchProcessor(store=store, max_workers=4)

        options = {
            "include_functions": include_functions,
            "include_data_labels": include_data_labels,
            "include_comments": include_comments,
            "include_structures": include_structures,
            "include_xrefs": include_xrefs,
        }

        if address_space_filter:
            options["address_space_filter"] = address_space_filter

        result = processor.export_multiple(
            project_path=project_path,
            formats=formats,
            output_dir=output_dir,
            options=options,
            parallel=parallel,
        )

        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }

    @mcp.tool()
    def get_batch_operation(
        project_path: str,
        operation_id: str,
    ) -> dict[str, Any]:
        """Get the status of a batch operation.

        Retrieves the current status and results of a previously started
        batch operation (index_directory, apply_labels, or export).

        Args:
            project_path: Project path (for context).
            operation_id: The operation ID returned by a batch operation.

        Returns:
            Dictionary with operation details including:
            - operation_id: The operation ID
            - operation_type: Type of operation
            - status: Current status (pending, running, completed, failed, cancelled)
            - progress: Number of items processed
            - total: Total number of items
            - result: Operation-specific results
            - errors: List of any errors encountered
        """
        from codemunch_pro.rex import BatchProcessor

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        processor = BatchProcessor(store=store)

        operation = processor.get_operation(operation_id)
        if operation is None:
            return {"error": f"Operation not found: {operation_id}"}

        return {
            "project": str(Path(project_path).resolve()),
            "operation": operation.to_dict(),
        }

    @mcp.tool()
    def list_batch_operations(
        project_path: str,
        status: str = "",
        operation_type: str = "",
    ) -> dict[str, Any]:
        """List batch operations with optional filtering.

        Args:
            project_path: Project path (for context).
            status: Optional filter by status (pending, running, completed, failed, cancelled).
            operation_type: Optional filter by operation type.

        Returns:
            Dictionary with list of operations and count.
        """
        from codemunch_pro.rex import BatchProcessor

        try:
            validate_path(project_path)
        except ValueError as e:
            return {"error": str(e)}

        store = _get_rex_store(project_path)
        processor = BatchProcessor(store=store)

        operations = processor.list_operations(
            status=status or None,
            operation_type=operation_type or None,
        )

        return {
            "project": str(Path(project_path).resolve()),
            "operations": [op.to_dict() for op in operations],
            "count": len(operations),
        }

def _dot_id(s: str) -> str:
    """Convert a string to a valid DOT identifier."""
    import re
    # Replace invalid characters with underscores
    safe = re.sub(r'[^a-zA-Z0-9_]', '_', s)
    # Ensure it starts with a letter
    if safe and safe[0].isdigit():
        safe = 'n' + safe
    return safe or 'node'


def _export_call_graph_dot(
    repo_path: str,
    symbol_name: str,
    depth: int = 3,
) -> dict[str, Any]:
    """Export call graph to Graphviz DOT format (implementation)."""
    db = _get_db(repo_path)
    depth = max(1, min(depth, 5))

    # Find the starting symbol
    start_sym = db.get_symbol(symbol_name)
    if not start_sym:
        return {'error': f'Symbol not found: {symbol_name}'}

    # Collect nodes and edges via BFS traversal
    nodes: dict[str, dict] = {}
    edges: set[tuple[str, str]] = set()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(symbol_name, 0)]

    # Color mapping for symbol kinds
    kind_colors = {
        'function': '#60A5FA',  # blue
        'class': '#FBBF24',     # orange
        'method': '#A78BFA',    # purple
        'type': '#34D399',      # green
        'interface': '#F472B6', # pink
        'constant': '#9CA3AF',  # gray
    }

    def add_node(sym_data: dict) -> None:
        qn = sym_data['qualified_name']
        if qn not in nodes:
            kind = sym_data.get('kind', 'unknown')
            nodes[qn] = {
                'id': _dot_id(qn),
                'label': f"{sym_data['name']}\\n({qn})",
                'kind': kind,
                'color': kind_colors.get(kind, '#9CA3AF'),
                'file': sym_data.get('file_path', ''),
                'line': sym_data.get('line', 0),
            }

    add_node(start_sym)

    while queue:
        current_qn, current_depth = queue.pop(0)
        if current_qn in visited or current_depth >= depth:
            continue
        visited.add(current_qn)

        # Get outgoing calls (callees)
        callees = db.get_callees(current_qn, depth=1)
        for callee in callees:
            callee_qn = callee.get('resolved_name') or callee.get('callee_name', '')
            if not callee_qn:
                continue

            # Add edge
            edges.add((_dot_id(current_qn), _dot_id(callee_qn)))

            # Add callee node if resolved
            if callee.get('resolved_name'):
                callee_sym = db.get_symbol(callee_qn)
                if callee_sym:
                    add_node(callee_sym)

            if callee_qn not in visited:
                queue.append((callee_qn, current_depth + 1))

        # Get incoming calls (callers) for bidirectional graph
        callers = db.get_callers(current_qn, depth=1)
        for caller in callers:
            caller_qn = caller.get('caller_name', '')
            if not caller_qn:
                continue

            edges.add((_dot_id(caller_qn), _dot_id(current_qn)))

            if caller_qn not in nodes:
                caller_sym = db.get_symbol(caller_qn)
                if caller_sym:
                    add_node(caller_sym)

            if caller_qn not in visited:
                queue.append((caller_qn, current_depth + 1))

    # Generate DOT format
    dot_lines = ['digraph CallGraph {']
    dot_lines.append('  rankdir=TB;')
    dot_lines.append('  node [shape=box, style=filled, fontname="Helvetica"];')
    dot_lines.append('')

    # Add nodes
    for qn, node in sorted(nodes.items()):
        dot_lines.append(
            f'  {node["id"]} [label="{node["label"]}", fillcolor="{node["color"]}"];'
        )

    dot_lines.append('')

    # Add edges
    for src, dst in sorted(edges):
        dot_lines.append(f'  {src} -> {dst};')

    dot_lines.append('}')

    return {
        'repo_path': str(Path(repo_path).resolve()),
        'symbol_name': symbol_name,
        'depth': depth,
        'node_count': len(nodes),
        'edge_count': len(edges),
        'dot': '\n'.join(dot_lines),
    }


def _export_reference_graph_dot(
    project_path: str,
    address: str,
    depth: int = 2,
) -> dict[str, Any]:
    """Export reference graph to Graphviz DOT format (implementation)."""
    store = _get_rex_store(project_path)
    depth = max(0, min(depth, 5))

    # Find entities by canonical reference
    entities = store.find_entities_by_canonical_ref(address)
    if not entities:
        return {'error': f'No entities found for address: {address}'}

    # Traverse graph from root entities
    root_ids = [e.entity_id for e in entities]
    traversal = store.traverse_entity_graph(root_ids, depth=depth, edge_limit=500)

    traversed_entities = traversal.get('entities', [])
    traversed_edges = traversal.get('edges', [])

    # Color mapping for entity kinds
    kind_colors = {
        'function': '#60A5FA',     # blue
        'data': '#34D399',         # green
        'reference': '#FBBF24',    # orange
        'document': '#A78BFA',     # purple
        'section': '#F472B6',      # pink
        'field': '#6EE7B7',        # teal
        'type': '#9CA3AF',         # gray
    }

    # Generate DOT format
    dot_lines = ['digraph ReferenceGraph {']
    dot_lines.append('  rankdir=TB;')
    dot_lines.append('  node [shape=box, style=filled, fontname="Helvetica"];')
    dot_lines.append('')

    # Add nodes
    for entity in traversed_entities:
        kind = entity.kind
        label = f"{entity.name}\\n({entity.canonical_ref or kind})"
        color = kind_colors.get(kind, '#9CA3AF')
        node_id = _dot_id(entity.entity_id)
        dot_lines.append(
            f'  {node_id} [label="{label}", fillcolor="{color}"];'
        )

    dot_lines.append('')

    # Add edges
    for edge in traversed_edges:
        src = _dot_id(edge.source_entity_id)
        dst = _dot_id(edge.target_entity_id)
        label = edge.kind
        dot_lines.append(f'  {src} -> {dst} [label="{label}"];')

    dot_lines.append('}')

    return {
        'project_path': str(Path(project_path).resolve()),
        'address': address,
        'depth': depth,
        'node_count': len(traversed_entities),
        'edge_count': len(traversed_edges),
        'dot': '\n'.join(dot_lines),
    }


def _export_data_flow_dot(
    project_path: str,
    symbol_name: str,
) -> dict[str, Any]:
    """Export data flow graph to Graphviz DOT format (implementation)."""
    db = _get_db(project_path)
    rex_store = _get_rex_store(project_path)

    # Find symbol in code database
    sym = db.get_symbol(symbol_name)
    if not sym:
        # Try to find in rex entities
        entities = rex_store.search_entities(symbol_name)
        if not entities:
            return {'error': f'Symbol not found: {symbol_name}'}
        # Use rex-based data flow
        return _export_rex_data_flow(rex_store, entities[0]['entity_id'], symbol_name)

    # Code-based data flow analysis
    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str, str]] = []  # (src, dst, label)

    kind_colors = {
        'function': '#60A5FA',
        'class': '#FBBF24',
        'method': '#A78BFA',
        'variable': '#34D399',
        'parameter': '#F472B6',
        'return': '#9CA3AF',
    }

    def add_node(qn: str, kind: str, label: str) -> str:
        node_id = _dot_id(qn)
        if qn not in nodes:
            nodes[qn] = {
                'id': node_id,
                'label': label,
                'kind': kind,
                'color': kind_colors.get(kind, '#9CA3AF'),
            }
        return node_id

    # Add root node
    root_id = add_node(
        sym['qualified_name'],
        sym.get('kind', 'function'),
        f"{sym['name']}\\n({sym['qualified_name']})"
    )

    # Add callers (data sources)
    callers = db.get_callers(sym['qualified_name'], depth=1)
    for caller in callers:
        caller_qn = caller.get('caller_name', '')
        if caller_qn:
            caller_id = add_node(caller_qn, 'function', caller_qn)
            edges.append((caller_id, root_id, 'calls'))

    # Add callees (data sinks)
    callees = db.get_callees(sym['qualified_name'], depth=1)
    for callee in callees:
        callee_qn = callee.get('resolved_name') or callee.get('callee_name', '')
        if callee_qn:
            callee_id = add_node(callee_qn, 'function', callee_qn)
            edges.append((root_id, callee_id, 'calls'))

    # Generate DOT
    dot_lines = ['digraph DataFlow {']
    dot_lines.append('  rankdir=LR;')
    dot_lines.append('  node [shape=box, style=filled, fontname="Helvetica"];')
    dot_lines.append('')

    for qn, node in sorted(nodes.items()):
        dot_lines.append(
            f'  {node["id"]} [label="{node["label"]}", fillcolor="{node["color"]}"];'
        )

    dot_lines.append('')

    for src, dst, label in edges:
        dot_lines.append(f'  {src} -> {dst} [label="{label}"];')

    dot_lines.append('}')

    return {
        'project_path': str(Path(project_path).resolve()),
        'symbol_name': symbol_name,
        'node_count': len(nodes),
        'edge_count': len(edges),
        'dot': '\n'.join(dot_lines),
    }


def _find_similar_functions(
    project_path: str,
    function_address: int,
    threshold: float = 0.7,
    top_k: int = 10,
    algorithm: str = "fuzzy_hash",
) -> dict[str, Any]:
    """Find functions similar to the function at the given address."""
    store = _get_rex_store(project_path)
    threshold = max(0.0, min(1.0, threshold))
    top_k = max(1, min(100, top_k))
    return store.find_similar_functions(
        function_address=function_address,
        threshold=threshold,
        top_k=top_k,
        algorithm=algorithm,
    )


def _get_graph_statistics(project_path: str) -> dict[str, Any]:
    """Get graph statistics for a project (implementation)."""
    db = _get_db(project_path)
    rex_store = _get_rex_store(project_path)

    # Code graph statistics
    code_stats = db.get_stats()

    # Get symbol counts by kind
    symbols_by_kind: dict[str, int] = {}
    all_symbols = db.get_all_symbols(limit=10000)
    for sym in all_symbols:
        kind = sym.get('kind', 'unknown')
        symbols_by_kind[kind] = symbols_by_kind.get(kind, 0) + 1

    # Get call edge count
    cur = db.conn.cursor()
    edge_count = cur.execute('SELECT COUNT(*) FROM call_edges').fetchone()[0]

    # Calculate density (actual edges / possible edges)
    node_count = code_stats.get('symbols', 0)
    max_edges = node_count * (node_count - 1) if node_count > 1 else 1
    density = edge_count / max_edges if max_edges > 0 else 0

    # REX graph statistics
    rex_stats = rex_store.stats()

    return {
        'project_path': str(Path(project_path).resolve()),
        'code_graph': {
            'total_nodes': node_count,
            'total_edges': edge_count,
            'density': round(density, 6),
            'nodes_by_kind': symbols_by_kind,
            'files': code_stats.get('files', 0),
        },
        'rex_graph': rex_stats,
        'summary': {
            'total_symbols': node_count,
            'total_call_edges': edge_count,
            'total_rex_entities': rex_stats.get('entities', 0),
            'total_rex_edges': rex_stats.get('edges', 0),
        },
    }

def _export_rex_data_flow(
    store: Any, entity_id: str, symbol_name: str
) -> dict[str, Any]:
    """Helper to export data flow for REX entities."""
    entity = store.get_entity(entity_id)
    if not entity:
        return {'error': f'Entity not found: {entity_id}'}

    # Get neighbors for data flow
    neighbors = store.get_neighbors(entity_id, limit=100)

    kind_colors = {
        'function': '#60A5FA',
        'data': '#34D399',
        'reference': '#FBBF24',
        'document': '#A78BFA',
        'section': '#F472B6',
    }

    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str, str]] = []

    def add_node(eid: str, kind: str, label: str) -> str:
        node_id = _dot_id(eid)
        if eid not in nodes:
            nodes[eid] = {
                'id': node_id,
                'label': label,
                'kind': kind,
                'color': kind_colors.get(kind, '#9CA3AF'),
            }
        return node_id

    # Add root entity
    root_id = add_node(entity_id, entity.kind, f"{entity.name}\\n({entity.kind})")

    # Add connected entities
    for edge in neighbors:
        if edge.source_entity_id == entity_id:
            # Outgoing edge
            target = store.get_entity(edge.target_entity_id)
            if target:
                tid = add_node(target.entity_id, target.kind, target.name)
                edges.append((root_id, tid, edge.kind))
        elif edge.target_entity_id == entity_id:
            # Incoming edge
            source = store.get_entity(edge.source_entity_id)
            if source:
                sid = add_node(source.entity_id, source.kind, source.name)
                edges.append((sid, root_id, edge.kind))

    # Generate DOT
    dot_lines = ['digraph DataFlow {']
    dot_lines.append('  rankdir=LR;')
    dot_lines.append('  node [shape=box, style=filled, fontname="Helvetica"];')
    dot_lines.append('')

    for eid, node in sorted(nodes.items()):
        dot_lines.append(
            f'  {node["id"]} [label="{node["label"]}", fillcolor="{node["color"]}"];'
        )

    dot_lines.append('')

    for src, dst, label in edges:
        dot_lines.append(f'  {src} -> {dst} [label="{label}"];')

    dot_lines.append('}')

    return {
        'project_path': '',
        'symbol_name': symbol_name,
        'node_count': len(nodes),
        'edge_count': len(edges),
        'dot': '\n'.join(dot_lines),
    }


def _resolve_file_path(project_path: str, file_path: str) -> Path:
    """Resolve a file path relative to project or absolute."""
    project_root = Path(project_path).resolve()
    candidate = Path(file_path)
    if not candidate.is_absolute():
        candidate = project_root / candidate
    return candidate.resolve()


def _analyze_entropy_file(
    project_path: str,
    file_path: str,
    address_space: str,
    window_size: int,
    base_address: int,
) -> dict[str, Any]:
    """Analyze entropy of a binary file (implementation)."""
    try:
        resolved = _resolve_file_path(project_path, file_path)
        if not resolved.is_file():
            return {'error': f'File not found: {file_path}'}

        # Read the binary file
        with open(resolved, 'rb') as f:
            data = f.read()

        if not data:
            return {'error': 'File is empty'}

        store = _get_rex_store(project_path)
        result = store.analyze_entropy(
            address_space=address_space,
            data=data,
            window_size=window_size,
            base_address=base_address,
        )
        result['file_path'] = str(resolved)
        result['file_size'] = len(data)
        return result

    except Exception as e:
        return {'error': f'Failed to analyze entropy: {e}'}


def _detect_packed_regions_file(
    project_path: str,
    file_path: str,
    address_space: str,
    threshold: float,
    min_region_size: int,
    window_size: int,
    base_address: int,
) -> dict[str, Any]:
    """Detect packed/encrypted regions in a binary file (implementation)."""
    try:
        resolved = _resolve_file_path(project_path, file_path)
        if not resolved.is_file():
            return {'error': f'File not found: {file_path}'}

        # Read the binary file
        with open(resolved, 'rb') as f:
            data = f.read()

        if not data:
            return {'error': 'File is empty'}

        store = _get_rex_store(project_path)
        result = store.detect_packed_regions(
            address_space=address_space,
            data=data,
            threshold=threshold,
            min_region_size=min_region_size,
            window_size=window_size,
            base_address=base_address,
        )
        result['file_path'] = str(resolved)
        result['file_size'] = len(data)
        return result

    except Exception as e:
        return {'error': f'Failed to detect packed regions: {e}'}


def _export_rex_project(
    project_path: str,
    format_type: str,
    output_path: str,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Export reverse-engineering project data to various formats.

    Args:
        project_path: Root path used to scope the reverse-engineering store.
        format_type: Export format - "ida", "ghidra", "binary_ninja", "json", "csv"
        output_path: Path for the output file(s)
        options: Optional export options

    Returns:
        Dictionary with export results
    """
    store = _get_rex_store(project_path)

    try:
        result = store.export_to_format(format_type, output_path, options)
        return {
            "project": str(Path(project_path).resolve()),
            **result,
        }
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Export failed: {e}"}


# ========================================================================
# Regression Testing Helper Functions
# ========================================================================

def _create_analysis_snapshot(
    project_path: str,
    version_tag: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a snapshot of the current analysis state for regression testing.

    Args:
        project_path: Root path used to scope the reverse-engineering store.
        version_tag: Identifier for this version (e.g., git commit hash).
        metadata: Optional additional metadata to store with the snapshot.

    Returns:
        Dictionary containing the snapshot data with entity counts,
        confidence scores, reference coverage, and other metrics.
    """
    store = _get_rex_store(project_path)
    result = store.create_analysis_snapshot(
        version_tag=version_tag,
        metadata=metadata,
    )
    return {
        "project": str(Path(project_path).resolve()),
        **result,
    }


def _compare_analysis_versions(
    project_path: str,
    version_a: str,
    version_b: str,
) -> dict[str, Any]:
    """Compare analysis between two versions and generate a regression report.

    Args:
        project_path: Root path used to scope the reverse-engineering store.
        version_a: The baseline version tag or snapshot ID.
        version_b: The new version tag or snapshot ID to compare.

    Returns:
        Dictionary containing the regression report with diffs of entity counts,
        confidence scores, coverage changes, and significant change detection.
    """
    store = _get_rex_store(project_path)
    result = store.compare_analysis_versions(
        version_a=version_a,
        version_b=version_b,
    )
    return {
        "project": str(Path(project_path).resolve()),
        **result,
    }


def _get_analysis_history(
    project_path: str,
    limit: int = 10,
    version_filter: str = "",
) -> dict[str, Any]:
    """Get the history of analysis snapshots for a project.

    Args:
        project_path: Root path used to scope the reverse-engineering store.
        limit: Maximum number of snapshots to return (default 10).
        version_filter: Optional version tag filter (substring match).

    Returns:
        Dictionary with list of snapshots and metadata.
    """
    store = _get_rex_store(project_path)
    result = store.get_analysis_history(
        limit=limit,
        version_filter=version_filter,
    )
    return {
        "project": str(Path(project_path).resolve()),
        **result,
    }


def _delete_analysis_snapshot(
    project_path: str,
    snapshot_id: str,
) -> dict[str, Any]:
    """Delete an analysis snapshot.

    Args:
        project_path: Root path used to scope the reverse-engineering store.
        snapshot_id: The snapshot ID to delete.

    Returns:
        Dictionary with deletion status.
    """
    store = _get_rex_store(project_path)
    result = store.delete_analysis_snapshot(snapshot_id)
    return {
        "project": str(Path(project_path).resolve()),
        **result,
    }


# ========================================================================
# Add MCP Tools for Regression Testing (inside create_server)
# ========================================================================

# These tools are added to the create_server function in the actual implementation.
# They are defined here as standalone functions that can be registered.

# Tool: create_analysis_snapshot
# Tool: compare_analysis_versions
# Tool: get_analysis_history
# Tool: delete_analysis_snapshot
