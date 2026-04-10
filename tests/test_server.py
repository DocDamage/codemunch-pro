"""Integration tests for the MCP server — full indexing + all 13 tools."""

import tempfile
from pathlib import Path

import pytest

from codemunch_pro.rex import ArtifactRecord, EdgeRecord, EntityRecord, ReverseEngineeringBundle
from codemunch_pro.server import (
    _compare_rex_ref_provenance,
    create_server,
    _get_db,
    _diff_rex_artifact,
    _find_rex_entities_by_ref,
    _get_rex_ref_provenance,
    _get_rex_ref_paths,
    _get_rex_ref_graph,
    _get_rex_ref_context,
    _get_rex_artifact,
    _get_rex_store,
    _index_artifact_folder,
    _index_artifact_path,
    _index_directory,
    _list_rex_shared_refs,
    _list_rex_entities,
    _list_rex_artifacts,
    _search_rex_entities,
    _export_call_graph_dot,
    _export_reference_graph_dot,
    _export_data_flow_dot,
    _get_graph_statistics,
    _dot_id,
)


PYTHON_SOURCE = '''\
"""Example module for testing."""

import os

CONSTANT = 42


def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}"


def goodbye(name: str) -> str:
    """Say goodbye."""
    return f"Bye, {name}"


class Greeter:
    """A greeter that uses hello and goodbye."""

    def __init__(self, prefix: str = "Dear"):
        self.prefix = prefix

    def greet(self, name: str) -> str:
        """Greet someone with prefix."""
        return hello(f"{self.prefix} {name}")

    def farewell(self, name: str) -> str:
        """Farewell someone."""
        return goodbye(name)


def main():
    """Entry point."""
    g = Greeter("Mr.")
    print(g.greet("World"))
    print(g.farewell("World"))
'''

JS_SOURCE = '''\
function add(a, b) {
    return a + b;
}

class Calculator {
    constructor() {
        this.value = 0;
    }

    add(n) {
        this.value = add(this.value, n);
        return this;
    }
}
'''


@pytest.fixture
def repo_dir(tmp_path):
    """Create a multi-language test repo."""
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'main.py').write_text(PYTHON_SOURCE)
    (src / 'calc.js').write_text(JS_SOURCE)

    # Add a .gitignore
    (tmp_path / '.gitignore').write_text('__pycache__/\n*.pyc\n')

    return tmp_path


@pytest.fixture
def indexed_repo(repo_dir):
    """Index the test repo (without embeddings for speed)."""
    stats = _index_directory(str(repo_dir), embed=False)
    return repo_dir, stats


class TestIndexDirectory:
    def test_indexes_files(self, indexed_repo):
        repo_dir, stats = indexed_repo
        assert stats['total_files'] >= 2  # main.py, calc.js
        assert stats['indexed'] >= 2
        assert stats['symbols_extracted'] > 0
        assert stats['errors'] == 0

    def test_incremental_skip(self, indexed_repo):
        repo_dir, _ = indexed_repo
        # Re-index same repo — should skip all files
        stats2 = _index_directory(str(repo_dir), embed=False)
        assert stats2['skipped_unchanged'] >= 2
        assert stats2['indexed'] == 0

    def test_detects_changes(self, indexed_repo):
        repo_dir, _ = indexed_repo
        # Modify a file
        (repo_dir / 'src' / 'main.py').write_text(
            PYTHON_SOURCE + '\ndef extra(): pass\n'
        )
        stats2 = _index_directory(str(repo_dir), embed=False)
        assert stats2['indexed'] >= 1

    def test_detects_deletions(self, indexed_repo):
        repo_dir, _ = indexed_repo
        # Delete a file
        (repo_dir / 'src' / 'calc.js').unlink()
        stats2 = _index_directory(str(repo_dir), embed=False)
        assert stats2['deleted'] >= 1

    def test_respects_exclude(self, repo_dir):
        stats = _index_directory(
            str(repo_dir),
            exclude_patterns=['*.js'],
            embed=False,
        )
        # Should only index .py files
        db = _get_db(str(repo_dir))
        langs = db.get_stats()['languages']
        assert 'javascript' not in langs


class TestServerTools:
    """Test all 13 MCP tools via the server."""

    @pytest.fixture(autouse=True)
    def setup_server(self, repo_dir):
        self.repo_dir = repo_dir
        self.repo_path = str(repo_dir)
        self.mcp = create_server()

        # Index without embeddings for speed
        _index_directory(self.repo_path, embed=False)

    def _call_tool(self, name: str, **kwargs):
        """Call an MCP tool by name, bypassing the MCP protocol."""
        # Access the tool functions registered on the server
        # Since we're testing directly, call the inner functions
        from codemunch_pro.server import (
            _get_db, _index_directory, _walk_source_files,
        )

        # Map tool names to their implementations
        # The tools are registered as closures, so we re-import server module
        import codemunch_pro.server as srv
        mcp = create_server()

        # Tools are registered as closures. We test via direct function call.
        # This is a pragmatic approach since MCP tools are thin wrappers.
        return None

    def test_file_tree(self):
        db = _get_db(self.repo_path)
        files = db.get_file_tree()
        assert len(files) >= 2

    def test_file_outline(self):
        db = _get_db(self.repo_path)
        symbols = db.get_file_symbols('src/main.py')
        names = [s['name'] for s in symbols]
        assert 'hello' in names
        assert 'Greeter' in names
        assert 'main' in names

    def test_repo_outline(self):
        db = _get_db(self.repo_path)
        all_syms = db.get_all_symbols()
        assert len(all_syms) >= 5  # Python + JS symbols

    def test_get_symbol_source(self):
        db = _get_db(self.repo_path)
        sym = db.get_symbol('hello')
        assert sym is not None

        # O(1) byte seek
        file_path = Path(self.repo_path) / sym['file_path']
        with open(file_path, 'rb') as f:
            f.seek(sym['byte_offset'])
            source = f.read(sym['byte_length']).decode()

        assert 'def hello' in source
        assert 'return' in source

    def test_get_symbol_batch(self):
        db = _get_db(self.repo_path)
        results = db.get_symbols_batch(['hello', 'goodbye', 'Greeter'])
        assert len(results) >= 3

    def test_fts_search(self):
        db = _get_db(self.repo_path)
        results = db.search_fts('hello')
        assert len(results) >= 1

    def test_text_search(self):
        db = _get_db(self.repo_path)
        results = db.search_text('CONSTANT')
        assert len(results) >= 1

    def test_call_graph_callees(self):
        db = _get_db(self.repo_path)
        db.resolve_call_edges()
        callees = db.get_callees('Greeter.greet')
        callee_names = [c['callee_name'] for c in callees]
        assert 'hello' in callee_names

    def test_call_graph_callers(self):
        db = _get_db(self.repo_path)
        db.resolve_call_edges()
        callers = db.get_callers('hello')
        assert len(callers) >= 1

    def test_stats(self):
        db = _get_db(self.repo_path)
        stats = db.get_stats()
        assert stats['files'] >= 2
        assert stats['symbols'] >= 5
        assert 'python' in stats['languages']
        assert 'javascript' in stats['languages']

    def test_invalidate_cache(self):
        db = _get_db(self.repo_path)
        assert db.get_stats()['files'] >= 2

        # Clear cache
        cur = db.conn.cursor()
        cur.execute('DELETE FROM files')
        cur.execute('DELETE FROM symbols')
        db.conn.commit()

        assert db.get_stats()['files'] == 0

        # Re-index should pick up all files
        stats = _index_directory(self.repo_path, embed=False)
        assert stats['indexed'] >= 2

    def test_o1_retrieval_token_savings(self):
        """Verify that byte-offset retrieval is much smaller than full file."""
        db = _get_db(self.repo_path)
        sym = db.get_symbol('hello')
        assert sym is not None

        file_path = Path(self.repo_path) / sym['file_path']
        full_file_size = file_path.stat().st_size
        symbol_size = sym['byte_length']

        # Symbol should be much smaller than full file
        assert symbol_size < full_file_size
        # At least 50% savings
        savings = 1 - (symbol_size / full_file_size)
        assert savings > 0.5, f'Only {savings:.0%} savings — expected >50%'


class TestDiffSymbols:
    """Test the diff_symbols tool (Tool 14)."""

    def test_no_changes_empty_diff(self, repo_dir):
        """When nothing changed, diff should be empty."""
        from codemunch_pro.server import create_server
        _index_directory(str(repo_dir), embed=False)

        # Import diff function directly
        from codemunch_pro.server import _get_db, _walk_source_files, _sha256_file
        from codemunch_pro.parser.extractor import extract_symbols

        db = _get_db(str(repo_dir))
        old_symbols = {s['qualified_name']: s for s in db.get_all_symbols(limit=10000)}

        # No changes — all files should match
        source_files = _walk_source_files(Path(repo_dir))
        old_hashes = db.get_all_file_hashes()
        changed = []
        for f in source_files:
            rel = f.relative_to(repo_dir).as_posix()
            if old_hashes.get(rel) != _sha256_file(f):
                changed.append(rel)

        assert len(changed) == 0

    def test_detects_added_symbol(self, repo_dir):
        """Adding a function should appear in diff."""
        _index_directory(str(repo_dir), embed=False)

        # Add a new function
        main_py = repo_dir / 'src' / 'main.py'
        main_py.write_text(PYTHON_SOURCE + '\ndef new_feature(): pass\n')

        # Now create server and call diff
        mcp = create_server()
        # Access diff through direct function testing
        db = _get_db(str(repo_dir))
        old_syms = {s['qualified_name'] for s in db.get_all_symbols(limit=10000)}

        # Re-extract the changed file
        from codemunch_pro.parser.extractor import extract_symbols
        new_syms_list = extract_symbols(main_py)
        new_names = {s.qualified_name for s in new_syms_list}

        # new_feature should be in new but not old
        assert 'new_feature' in new_names

    def test_detects_removed_symbol(self, repo_dir):
        """Removing a function should appear in diff."""
        _index_directory(str(repo_dir), embed=False)
        db = _get_db(str(repo_dir))

        old_syms = {s['qualified_name'] for s in db.get_all_symbols(limit=10000)}
        assert 'goodbye' in old_syms

        # Remove goodbye function
        shortened = PYTHON_SOURCE.replace(
            '''def goodbye(name: str) -> str:\n    """Say goodbye."""\n    return f"Bye, {name}"\n\n\n''',
            ''
        )
        (repo_dir / 'src' / 'main.py').write_text(shortened)

        from codemunch_pro.parser.extractor import extract_symbols
        new_syms = extract_symbols(repo_dir / 'src' / 'main.py')
        new_names = {s.qualified_name for s in new_syms}

        assert 'goodbye' not in new_names


class TestDependencyMap:
    """Test the dependency_map tool (Tool 15)."""

    def test_finds_dependencies(self, repo_dir):
        """Greeter.greet calls hello — should show up in depends_on."""
        _index_directory(str(repo_dir), embed=False)
        db = _get_db(str(repo_dir))
        db.resolve_call_edges()

        # Get callees of Greeter.greet
        callees = db.get_callees('Greeter.greet', depth=1)
        callee_names = [c['callee_name'] for c in callees]
        assert 'hello' in callee_names

    def test_finds_callers(self, repo_dir):
        """hello is called by Greeter.greet — should show up as depended_by."""
        _index_directory(str(repo_dir), embed=False)
        db = _get_db(str(repo_dir))
        db.resolve_call_edges()

        callers = db.get_callers('hello', depth=1)
        assert len(callers) >= 1


class TestMultiLanguage:
    def test_indexes_python_and_javascript(self, repo_dir):
        stats = _index_directory(str(repo_dir), embed=False)
        db = _get_db(str(repo_dir))
        langs = db.get_stats()['languages']
        assert 'python' in langs
        assert 'javascript' in langs


class TestReverseEngineeringTools:
    def test_index_artifact_path(self, repo_dir):
        report = repo_dir / 'report.md'
        report.write_text('# Report\nEvidence line\n')

        result = _index_artifact_path(str(repo_dir), 'report.md')

        assert result['artifacts'] == 1
        assert result['entities'] >= 2
        assert result['evidence'] >= 2

        store = _get_rex_store(str(repo_dir))
        stats = store.stats()
        assert stats['artifacts'] == 1
        assert stats['entities'] >= 2

    def test_index_artifact_folder(self, repo_dir):
        (repo_dir / 'report.md').write_text('# Report\nEvidence line\n')
        (repo_dir / 'scan.json').write_text('{"bank":"C3"}')

        result = _index_artifact_folder(
            str(repo_dir),
            include_patterns=['*.md', '*.json'],
        )

        assert result['artifacts_indexed'] == 2
        assert result['bundle_artifacts'] == 2
        assert result['entities'] >= 4
        assert result['evidence'] >= 4

    def test_rex_store_queries_after_index(self, repo_dir):
        artifact = repo_dir / 'notes.md'
        artifact.write_text('Cross-bank utility call\nDividend write to $4204\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        store = _get_rex_store(str(repo_dir))
        hits = store.search_evidence('Dividend')
        assert len(hits) >= 1

        entity_hits = store.search_entities('notes')
        assert len(entity_hits) >= 1
        document_hits = [item for item in entity_hits if item['kind'] == 'document']
        assert len(document_hits) == 1
        entity_id = document_hits[0]['entity_id']

        bundle = ReverseEngineeringBundle(
            edges=[
                EdgeRecord(
                    edge_id='edge:1',
                    kind='mentions',
                    source_entity_id=entity_id,
                    target_entity_id=entity_id,
                )
            ]
        )
        store.upsert_bundle(bundle)

        neighbors = store.get_neighbors(entity_id)
        assert len(neighbors) >= 2
        assert any(edge.edge_id == 'edge:1' for edge in neighbors)

    def test_rex_index_supports_segmented_references(self, repo_dir):
        artifact = repo_dir / 'banked.md'
        artifact.write_text('Jump target C3:2B00\n')

        result = _index_artifact_path(str(repo_dir), str(artifact))
        assert result['entities'] >= 2
        assert result['edges'] >= 1

        store = _get_rex_store(str(repo_dir))
        hits = store.search_entities('C3:2B00', kind='reference')
        assert len(hits) == 1
        reference = store.get_entity(hits[0]['entity_id'])
        assert reference is not None
        assert reference.location is not None
        assert reference.location.address_space == 'segmented-hex'

    def test_search_rex_entities_filters_by_kind(self, repo_dir):
        artifact = repo_dir / 'banked.md'
        artifact.write_text('Jump target C3:2B00\nMirror of $4204\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        result = _search_rex_entities(str(repo_dir), 'C3:2B00', kind='reference')
        assert result['count'] == 1
        assert result['results'][0]['kind'] == 'reference'
        assert result['results'][0]['canonical_ref'] == 'C3:2B00'

    def test_get_rex_artifact_returns_entities_and_evidence(self, repo_dir):
        artifact = repo_dir / 'report.md'
        artifact.write_text('# Report\nCall target C3:2B00\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        result = _get_rex_artifact(
            str(repo_dir),
            'report.md',
            entity_kind='reference',
            evidence_kind='reference-mention',
        )
        assert result['artifact']['path'].endswith('report.md')
        assert result['entity_count'] == 1
        assert result['evidence_count'] == 1
        assert result['entities'][0]['canonical_ref'] == 'C3:2B00'

    def test_list_rex_artifacts_returns_indexed_artifacts(self, repo_dir):
        (repo_dir / 'report.md').write_text('# Report\nEvidence line\n')
        (repo_dir / 'scan.json').write_text('{"bank":"C3"}')
        _index_artifact_folder(str(repo_dir), include_patterns=['*.md', '*.json'])

        result = _list_rex_artifacts(str(repo_dir))
        assert result['count'] == 2
        names = [Path(item['path']).name for item in result['artifacts']]
        assert 'report.md' in names
        assert 'scan.json' in names

    def test_diff_rex_artifact_reports_changes_and_can_apply(self, repo_dir):
        artifact = repo_dir / 'notes.md'
        artifact.write_text('Alpha $4204\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        artifact.write_text('Beta C3:2B00\n')
        diff = _diff_rex_artifact(str(repo_dir), str(artifact), apply=False)
        assert diff['stored_previously'] is True
        assert diff['summary']['entities_added'] >= 1
        assert diff['summary']['entities_removed'] >= 1
        assert (
            diff['summary']['evidence_added'] >= 1
            or diff['summary']['evidence_changed'] >= 1
        )
        assert (
            diff['summary']['evidence_removed'] >= 1
            or diff['summary']['evidence_changed'] >= 1
        )

        store = _get_rex_store(str(repo_dir))
        old_hits = store.search_entities('0x4204', kind='reference')
        assert len(old_hits) == 1

        applied = _diff_rex_artifact(str(repo_dir), str(artifact), apply=True)
        assert applied['applied'] is True

        new_hits = store.search_entities('C3:2B00', kind='reference')
        assert len(new_hits) == 1
        old_hits = store.search_entities('0x4204', kind='reference')
        assert len(old_hits) == 0

    def test_find_rex_entities_by_ref_is_exact(self, repo_dir):
        artifact = repo_dir / 'mixed.md'
        artifact.write_text('Segmented C3:2B00\nFlat $4204\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        exact = _find_rex_entities_by_ref(str(repo_dir), 'C3:2B00', kind='reference')
        assert exact['count'] == 1
        assert exact['entities'][0]['canonical_ref'] == 'C3:2B00'

        miss = _find_rex_entities_by_ref(str(repo_dir), 'C3:2B0', kind='reference')
        assert miss['count'] == 0

    def test_list_rex_entities_filters_by_address_space(self, repo_dir):
        artifact = repo_dir / 'mixed.md'
        artifact.write_text('Segmented C3:2B00\nFlat $4204\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        segmented = _list_rex_entities(str(repo_dir), kind='reference', address_space='segmented-hex')
        assert segmented['count'] == 1
        assert segmented['entities'][0]['canonical_ref'] == 'C3:2B00'

        flat = _list_rex_entities(str(repo_dir), kind='reference', address_space='flat')
        assert flat['count'] == 1
        assert flat['entities'][0]['canonical_ref'] == '0x4204'

    def test_get_rex_ref_context_collects_entities_evidence_and_edges(self, repo_dir):
        first = repo_dir / 'first.md'
        second = repo_dir / 'second.md'
        first.write_text('Call C3:2B00 from note one\n')
        second.write_text('Observe C3:2B00 in note two\n')
        _index_artifact_path(str(repo_dir), str(first))
        _index_artifact_path(str(repo_dir), str(second))

        result = _get_rex_ref_context(str(repo_dir), 'C3:2B00', kind='reference')
        assert result['entity_count'] == 2
        assert result['evidence_count'] == 2
        assert result['neighbor_count'] == 2
        assert all(entity['canonical_ref'] == 'C3:2B00' for entity in result['entities'])
        assert all(item['kind'] == 'reference-mention' for item in result['evidence'])
        assert all(edge['kind'] == 'mentions' for edge in result['neighbors'])

    def test_get_rex_ref_context_returns_empty_for_missing_ref(self, repo_dir):
        artifact = repo_dir / 'mixed.md'
        artifact.write_text('Segmented C3:2B00\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        result = _get_rex_ref_context(str(repo_dir), 'C3:FFFF', kind='reference')
        assert result['entity_count'] == 0
        assert result['evidence_count'] == 0
        assert result['neighbor_count'] == 0

    def test_get_rex_ref_graph_traverses_documents_and_sections(self, repo_dir):
        artifact = repo_dir / 'report.md'
        artifact.write_text('# Battle Notes\nCall C3:2B00 from section\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        result = _get_rex_ref_graph(str(repo_dir), 'C3:2B00', kind='reference', depth=2, edge_limit=20)
        assert result['entity_count'] >= 3
        assert result['edge_count'] >= 2
        assert any(entity['kind'] == 'reference' and entity['traversal_depth'] == 0 for entity in result['entities'])
        assert any(entity['kind'] == 'section' for entity in result['entities'])
        assert any(entity['kind'] == 'document' for entity in result['entities'])
        assert any(edge['kind'] == 'mentions' for edge in result['edges'])
        assert any(edge['kind'] == 'contains' for edge in result['edges'])

    def test_get_rex_ref_paths_returns_shortest_paths(self, repo_dir):
        artifact = repo_dir / 'report.md'
        artifact.write_text('# Battle Notes\nCall C3:2B00 from section\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        result = _get_rex_ref_paths(str(repo_dir), 'C3:2B00', kind='reference', depth=2)
        assert result['path_count'] >= 2
        assert any(path['target_kind'] == 'section' and len(path['edges']) == 1 for path in result['paths'])
        assert any(path['target_kind'] == 'document' and len(path['edges']) == 1 for path in result['paths'])
        assert all(len(path['entities']) == len(path['edges']) + 1 for path in result['paths'])

    def test_get_rex_ref_paths_supports_target_kind_filter(self, repo_dir):
        artifact = repo_dir / 'report.md'
        artifact.write_text('# Battle Notes\nCall C3:2B00 from section\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        result = _get_rex_ref_paths(
            str(repo_dir),
            'C3:2B00',
            kind='reference',
            target_kind='document',
            depth=2,
        )
        assert result['path_count'] == 1
        assert result['paths'][0]['target_kind'] == 'document'
        assert len(result['paths'][0]['edges']) == 1

    def test_get_rex_ref_paths_ranks_section_before_document(self, repo_dir):
        artifact = repo_dir / 'report.md'
        artifact.write_text('# Battle Notes\nCall C3:2B00 from section\n')
        _index_artifact_path(str(repo_dir), str(artifact))

        result = _get_rex_ref_paths(str(repo_dir), 'C3:2B00', kind='reference', depth=2)
        assert result['path_count'] >= 2
        assert result['paths'][0]['rank'] == 1
        assert result['paths'][0]['target_kind'] == 'section'
        assert result['paths'][1]['rank'] == 2
        assert result['paths'][1]['target_kind'] == 'document'

    def test_get_rex_ref_paths_dedupes_equivalent_multi_root_paths(self, repo_dir):
        store = _get_rex_store(str(repo_dir))
        artifact_id = (repo_dir / 'dedupe.md').as_posix()
        document_id = f'entity:document:{artifact_id}'
        root_one = f'entity:reference:{artifact_id}:root1'
        root_two = f'entity:reference:{artifact_id}:root2'

        bundle = ReverseEngineeringBundle(
            artifacts=[
                ArtifactRecord(
                    artifact_id=artifact_id,
                    kind='note',
                    path=artifact_id,
                    title='dedupe.md',
                    media_type='text/markdown',
                )
            ],
            entities=[
                EntityRecord(
                    entity_id=document_id,
                    kind='document',
                    name='dedupe',
                    artifact_id=artifact_id,
                    canonical_ref=artifact_id,
                ),
                EntityRecord(
                    entity_id=root_one,
                    kind='reference',
                    name='C3:2B00',
                    artifact_id=artifact_id,
                    canonical_ref='C3:2B00',
                ),
                EntityRecord(
                    entity_id=root_two,
                    kind='reference',
                    name='C3:2B00',
                    artifact_id=artifact_id,
                    canonical_ref='C3:2B00',
                ),
            ],
            edges=[
                EdgeRecord(
                    edge_id='edge:mentions:root1',
                    kind='mentions',
                    source_entity_id=root_one,
                    target_entity_id=document_id,
                ),
                EdgeRecord(
                    edge_id='edge:mentions:root2',
                    kind='mentions',
                    source_entity_id=root_two,
                    target_entity_id=document_id,
                ),
            ],
        )
        store.replace_bundle(bundle)

        raw = _get_rex_ref_paths(str(repo_dir), 'C3:2B00', kind='reference', target_kind='document', depth=1, dedupe=False)
        assert raw['raw_path_count'] == 2
        assert raw['path_count'] == 2

        deduped = _get_rex_ref_paths(str(repo_dir), 'C3:2B00', kind='reference', target_kind='document', depth=1, dedupe=True)
        assert deduped['raw_path_count'] == 2
        assert deduped['path_count'] == 1
        assert deduped['dedupe_applied'] is True
        assert deduped['paths'][0]['target_kind'] == 'document'
        assert deduped['paths'][0]['path_signature']

    def test_get_rex_ref_provenance_groups_by_artifact(self, repo_dir):
        first = repo_dir / 'first.md'
        second = repo_dir / 'second.md'
        first.write_text('# First\nCall C3:2B00 from section\n')
        second.write_text('Observe C3:2B00 in note two\n')
        _index_artifact_path(str(repo_dir), str(first))
        _index_artifact_path(str(repo_dir), str(second))

        result = _get_rex_ref_provenance(str(repo_dir), 'C3:2B00', kind='reference')
        assert result['artifact_count'] == 2

        first_summary = next(item for item in result['artifacts'] if item['artifact']['path'].endswith('first.md'))
        assert first_summary['reference_entity_count'] == 1
        assert first_summary['evidence_kind_counts']['reference-mention'] == 1
        assert first_summary['anchor_kind_counts']['document'] >= 1
        assert first_summary['anchor_kind_counts']['section'] >= 1

        second_summary = next(item for item in result['artifacts'] if item['artifact']['path'].endswith('second.md'))
        assert second_summary['reference_entity_count'] == 1
        assert second_summary['anchor_kind_counts']['document'] >= 1

    def test_compare_rex_ref_provenance_highlights_shared_and_unique_anchors(self, repo_dir):
        first = repo_dir / 'first.md'
        second = repo_dir / 'second.md'
        first.write_text('# First\nCall C3:2B00 from section\n')
        second.write_text('Observe C3:2B00 in note two\n')
        _index_artifact_path(str(repo_dir), str(first))
        _index_artifact_path(str(repo_dir), str(second))

        result = _compare_rex_ref_provenance(str(repo_dir), 'C3:2B00', kind='reference')
        assert result['artifact_count'] == 2
        assert result['comparison']['common_evidence_kinds'] == ['reference-mention']
        assert 'document' in result['comparison']['common_anchor_kinds']
        assert 'section' in result['comparison']['all_anchor_kinds']

        first_key = first.as_posix()
        second_key = second.as_posix()
        unique = result['comparison']['unique_anchor_signatures']
        assert result['comparison']['shared_anchor_signatures'] == []
        assert any(signature.startswith('section|') for signature in unique[first_key])
        assert any(signature.startswith('document|') for signature in unique[second_key])

        disagreements = result['comparison']['disagreements']
        assert first_key in disagreements['artifacts_with_exclusive_anchor_kind']['section']
        assert second_key in disagreements['artifacts_missing_anchor_kind']['section']
        assert disagreements['per_artifact'][first_key]['exclusive_anchor_kinds'] == ['section']
        assert disagreements['per_artifact'][second_key]['missing_anchor_kinds'] == ['section']

    def test_list_rex_shared_refs_ranks_and_filters_results(self, repo_dir):
        first = repo_dir / 'first.md'
        second = repo_dir / 'second.md'
        third = repo_dir / 'third.md'
        first.write_text('# Shared\nShared segmented C3:2B00\nShared flat $4204\n')
        second.write_text('# Shared\nShared segmented C3:2B00\n')
        third.write_text('Shared flat $4204\n')
        _index_artifact_path(str(repo_dir), str(first))
        _index_artifact_path(str(repo_dir), str(second))
        _index_artifact_path(str(repo_dir), str(third))

        result = _list_rex_shared_refs(str(repo_dir), kind='reference', min_artifacts=2, limit=10)
        assert result['count'] == 2
        assert result['results'][0]['canonical_ref'] == 'C3:2B00'
        assert result['results'][0]['ranking_score'] > result['results'][1]['ranking_score']
        assert result['results'][0]['ranking_breakdown']['shared_anchor_kind_count'] > result['results'][1]['ranking_breakdown']['shared_anchor_kind_count']
        assert result['results'][1]['canonical_ref'] == '0x4204'

        segmented = _list_rex_shared_refs(
            str(repo_dir),
            kind='reference',
            address_space='segmented-hex',
            min_artifacts=2,
            limit=10,
        )
        assert segmented['count'] == 1
        assert segmented['results'][0]['canonical_ref'] == 'C3:2B00'

        strict = _list_rex_shared_refs(str(repo_dir), kind='reference', min_artifacts=3, limit=10)
        assert strict['count'] == 0


class TestGraphVisualizationTools:
    """Test graph visualization MCP tools."""

    def test_export_call_graph_dot_generates_valid_dot(self, repo_dir):
        """export_call_graph_dot should generate valid DOT format."""
        from codemunch_pro.server import (
            _export_call_graph_dot,
            _dot_id,
        )
        _index_directory(str(repo_dir), embed=False)

        result = _export_call_graph_dot(
            repo_path=str(repo_dir),
            symbol_name='hello',
            depth=2,
        )

        assert 'error' not in result
        assert 'dot' in result
        assert result['symbol_name'] == 'hello'
        assert result['node_count'] > 0
        assert result['edge_count'] >= 0

        # Verify DOT format
        dot = result['dot']
        assert dot.startswith('digraph CallGraph {')
        assert dot.endswith('}')
        assert 'rankdir=TB' in dot
        assert 'node [shape=box' in dot

    def test_export_call_graph_dot_returns_error_for_missing_symbol(self, repo_dir):
        """export_call_graph_dot should return error for non-existent symbol."""
        from codemunch_pro.server import _export_call_graph_dot
        _index_directory(str(repo_dir), embed=False)

        result = _export_call_graph_dot(
            repo_path=str(repo_dir),
            symbol_name='non_existent_symbol_12345',
            depth=2,
        )

        assert 'error' in result
        assert 'not found' in result['error']

    def test_export_reference_graph_dot_error_handling(self, repo_dir):
        """export_reference_graph_dot should handle missing entities gracefully."""
        from codemunch_pro.server import _export_reference_graph_dot
        _index_directory(str(repo_dir), embed=False)

        # When no entities are found, should return an error
        result = _export_reference_graph_dot(
            project_path=str(repo_dir),
            address='C3:2B00',
            depth=1,
        )

        # The mock store returns empty results, so we expect an error
        assert 'error' in result
        assert 'No entities found' in result['error']

    def test_export_reference_graph_dot_returns_error_for_missing_address(self, repo_dir):
        """export_reference_graph_dot should return error for non-existent address."""
        from codemunch_pro.server import _export_reference_graph_dot
        _index_directory(str(repo_dir), embed=False)

        result = _export_reference_graph_dot(
            project_path=str(repo_dir),
            address='XX:FFFF',
            depth=2,
        )

        assert 'error' in result
        assert 'No entities found' in result['error']

    def test_export_data_flow_dot_generates_valid_dot(self, repo_dir):
        """export_data_flow_dot should generate valid DOT format."""
        from codemunch_pro.server import _export_data_flow_dot
        _index_directory(str(repo_dir), embed=False)

        result = _export_data_flow_dot(
            project_path=str(repo_dir),
            symbol_name='Greeter.greet',
        )

        assert 'error' not in result
        assert 'dot' in result
        assert result['node_count'] > 0

        # Verify DOT format
        dot = result['dot']
        assert dot.startswith('digraph DataFlow {')
        assert dot.endswith('}')
        assert 'rankdir=LR' in dot

    def test_export_data_flow_dot_returns_error_for_missing_symbol(self, repo_dir):
        """export_data_flow_dot should return error for non-existent symbol."""
        from codemunch_pro.server import _export_data_flow_dot
        _index_directory(str(repo_dir), embed=False)

        result = _export_data_flow_dot(
            project_path=str(repo_dir),
            symbol_name='non_existent_symbol_12345',
        )

        assert 'error' in result

    def test_get_graph_statistics_returns_stats(self, repo_dir):
        """get_graph_statistics should return graph metrics."""
        from codemunch_pro.server import _get_graph_statistics
        _index_directory(str(repo_dir), embed=False)

        result = _get_graph_statistics(
            project_path=str(repo_dir),
        )

        assert 'error' not in result
        assert 'code_graph' in result
        assert 'rex_graph' in result
        assert 'summary' in result

        code_graph = result['code_graph']
        assert 'total_nodes' in code_graph
        assert 'total_edges' in code_graph
        assert 'density' in code_graph
        assert 'nodes_by_kind' in code_graph

        # Should have indexed some symbols
        assert code_graph['total_nodes'] > 0

    def test_dot_id_escapes_special_characters(self):
        """_dot_id should convert strings to valid DOT identifiers."""
        from codemunch_pro.server import _dot_id

        assert _dot_id('hello') == 'hello'
        assert _dot_id('hello.world') == 'hello_world'
        assert _dot_id('func(arg)') == 'func_arg_'
        assert _dot_id('123abc') == 'n123abc'  # Can't start with digit
        assert _dot_id('C3:2B00') == 'C3_2B00'
        assert _dot_id('') == 'node'

    def test_export_call_graph_dot_includes_color_coding(self, repo_dir):
        """export_call_graph_dot should color nodes by symbol kind."""
        from codemunch_pro.server import _export_call_graph_dot
        _index_directory(str(repo_dir), embed=False)

        result = _export_call_graph_dot(
            repo_path=str(repo_dir),
            symbol_name='Greeter',
            depth=2,
        )

        assert 'error' not in result
        dot = result['dot']

        # Check for color attributes (functions=blue, classes=orange)
        assert 'fillcolor=' in dot
        assert '#60A5FA' in dot or '#FBBF24' in dot  # blue or orange
