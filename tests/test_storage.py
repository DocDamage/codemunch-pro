"""Tests for SQLite storage layer — FTS5, CRUD, incremental indexing."""

import tempfile
from pathlib import Path

import pytest

from codemunch_pro.parser.extractor import extract_symbols
from codemunch_pro.parser.languages import get_language_for_file
from codemunch_pro.storage.database import Database


PYTHON_SOURCE = '''\
def hello(name: str) -> str:
    """Say hello."""
    return f"Hello, {name}"


class Greeter:
    """A greeter class."""

    def greet(self, name: str) -> str:
        return hello(name)
'''

PYTHON_SOURCE_V2 = '''\
def hello(name: str) -> str:
    """Say hello (updated)."""
    return f"Hi, {name}"


class Greeter:
    """A greeter class."""

    def greet(self, name: str) -> str:
        return hello(name)

    def farewell(self, name: str) -> str:
        return f"Bye, {name}"
'''

DUPLICATE_NAME_SOURCE_A = '''\
def main():
    return 1


def helper():
    return main()
'''

DUPLICATE_NAME_SOURCE_B = '''\
def main():
    return 2


def helper2():
    return main()
'''


@pytest.fixture
def repo_dir(tmp_path):
    """Create a temporary repo directory with Python files."""
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'main.py').write_text(PYTHON_SOURCE)
    (src / 'utils.py').write_text('''
def add(a, b):
    """Add two numbers."""
    return a + b

def multiply(a, b):
    return a * b
''')
    return tmp_path


@pytest.fixture
def db_dir(tmp_path):
    """Temporary directory for database files."""
    d = tmp_path / 'dbs'
    d.mkdir()
    return d


@pytest.fixture
def db(repo_dir, db_dir):
    """Create a database for the test repo."""
    database = Database(str(repo_dir), db_dir=db_dir)
    yield database
    database.close()


class TestDatabaseCreation:
    def test_creates_db_file(self, db, db_dir):
        assert db.db_path.exists()
        assert db.db_path.suffix == '.db'

    def test_schema_version(self, db):
        row = db.conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        assert row['value'] == '1'

    def test_stores_repo_path(self, db, repo_dir):
        row = db.conn.execute(
            "SELECT value FROM meta WHERE key = 'repo_path'"
        ).fetchone()
        assert row['value'] == str(Path(repo_dir).resolve())


class TestFileOperations:
    def test_upsert_file(self, db, repo_dir):
        file_path = str(repo_dir / 'src' / 'main.py')
        symbols = extract_symbols(file_path)
        file_id = db.upsert_file(
            path='src/main.py',
            sha256='abc123',
            language='python',
            size_bytes=100,
            symbols=symbols,
            file_content=PYTHON_SOURCE,
        )
        assert file_id > 0

    def test_get_file_hash(self, db):
        db.upsert_file(
            path='src/main.py',
            sha256='abc123',
            language='python',
            size_bytes=100,
            symbols=[],
        )
        assert db.get_file_hash('src/main.py') == 'abc123'

    def test_get_file_hash_missing(self, db):
        assert db.get_file_hash('nonexistent.py') is None

    def test_delete_file(self, db, repo_dir):
        file_path = str(repo_dir / 'src' / 'main.py')
        symbols = extract_symbols(file_path)
        db.upsert_file(
            path='src/main.py',
            sha256='abc123',
            language='python',
            size_bytes=100,
            symbols=symbols,
        )
        assert db.get_file_hash('src/main.py') is not None
        db.delete_file('src/main.py')
        assert db.get_file_hash('src/main.py') is None

    def test_get_all_file_hashes(self, db):
        db.upsert_file(
            path='src/a.py', sha256='hash_a',
            language='python', size_bytes=10, symbols=[],
        )
        db.upsert_file(
            path='src/b.py', sha256='hash_b',
            language='python', size_bytes=20, symbols=[],
        )
        hashes = db.get_all_file_hashes()
        assert hashes == {'src/a.py': 'hash_a', 'src/b.py': 'hash_b'}


class TestSymbolQueries:
    @pytest.fixture(autouse=True)
    def index_file(self, db, repo_dir):
        file_path = str(repo_dir / 'src' / 'main.py')
        symbols = extract_symbols(file_path)
        db.upsert_file(
            path='src/main.py',
            sha256='abc123',
            language='python',
            size_bytes=100,
            symbols=symbols,
            file_content=PYTHON_SOURCE,
        )

    def test_get_symbol(self, db):
        sym = db.get_symbol('hello')
        assert sym is not None
        assert sym['name'] == 'hello'
        assert sym['kind'] == 'function'

    def test_get_symbol_missing(self, db):
        assert db.get_symbol('nonexistent') is None

    def test_get_file_symbols(self, db):
        symbols = db.get_file_symbols('src/main.py')
        assert len(symbols) >= 3  # hello, Greeter, greet
        names = [s['name'] for s in symbols]
        assert 'hello' in names
        assert 'Greeter' in names

    def test_get_all_symbols(self, db):
        symbols = db.get_all_symbols()
        assert len(symbols) >= 3

    def test_get_all_symbols_kind_filter(self, db):
        funcs = db.get_all_symbols(kind_filter='function')
        for f in funcs:
            assert f['kind'] == 'function'

    def test_get_symbols_batch(self, db):
        results = db.get_symbols_batch(['hello', 'Greeter'])
        assert len(results) >= 2


class TestFTSSearch:
    @pytest.fixture(autouse=True)
    def index_files(self, db, repo_dir):
        for name in ('main.py', 'utils.py'):
            file_path = str(repo_dir / 'src' / name)
            symbols = extract_symbols(file_path)
            content = Path(file_path).read_text()
            db.upsert_file(
                path=f'src/{name}',
                sha256=f'hash_{name}',
                language='python',
                size_bytes=len(content),
                symbols=symbols,
                file_content=content,
            )

    def test_search_by_name(self, db):
        results = db.search_fts('hello')
        assert len(results) >= 1
        assert results[0]['name'] == 'hello'

    def test_search_by_docstring(self, db):
        results = db.search_fts('Add two numbers')
        assert len(results) >= 1

    def test_search_no_results(self, db):
        results = db.search_fts('xyznonexistent')
        assert len(results) == 0

    def test_text_search_in_content(self, db):
        results = db.search_text('return')
        assert len(results) >= 1

    def test_text_search_with_glob(self, db):
        results = db.search_text('return', glob='src/utils.py')
        assert len(results) >= 1
        for r in results:
            assert 'utils' in r['path']


class TestCallGraph:
    @pytest.fixture(autouse=True)
    def index_file(self, db, repo_dir):
        file_path = str(repo_dir / 'src' / 'main.py')
        symbols = extract_symbols(file_path)
        db.upsert_file(
            path='src/main.py',
            sha256='abc123',
            language='python',
            size_bytes=100,
            symbols=symbols,
        )
        db.resolve_call_edges()

    def test_get_callees(self, db):
        callees = db.get_callees('Greeter.greet')
        # greet calls hello
        callee_names = [c['callee_name'] for c in callees]
        assert 'hello' in callee_names

    def test_get_callers(self, db):
        callers = db.get_callers('hello')
        # hello is called by Greeter.greet
        assert len(callers) >= 1

    def test_resolve_call_edges(self, db):
        # Already resolved in fixture
        resolved = db.conn.execute(
            'SELECT COUNT(*) as c FROM call_edges WHERE callee_id IS NOT NULL'
        ).fetchone()['c']
        assert resolved >= 1


class TestStats:
    def test_get_stats(self, db, repo_dir):
        file_path = str(repo_dir / 'src' / 'main.py')
        symbols = extract_symbols(file_path)
        db.upsert_file(
            path='src/main.py',
            sha256='abc123',
            language='python',
            size_bytes=100,
            symbols=symbols,
        )
        stats = db.get_stats()
        assert stats['files'] == 1
        assert stats['symbols'] >= 3
        assert 'python' in stats['languages']


class TestIncrementalIndexing:
    def test_upsert_same_file_updates(self, db, repo_dir):
        file_path = str(repo_dir / 'src' / 'main.py')

        # First index
        symbols = extract_symbols(file_path)
        db.upsert_file(
            path='src/main.py',
            sha256='v1',
            language='python',
            size_bytes=100,
            symbols=symbols,
        )
        count1 = db.conn.execute('SELECT COUNT(*) as c FROM symbols').fetchone()['c']

        # Update source with more symbols
        Path(file_path).write_text(PYTHON_SOURCE_V2)
        symbols2 = extract_symbols(file_path)
        db.upsert_file(
            path='src/main.py',
            sha256='v2',
            language='python',
            size_bytes=200,
            symbols=symbols2,
        )
        count2 = db.conn.execute('SELECT COUNT(*) as c FROM symbols').fetchone()['c']

        # Should have more symbols (farewell added)
        assert count2 > count1
        # File hash should be updated
        assert db.get_file_hash('src/main.py') == 'v2'


class TestDuplicateQualifiedNames:
    def test_resolves_same_file_edges_for_duplicate_names(self, db_dir, tmp_path):
        (tmp_path / 'a.py').write_text(DUPLICATE_NAME_SOURCE_A)
        (tmp_path / 'b.py').write_text(DUPLICATE_NAME_SOURCE_B)

        db = Database(str(tmp_path), db_dir=db_dir)
        try:
            for name in ('a.py', 'b.py'):
                file_path = tmp_path / name
                source = file_path.read_text()
                db.upsert_file(
                    path=name,
                    sha256=f'hash_{name}',
                    language='python',
                    size_bytes=len(source),
                    symbols=extract_symbols(file_path),
                    file_content=source,
                )

            db.resolve_call_edges()

            helper_callees = db.get_callees('helper')
            helper2_callees = db.get_callees('helper2')

            assert any(
                row['resolved_name'] == 'main' and row['def_file'] == 'a.py'
                for row in helper_callees
            )
            assert any(
                row['resolved_name'] == 'main' and row['def_file'] == 'b.py'
                for row in helper2_callees
            )
        finally:
            db.close()
