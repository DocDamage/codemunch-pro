"""Tests for CodeMunch Pro REX web interface."""

import pytest
from fastapi.testclient import TestClient

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)
from codemunch_pro.rex.storage import ReverseEngineeringStore
from codemunch_pro.rex.web.app import create_app


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary database path."""
    return tmp_path / "test_rex.db"


@pytest.fixture
def store(temp_db_path):
    """Create a ReverseEngineeringStore with test data."""
    store = ReverseEngineeringStore(temp_db_path)
    
    # Create test bundle
    bundle = ReverseEngineeringBundle()
    
    # Add artifact
    artifact = ArtifactRecord(
        artifact_id="test-manifest",
        kind="manifest",
        path="/test/manifest.json",
        title="Test Manifest",
    )
    bundle.artifacts.append(artifact)
    
    # Add entities
    func1 = EntityRecord(
        entity_id="func-001",
        kind="function",
        name="main",
        artifact_id="test-manifest",
        canonical_ref="C:main",
        summary="Main function",
        location=AddressLocation(
            address_space="rom",
            start=0xC000,
            end=0xC100,
            display="C000",
        ),
        attributes={"return_type": "void", "param_count": 0},
    )
    func2 = EntityRecord(
        entity_id="func-002",
        kind="function",
        name="init",
        artifact_id="test-manifest",
        canonical_ref="C:init",
        location=AddressLocation(
            address_space="rom",
            start=0xC100,
            end=0xC200,
            display="C100",
        ),
    )
    data1 = EntityRecord(
        entity_id="data-001",
        kind="data",
        name="game_state",
        artifact_id="test-manifest",
        location=AddressLocation(
            address_space="ram",
            start=0x7E0010,
            end=0x7E001F,
            display="7E:0010",
        ),
    )
    bundle.entities.extend([func1, func2, data1])
    
    # Add evidence
    ev1 = EvidenceRecord(
        evidence_id="ev-001",
        kind="disassembly",
        artifact_id="test-manifest",
        entity_ids=("func-001",),
        location=AddressLocation(
            address_space="rom",
            start=0xC000,
            end=0xC010,
            display="C000",
        ),
        excerpt="C000: LDA #$01\nC002: STA $2100",
        confidence=0.95,
    )
    bundle.evidence.append(ev1)
    
    # Add edges
    edge1 = EdgeRecord(
        edge_id="edge-001",
        kind="calls",
        source_entity_id="func-001",
        target_entity_id="func-002",
        evidence_id="ev-001",
    )
    bundle.edges.append(edge1)
    
    store.upsert_bundle(bundle)
    
    yield store
    
    store.close()


@pytest.fixture
def client(store, temp_db_path):
    """Create a test client with the populated store."""
    app = create_app(temp_db_path)
    return TestClient(app)


class TestDashboard:
    """Test dashboard endpoints."""
    
    def test_dashboard_page(self, client):
        """Test dashboard page loads."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "CodeMunch Pro REX" in response.text
        assert "Dashboard" in response.text
    
    def test_dashboard_shows_stats(self, client):
        """Test dashboard displays statistics."""
        response = client.get("/")
        assert response.status_code == 200
        # Check for stat cards
        assert "Artifacts" in response.text
        assert "Entities" in response.text
        assert "Evidence" in response.text
        assert "Edges" in response.text


class TestSearch:
    """Test search functionality."""
    
    def test_search_page(self, client):
        """Test search page loads."""
        response = client.get("/search")
        assert response.status_code == 200
        assert "Search" in response.text
    
    def test_search_with_query(self, client):
        """Test search with query returns results."""
        response = client.get("/search?q=main")
        assert response.status_code == 200
        assert "main" in response.text
        assert "func-001" in response.text
    
    def test_search_with_kind_filter(self, client):
        """Test search with kind filter."""
        response = client.get("/search?q=func&kind=function")
        assert response.status_code == 200
    
    def test_search_no_results(self, client):
        """Test search with no matching results."""
        response = client.get("/search?q=nonexistent")
        assert response.status_code == 200
        assert "No results" in response.text


class TestEntityDetail:
    """Test entity detail pages."""
    
    def test_entity_detail_page(self, client):
        """Test entity detail page loads."""
        response = client.get("/entity/func-001")
        assert response.status_code == 200
        assert "main" in response.text
        assert "function" in response.text
        assert "C000" in response.text
    
    def test_entity_detail_not_found(self, client):
        """Test entity detail page for nonexistent entity."""
        response = client.get("/entity/nonexistent")
        assert response.status_code == 404
    
    def test_entity_detail_shows_evidence(self, client):
        """Test entity detail page shows evidence."""
        response = client.get("/entity/func-001")
        assert response.status_code == 200
        assert "Evidence" in response.text
    
    def test_entity_detail_shows_relations(self, client):
        """Test entity detail page shows relations."""
        response = client.get("/entity/func-001")
        assert response.status_code == 200
        assert "Relations" in response.text


class TestGraphView:
    """Test graph view page."""
    
    def test_graph_page(self, client):
        """Test graph page loads."""
        response = client.get("/graph")
        assert response.status_code == 200
        assert "Graph View" in response.text
    
    def test_graph_with_entity(self, client):
        """Test graph page with entity parameter."""
        response = client.get("/graph?entity_id=func-001&depth=2")
        assert response.status_code == 200
        # Check for Cytoscape initialization
        assert "cytoscape" in response.text.lower() or "graph-container" in response.text


class TestMemoryMap:
    """Test memory map page."""
    
    def test_memory_page(self, client):
        """Test memory map page loads."""
        response = client.get("/memory")
        assert response.status_code == 200
        assert "Memory Map" in response.text
    
    def test_memory_with_address_space(self, client):
        """Test memory map with address space filter."""
        response = client.get("/memory?address_space=rom")
        assert response.status_code == 200
        # Should show memory blocks
        assert "rom" in response.text or "Memory" in response.text


class TestArtifactDetail:
    """Test artifact detail pages."""
    
    def test_artifact_detail_page(self, client):
        """Test artifact detail page loads."""
        response = client.get("/artifact/test-manifest")
        assert response.status_code == 200
        assert "Test Manifest" in response.text
    
    def test_artifact_detail_not_found(self, client):
        """Test artifact detail page for nonexistent artifact."""
        response = client.get("/artifact/nonexistent")
        assert response.status_code == 404


class TestEvidenceDetail:
    """Test evidence detail pages."""
    
    def test_evidence_detail_page(self, client):
        """Test evidence detail page loads."""
        response = client.get("/evidence/ev-001")
        assert response.status_code == 200
        assert "ev-001" in response.text
        assert "LDA" in response.text  # Check for disassembly content
    
    def test_evidence_detail_not_found(self, client):
        """Test evidence detail page for nonexistent evidence."""
        response = client.get("/evidence/nonexistent")
        assert response.status_code == 404


class TestAPI:
    """Test API endpoints."""
    
    def test_api_search(self, client):
        """Test API search endpoint."""
        response = client.get("/api/search?q=main")
        assert response.status_code == 200
        data = response.json()
        assert "entities" in data
        assert "evidence" in data
        assert data["query"] == "main"
    
    def test_api_autocomplete(self, client):
        """Test API autocomplete endpoint."""
        response = client.get("/api/autocomplete?q=ma")
        assert response.status_code == 200
        data = response.json()
        assert "suggestions" in data
    
    def test_api_entity(self, client):
        """Test API entity endpoint."""
        response = client.get("/api/entity/func-001")
        assert response.status_code == 200
        data = response.json()
        assert "entity" in data
        assert data["entity"]["entity_id"] == "func-001"
    
    def test_api_entity_not_found(self, client):
        """Test API entity endpoint for nonexistent entity."""
        response = client.get("/api/entity/nonexistent")
        assert response.status_code == 404
    
    def test_api_graph(self, client):
        """Test API graph endpoint."""
        response = client.get("/api/graph?entity_ids=func-001&depth=2")
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data
    
    def test_api_stats(self, client):
        """Test API stats endpoint."""
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "artifacts" in data
        assert "entities" in data
        assert "evidence" in data
        assert "edges" in data
    
    def test_api_memory_map(self, client):
        """Test API memory map endpoint."""
        response = client.get("/api/memory-map?address_space=rom")
        assert response.status_code == 200
        data = response.json()
        assert "address_space" in data
        assert "blocks" in data


class TestStaticFiles:
    """Test static file serving."""
    
    def test_css_file(self, client):
        """Test CSS file is served."""
        response = client.get("/static/css/style.css")
        assert response.status_code == 200
        assert "text/css" in response.headers["content-type"]
    
    def test_js_file(self, client):
        """Test JS file is served."""
        response = client.get("/static/js/main.js")
        assert response.status_code == 200
        assert "javascript" in response.headers["content-type"]


class TestCLI:
    """Test CLI functionality."""
    
    def test_create_app(self, temp_db_path):
        """Test app creation."""
        from codemunch_pro.rex.web.app import create_app
        app = create_app(temp_db_path)
        assert app is not None
        assert app.title == "CodeMunch Pro REX"
