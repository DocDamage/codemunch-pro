"""FastAPI web application for CodeMunch Pro REX."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from codemunch_pro.rex.storage import DEFAULT_REX_DB_DIR, ReverseEngineeringStore


def create_app(db_path: Path | str | None = None) -> FastAPI:
    """Create the FastAPI application."""
    app = FastAPI(
        title="CodeMunch Pro REX",
        description="Reverse Engineering Exploration Interface",
        version="1.2.0",
    )

    # Determine database path
    if db_path is None:
        db_path = DEFAULT_REX_DB_DIR / "rex.db"
    db_path = Path(db_path)

    # Setup static files and templates
    web_dir = Path(__file__).parent
    static_dir = web_dir / "static"
    templates_dir = web_dir / "templates"

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    templates = Jinja2Templates(directory=str(templates_dir))

    # Helper to get a store instance (for thread safety)
    def get_store() -> ReverseEngineeringStore:
        """Get a new store instance for the current thread."""
        return ReverseEngineeringStore(db_path)

    # Context processor for templates
    def get_base_context(request: Request) -> dict[str, Any]:
        """Get base context for all templates."""
        store = get_store()
        try:
            stats = store.stats()
            return {
                "request": request,
                "stats": stats,
                "app_version": "1.2.0",
            }
        finally:
            store.close()

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        """Main dashboard page."""
        store = get_store()
        try:
            context = get_base_context(request)
            
            # Get recent artifacts
            artifacts = store.list_artifacts(limit=10)
            context["artifacts"] = [a.to_dict() for a in artifacts]
            
            # Get entity counts by kind
            entity_kinds = {}
            for kind in ["function", "data", "string", "section", "reference", "label"]:
                entities = store.list_entities(kind=kind, limit=1)
                if entities:
                    count = store._conn.execute(
                        "SELECT COUNT(*) FROM entities WHERE kind = ?", (kind,)
                    ).fetchone()[0]
                    entity_kinds[kind] = count
            
            context["entity_kinds"] = entity_kinds
            context["total_kinds"] = len([k for k, v in entity_kinds.items() if v > 0])
            
            # Get recent entities
            recent_entities = store.list_entities(limit=20)
            context["recent_entities"] = [e.to_dict() for e in recent_entities]
            
            return templates.TemplateResponse(request, "dashboard.html", context)
        finally:
            store.close()

    @app.get("/search", response_class=HTMLResponse)
    async def search_page(
        request: Request,
        q: str = Query("", description="Search query"),
        kind: str = Query("", description="Entity kind filter"),
    ) -> HTMLResponse:
        """Search page with results."""
        store = get_store()
        try:
            context = get_base_context(request)
            context["query"] = q
            context["kind"] = kind
            context["has_query"] = bool(q)
            
            if q:
                # Search entities
                entities = store.search_entities(q, kind=kind or None, limit=50)
                context["entities"] = entities
                context["entity_count"] = len(entities)
                
                # Search evidence
                evidence = store.search_evidence(q, limit=50)
                context["evidence"] = evidence
                context["evidence_count"] = len(evidence)
            else:
                context["entities"] = []
                context["evidence"] = []
                context["entity_count"] = 0
                context["evidence_count"] = 0
            
            return templates.TemplateResponse(request, "search.html", context)
        finally:
            store.close()

    @app.get("/entity/{entity_id}", response_class=HTMLResponse)
    async def entity_detail(request: Request, entity_id: str) -> HTMLResponse:
        """Entity detail page."""
        store = get_store()
        try:
            context = get_base_context(request)
            
            entity = store.get_entity(entity_id)
            if entity is None:
                raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found")
            
            context["entity"] = entity.to_dict()
            
            # Get evidence for this entity
            evidence = store.get_evidence_for_entity(entity_id, limit=100)
            context["evidence"] = [e.to_dict() for e in evidence]
            
            # Get neighbors (edges)
            edges = store.get_neighbors(entity_id, limit=100)
            context["edges"] = [e.to_dict() for e in edges]
            
            # Build neighbor details
            neighbors = []
            for edge in edges:
                other_id = edge.target_entity_id if edge.source_entity_id == entity_id else edge.source_entity_id
                other = store.get_entity(other_id)
                if other:
                    neighbors.append({
                        "edge": edge.to_dict(),
                        "entity": other.to_dict(),
                        "direction": "outgoing" if edge.source_entity_id == entity_id else "incoming",
                    })
            context["neighbors"] = neighbors
            
            # Get artifact info
            if entity.artifact_id:
                artifact = store.get_artifact(entity.artifact_id)
                context["artifact"] = artifact.to_dict() if artifact else None
            else:
                context["artifact"] = None
            
            return templates.TemplateResponse(request, "entity_detail.html", context)
        finally:
            store.close()

    @app.get("/graph", response_class=HTMLResponse)
    async def graph_view(
        request: Request,
        entity_id: str = Query("", description="Root entity ID"),
        depth: int = Query(2, description="Traversal depth", ge=1, le=5),
    ) -> HTMLResponse:
        """Interactive graph view."""
        store = get_store()
        try:
            context = get_base_context(request)
            context["entity_id"] = entity_id
            context["depth"] = depth
            
            if entity_id:
                # Get graph data
                graph_data = store.traverse_entity_graph([entity_id], depth=depth, edge_limit=200)
                
                # Convert to format suitable for D3/Cytoscape
                nodes = []
                for entity in graph_data["entities"]:
                    node = {
                        "id": entity.entity_id,
                        "label": entity.name or entity.entity_id,
                        "kind": entity.kind,
                        "depth": graph_data["depths"].get(entity.entity_id, 0),
                    }
                    if entity.location:
                        node["address"] = f"0x{entity.location.start:04X}"
                    nodes.append(node)
                
                edges_data = []
                for edge in graph_data["edges"]:
                    edges_data.append({
                        "id": edge.edge_id,
                        "source": edge.source_entity_id,
                        "target": edge.target_entity_id,
                        "kind": edge.kind,
                    })
                
                context["graph_data"] = {
                    "nodes": nodes,
                    "edges": edges_data,
                    "root_entity_ids": graph_data["root_entity_ids"],
                }
                context["has_data"] = True
            else:
                # Get all entities for selection
                all_entities = store.list_entities(limit=1000)
                context["available_entities"] = [
                    {"id": e.entity_id, "name": e.name or e.entity_id, "kind": e.kind}
                    for e in all_entities
                ]
                context["has_data"] = False
                context["graph_data"] = None
            
            return templates.TemplateResponse(request, "graph.html", context)
        finally:
            store.close()

    @app.get("/memory", response_class=HTMLResponse)
    async def memory_map(
        request: Request,
        address_space: str = Query("", description="Address space to view"),
    ) -> HTMLResponse:
        """Memory map visualization."""
        store = get_store()
        try:
            context = get_base_context(request)
            
            # Get all address spaces from entities
            cursor = store._conn.cursor()
            cursor.execute(
                "SELECT DISTINCT json_extract(location_json, '$.address_space') as space "
                "FROM entities WHERE location_json IS NOT NULL"
            )
            address_spaces = [row[0] for row in cursor.fetchall() if row[0]]
            context["address_spaces"] = sorted(set(address_spaces))
            context["current_space"] = address_space
            
            if address_space:
                # Get all entities in this address space
                entities = store.list_entities(address_space=address_space, limit=10000)
                
                # Calculate memory map ranges
                if entities:
                    min_addr = min(e.location.start for e in entities if e.location)
                    max_addr = max(e.location.end for e in entities if e.location)
                    
                    # Create memory blocks
                    blocks = []
                    for entity in entities:
                        if entity.location:
                            blocks.append({
                                "id": entity.entity_id,
                                "name": entity.name or entity.entity_id,
                                "kind": entity.kind,
                                "start": entity.location.start,
                                "end": entity.location.end,
                                "size": entity.location.size,
                                "display": entity.location.display or f"0x{entity.location.start:04X}",
                            })
                    
                    # Sort by address
                    blocks.sort(key=lambda x: x["start"])
                    
                    context["memory_map"] = {
                        "address_space": address_space,
                        "min_address": min_addr,
                        "max_address": max_addr,
                        "total_size": max_addr - min_addr + 1,
                        "blocks": blocks,
                        "block_count": len(blocks),
                    }
                else:
                    context["memory_map"] = None
            else:
                context["memory_map"] = None
            
            return templates.TemplateResponse(request, "memory.html", context)
        finally:
            store.close()

    @app.get("/artifact/{artifact_id}", response_class=HTMLResponse)
    async def artifact_detail(request: Request, artifact_id: str) -> HTMLResponse:
        """Artifact detail page."""
        store = get_store()
        try:
            context = get_base_context(request)
            
            artifact = store.get_artifact(artifact_id)
            if artifact is None:
                raise HTTPException(status_code=404, detail=f"Artifact '{artifact_id}' not found")
            
            context["artifact"] = artifact.to_dict()
            
            # Get entities for this artifact
            entities = store.get_entities_for_artifact(artifact_id, limit=1000)
            context["entities"] = [e.to_dict() for e in entities]
            
            # Group entities by kind
            by_kind = {}
            for entity in entities:
                if entity.kind not in by_kind:
                    by_kind[entity.kind] = []
                by_kind[entity.kind].append(entity.to_dict())
            context["entities_by_kind"] = by_kind
            
            # Get evidence for this artifact
            evidence = store.get_evidence_for_artifact(artifact_id, limit=1000)
            context["evidence"] = [e.to_dict() for e in evidence]
            
            return templates.TemplateResponse(request, "artifact_detail.html", context)
        finally:
            store.close()

    @app.get("/evidence/{evidence_id}", response_class=HTMLResponse)
    async def evidence_detail(request: Request, evidence_id: str) -> HTMLResponse:
        """Evidence detail page."""
        store = get_store()
        try:
            context = get_base_context(request)
            
            # Get evidence directly from database
            cursor = store._conn.cursor()
            cursor.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
            row = cursor.fetchone()
            
            if row is None:
                raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found")
            
            evidence = store._row_to_evidence(row)
            context["evidence"] = evidence.to_dict()
            
            # Get related entities
            related_entities = []
            for entity_id in evidence.entity_ids:
                entity = store.get_entity(entity_id)
                if entity:
                    related_entities.append(entity.to_dict())
            context["related_entities"] = related_entities
            
            # Get artifact info
            if evidence.artifact_id:
                artifact = store.get_artifact(evidence.artifact_id)
                context["artifact"] = artifact.to_dict() if artifact else None
            else:
                context["artifact"] = None
            
            return templates.TemplateResponse(request, "evidence_detail.html", context)
        finally:
            store.close()

    # API Endpoints
    @app.get("/api/search")
    async def api_search(
        q: str = Query(..., description="Search query"),
        kind: str = Query("", description="Entity kind filter"),
        limit: int = Query(20, description="Maximum results", ge=1, le=100),
    ) -> JSONResponse:
        """API endpoint for searching entities."""
        store = get_store()
        try:
            entities = store.search_entities(q, kind=kind or None, limit=limit)
            evidence = store.search_evidence(q, limit=limit)
            
            return JSONResponse({
                "query": q,
                "entities": entities,
                "evidence": evidence,
                "entity_count": len(entities),
                "evidence_count": len(evidence),
            })
        finally:
            store.close()

    @app.get("/api/autocomplete")
    async def api_autocomplete(
        q: str = Query(..., description="Search prefix"),
        limit: int = Query(10, description="Maximum results", ge=1, le=50),
    ) -> JSONResponse:
        """API endpoint for autocomplete suggestions."""
        store = get_store()
        try:
            # Search entities by name
            entities = store.search_entities(q, limit=limit)
            
            suggestions = []
            for entity in entities:
                suggestions.append({
                    "id": entity["entity_id"],
                    "name": entity["name"],
                    "kind": entity["kind"],
                    "display": f"{entity['name']} ({entity['kind']})",
                })
            
            return JSONResponse({
                "query": q,
                "suggestions": suggestions,
            })
        finally:
            store.close()

    @app.get("/api/entity/{entity_id}")
    async def api_entity(entity_id: str) -> JSONResponse:
        """API endpoint for getting entity details."""
        store = get_store()
        try:
            entity = store.get_entity(entity_id)
            if entity is None:
                raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found")
            
            evidence = store.get_evidence_for_entity(entity_id, limit=100)
            edges = store.get_neighbors(entity_id, limit=100)
            
            return JSONResponse({
                "entity": entity.to_dict(),
                "evidence": [e.to_dict() for e in evidence],
                "edges": [e.to_dict() for e in edges],
            })
        finally:
            store.close()

    @app.get("/api/graph")
    async def api_graph(
        entity_ids: str = Query(..., description="Comma-separated entity IDs"),
        depth: int = Query(2, description="Traversal depth", ge=1, le=5),
        edge_limit: int = Query(200, description="Maximum edges", ge=1, le=1000),
    ) -> JSONResponse:
        """API endpoint for getting graph data."""
        store = get_store()
        try:
            ids = [id.strip() for id in entity_ids.split(",") if id.strip()]
            if not ids:
                raise HTTPException(status_code=400, detail="No entity IDs provided")
            
            graph_data = store.traverse_entity_graph(ids, depth=depth, edge_limit=edge_limit)
            
            return JSONResponse({
                "nodes": [e.to_dict() for e in graph_data["entities"]],
                "edges": [e.to_dict() for e in graph_data["edges"]],
                "depths": graph_data["depths"],
                "root_entity_ids": graph_data["root_entity_ids"],
            })
        finally:
            store.close()

    @app.get("/api/stats")
    async def api_stats() -> JSONResponse:
        """API endpoint for database statistics."""
        store = get_store()
        try:
            return JSONResponse(store.stats())
        finally:
            store.close()

    @app.get("/api/memory-map")
    async def api_memory_map(
        address_space: str = Query(..., description="Address space"),
    ) -> JSONResponse:
        """API endpoint for memory map data."""
        store = get_store()
        try:
            entities = store.list_entities(address_space=address_space, limit=10000)
            
            blocks = []
            for entity in entities:
                if entity.location:
                    blocks.append({
                        "id": entity.entity_id,
                        "name": entity.name or entity.entity_id,
                        "kind": entity.kind,
                        "start": entity.location.start,
                        "end": entity.location.end,
                        "size": entity.location.size,
                    })
            
            blocks.sort(key=lambda x: x["start"])
            
            return JSONResponse({
                "address_space": address_space,
                "blocks": blocks,
                "block_count": len(blocks),
            })
        finally:
            store.close()

    return app


def run_server(
    db_path: Path | str | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    reload: bool = False,
) -> None:
    """Run the web server."""
    import uvicorn
    
    app = create_app(db_path)
    uvicorn.run(app, host=host, port=port, reload=reload)


if __name__ == "__main__":
    run_server()
