# CodeMunch Pro

<!-- mcp-name: io.github.BigJai/codemunch-pro -->

Intelligent code indexing MCP server. 32 tools, 10 languages, tree-sitter AST extraction, hybrid search (FTS5 + vector), call graphs, remote repo indexing, incremental indexing, and reverse-engineering evidence indexing.

**Save 99% of tokens** — get exact function source via byte-offset seek instead of reading entire files.

## Install

```bash
pip install codemunch-pro
```

## Quick Start

### Claude Desktop / Cline

Add to your MCP client config:

```json
{
  "mcpServers": {
    "codemunch-pro": {
      "command": "codemunch-pro"
    }
  }
}
```

### HTTP Server

```bash
codemunch-pro --transport streamable-http --port 5002
```

## 32 MCP Tools

| Tool | Description |
|------|-------------|
| `index_folder` | Index a local directory (incremental, SHA-256 based) |
| `index_repo` | Index a GitHub/GitLab repo (tarball download, no git needed) |
| `list_repos` | List all indexed repositories with stats |
| `invalidate_cache` | Force re-index a repository |
| `file_tree` | Get directory tree with file counts |
| `file_outline` | List symbols in a single file |
| `repo_outline` | List all symbols in repo (summary) |
| `get_symbol` | Get full source of one symbol (O(1) byte seek) |
| `get_symbols` | Batch get multiple symbols |
| `search_symbols` | Hybrid search (FTS5 + vector RRF) |
| `search_text` | Full-text search in file contents |
| `get_callees` | What does this function call? |
| `get_callers` | Who calls this function? |
| `diff_symbols` | What changed since last index? (PR review) |
| `dependency_map` | What does this file depend on? What depends on it? |
| `index_artifact` | Index one reverse-engineering artifact into the rex store |
| `index_artifact_folder` | Index importer-supported artifacts in a folder |
| `search_evidence` | Search reverse-engineering evidence excerpts |
| `get_rex_entity` | Fetch a reverse-engineering entity with linked evidence |
| `get_rex_neighbors` | Get reverse-engineering graph edges for an entity |
| `search_rex_entities` | Search reverse-engineering entities by name or canonical reference |
| `get_rex_artifact` | Fetch one indexed reverse-engineering artifact with linked entities and evidence |
| `list_rex_artifacts` | List indexed reverse-engineering artifacts for a project |
| `diff_rex_artifact` | Compare stored rex records for one artifact against current importer output |
| `find_rex_entities_by_ref` | Find reverse-engineering entities by exact canonical reference |
| `list_rex_entities` | List reverse-engineering entities with kind and address-space filters |
| `get_rex_ref_context` | Fetch entities, evidence, and graph edges linked to an exact canonical reference |
| `get_rex_ref_graph` | Traverse the reverse-engineering graph outward from an exact canonical reference |
| `get_rex_ref_paths` | Return ranked, optionally deduplicated shortest-path style expansions from an exact canonical reference |
| `get_rex_ref_provenance` | Summarize exact-reference provenance per artifact |
| `compare_rex_ref_provenance` | Compare exact-reference provenance across artifacts, including disagreement summaries |
| `list_rex_shared_refs` | List and rank canonical references shared across multiple artifacts |

## 10 Languages

Python, JavaScript, TypeScript, Go, Rust, Java, C, C++, C#, Ruby

All via [tree-sitter-language-pack](https://pypi.org/project/tree-sitter-language-pack/) — zero compilation, pre-built binaries.

## Key Features

### O(1) Symbol Retrieval
Every symbol stores its byte offset and length. `get_symbol` seeks directly to the function source — no reading entire files. A 200-byte function from a 40KB file = **99.5% token savings**.

### Incremental Indexing
Files are hashed (SHA-256). Only changed files are re-parsed. Re-indexing a 10K file repo after changing one file takes milliseconds.

### Hybrid Search (FTS5 + Vector)
Combines BM25 keyword matching with semantic vector similarity using Reciprocal Rank Fusion. Search "authentication middleware" and find `auth_middleware`, `verify_token`, and `login_handler`.

### Call Graphs
Traces function calls through the AST. `get_callees("main")` shows what `main` calls. `get_callers("authenticate")` shows who calls `authenticate`. Supports depth traversal.

### Remote Repo Indexing (v1.1)
Index any public GitHub or GitLab repo by URL — no git binary needed. Downloads the tarball via API, extracts, and indexes. Cached locally with SHA-based freshness checks. Supports private repos with auth tokens and sparse paths.

### Full-Text Content Search
Search raw file contents — string literals, TODO comments, config values, error messages. Not just symbol names.

## How It Works

1. **Parse** — tree-sitter builds an AST for each source file
2. **Extract** — Walk AST to find functions, classes, methods, types, interfaces
3. **Store** — SQLite database per repo with FTS5 virtual tables
4. **Embed** — FastEmbed (ONNX, CPU-only) generates 384-dim vectors for semantic search
5. **Graph** — Call expressions extracted from function bodies, edges stored and resolved
6. **Serve** — FastMCP exposes 32 tools via stdio or HTTP

## Architecture

```
~/.codemunch-pro/
├── myproject_a1b2c3d4e5f6.db    # Per-repo SQLite database
├── otherproject_7890abcdef.db
└── ...

Each DB contains:
├── files          # Indexed files with SHA-256 hashes
├── symbols        # Functions, classes, methods, types
├── symbols_fts    # FTS5 full-text search index
├── symbols_vec    # sqlite-vec 384-dim vector index
├── call_edges     # Call graph (caller → callee)
└── file_content_fts  # Raw file content search
```

## Use Cases

- **AI Coding Agents**: Give your agent surgical access to codebases without burning context
- **Code Review**: Find all callers of a function before changing its signature
- **Onboarding**: Search symbols semantically — "where is error handling?" finds relevant code
- **Refactoring**: Map call graphs before moving functions between modules
- **Documentation**: Extract all public APIs with signatures and docstrings

## Reverse Engineering Foundation

CodeMunch Pro now includes an initial ROM-agnostic reverse-engineering model
under `codemunch_pro.rex`.

This layer is intended to support binary and reverse-engineering projects
without hardcoding platform-specific concepts into the core package.

Current foundation pieces:
- generic `ArtifactRecord`, `EntityRecord`, `EvidenceRecord`, and `EdgeRecord`
- generic `AddressLocation` with named address spaces
- adapter interfaces for address codecs and reverse-engineering importers
- a minimal `FlatAddressCodec` for raw offset-based binaries
- a generic `SegmentedHexAddressCodec` for bank/segment:offset references such as `C3:2B00`
- `GenericDocumentImporter` for `.md`, `.txt`, `.json`, `.yaml`, `.yml`, `.asm`, `.s`, and `.inc`
- section extraction, structured field promotion, and codec-assisted reference extraction
- artifact replacement on re-index so stale rex records do not linger
- `ReverseEngineeringStore` for SQLite-backed persistence and text search over evidence

Design notes and the roadmap live in:
- `docs/reverse_engineering_foundation.md`

Planned next steps:
- add richer reverse-engineering query tools on top of the rex store
- add optional project-specific importers for manifests, traces, and labels
- add platform adapters such as SNES HiROM and LoROM as optional codecs

## License

MIT
