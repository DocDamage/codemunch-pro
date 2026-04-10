# Reverse Engineering Foundation

This document defines a ROM-agnostic path for evolving CodeMunch Pro from a
source-code indexer into a broader reverse-engineering evidence index.

## Goal

Support reverse-engineering workflows without hardcoding a specific console,
ROM format, ISA, or project layout into the core model.

The core should be able to represent:

- artifacts such as manifests, notes, JSON reports, labels, and disassembly
- entities such as functions, ranges, tables, labels, strings, and candidates
- evidence tied to those entities
- edges such as calls, branches_to, mentions, reads, writes, or derived_from
- address ranges in arbitrary address spaces

## Design Principles

1. Keep the core model platform-agnostic.
2. Push mapping and formatting rules into adapters.
3. Support both text-first projects and binary-first projects.
4. Preserve exact provenance from source artifacts.
5. Allow partial knowledge. Reverse-engineering data is often incomplete.

## Core Records

### ArtifactRecord

Describes an indexed file or generated source artifact.

Examples:
- `manifest`
- `report`
- `disassembly_note`
- `label_file`
- `scan_output`

### EntityRecord

Describes a thing discovered by analysis.

Examples:
- `function`
- `data_table`
- `jump_table`
- `range`
- `page`
- `candidate`
- `string`
- `hardware_register_use`

### EvidenceRecord

Stores a concrete supporting fact for one or more entities.

Examples:
- quoted excerpt from a note
- manifest decision for a range
- branch target observation
- score assignment
- human annotation

### EdgeRecord

Stores directional relationships between entities.

Examples:
- `calls`
- `branches_to`
- `reads_from`
- `writes_to`
- `mentions`
- `adjacent_to`
- `derived_from`
- `closed_by`

### AddressLocation

Represents a generic inclusive address range inside a named address space.

Examples:
- `flat` for raw offsets
- `snes-hirom`
- `snes-lorom`
- `gba-rom`
- `segmented-16`

The core does not need to know how those spaces map to file offsets.

## Adapter Layer

Platform and project specifics live in adapters.

### AddressCodec

Responsible for:
- parsing textual references
- extracting reference tokens from artifact text
- formatting canonical references
- mapping locations to file offsets when possible

### ReverseEngineeringImporter

Responsible for:
- deciding whether a file is supported
- producing artifact, entity, evidence, and edge records

Importers can be built for:
- generic markdown and JSON evidence
- symbol tables
- emulator traces
- project-specific manifest formats
- ISA-specific analysis outputs

## Implemented So Far

The current branch includes:

- a generic reverse-engineering data model in `codemunch_pro.rex.model`
- adapter interfaces plus `FlatAddressCodec` and `SegmentedHexAddressCodec` in `codemunch_pro.rex.adapter`
- a `GenericDocumentImporter` in `codemunch_pro.rex.importers`
- a `ReverseEngineeringStore` in `codemunch_pro.rex.storage`

This is enough to:

- ingest notes, reports, manifests, and asm-like text files as artifacts
- chunk those artifacts into searchable evidence records
- extract markdown and setext-style sections into first-class entities
- promote structured JSON and YAML fields into entity and evidence records
- detect explicit hex-style references such as `0x1234`, `$1234`, and `C3:2B00`
- generate `contains` and `mentions` edges from imported artifact structure
- persist artifacts, entities, evidence, and edges in SQLite
- run FTS queries over evidence excerpts and entity names
- retrieve indexed artifacts together with their linked entities and evidence
- list indexed reverse-engineering artifacts from MCP
- diff a stored artifact graph against a freshly imported artifact revision
- replace stale artifact-scoped rows during re-index instead of accumulating them
- resolve canonical references exactly without relying on FTS tokenization
- filter location-bearing entities by address space such as `flat` or `segmented-hex`
- fetch one-hop evidence and graph context from an exact canonical reference
- perform bounded graph traversal from an exact canonical reference into connected entities
- materialize shortest-path style routes from a canonical reference to connected entities
- rank and deduplicate equivalent shortest paths across multi-root reference traversals
- summarize exact-reference provenance on a per-artifact basis
- compare exact-reference provenance across artifacts to surface common and divergent anchors
- emit explicit disagreement summaries such as missing or exclusive anchor and evidence kinds
- cluster shared canonical references across artifacts for project-level discovery
- rank shared canonical references using structural support rather than lexical order alone

## Recommended Next Steps

1. Expand MCP retrieval further with:
   - range-aware evidence retrieval
   - user-tunable ranking heuristics for path and cluster output
   - richer disagreement summaries for per-artifact provenance comparisons
   - reference scoring tuned for specific reverse-engineering workflows
2. Add more concrete codec implementations:
   - `snes-hirom`
   - `snes-lorom`
   - other project-specific banked layouts as optional adapters
3. Add project importers as optional plugins rather than hardcoded core behavior.
4. Expand the generic extraction layer further:
   - section-aware evidence retrieval
   - configurable reference token patterns
   - optional importer plugins for manifests, traces, and label files
   - codec-assisted location inference beyond flat offsets

## Why This Stays ROM-Agnostic

The core model does not assume:
- banks
- pages
- SNES opcodes
- ROM headers
- manifest naming conventions

Those are adapter concerns. The shared model remains useful for:
- ROM hacking projects
- firmware reverse engineering
- emulator-assisted analysis
- decompilation support pipelines
