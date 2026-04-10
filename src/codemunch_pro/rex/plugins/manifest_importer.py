"""Chrono Trigger manifest importer."""

from __future__ import annotations

import json
from pathlib import Path

from codemunch_pro.rex.model import (
    ArtifactRecord,
    EntityRecord,
    ReverseEngineeringBundle,
)


class ChronoTriggerManifestImporter:
    """Importer for Chrono Trigger manifest files."""

    name: str = "chrono-trigger-manifest"

    def supports(self, path: Path) -> bool:
        """Check if this importer supports the given path."""
        if path.suffix.lower() != ".json":
            return False
        try:
            data = json.loads(path.read_text())
            return "address" in data
        except (json.JSONDecodeError, IOError):
            return False

    def ingest(self, path: Path) -> ReverseEngineeringBundle:
        """Ingest a manifest file."""
        data = json.loads(path.read_text())
        artifact = ArtifactRecord(
            artifact_id=path.as_posix(),
            kind="manifest",
            path=path.as_posix(),
        )
        entity = EntityRecord(
            entity_id=f"entity:function:{data.get('address', 'unknown')}",
            kind="function",
            name=data.get("name", "unknown"),
            canonical_ref=data.get("address", ""),
        )
        return ReverseEngineeringBundle(artifacts=[artifact], entities=[entity])
