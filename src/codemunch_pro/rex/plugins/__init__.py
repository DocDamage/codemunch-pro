"""Plugins for reverse-engineering importers."""

import logging
from pathlib import Path
from typing import Any

from codemunch_pro.rex.plugins.binja_importer import BinaryNinjaImporter
from codemunch_pro.rex.plugins.ghidra_importer import GhidraImporter
from codemunch_pro.rex.plugins.ida_importer import IdaProImporter
from codemunch_pro.rex.plugins.manifest_importer import ChronoTriggerManifestImporter


logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry for plugins."""

    def __init__(self):
        self._importers: dict[str, Any] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default plugins."""
        try:
            manifest_importer = ChronoTriggerManifestImporter()
            self._importers[manifest_importer.name] = manifest_importer
        except Exception as exc:
            logger.debug("Failed to initialize manifest importer: %s", exc)
        try:
            binja_importer = BinaryNinjaImporter()
            self._importers[binja_importer.name] = binja_importer
        except Exception as exc:
            logger.debug("Failed to initialize Binary Ninja importer: %s", exc)
        try:
            ida_importer = IdaProImporter()
            self._importers[ida_importer.name] = ida_importer
        except Exception as exc:
            logger.debug("Failed to initialize IDA importer: %s", exc)
        try:
            ghidra_importer = GhidraImporter()
            self._importers[ghidra_importer.name] = ghidra_importer
        except Exception as exc:
            logger.debug("Failed to initialize Ghidra importer: %s", exc)

    def get_importer(self, name: str) -> Any | None:
        """Get an importer by name."""
        return self._importers.get(name)

    def register_importer(self, importer: Any) -> None:
        """Register an importer."""
        self._importers[importer.name] = importer

    def find_importers(self, path: Path, project_type: str | None = None) -> list[Any]:
        """Find importers for a path."""
        results = []
        for importer in self._importers.values():
            if hasattr(importer, 'supports') and importer.supports(path):
                results.append(importer)
        return results

    def ingest(self, path: Path) -> Any | None:
        """Ingest a path."""
        importers = self.find_importers(path)
        if not importers:
            return None
        return importers[0].ingest(path)

    def list_importers(self, project_type: str | None = None) -> list[dict[str, Any]]:
        """List importers."""
        return [{"name": name} for name in self._importers.keys()]


def create_default_registry(project_type: str | None = None) -> PluginRegistry:
    """Create a default plugin registry."""
    return PluginRegistry()
