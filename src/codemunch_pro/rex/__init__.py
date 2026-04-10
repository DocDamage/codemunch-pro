"""CodeMunch Pro REX module."""

from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)
from codemunch_pro.rex.storage import ReverseEngineeringStore, DEFAULT_REX_DB_DIR
from codemunch_pro.rex.batch_ops import (
    BatchOperation,
    BatchProcessor,
    Checkpoint,
)
from codemunch_pro.rex.adapter import (
    AdapterRegistry,
    AddressCodec,
    FlatAddressCodec,
    SegmentedHexAddressCodec,
)
from codemunch_pro.rex.pattern_matcher import (
    BytePattern,
    PatternMatcher,
)
from codemunch_pro.rex.importers import (
    GenericDocumentImporter,
)
from codemunch_pro.rex.git_integration import (
    GitError,
    REProjectRepo,
)
from codemunch_pro.rex.rom_codecs import (
    AtariJaguarRomCodec,
)

try:
    from codemunch_pro.rex.async_storage import AsyncReverseEngineeringStore
except ImportError:
    AsyncReverseEngineeringStore = None  # noqa: N816

# Import regression testing classes
try:
    from codemunch_pro.rex.regression import (
        AnalysisSnapshot,
        RegressionReport,
        RegressionTester,
        MetricDiff,
    )
except ImportError:
    AnalysisSnapshot = None  # noqa: N816
    RegressionReport = None  # noqa: N816
    RegressionTester = None  # noqa: N816
    MetricDiff = None  # noqa: N816

__all__ = [
    "AddressLocation",
    "ArtifactRecord",
    "EdgeRecord",
    "EntityRecord",
    "EvidenceRecord",
    "ReverseEngineeringBundle",
    "ReverseEngineeringStore",
    "DEFAULT_REX_DB_DIR",
    "AsyncReverseEngineeringStore",
    "AdapterRegistry",
    "AddressCodec",
    "FlatAddressCodec",
    "SegmentedHexAddressCodec",
    "BytePattern",
    "PatternMatcher",
    "GenericDocumentImporter",
    "GitError",
    "REProjectRepo",
    "AtariJaguarRomCodec",
    "AnalysisSnapshot",
    "RegressionReport",
    "RegressionTester",
    "MetricDiff",
    "BatchOperation",
    "BatchProcessor",
    "Checkpoint",
]
