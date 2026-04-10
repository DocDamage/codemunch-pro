"""Tests for the smart rename suggestion functionality."""

import pytest
from codemunch_pro.rex.smart_rename import (
    RenameSuggester,
    RenameSuggestion,
    RenameResult,
)
from codemunch_pro.rex import ReverseEngineeringStore
from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)


class TestRenameSuggestion:
    """Tests for RenameSuggestion dataclass."""

    def test_create_suggestion(self):
        suggestion = RenameSuggestion(
            suggested_name="GetStringLength",
            confidence=0.85,
            heuristic="library_signature",
            reasoning="Name matches strlen signature",
        )
        assert suggestion.suggested_name == "GetStringLength"
        assert suggestion.confidence == 0.85
        assert suggestion.heuristic == "library_signature"
        assert suggestion.platform == "generic"  # default

    def test_confidence_bounds(self):
        with pytest.raises(ValueError):
            RenameSuggestion(
                suggested_name="Test",
                confidence=1.5,  # Too high
                heuristic="test",
                reasoning="test",
            )

        with pytest.raises(ValueError):
            RenameSuggestion(
                suggested_name="Test",
                confidence=-0.1,  # Too low
                heuristic="test",
                reasoning="test",
            )


class TestRenameResult:
    """Tests for RenameResult dataclass."""

    def test_best_suggestion(self):
        suggestions = [
            RenameSuggestion("NameB", 0.7, "test", "test"),
            RenameSuggestion("NameA", 0.9, "test", "test"),
            RenameSuggestion("NameC", 0.5, "test", "test"),
        ]
        result = RenameResult(
            entity_id="test:1",
            current_name="old_name",
            suggestions=suggestions,
        )
        best = result.best_suggestion
        assert best is not None
        assert best.suggested_name == "NameA"
        assert best.confidence == 0.9

    def test_best_suggestion_empty(self):
        result = RenameResult(
            entity_id="test:1",
            current_name="old_name",
            suggestions=[],
        )
        assert result.best_suggestion is None


class TestRenameSuggester:
    """Tests for RenameSuggester class."""

    def test_init_default_platform(self):
        suggester = RenameSuggester()
        assert suggester.platform == "generic"

    def test_init_windows_platform(self):
        suggester = RenameSuggester(platform="windows")
        assert suggester.platform == "windows"
        # Should have Windows signatures loaded
        assert "CreateFileA" in suggester._library_sigs

    def test_to_pascal_case(self):
        suggester = RenameSuggester()
        assert suggester._to_pascal_case("get_name") == "GetName"
        assert suggester._to_pascal_case("get-name") == "GetName"
        assert suggester._to_pascal_case("get name") == "GetName"
        assert suggester._to_pascal_case("get") == "Get"
        assert suggester._to_pascal_case("") == ""

    def test_to_camel_case(self):
        suggester = RenameSuggester()
        assert suggester._to_camel_case("GetName") == "getName"
        assert suggester._to_camel_case("get_name") == "getName"
        assert suggester._to_camel_case("getName") == "getName"

    def test_analyze_naming_patterns_getter(self):
        suggester = RenameSuggester()
        suggestions = suggester._analyze_naming_patterns("get_user_name")
        assert any(s.suggested_name == "GetUserName" for s in suggestions)
        assert any(s.heuristic == "getter_pattern" for s in suggestions)

    def test_analyze_naming_patterns_setter(self):
        suggester = RenameSuggester()
        suggestions = suggester._analyze_naming_patterns("set_value")
        assert any(s.suggested_name == "SetValue" for s in suggestions)
        assert any(s.heuristic == "setter_pattern" for s in suggestions)

    def test_analyze_naming_patterns_init(self):
        suggester = RenameSuggester()
        suggestions = suggester._analyze_naming_patterns("init_system")
        assert any(s.suggested_name == "InitializeSystem" for s in suggestions)
        assert any(s.heuristic == "init_pattern" for s in suggestions)

    def test_analyze_naming_patterns_cleanup(self):
        suggester = RenameSuggester()
        suggestions = suggester._analyze_naming_patterns("cleanup")
        assert any(s.suggested_name == "Cleanup" for s in suggestions)
        assert any(s.heuristic == "cleanup_pattern" for s in suggestions)

    def test_analyze_library_signatures(self):
        suggester = RenameSuggester()
        suggestions = suggester._analyze_library_signatures("my_strlen", [])
        assert any(s.suggested_name == "GetStringLength" for s in suggestions)
        assert any(s.heuristic == "library_signature" for s in suggestions)


class TestRenameSuggesterWithStore:
    """Tests for RenameSuggester with actual store data."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a temporary store with test data."""
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Create a test artifact and function entity
        bundle = ReverseEngineeringBundle(
            artifacts=[
                ArtifactRecord(
                    artifact_id="test:artifact:1",
                    kind="analysis",
                    path="test.asm",
                )
            ],
            entities=[
                EntityRecord(
                    entity_id="test:func:sub_1234",
                    kind="function",
                    name="sub_1234",
                    artifact_id="test:artifact:1",
                    canonical_ref="0x1234",
                    location=AddressLocation(
                        address_space="flat",
                        start=0x1234,
                        end=0x1250,
                    ),
                ),
                EntityRecord(
                    entity_id="test:data:buffer",
                    kind="data",
                    name="unk_buffer",
                    artifact_id="test:artifact:1",
                    canonical_ref="0x2000",
                    location=AddressLocation(
                        address_space="flat",
                        start=0x2000,
                        end=0x2100,
                    ),
                    attributes={"size": 256, "type": "buffer"},
                ),
            ],
            evidence=[
                EvidenceRecord(
                    evidence_id="test:ev:1",
                    kind="disassembly",
                    artifact_id="test:artifact:1",
                    entity_ids=("test:func:sub_1234",),
                    excerpt="call strlen ; get string length",
                    confidence=0.9,
                ),
            ],
        )
        store.upsert_bundle(bundle)
        return store

    def test_suggest_function_name_not_found(self, store):
        suggester = RenameSuggester()
        result = suggester.suggest_function_name("nonexistent", store)
        assert result.current_name == ""
        assert "error" in result.metadata

    def test_suggest_function_name_not_function(self, store):
        suggester = RenameSuggester()
        result = suggester.suggest_function_name("test:data:buffer", store)
        assert result.current_name == "unk_buffer"
        assert "error" in result.metadata
        assert result.metadata["error"] == "Entity is not a function"

    def test_suggest_function_name_success(self, store):
        suggester = RenameSuggester()
        result = suggester.suggest_function_name("test:func:sub_1234", store)
        assert result.entity_id == "test:func:sub_1234"
        assert result.current_name == "sub_1234"
        # Check that the result has proper structure (suggestions may or may not be generated)
        assert isinstance(result.suggestions, list)
        assert result.metadata["evidence_count"] == 1

    def test_suggest_data_label_success(self, store):
        suggester = RenameSuggester()
        result = suggester.suggest_data_label("test:data:buffer", store)
        assert result.entity_id == "test:data:buffer"
        assert result.current_name == "unk_buffer"
        # Should have suggestions based on type
        assert len(result.suggestions) > 0

    def test_batch_suggest_names(self, store):
        suggester = RenameSuggester()
        entity_ids = ["test:func:sub_1234", "test:data:buffer"]
        results = suggester.batch_suggest_names(entity_ids, store)
        assert len(results) == 2
        assert results[0].entity_id == "test:func:sub_1234"
        assert results[1].entity_id == "test:data:buffer"


class TestStoreSuggestRename:
    """Tests for ReverseEngineeringStore.suggest_rename method."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a temporary store with test data."""
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        bundle = ReverseEngineeringBundle(
            artifacts=[
                ArtifactRecord(
                    artifact_id="test:artifact:1",
                    kind="analysis",
                    path="test.asm",
                )
            ],
            entities=[
                EntityRecord(
                    entity_id="test:func:my_strlen",
                    kind="function",
                    name="my_strlen",
                    artifact_id="test:artifact:1",
                    canonical_ref="0x1234",
                    location=AddressLocation(
                        address_space="flat",
                        start=0x1234,
                        end=0x1250,
                    ),
                ),
            ],
            evidence=[],
        )
        store.upsert_bundle(bundle)
        return store

    def test_suggest_rename_entity_not_found(self, store):
        result = store.suggest_rename("nonexistent", platform="generic")
        assert result["success"] is False
        assert "error" in result

    def test_suggest_rename_function(self, store):
        result = store.suggest_rename("test:func:my_strlen", platform="generic")
        assert result["success"] is True
        assert result["entity_id"] == "test:func:my_strlen"
        assert result["current_name"] == "my_strlen"
        assert result["platform"] == "generic"
        assert "best_suggestion" in result
        assert "suggestions" in result
        assert isinstance(result["suggestions"], list)

    def test_suggest_rename_with_windows_platform(self, store):
        result = store.suggest_rename("test:func:my_strlen", platform="windows")
        assert result["success"] is True
        assert result["platform"] == "windows"
