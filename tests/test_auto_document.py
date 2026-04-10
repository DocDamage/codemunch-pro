"""Tests for the auto-documentation module."""

from __future__ import annotations

import pytest

from codemunch_pro.rex.auto_document import (
    DocumentationTemplate,
    FunctionContext,
    FunctionDocumenter,
    OutputFormat,
)
from codemunch_pro.rex.model import (
    AddressLocation,
    ArtifactRecord,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)
from codemunch_pro.rex.storage import ReverseEngineeringStore


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_markdown_format(self):
        assert OutputFormat.MARKDOWN.value == "markdown"

    def test_plain_text_format(self):
        assert OutputFormat.PLAIN_TEXT.value == "plain_text"


class TestFunctionContext:
    """Tests for FunctionContext dataclass."""

    def test_context_creation(self):
        context = FunctionContext(
            function_address=0x1234,
            function_name="test_function",
            entity_id="test:entity:1",
        )
        assert context.function_address == 0x1234
        assert context.function_name == "test_function"
        assert context.entity_id == "test:entity:1"
        assert context.called_functions == []
        assert context.calling_functions == []
        assert context.string_references == []
        assert context.data_access_patterns == []

    def test_context_with_relationships(self):
        context = FunctionContext(
            function_address=0x1234,
            called_functions=[
                {"name": "sub_5678", "address": 0x5678, "entity_id": "test:2"},
            ],
            calling_functions=[
                {"name": "main", "address": 0x1000, "entity_id": "test:3"},
            ],
        )
        assert len(context.called_functions) == 1
        assert len(context.calling_functions) == 1
        assert context.called_functions[0]["name"] == "sub_5678"


class TestDocumentationTemplate:
    """Tests for DocumentationTemplate dataclass."""

    def test_template_creation(self):
        doc = DocumentationTemplate(
            function_address=0x1234,
            function_name="test_function",
            purpose="Test purpose",
            confidence=0.8,
        )
        assert doc.function_address == 0x1234
        assert doc.function_name == "test_function"
        assert doc.purpose == "Test purpose"
        assert doc.confidence == 0.8

    def test_to_markdown(self):
        doc = DocumentationTemplate(
            function_address=0x1234,
            function_name="test_function",
            purpose="Test purpose",
            description="Test description",
            parameters=[
                {"name": "param1", "type": "int", "description": "First param"},
            ],
            return_values=[
                {"type": "bool", "description": "Success flag"},
            ],
            side_effects=["Modifies memory at 0x2000"],
            related_functions=[
                {"name": "helper", "address": 0x5678, "relationship": "calls"},
            ],
            notes=["Note 1"],
            confidence=0.85,
        )
        markdown = doc.to_markdown()
        assert "## test_function" in markdown
        assert "0x1234" in markdown
        assert "Test purpose" in markdown
        assert "Test description" in markdown
        assert "param1" in markdown
        assert "Modifies memory at 0x2000" in markdown
        assert "helper" in markdown
        assert "85%" in markdown

    def test_to_plain_text(self):
        doc = DocumentationTemplate(
            function_address=0x1234,
            function_name="test_function",
            purpose="Test purpose",
            confidence=0.8,
        )
        text = doc.to_plain_text()
        assert "Function: test_function" in text
        assert "0x1234" in text
        assert "Test purpose" in text
        assert "80%" in text

    def test_to_dict(self):
        doc = DocumentationTemplate(
            function_address=0x1234,
            function_name="test_function",
            purpose="Test purpose",
            parameters=[{"name": "x", "type": "int"}],
            confidence=0.9,
        )
        data = doc.to_dict()
        assert data["function_address"] == 0x1234
        assert data["function_name"] == "test_function"
        assert data["purpose"] == "Test purpose"
        assert data["confidence"] == 0.9
        assert len(data["parameters"]) == 1


class TestFunctionDocumenter:
    """Tests for FunctionDocumenter class."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a temporary store for testing."""
        db_path = tmp_path / "test.db"
        return ReverseEngineeringStore(db_path)

    @pytest.fixture
    def populated_store(self, store):
        """Create a store with test data."""
        # Create artifact
        artifact = ArtifactRecord(
            artifact_id="test:artifact:1",
            kind="disassembly",
            path="test.asm",
        )

        # Create function entity
        function_entity = EntityRecord(
            entity_id="test:function:main",
            kind="function",
            name="main_function",
            artifact_id="test:artifact:1",
            canonical_ref="0x0800",
            location=AddressLocation(
                address_space="rom",
                start=0x0800,
                end=0x0820,
            ),
        )

        # Create called function entity
        called_entity = EntityRecord(
            entity_id="test:function:helper",
            kind="function",
            name="helper_function",
            artifact_id="test:artifact:1",
            canonical_ref="0x0900",
            location=AddressLocation(
                address_space="rom",
                start=0x0900,
                end=0x0910,
            ),
        )

        # Create string entity
        string_entity = EntityRecord(
            entity_id="test:string:1",
            kind="string",
            name="Hello",
            artifact_id="test:artifact:1",
            canonical_ref="0x1000",
            location=AddressLocation(
                address_space="rom",
                start=0x1000,
                end=0x1005,
            ),
            attributes={"full_text": "Hello World"},
        )

        # Create evidence (disassembly)
        evidence = EvidenceRecord(
            evidence_id="test:evidence:1",
            kind="disassembly",
            artifact_id="test:artifact:1",
            entity_ids=("test:function:main",),
            location=AddressLocation(
                address_space="rom",
                start=0x0800,
                end=0x0802,
            ),
            excerpt="0800: JSR $0900",
        )

        # Create edges
        call_edge = EdgeRecord(
            edge_id="test:edge:call",
            kind="calls",
            source_entity_id="test:function:main",
            target_entity_id="test:function:helper",
        )

        string_edge = EdgeRecord(
            edge_id="test:edge:string",
            kind="references_string",
            source_entity_id="test:function:main",
            target_entity_id="test:string:1",
        )

        bundle = ReverseEngineeringBundle(
            artifacts=[artifact],
            entities=[function_entity, called_entity, string_entity],
            evidence=[evidence],
            edges=[call_edge, string_edge],
        )

        store.upsert_bundle(bundle)
        return store, function_entity

    def test_documenter_creation(self, store):
        documenter = FunctionDocumenter(store)
        assert documenter.store == store

    def test_analyze_function(self, populated_store):
        store, function_entity = populated_store
        documenter = FunctionDocumenter(store)

        context = documenter.analyze_function(0x0800, address_space="rom")

        assert context.function_address == 0x0800
        assert context.function_name == "main_function"
        assert context.entity_id == "test:function:main"
        assert len(context.called_functions) == 1
        assert context.called_functions[0]["name"] == "helper_function"
        assert len(context.string_references) == 1
        assert context.string_references[0]["text"] == "Hello World"

    def test_analyze_function_not_found(self, store):
        documenter = FunctionDocumenter(store)
        context = documenter.analyze_function(0x9999)
        assert context.function_address == 0x9999
        assert context.entity_id == ""

    def test_generate_documentation(self, populated_store):
        store, function_entity = populated_store
        documenter = FunctionDocumenter(store)

        doc = documenter.generate_documentation(
            function_address=0x0800,
            context_hint="Main entry point",
            address_space="rom",
            output_format=OutputFormat.MARKDOWN,
        )

        assert doc.function_address == 0x0800
        assert doc.function_name == "main_function"
        assert doc.confidence > 0
        assert "Context hint: Main entry point" in doc.notes
        assert len(doc.related_functions) == 1
        assert doc.related_functions[0]["name"] == "helper_function"

    def test_generate_documentation_plain_text(self, populated_store):
        store, function_entity = populated_store
        documenter = FunctionDocumenter(store)

        doc = documenter.generate_documentation(
            function_address=0x0800,
            output_format=OutputFormat.PLAIN_TEXT,
        )

        formatted = documenter.format_output(doc, OutputFormat.PLAIN_TEXT)
        assert "Function:" in formatted
        assert "main_function" in formatted

    def test_format_output_markdown(self, populated_store):
        store, function_entity = populated_store
        documenter = FunctionDocumenter(store)

        doc = documenter.generate_documentation(0x0800)
        markdown = documenter.format_output(doc, OutputFormat.MARKDOWN)

        assert "## main_function" in markdown
        assert "0x0800" in markdown

    def test_analyze_disassembly_branch_detection(self, populated_store):
        store, function_entity = populated_store
        documenter = FunctionDocumenter(store)

        # Add evidence with branch instruction
        evidence = EvidenceRecord(
            evidence_id="test:evidence:branch",
            kind="disassembly",
            artifact_id="test:artifact:1",
            entity_ids=("test:function:main",),
            location=AddressLocation(
                address_space="rom",
                start=0x0802,
                end=0x0804,
            ),
            excerpt="0802: BNE $0808",
        )
        store.upsert_bundle(ReverseEngineeringBundle(evidence=[evidence]))

        doc = documenter.generate_documentation(0x0800)

        # Should detect branch in notes
        branch_notes = [n for n in doc.notes if "branch" in n.lower()]
        assert len(branch_notes) > 0

    def test_analyze_call_relationships_inference(self, populated_store):
        store, function_entity = populated_store
        documenter = FunctionDocumenter(store)

        # Rename helper to suggest graphics purpose
        store._conn.execute(
            "UPDATE entities SET name = ? WHERE entity_id = ?",
            ("draw_sprite", "test:function:helper"),
        )
        store._conn.commit()

        doc = documenter.generate_documentation(0x0800)

        # Should infer graphics purpose from called function name
        assert "graphics" in doc.purpose.lower() or "render" in doc.purpose.lower() or "draw" in doc.purpose.lower()

    def test_calculate_confidence(self, populated_store):
        store, function_entity = populated_store
        documenter = FunctionDocumenter(store)

        context = documenter.analyze_function(0x0800, address_space="rom")
        doc = DocumentationTemplate(
            function_address=0x0800,
            function_name="test",
            purpose="Test",
        )

        confidence = documenter._calculate_confidence(doc, context)
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.0  # Should have some confidence with our test data


class TestReverseEngineeringStoreAutoDocument:
    """Tests for ReverseEngineeringStore.auto_document_function method."""

    @pytest.fixture
    def populated_store(self, tmp_path):
        """Create a store with test data."""
        db_path = tmp_path / "test.db"
        store = ReverseEngineeringStore(db_path)

        # Create function entity
        function_entity = EntityRecord(
            entity_id="test:function:main",
            kind="function",
            name="main_function",
            artifact_id="test:artifact:1",
            canonical_ref="0x0800",
            location=AddressLocation(
                address_space="rom",
                start=0x0800,
                end=0x0820,
            ),
        )

        # Create evidence
        evidence = EvidenceRecord(
            evidence_id="test:evidence:1",
            kind="disassembly",
            artifact_id="test:artifact:1",
            entity_ids=("test:function:main",),
            location=AddressLocation(
                address_space="rom",
                start=0x0800,
                end=0x0802,
            ),
            excerpt="0800: NOP",
        )

        bundle = ReverseEngineeringBundle(
            artifacts=[
                ArtifactRecord(
                    artifact_id="test:artifact:1",
                    kind="disassembly",
                    path="test.asm",
                ),
            ],
            entities=[function_entity],
            evidence=[evidence],
        )

        store.upsert_bundle(bundle)
        return store

    def test_auto_document_function(self, populated_store):
        result = populated_store.auto_document_function(
            function_address=0x0800,
            context_hint="Test function",
            address_space="rom",
            output_format="markdown",
            store_as_evidence=True,
        )

        assert result["function_address"] == 0x0800
        assert result["function_name"] == "main_function"
        assert "documentation" in result
        assert "template" in result
        assert "confidence" in result
        assert result["confidence"] > 0
        assert result["evidence_id"] != ""  # Should be stored

    def test_auto_document_function_not_found(self, populated_store):
        result = populated_store.auto_document_function(
            function_address=0x9999,
            address_space="rom",
        )

        assert result["function_address"] == 0x9999
        # When function not found, evidence_id should be empty
        assert result["evidence_id"] == ""

    def test_auto_document_function_plain_text(self, populated_store):
        result = populated_store.auto_document_function(
            function_address=0x0800,
            output_format="plain_text",
            store_as_evidence=False,
        )

        assert "Function:" in result["documentation"]
        assert result["evidence_id"] == ""  # Not stored

    def test_stored_evidence_content(self, populated_store):
        result = populated_store.auto_document_function(
            function_address=0x0800,
            context_hint="Test hint",
            store_as_evidence=True,
        )

        # Retrieve the stored evidence
        evidence_id = result["evidence_id"]
        assert evidence_id != ""

        evidence_list = populated_store.get_evidence_for_entity(
            "test:function:main",
            limit=10,
        )

        auto_doc_evidence = [e for e in evidence_list if e.kind == "auto_documentation"]
        assert len(auto_doc_evidence) == 1
        assert auto_doc_evidence[0].evidence_id == evidence_id
        assert auto_doc_evidence[0].attributes.get("context_hint") == "Test hint"


class TestDocumentationOutputFormats:
    """Tests for documentation output formats."""

    def test_markdown_formatting(self):
        doc = DocumentationTemplate(
            function_address=0x1234,
            function_name="TestFunc",
            purpose="Test purpose",
            parameters=[
                {"name": "arg1", "type": "uint8", "description": "First argument"},
                {"name": "arg2", "type": "uint16", "description": "Second argument"},
            ],
            return_values=[
                {"type": "bool", "description": "True on success"},
            ],
            side_effects=["Modifies register A", "Updates status flags"],
            related_functions=[
                {"name": "InitSystem", "address": 0x1000, "relationship": "called_by"},
            ],
            notes=["Called during initialization"],
            confidence=0.85,
        )

        markdown = doc.to_markdown()

        # Check markdown structure
        assert "## TestFunc" in markdown
        assert "0x1234" in markdown
        assert "### Purpose" in markdown
        assert "### Parameters" in markdown
        assert "arg1" in markdown
        assert "uint8" in markdown
        assert "### Return Values" in markdown
        assert "bool" in markdown
        assert "### Side Effects" in markdown
        assert "Modifies register A" in markdown
        assert "### Related Functions" in markdown
        assert "InitSystem" in markdown
        assert "0x1000" in markdown
        assert "### Notes" in markdown
        assert "85%" in markdown

    def test_plain_text_formatting(self):
        doc = DocumentationTemplate(
            function_address=0x1234,
            function_name="TestFunc",
            purpose="Test purpose",
            parameters=[
                {"name": "arg1", "type": "uint8", "description": "First argument"},
            ],
            confidence=0.75,
        )

        text = doc.to_plain_text()

        # Check plain text structure
        assert "Function: TestFunc" in text
        assert "0x1234" in text
        assert "PURPOSE:" in text
        assert "PARAMETERS:" in text
        assert "arg1" in text
        assert "uint8" in text
        assert "75%" in text

    def test_empty_documentation(self):
        doc = DocumentationTemplate(
            function_address=0x1234,
            function_name="EmptyFunc",
            confidence=0.0,
        )

        markdown = doc.to_markdown()
        text = doc.to_plain_text()

        assert "## EmptyFunc" in markdown
        assert "Function: EmptyFunc" in text
        assert "0%" in markdown
        assert "0%" in text

    def test_documentation_with_many_related_functions(self):
        doc = DocumentationTemplate(
            function_address=0x1234,
            function_name="HubFunction",
            related_functions=[
                {"name": f"Func{i}", "address": 0x1000 + i, "relationship": "calls"}
                for i in range(15)
            ],
            confidence=0.9,
        )

        markdown = doc.to_markdown()

        # All related functions should be present
        for i in range(15):
            assert f"Func{i}" in markdown
            assert f"0x{0x1000 + i:04X}" in markdown


class TestFunctionDocumenterEdgeCases:
    """Tests for edge cases in FunctionDocumenter."""

    @pytest.fixture
    def empty_store(self, tmp_path):
        """Create an empty store."""
        db_path = tmp_path / "empty.db"
        return ReverseEngineeringStore(db_path)

    def test_empty_store_analysis(self, empty_store):
        documenter = FunctionDocumenter(empty_store)
        context = documenter.analyze_function(0x1234)

        assert context.function_address == 0x1234
        assert context.function_name == ""
        assert context.entity_id == ""
        assert context.called_functions == []
        assert context.calling_functions == []

    def test_empty_store_documentation(self, empty_store):
        documenter = FunctionDocumenter(empty_store)
        doc = documenter.generate_documentation(0x1234)

        assert doc.function_address == 0x1234
        assert doc.function_name == "sub_1234"
        assert doc.confidence == 0.0

    def test_no_disassembly(self, empty_store):
        # Create entity without evidence
        entity = EntityRecord(
            entity_id="test:no_evidence",
            kind="function",
            name="no_evidence_func",
            location=AddressLocation(
                address_space="rom",
                start=0x1234,
                end=0x1250,
            ),
        )
        bundle = ReverseEngineeringBundle(entities=[entity])
        empty_store.upsert_bundle(bundle)

        documenter = FunctionDocumenter(empty_store)
        doc = documenter.generate_documentation(0x1234)

        assert doc.function_name == "no_evidence_func"
        # Confidence should be lower without disassembly

    def test_multiple_callers(self, empty_store):
        # Create function with multiple callers
        main_func = EntityRecord(
            entity_id="test:main",
            kind="function",
            name="main",
            location=AddressLocation(
                address_space="rom",
                start=0x1000,
                end=0x1020,
            ),
        )

        helper = EntityRecord(
            entity_id="test:helper",
            kind="function",
            name="helper",
            location=AddressLocation(
                address_space="rom",
                start=0x2000,
                end=0x2010,
            ),
        )

        # Create multiple callers with "called_by" edge kind
        callers = []
        edges = []
        for i in range(5):
            caller = EntityRecord(
                entity_id=f"test:caller:{i}",
                kind="function",
                name=f"caller_{i}",
                location=AddressLocation(
                    address_space="rom",
                    start=0x3000 + i * 0x20,
                    end=0x3010 + i * 0x20,
                ),
            )
            callers.append(caller)
            # Use "called_by" edge kind to indicate these are callers of main
            edges.append(EdgeRecord(
                edge_id=f"test:edge:called_by:{i}",
                kind="called_by",
                source_entity_id=main_func.entity_id,
                target_entity_id=caller.entity_id,
            ))

        bundle = ReverseEngineeringBundle(
            entities=[main_func, helper] + callers,
            edges=edges,
        )
        empty_store.upsert_bundle(bundle)

        documenter = FunctionDocumenter(empty_store)
        context = documenter.analyze_function(0x1000)

        assert len(context.calling_functions) == 5

    def test_string_reference_inference(self, empty_store):
        # Create function with string references
        func = EntityRecord(
            entity_id="test:func",
            kind="function",
            name="error_handler",
            location=AddressLocation(
                address_space="rom",
                start=0x1000,
                end=0x1020,
            ),
        )

        error_string = EntityRecord(
            entity_id="test:string:error",
            kind="string",
            name="ErrorMsg",
            location=AddressLocation(
                address_space="rom",
                start=0x2000,
                end=0x2010,
            ),
            attributes={"full_text": "Invalid input error"},
        )

        edge = EdgeRecord(
            edge_id="test:edge:ref",
            kind="references_string",
            source_entity_id="test:func",
            target_entity_id="test:string:error",
        )

        bundle = ReverseEngineeringBundle(
            entities=[func, error_string],
            edges=[edge],
        )
        empty_store.upsert_bundle(bundle)

        documenter = FunctionDocumenter(empty_store)
        doc = documenter.generate_documentation(0x1000)

        # Should infer error handling purpose from string
        assert "error" in doc.purpose.lower() or "handling" in doc.purpose.lower()
        # Check notes contain the string reference
        string_notes = [n for n in doc.notes if "References string" in n]
        assert len(string_notes) == 1
        assert "Invalid input error" in string_notes[0]

    def test_data_access_patterns(self, empty_store):
        # Create function with data access
        func = EntityRecord(
            entity_id="test:func",
            kind="function",
            name="data_processor",
            location=AddressLocation(
                address_space="rom",
                start=0x1000,
                end=0x1020,
            ),
        )

        data = EntityRecord(
            entity_id="test:data",
            kind="data",
            name="player_data",
            location=AddressLocation(
                address_space="ram",
                start=0x7000,
                end=0x7010,
            ),
        )

        write_edge = EdgeRecord(
            edge_id="test:edge:write",
            kind="writes",
            source_entity_id="test:func",
            target_entity_id="test:data",
        )

        bundle = ReverseEngineeringBundle(
            entities=[func, data],
            edges=[write_edge],
        )
        empty_store.upsert_bundle(bundle)

        documenter = FunctionDocumenter(empty_store)
        context = documenter.analyze_function(0x1000)
        doc = documenter.generate_documentation(0x1000)

        assert len(context.data_access_patterns) == 1
        assert context.data_access_patterns[0]["access_type"] == "writes"
        assert len(doc.side_effects) == 1
        assert "player_data" in doc.side_effects[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
