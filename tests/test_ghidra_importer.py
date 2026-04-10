"""Tests for the Ghidra project importer."""

import gzip
import zipfile

import pytest

from codemunch_pro.rex.plugins.ghidra_importer import (
    GhidraComment,
    GhidraDataType,
    GhidraFunction,
    GhidraImporter,
    GhidraMemoryBlock,
    GhidraReference,
    GhidraSymbol,
)


class TestGhidraImporter:
    """Tests for the GhidraImporter class."""

    def test_importer_name_is_ghidra(self):
        importer = GhidraImporter()
        assert importer.name == "ghidra"

    def test_supports_xml_file(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_file.write_text("<PROGRAM NAME='test'></PROGRAM>")
        assert importer.supports(xml_file) is True

    def test_supports_xml_file_case_insensitive(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.XML"
        xml_file.write_text("<PROGRAM NAME='test'></PROGRAM>")
        assert importer.supports(xml_file) is True

    def test_rejects_non_xml_file(self, tmp_path):
        importer = GhidraImporter()
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("not xml")
        assert importer.supports(txt_file) is False

    def test_supports_gzf_file(self, tmp_path):
        importer = GhidraImporter()
        gzf_file = tmp_path / "test.gzf"
        with zipfile.ZipFile(gzf_file, "w") as zf:
            zf.writestr("program.info", "name=test")
        assert importer.supports(gzf_file) is True

    def test_rejects_invalid_gzf(self, tmp_path):
        importer = GhidraImporter()
        gzf_file = tmp_path / "test.gzf"
        with zipfile.ZipFile(gzf_file, "w") as zf:
            zf.writestr("other.txt", "not a program file")
        assert importer.supports(gzf_file) is False


class TestGhidraXmlParsing:
    """Tests for parsing Ghidra XML exports."""

    def test_parse_function(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM NAME="test">
            <FUNCTION NAME="main" ENTRY_POINT="0x00401000" BODY_START="0x00401000" BODY_END="0x00401100"
                      SIGNATURE="int main(int argc, char** argv)" RETURN_TYPE="int">
                <PARAMETER NAME="argc" TYPE="int"/>
                <PARAMETER NAME="argv" TYPE="char**"/>
            </FUNCTION>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        assert len(bundle.entities) == 1

        func_entity = bundle.entities[0]
        assert func_entity.kind == "function"
        assert func_entity.name == "main"
        assert func_entity.canonical_ref == "0x00401000"
        assert func_entity.attributes["signature"] == "int main(int argc, char** argv)"
        assert func_entity.attributes["return_type"] == "int"
        assert len(func_entity.attributes["parameters"]) == 2

    def test_parse_symbol(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM NAME="test">
            <SYMBOL NAME="g_data" ADDRESS="0x00402000" TYPE="data" NAMESPACE="global"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        assert len(bundle.entities) == 1

        sym_entity = bundle.entities[0]
        assert sym_entity.kind == "symbol"
        assert sym_entity.name == "g_data"
        assert sym_entity.canonical_ref == "0x00402000"
        assert sym_entity.attributes["namespace"] == "global"

    def test_parse_memory_block(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM NAME="test">
            <MEMORY_BLOCK NAME=".text" START="0x00400000" SIZE="0x1000"
                         READ="true" WRITE="false" EXECUTE="true"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        assert len(bundle.entities) == 1

        block_entity = bundle.entities[0]
        assert block_entity.kind == "memory_block"
        assert block_entity.name == ".text"
        assert block_entity.location.start == 0x00400000
        assert block_entity.location.end == 0x00400FFF
        assert block_entity.attributes["permissions"]["read"] is True
        assert block_entity.attributes["permissions"]["write"] is False
        assert block_entity.attributes["permissions"]["execute"] is True

    def test_parse_reference(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM NAME="test">
            <FUNCTION NAME="caller" ENTRY_POINT="0x00401000"/>
            <FUNCTION NAME="callee" ENTRY_POINT="0x00401100"/>
            <REFERENCE FROM="0x00401000" TO="0x00401100" TYPE="call"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        # Should have 2 entities (caller, callee) since they already exist
        assert len(bundle.entities) == 2
        # Should have 1 edge
        assert len(bundle.edges) == 1

        edge = bundle.edges[0]
        assert edge.kind == "reference"
        assert edge.source_entity_id == "entity:function:00401000"
        assert edge.target_entity_id == "entity:function:00401100"

    def test_parse_comment(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM NAME="test">
            <COMMENT ADDRESS="0x00401000" TEXT="This is a comment" TYPE="plate"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        assert len(bundle.evidence) == 1

        ev = bundle.evidence[0]
        assert ev.kind == "comment"
        assert ev.excerpt == "This is a comment"
        assert ev.location.start == 0x00401000

    def test_parse_bookmark(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM NAME="test">
            <BOOKMARK ADDRESS="0x00401000" NOTE="Important location" TYPE="info"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        assert len(bundle.evidence) == 1

        ev = bundle.evidence[0]
        assert ev.kind == "comment"
        assert ev.excerpt == "Important location"
        assert ev.attributes["comment_type"] == "bookmark:info"

    def test_parse_data_type(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM NAME="test">
            <DATATYPE NAME="Point" KIND="struct" SIZE="8">
                <MEMBER NAME="x" TYPE="int" OFFSET="0"/>
                <MEMBER NAME="y" TYPE="int" OFFSET="4"/>
            </DATATYPE>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        assert len(bundle.entities) == 1

        dt_entity = bundle.entities[0]
        assert dt_entity.kind == "data_type"
        assert dt_entity.name == "Point"
        assert dt_entity.attributes["data_type_kind"] == "struct"
        assert dt_entity.attributes["size"] == 8
        assert len(dt_entity.attributes["members"]) == 2

    def test_parse_complete_program(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM NAME="test_program" LANGUAGE="x86:LE:32:default">
            <MEMORY_BLOCK NAME=".text" START="0x00400000" SIZE="0x1000" READ="true" EXECUTE="true"/>
            <MEMORY_BLOCK NAME=".data" START="0x00401000" SIZE="0x1000" READ="true" WRITE="true"/>
            <FUNCTION NAME="_start" ENTRY_POINT="0x00400000"/>
            <FUNCTION NAME="main" ENTRY_POINT="0x00400100"/>
            <SYMBOL NAME="g_var" ADDRESS="0x00401000"/>
            <REFERENCE FROM="0x00400000" TO="0x00400100" TYPE="call"/>
            <COMMENT ADDRESS="0x00400100" TEXT="Entry point"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)

        # Check artifact
        assert len(bundle.artifacts) == 1
        assert bundle.artifacts[0].kind == "ghidra-project"
        assert bundle.artifacts[0].title == "test_program"

        # Check entities (2 blocks + 2 functions + 1 symbol)
        assert len(bundle.entities) == 5

        # Check edges (1 reference)
        assert len(bundle.edges) == 1

        # Check evidence (1 comment)
        assert len(bundle.evidence) == 1


class TestGhidraGzfParsing:
    """Tests for parsing Ghidra .gzf files."""

    def test_parse_gzf_with_xml_content(self, tmp_path):
        importer = GhidraImporter()
        gzf_file = tmp_path / "test.gzf"

        # Create GZF file with program.info and program.data
        with zipfile.ZipFile(gzf_file, "w") as zf:
            zf.writestr("program.info", "name=test_program\nlanguage=x86:LE:32")

            xml_content = """<?xml version="1.0"?>
            <PROGRAM>
                <FUNCTION NAME="main" ENTRY_POINT="0x00401000"/>
            </PROGRAM>
            """
            zf.writestr("program.data", xml_content)

        bundle = importer.ingest(gzf_file)

        assert len(bundle.artifacts) == 1
        assert bundle.artifacts[0].title == "test_program"
        assert len(bundle.entities) == 1
        assert bundle.entities[0].name == "main"

    def test_parse_gzf_with_gzipped_content(self, tmp_path):
        importer = GhidraImporter()
        gzf_file = tmp_path / "test.gzf"

        with zipfile.ZipFile(gzf_file, "w") as zf:
            info_content = b"name=test\nlanguage=x86"
            zf.writestr("program.info", gzip.compress(info_content))

            xml_content = b"""<?xml version="1.0"?>
            <PROGRAM>
                <FUNCTION NAME="test_func" ENTRY_POINT="0x00402000"/>
            </PROGRAM>
            """
            zf.writestr("program.data", gzip.compress(xml_content))

        bundle = importer.ingest(gzf_file)

        assert len(bundle.entities) == 1
        assert bundle.entities[0].name == "test_func"


class TestAddressParsing:
    """Tests for address parsing."""

    def test_parse_hex_address_with_0x(self):
        importer = GhidraImporter()
        assert importer._parse_address("0x00401000") == 0x00401000
        assert importer._parse_address("0xABC123") == 0xABC123

    def test_parse_hex_address_with_dollar(self):
        importer = GhidraImporter()
        assert importer._parse_address("$00401000") == 0x00401000
        assert importer._parse_address("$ABC") == 0xABC

    def test_parse_hex_address_plain(self):
        importer = GhidraImporter()
        assert importer._parse_address("00401000") == 0x00401000
        assert importer._parse_address("ABC123") == 0xABC123

    def test_parse_decimal_address(self):
        importer = GhidraImporter()
        # Note: Numeric strings without hex markers are parsed as hex in RE context
        # This is expected behavior since Ghidra always uses hex addresses
        assert importer._parse_address("4194304") == 0x4194304  # Parsed as hex

    def test_parse_invalid_address(self):
        importer = GhidraImporter()
        assert importer._parse_address("not_an_address") is None
        assert importer._parse_address("0xGGGG") is None
        assert importer._parse_address("") is None

    def test_parse_case_insensitive(self):
        importer = GhidraImporter()
        assert importer._parse_address("0xAbC123") == 0xABC123
        assert importer._parse_address("  0x00401000  ") == 0x00401000


class TestGhidraDataTypes:
    """Tests for Ghidra dataclass types."""

    def test_ghidra_function_defaults(self):
        func = GhidraFunction(name="test", entry_point=0x1000)
        assert func.name == "test"
        assert func.entry_point == 0x1000
        assert func.body_start is None
        assert func.body_end is None
        assert func.parameters == []

    def test_ghidra_symbol_creation(self):
        sym = GhidraSymbol(name="sym", address=0x2000, symbol_type="data")
        assert sym.name == "sym"
        assert sym.address == 0x2000
        assert sym.symbol_type == "data"

    def test_ghidra_memory_block(self):
        block = GhidraMemoryBlock(
            name=".text",
            start=0x1000,
            end=0x2000,
            permissions={"read": True, "execute": True}
        )
        assert block.name == ".text"
        assert block.permissions["execute"] is True

    def test_ghidra_reference(self):
        ref = GhidraReference(from_addr=0x1000, to_addr=0x2000, ref_type="call")
        assert ref.from_addr == 0x1000
        assert ref.to_addr == 0x2000
        assert ref.ref_type == "call"

    def test_ghidra_comment(self):
        comment = GhidraComment(address=0x1000, text="test comment", comment_type="pre")
        assert comment.address == 0x1000
        assert comment.text == "test comment"

    def test_ghidra_data_type(self):
        dtype = GhidraDataType(
            name="MyStruct",
            kind="struct",
            size=16,
            members=[{"name": "field1", "type": "int"}]
        )
        assert dtype.name == "MyStruct"
        assert dtype.kind == "struct"
        assert dtype.size == 16
        assert len(dtype.members) == 1


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_xml(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_file.write_text("<PROGRAM></PROGRAM>")

        bundle = importer.ingest(xml_file)
        assert len(bundle.entities) == 0
        assert len(bundle.edges) == 0

    def test_malformed_xml(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_file.write_text("not valid xml")

        with pytest.raises(Exception):
            importer.ingest(xml_file)

    def test_function_without_name(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM>
            <FUNCTION ENTRY_POINT="0x00401000"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        assert len(bundle.entities) == 0

    def test_function_without_entry_point(self, tmp_path):
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM>
            <FUNCTION NAME="main"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        assert len(bundle.entities) == 0

    def test_reference_creates_placeholder_entities(self, tmp_path):
        """Test that references create placeholder entities if they don't exist."""
        importer = GhidraImporter()
        xml_file = tmp_path / "test.xml"
        xml_content = """<?xml version="1.0"?>
        <PROGRAM>
            <REFERENCE FROM="0x00401000" TO="0x00402000" TYPE="call"/>
        </PROGRAM>
        """
        xml_file.write_text(xml_content)

        bundle = importer.ingest(xml_file)
        # Should create 2 placeholder entities + 1 edge
        assert len(bundle.entities) == 2
        assert len(bundle.edges) == 1

        # Check placeholder entities have proper names
        entity_names = {e.name for e in bundle.entities}
        assert "sub_00401000" in entity_names
        assert "sub_00402000" in entity_names
