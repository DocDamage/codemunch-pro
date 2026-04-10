"""Tests for the generic reverse-engineering model and adapter layer."""


import pytest

from codemunch_pro.rex import (
    AddressLocation,
    ArtifactRecord,
    AtariJaguarRomCodec,
    EdgeRecord,
    EntityRecord,
    EvidenceRecord,
    ReverseEngineeringBundle,
)


class TestAddressLocation:
    def test_size_is_inclusive(self):
        location = AddressLocation(address_space="flat", start=0x1000, end=0x10FF)
        assert location.size == 0x100

    def test_contains(self):
        location = AddressLocation(address_space="flat", start=16, end=31)
        assert location.contains(20)
        assert not location.contains(32)

    def test_overlap_requires_same_space(self):
        a = AddressLocation(address_space="flat", start=0, end=15)
        b = AddressLocation(address_space="flat", start=10, end=20)
        c = AddressLocation(address_space="other", start=10, end=20)
        assert a.overlaps(b)
        assert not a.overlaps(c)

    def test_invalid_range_raises(self):
        with pytest.raises(ValueError):
            AddressLocation(address_space="flat", start=10, end=1)


class TestRecords:
    def test_entity_serializes_location(self):
        location = AddressLocation(address_space="flat", start=0x20, end=0x2F)
        entity = EntityRecord(
            entity_id="entity:function:1",
            kind="function",
            name="Function1",
            canonical_ref="0x20",
            location=location,
            aliases=("entry",),
        )
        payload = entity.to_dict()
        assert payload["location"]["start"] == 0x20
        assert payload["aliases"] == ["entry"]

    def test_evidence_confidence_is_bounded(self):
        with pytest.raises(ValueError):
            EvidenceRecord(
                evidence_id="evidence:1",
                kind="note",
                artifact_id="artifact:1",
                confidence=1.5,
            )

    def test_bundle_serializes_all_sections(self):
        bundle = ReverseEngineeringBundle(
            artifacts=[ArtifactRecord(artifact_id="artifact:1", kind="note", path="notes.md")],
            entities=[EntityRecord(entity_id="entity:1", kind="range", name="Range1")],
            evidence=[EvidenceRecord(evidence_id="evidence:1", kind="excerpt", artifact_id="artifact:1")],
            edges=[EdgeRecord(edge_id="edge:1", kind="mentions", source_entity_id="entity:1", target_entity_id="entity:1")],
            metadata={"project": "demo"},
        )
        payload = bundle.to_dict()
        assert payload["metadata"]["project"] == "demo"
        assert len(payload["artifacts"]) == 1
        assert len(payload["entities"]) == 1
        assert len(payload["evidence"]) == 1
        assert len(payload["edges"]) == 1


class TestAtariJaguarRomCodec:
    """Tests for the Atari Jaguar ROM/COF/ABS address codec."""

    def test_codec_name_is_jaguar_rom(self):
        codec = AtariJaguarRomCodec()
        assert codec.name == "jaguar-rom"

    def test_extract_refs_finds_dollar_prefixed_addresses(self):
        codec = AtariJaguarRomCodec()
        text = "Jump to $800000 and $9FFFFF, also check $F00000"
        refs = codec.extract_refs(text)
        assert "$800000" in refs
        assert "$9FFFFF" in refs
        assert "$F00000" in refs

    def test_extract_refs_finds_0x_prefixed_addresses(self):
        codec = AtariJaguarRomCodec()
        text = "Address 0x00800000 and 0x009FFFFF, also 0x00F00000"
        refs = codec.extract_refs(text)
        assert "$800000" in refs
        assert "$9FFFFF" in refs
        assert "$F00000" in refs

    def test_extract_refs_finds_raw_hex_addresses(self):
        codec = AtariJaguarRomCodec()
        text = "Raw addresses 800000 and 001000"
        refs = codec.extract_refs(text)
        assert "$800000" in refs
        assert "$001000" in refs

    def test_parse_cartridge_address_returns_location(self):
        codec = AtariJaguarRomCodec()
        location = codec.parse("$800000")
        assert location is not None
        assert location.address_space == "jaguar-rom"
        assert location.start == 0x800000
        assert location.end == 0x800000
        assert location.display == "$800000"
        assert location.attributes["address"] == 0x800000
        assert location.attributes["region"] == "cart_rom"
        assert location.attributes["is_cartridge"] is True
        assert location.attributes["is_boot_rom"] is False

    def test_parse_cartridge_address_with_0x_prefix(self):
        codec = AtariJaguarRomCodec()
        location = codec.parse("0x00800000")
        assert location is not None
        assert location.start == 0x800000
        assert location.attributes["address"] == 0x800000
        assert location.attributes["region"] == "cart_rom"

    def test_parse_ram_address(self):
        codec = AtariJaguarRomCodec()
        location = codec.parse("$000000")
        assert location is not None
        assert location.attributes["region"] == "ram"
        assert location.attributes["is_cartridge"] is False
        assert location.attributes["is_boot_rom"] is False

    def test_parse_gpu_ram_address(self):
        codec = AtariJaguarRomCodec()
        location = codec.parse("$F00000")
        assert location is not None
        assert location.attributes["region"] == "gpu_ram"
        assert location.segment == "gpu_ram"

    def test_parse_dsp_ram_address(self):
        codec = AtariJaguarRomCodec()
        location = codec.parse("$F10000")
        assert location is not None
        assert location.attributes["region"] == "dsp_ram"
        assert location.segment == "dsp_ram"

    def test_parse_rejects_invalid_addresses(self):
        codec = AtariJaguarRomCodec()
        # 7 digits is invalid for 24-bit
        assert codec.parse("$1234567") is None
        # Invalid hex characters
        assert codec.parse("$GGGGGG") is None

    def test_cartridge_file_offset_calculation(self):
        codec = AtariJaguarRomCodec()
        # Standard cartridge: offset = address - 0x800000
        loc1 = codec.parse("$800000")
        assert loc1.attributes["file_offset"] == 0
        loc2 = codec.parse("$801000")
        assert loc2.attributes["file_offset"] == 0x1000
        loc3 = codec.parse("$9FFFFF")
        assert loc3.attributes["file_offset"] == 0x1FFFFF

    def test_ram_has_no_file_offset(self):
        codec = AtariJaguarRomCodec()
        # RAM addresses have no file offset
        loc1 = codec.parse("$000000")
        assert loc1.attributes["file_offset"] is None
        loc2 = codec.parse("$1FFFFF")
        assert loc2.attributes["file_offset"] is None

    def test_format_cartridge_address(self):
        codec = AtariJaguarRomCodec()
        location = AddressLocation(
            address_space="jaguar-rom",
            start=0x800000,
            end=0x800000,
            attributes={"address": 0x800000},
        )
        assert codec.format(location) == "$800000"

    def test_format_raises_for_wrong_address_space(self):
        codec = AtariJaguarRomCodec()
        location = AddressLocation(
            address_space="flat",
            start=0x1000,
            end=0x1000,
            attributes={"address": 0x1000},
        )
        with pytest.raises(ValueError):
            codec.format(location)


# =============================================================================
# Debugger Integration Tests
# =============================================================================


class TestDebuggerState:
    """Tests for DebuggerState enum."""

    def test_state_values(self):
        from codemunch_pro.rex.debugger import DebuggerState
        assert DebuggerState.DISCONNECTED.value == "disconnected"
        assert DebuggerState.CONNECTING.value == "connecting"
        assert DebuggerState.STOPPED.value == "stopped"
        assert DebuggerState.RUNNING.value == "running"
        assert DebuggerState.PAUSED.value == "paused"
        assert DebuggerState.ERROR.value == "error"


class TestRegisterSet:
    """Tests for RegisterSet dataclass."""

    def test_register_set_creation(self):
        from codemunch_pro.rex.debugger import RegisterSet
        regs = RegisterSet(
            pc=0x08001234,
            sp=0x7FFF0000,
            general={"r0": 1, "r1": 2, "r2": 3},
            flags={"Z": True, "N": False, "C": True},
        )
        assert regs.pc == 0x08001234
        assert regs.sp == 0x7FFF0000
        assert regs.general["r0"] == 1
        assert regs.flags["Z"] is True

    def test_register_set_to_dict(self):
        from codemunch_pro.rex.debugger import RegisterSet
        regs = RegisterSet(
            pc=0x08001234,
            sp=0x7FFF0000,
            general={"r0": 1},
            flags={"Z": True},
        )
        data = regs.to_dict()
        assert data["pc"] == 0x08001234
        assert data["sp"] == 0x7FFF0000
        assert data["general"]["r0"] == 1
        assert data["flags"]["Z"] is True


class TestStackFrame:
    """Tests for StackFrame dataclass."""

    def test_stack_frame_creation(self):
        from codemunch_pro.rex.debugger import StackFrame, RegisterSet
        frame = StackFrame(
            address=0x08001234,
            function_name="main",
            module="main.exe",
            source_file="main.c",
            source_line=42,
            registers=RegisterSet(pc=0x08001234, sp=0x7FFF0000),
        )
        assert frame.address == 0x08001234
        assert frame.function_name == "main"
        assert frame.source_line == 42

    def test_stack_frame_to_dict(self):
        from codemunch_pro.rex.debugger import StackFrame, RegisterSet
        frame = StackFrame(
            address=0x08001234,
            function_name="main",
            registers=RegisterSet(pc=0x08001234, sp=0x7FFF0000),
        )
        data = frame.to_dict()
        assert data["address"] == 0x08001234
        assert data["function_name"] == "main"
        assert "registers" in data


class TestBreakpoint:
    """Tests for Breakpoint dataclass."""

    def test_breakpoint_creation(self):
        from codemunch_pro.rex.debugger import Breakpoint
        bp = Breakpoint(
            id="bp1",
            address=0x08001234,
            enabled=True,
            condition="x > 0",
            hit_condition="5",
        )
        assert bp.id == "bp1"
        assert bp.address == 0x08001234
        assert bp.enabled is True
        assert bp.condition == "x > 0"
        assert bp.hit_condition == "5"

    def test_breakpoint_to_dict(self):
        from codemunch_pro.rex.debugger import Breakpoint
        bp = Breakpoint(id="bp1", address=0x08001234)
        data = bp.to_dict()
        assert data["id"] == "bp1"
        assert data["address"] == 0x08001234
        assert data["enabled"] is True


class TestMemoryRead:
    """Tests for MemoryRead dataclass."""

    def test_memory_read_success(self):
        from codemunch_pro.rex.debugger import MemoryRead
        result = MemoryRead(
            address=0x08000000,
            data=b"\x00\x01\x02\x03",
            success=True,
        )
        assert result.address == 0x08000000
        assert result.data == b"\x00\x01\x02\x03"
        assert result.success is True

    def test_memory_read_failure(self):
        from codemunch_pro.rex.debugger import MemoryRead
        result = MemoryRead(
            address=0x08000000,
            data=b"",
            success=False,
            error="Invalid address",
        )
        assert result.success is False
        assert result.error == "Invalid address"

    def test_memory_read_to_dict(self):
        from codemunch_pro.rex.debugger import MemoryRead
        result = MemoryRead(
            address=0x08000000,
            data=b"\x00\x01\x02\x03",
            success=True,
        )
        data = result.to_dict()
        assert data["address"] == 0x08000000
        assert data["data"] == "00010203"
        assert data["size"] == 4
        assert data["success"] is True


class TestExecutionTrace:
    """Tests for ExecutionTrace dataclass."""

    def test_execution_trace_creation(self):
        from codemunch_pro.rex.debugger import ExecutionTrace
        trace = ExecutionTrace(
            timestamp=1234567890.0,
            address=0x08001234,
            instruction_bytes=b"\x00\x00",
            disassembly="NOP",
        )
        assert trace.timestamp == 1234567890.0
        assert trace.address == 0x08001234
        assert trace.disassembly == "NOP"

    def test_execution_trace_to_dict(self):
        from codemunch_pro.rex.debugger import ExecutionTrace, RegisterSet
        trace = ExecutionTrace(
            timestamp=1234567890.0,
            address=0x08001234,
            instruction_bytes=b"\x00\x00",
            disassembly="NOP",
            registers=RegisterSet(pc=0x08001234, sp=0x7FFF0000),
        )
        data = trace.to_dict()
        assert data["timestamp"] == 1234567890.0
        assert data["address"] == 0x08001234
        assert data["instruction_bytes"] == "0000"
        assert "registers" in data


class TestTraceCapture:
    """Tests for TraceCapture dataclass."""

    def test_trace_capture_creation(self):
        from codemunch_pro.rex.debugger import TraceCapture
        capture = TraceCapture(
            capture_id="capture1",
            start_address=0x08001234,
            end_address=0x08002000,
        )
        assert capture.capture_id == "capture1"
        assert capture.start_address == 0x08001234
        assert capture.end_address == 0x08002000

    def test_trace_capture_add_entry(self):
        from codemunch_pro.rex.debugger import TraceCapture, ExecutionTrace
        capture = TraceCapture(
            capture_id="capture1",
            start_address=0x08001234,
        )
        entry = ExecutionTrace(
            timestamp=1234567890.0,
            address=0x08001234,
            instruction_bytes=b"\x00\x00",
            disassembly="NOP",
        )
        capture.add_entry(entry)
        assert len(capture.entries) == 1

    def test_trace_capture_finalize(self):
        from codemunch_pro.rex.debugger import TraceCapture
        capture = TraceCapture(
            capture_id="capture1",
            start_address=0x08001234,
        )
        capture.finalize()
        assert capture.end_time > 0

    def test_trace_capture_to_dict(self):
        from codemunch_pro.rex.debugger import TraceCapture, ExecutionTrace
        capture = TraceCapture(
            capture_id="capture1",
            start_address=0x08001234,
        )
        capture.add_entry(ExecutionTrace(
            timestamp=1234567890.0,
            address=0x08001234,
            instruction_bytes=b"\x00\x00",
            disassembly="NOP",
        ))
        capture.finalize()
        data = capture.to_dict()
        assert data["capture_id"] == "capture1"
        assert data["start_address"] == 0x08001234
        assert data["entry_count"] == 1


class TestDebuggerSession:
    """Tests for DebuggerSession base class."""

    def test_session_initial_state(self):
        from codemunch_pro.rex.debugger import DebuggerSession, DebuggerState

        class MockSession(DebuggerSession):
            def attach(self, target: str, **kwargs):
                return True
            def detach(self):
                return True
            def read_memory(self, address: int, size: int):
                from codemunch_pro.rex.debugger import MemoryRead
                return MemoryRead(address, b"")
            def write_memory(self, address: int, data: bytes):
                return True
            def set_breakpoint(self, address: int, condition: str = "", hit_count: int = 0):
                from codemunch_pro.rex.debugger import Breakpoint
                return Breakpoint(id="bp1", address=address)
            def remove_breakpoint(self, breakpoint_id: str):
                return True
            def continue_execution(self):
                return True
            def step(self, into: bool = True):
                return True
            def get_registers(self):
                from codemunch_pro.rex.debugger import RegisterSet
                return RegisterSet(pc=0, sp=0)
            def get_backtrace(self, max_frames: int = 50):
                return []

        session = MockSession(name="test")
        assert session.name == "test"
        assert session.state == DebuggerState.DISCONNECTED
        assert not session.is_connected

    def test_session_capture_management(self):
        from codemunch_pro.rex.debugger import DebuggerSession, ExecutionTrace

        class MockSession(DebuggerSession):
            def attach(self, target: str, **kwargs):
                return True
            def detach(self):
                return True
            def read_memory(self, address: int, size: int):
                from codemunch_pro.rex.debugger import MemoryRead
                return MemoryRead(address, b"")
            def write_memory(self, address: int, data: bytes):
                return True
            def set_breakpoint(self, address: int, condition: str = "", hit_count: int = 0):
                from codemunch_pro.rex.debugger import Breakpoint
                return Breakpoint(id="bp1", address=address)
            def remove_breakpoint(self, breakpoint_id: str):
                return True
            def continue_execution(self):
                return True
            def step(self, into: bool = True):
                return True
            def get_registers(self):
                from codemunch_pro.rex.debugger import RegisterSet
                return RegisterSet(pc=0, sp=0)
            def get_backtrace(self, max_frames: int = 50):
                return []

        session = MockSession(name="test")
        capture = session.start_capture("cap1", 0x08000000)
        assert capture.capture_id == "cap1"
        assert session._active_capture is capture

        session._record_trace_entry(ExecutionTrace(
            timestamp=1234567890.0,
            address=0x08000000,
            instruction_bytes=b"\x00\x00",
            disassembly="NOP",
        ))
        assert len(capture.entries) == 1

        stopped = session.stop_capture()
        assert stopped is capture
        assert stopped.end_time > 0


class TestGDBSession:
    """Tests for GDBSession class."""

    def test_gdb_session_creation(self):
        from codemunch_pro.rex.debugger import GDBSession, DebuggerState
        session = GDBSession(name="gdb-test")
        assert session.name == "gdb-test"
        assert session.state == DebuggerState.DISCONNECTED

    def test_gdb_session_to_dict(self):
        from codemunch_pro.rex.debugger import GDBSession
        session = GDBSession(name="gdb-test")
        data = session.to_dict()
        assert data["name"] == "gdb-test"
        assert data["connected"] is False


class TestLLDBSession:
    """Tests for LLDBSession class."""

    def test_lldb_session_creation(self):
        from codemunch_pro.rex.debugger import LLDBSession, DebuggerState
        session = LLDBSession(name="lldb-test")
        assert session.name == "lldb-test"
        assert session.state == DebuggerState.DISCONNECTED


class TestEmulatorSession:
    """Tests for EmulatorSession class."""

    def test_emulator_session_creation(self):
        from codemunch_pro.rex.debugger import EmulatorSession, DebuggerState
        session = EmulatorSession(
            name="emu-test",
            emulator_type="mgba",
        )
        assert "emu-test" in session.name
        assert session._emulator_type == "mgba"
        assert session.state == DebuggerState.DISCONNECTED

    def test_emulator_session_types(self):
        from codemunch_pro.rex.debugger import EmulatorSession
        assert EmulatorSession.MGBA == "mgba"
        assert EmulatorSession.MESEN == "mesen"
        assert EmulatorSession.BIZHAWK == "bizhawk"


class TestDebuggerFactory:
    """Tests for debugger factory functions."""

    def test_create_gdb_session(self):
        from codemunch_pro.rex.debugger import create_session, get_session, remove_session
        session = create_session("gdb", "gdb-test-session")
        assert session is not None
        assert session.name == "gdb-test-session"

        # Verify it's registered
        retrieved = get_session("gdb-test-session")
        assert retrieved is session

        # Clean up
        remove_session("gdb-test-session")
        assert get_session("gdb-test-session") is None

    def test_create_lldb_session(self):
        from codemunch_pro.rex.debugger import create_session, remove_session
        session = create_session("lldb", "lldb-test-session")
        assert session is not None
        remove_session("lldb-test-session")

    def test_create_emulator_session(self):
        from codemunch_pro.rex.debugger import create_session, remove_session
        session = create_session("emulator", "emu-test-session", emulator_type="mgba")
        assert session is not None
        remove_session("emu-test-session")

    def test_create_invalid_session_type(self):
        from codemunch_pro.rex.debugger import create_session
        session = create_session("invalid", "invalid-session")
        assert session is None

    def test_list_sessions(self):
        from codemunch_pro.rex.debugger import create_session, list_sessions, remove_session
        create_session("gdb", "gdb-list-1")
        create_session("lldb", "lldb-list-1")

        sessions = list_sessions()
        assert len(sessions) >= 2
        session_ids = [sid for sid, _ in sessions]
        assert "gdb-list-1" in session_ids
        assert "lldb-list-1" in session_ids

        # Clean up
        remove_session("gdb-list-1")
        remove_session("lldb-list-1")

    def test_remove_nonexistent_session(self):
        from codemunch_pro.rex.debugger import remove_session
        result = remove_session("nonexistent-session")
        assert result is False


class TestDebuggerMemoryOperations:
    """Tests for debugger memory read/write operations."""

    def test_memory_read_success(self):
        from codemunch_pro.rex.debugger import MemoryRead
        result = MemoryRead(address=0x08000000, data=b"\x12\x34\x56\x78", success=True)
        assert result.success is True
        assert result.data == b"\x12\x34\x56\x78"
        data = result.to_dict()
        assert data["data"] == "12345678"

    def test_memory_read_failure(self):
        from codemunch_pro.rex.debugger import MemoryRead
        result = MemoryRead(address=0x08000000, data=b"", success=False, error="Bus error")
        assert result.success is False
        assert result.error == "Bus error"
        data = result.to_dict()
        assert data["success"] is False
        assert data["error"] == "Bus error"


# =============================================================================
# Execution Trace Storage Tests
# =============================================================================


class TestExecutionTraceStorage:
    """Tests for storing execution traces in ReverseEngineeringStore."""

    def test_store_execution_trace(self, tmp_path):
        from codemunch_pro.rex import ReverseEngineeringStore

        db_path = tmp_path / "test_trace.db"
        store = ReverseEngineeringStore(db_path)

        entries = [
            {
                "address": 0x08000000,
                "instruction_bytes": "0000",
                "disassembly": "NOP",
                "timestamp": 1234567890.0,
            },
            {
                "address": 0x08000002,
                "instruction_bytes": "4770",
                "disassembly": "BX LR",
                "timestamp": 1234567890.1,
            },
        ]

        result = store.store_execution_trace("test_capture", entries)
        assert result["capture_id"] == "test_capture"
        assert result["entity_count"] == 2
        assert result["evidence_count"] == 2

        store.close()

    def test_get_execution_trace(self, tmp_path):
        from codemunch_pro.rex import ReverseEngineeringStore

        db_path = tmp_path / "test_trace.db"
        store = ReverseEngineeringStore(db_path)

        entries = [
            {
                "address": 0x08000000,
                "instruction_bytes": "0000",
                "disassembly": "NOP",
                "timestamp": 1234567890.0,
            },
        ]

        store.store_execution_trace("test_capture", entries)
        trace = store.get_execution_trace("test_capture")

        assert trace is not None
        assert trace["capture_id"] == "test_capture"
        assert trace["entry_count"] == 1
        assert len(trace["entries"]) == 1

        store.close()

    def test_get_nonexistent_trace(self, tmp_path):
        from codemunch_pro.rex import ReverseEngineeringStore

        db_path = tmp_path / "test_trace.db"
        store = ReverseEngineeringStore(db_path)

        trace = store.get_execution_trace("nonexistent")
        assert trace is None

        store.close()

    def test_list_execution_traces(self, tmp_path):
        from codemunch_pro.rex import ReverseEngineeringStore

        db_path = tmp_path / "test_trace.db"
        store = ReverseEngineeringStore(db_path)

        entries = [{"address": 0x08000000, "instruction_bytes": "00", "disassembly": "NOP"}]
        store.store_execution_trace("capture1", entries, {"test": True})
        store.store_execution_trace("capture2", entries)

        traces = store.list_execution_traces()
        assert len(traces) == 2
        capture_ids = [t["capture_id"] for t in traces]
        assert "capture1" in capture_ids
        assert "capture2" in capture_ids

        store.close()

    def test_delete_execution_trace(self, tmp_path):
        from codemunch_pro.rex import ReverseEngineeringStore

        db_path = tmp_path / "test_trace.db"
        store = ReverseEngineeringStore(db_path)

        entries = [{"address": 0x08000000, "instruction_bytes": "00", "disassembly": "NOP"}]
        store.store_execution_trace("delete_me", entries)

        assert store.get_execution_trace("delete_me") is not None

        result = store.delete_execution_trace("delete_me")
        assert result is True

        assert store.get_execution_trace("delete_me") is None

        store.close()

    def test_correlate_trace_with_static(self, tmp_path):
        from codemunch_pro.rex import ReverseEngineeringStore, AddressLocation, EntityRecord

        db_path = tmp_path / "test_trace.db"
        store = ReverseEngineeringStore(db_path)

        # Create a static function entity
        entity = EntityRecord(
            entity_id="test:function:main",
            kind="function",
            name="main",
            canonical_ref="0x08000000",
            location=AddressLocation(
                address_space="rom",
                start=0x08000000,
                end=0x08000100,
            ),
        )

        # Create a bundle with the static entity
        from codemunch_pro.rex import ReverseEngineeringBundle, ArtifactRecord
        bundle = ReverseEngineeringBundle(
            artifacts=[ArtifactRecord(artifact_id="test:static", kind="analysis", path="test.asm")],
            entities=[entity],
        )
        store.upsert_bundle(bundle)

        # Store a trace that hits the function
        entries = [
            {"address": 0x08000000, "instruction_bytes": "00", "disassembly": "NOP"},
            {"address": 0x08000010, "instruction_bytes": "00", "disassembly": "NOP"},
        ]
        store.store_execution_trace("correlate_test", entries)

        # Correlate trace with static analysis
        result = store.correlate_trace_with_static("correlate_test", address_space="rom")

        assert result["capture_id"] == "correlate_test"
        assert result["trace_entry_count"] == 2
        assert result["address_space"] == "rom"

        store.close()
