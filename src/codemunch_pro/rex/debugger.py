"""Debugger integration for dynamic analysis.

This module provides abstractions for connecting to various debuggers
and emulators to perform dynamic analysis and collect execution traces.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


class DebuggerState(Enum):
    """States a debugger session can be in."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RegisterSet:
    """CPU register values at a point in time."""

    pc: int  # Program counter
    sp: int  # Stack pointer
    general: dict[str, int] = field(default_factory=dict)
    flags: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "pc": self.pc,
            "sp": self.sp,
            "general": dict(self.general),
            "flags": dict(self.flags),
        }


@dataclass(frozen=True, slots=True)
class StackFrame:
    """A single frame in a call stack."""

    address: int
    function_name: str = ""
    module: str = ""
    source_file: str = ""
    source_line: int = 0
    registers: RegisterSet | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result: dict[str, Any] = {
            "address": self.address,
            "function_name": self.function_name,
            "module": self.module,
            "source_file": self.source_file,
            "source_line": self.source_line,
        }
        if self.registers:
            result["registers"] = self.registers.to_dict()
        return result


@dataclass(frozen=True, slots=True)
class Breakpoint:
    """A debugger breakpoint."""

    id: str
    address: int
    enabled: bool = True
    hit_count: int = 0
    condition: str = ""
    hit_condition: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "address": self.address,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "condition": self.condition,
            "hit_condition": self.hit_condition,
        }


@dataclass(frozen=True, slots=True)
class MemoryRead:
    """Result of a memory read operation."""

    address: int
    data: bytes
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "address": self.address,
            "data": self.data.hex() if self.data else "",
            "size": len(self.data) if self.data else 0,
            "success": self.success,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class ExecutionTrace:
    """A single step/trace entry from dynamic execution."""

    timestamp: float
    address: int
    instruction_bytes: bytes
    disassembly: str = ""
    registers: RegisterSet | None = None
    memory_accesses: list[dict[str, Any]] = field(default_factory=list)
    timestamp_rel: float = 0.0  # Relative to trace start

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result: dict[str, Any] = {
            "timestamp": self.timestamp,
            "address": self.address,
            "instruction_bytes": self.instruction_bytes.hex() if self.instruction_bytes else "",
            "disassembly": self.disassembly,
            "memory_accesses": list(self.memory_accesses),
            "timestamp_rel": self.timestamp_rel,
        }
        if self.registers:
            result["registers"] = self.registers.to_dict()
        return result


@dataclass(slots=True)
class TraceCapture:
    """A complete execution trace capture."""

    capture_id: str
    start_address: int
    end_address: int | None = None
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    entries: list[ExecutionTrace] = field(default_factory=list)
    breakpoints_hit: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_entry(self, entry: ExecutionTrace) -> None:
        """Add a trace entry."""
        self.entries.append(entry)

    def finalize(self) -> None:
        """Finalize the capture."""
        self.end_time = time.time()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "capture_id": self.capture_id,
            "start_address": self.start_address,
            "end_address": self.end_address,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.end_time - self.start_time if self.end_time else 0,
            "entry_count": len(self.entries),
            "breakpoints_hit": self.breakpoints_hit,
            "metadata": dict(self.metadata),
        }


class DebuggerSession(ABC):
    """Abstract base class for debugger sessions.

    Provides a common interface for connecting to and controlling
    various debuggers (GDB, LLDB) and emulator debug interfaces.
    """

    def __init__(self, name: str = ""):
        self._name = name or self.__class__.__name__
        self._state = DebuggerState.DISCONNECTED
        self._breakpoints: dict[str, Breakpoint] = {}
        self._trace_captures: dict[str, TraceCapture] = {}
        self._active_capture: TraceCapture | None = None
        self._error_message: str = ""

    @property
    def name(self) -> str:
        """Get the session name."""
        return self._name

    @property
    def state(self) -> DebuggerState:
        """Get the current debugger state."""
        return self._state

    @property
    def is_connected(self) -> bool:
        """Check if connected to the debugger."""
        return self._state not in (DebuggerState.DISCONNECTED, DebuggerState.ERROR)

    @property
    def error_message(self) -> str:
        """Get the last error message."""
        return self._error_message

    @abstractmethod
    def attach(self, target: str, **kwargs: Any) -> bool:
        """Attach to a target process or device.

        Args:
            target: Target identifier (PID, host:port, device path, etc.)
            **kwargs: Implementation-specific arguments

        Returns:
            True if attach was successful
        """
        raise NotImplementedError

    @abstractmethod
    def detach(self) -> bool:
        """Detach from the target.

        Returns:
            True if detach was successful
        """
        raise NotImplementedError

    @abstractmethod
    def read_memory(self, address: int, size: int) -> MemoryRead:
        """Read memory from the target.

        Args:
            address: Memory address to read from
            size: Number of bytes to read

        Returns:
            MemoryRead result
        """
        raise NotImplementedError

    @abstractmethod
    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory to the target.

        Args:
            address: Memory address to write to
            data: Bytes to write

        Returns:
            True if write was successful
        """
        raise NotImplementedError

    @abstractmethod
    def set_breakpoint(
        self, address: int, condition: str = "", hit_count: int = 0
    ) -> Breakpoint | None:
        """Set a breakpoint at an address.

        Args:
            address: Address to break at
            condition: Optional condition expression
            hit_count: Optional hit count condition

        Returns:
            The created breakpoint or None on failure
        """
        raise NotImplementedError

    @abstractmethod
    def remove_breakpoint(self, breakpoint_id: str) -> bool:
        """Remove a breakpoint.

        Args:
            breakpoint_id: ID of the breakpoint to remove

        Returns:
            True if removal was successful
        """
        raise NotImplementedError

    @abstractmethod
    def continue_execution(self) -> bool:
        """Continue execution until next stop.

        Returns:
            True if command was successful
        """
        raise NotImplementedError

    @abstractmethod
    def step(self, into: bool = True) -> bool:
        """Step execution by one instruction.

        Args:
            into: If True, step into function calls; else step over

        Returns:
            True if step was successful
        """
        raise NotImplementedError

    @abstractmethod
    def get_registers(self) -> RegisterSet | None:
        """Get current CPU register values.

        Returns:
            Current register values or None on failure
        """
        raise NotImplementedError

    @abstractmethod
    def get_backtrace(self, max_frames: int = 50) -> list[StackFrame]:
        """Get the current call stack.

        Args:
            max_frames: Maximum number of frames to retrieve

        Returns:
            List of stack frames (most recent first)
        """
        raise NotImplementedError

    def start_capture(
        self, capture_id: str, start_address: int, end_address: int | None = None, **metadata: Any
    ) -> TraceCapture:
        """Start a new execution trace capture.

        Args:
            capture_id: Unique identifier for this capture
            start_address: Address where capture started
            end_address: Optional end address for auto-stop
            **metadata: Additional metadata to store with the capture

        Returns:
            The new TraceCapture
        """
        capture = TraceCapture(
            capture_id=capture_id,
            start_address=start_address,
            end_address=end_address,
            metadata=metadata,
        )
        self._trace_captures[capture_id] = capture
        self._active_capture = capture
        return capture

    def stop_capture(self, capture_id: str | None = None) -> TraceCapture | None:
        """Stop an execution trace capture.

        Args:
            capture_id: ID of capture to stop (None = active capture)

        Returns:
            The finalized TraceCapture or None if not found
        """
        if capture_id is None:
            capture = self._active_capture
        else:
            capture = self._trace_captures.get(capture_id)

        if capture:
            capture.finalize()
            if self._active_capture is capture:
                self._active_capture = None
            return capture
        return None

    def get_capture(self, capture_id: str) -> TraceCapture | None:
        """Get a capture by ID.

        Args:
            capture_id: The capture ID

        Returns:
            The TraceCapture or None if not found
        """
        return self._trace_captures.get(capture_id)

    def list_captures(self) -> list[TraceCapture]:
        """List all captures.

        Returns:
            List of all trace captures
        """
        return list(self._trace_captures.values())

    def _record_trace_entry(self, entry: ExecutionTrace) -> None:
        """Internal method to record a trace entry."""
        if self._active_capture:
            self._active_capture.add_entry(entry)

    def to_dict(self) -> dict[str, Any]:
        """Serialize session state to dictionary."""
        return {
            "name": self._name,
            "state": self._state.value,
            "connected": self.is_connected,
            "breakpoint_count": len(self._breakpoints),
            "capture_count": len(self._trace_captures),
            "active_capture": self._active_capture.capture_id if self._active_capture else None,
            "error": self._error_message,
        }


class GDBSession(DebuggerSession):
    """GDB remote debugging session.

    Connects to GDB via the GDB Remote Serial Protocol (RSP) or
    by launching a local GDB process with mi2 interface.
    """

    def __init__(self, name: str = "", use_mi: bool = True, gdb_path: str = "gdb"):
        super().__init__(name or "gdb-session")
        self._use_mi = use_mi
        self._gdb_path = gdb_path
        self._process: subprocess.Popen | None = None
        self._socket: socket.socket | None = None
        self._host: str = ""
        self._port: int = 0
        self._next_breakpoint_id = 1

    def attach(self, target: str, **kwargs: Any) -> bool:
        """Attach to a GDB target.

        Args:
            target: Either "host:port" for remote or executable path
            **kwargs: Additional options including 'symbols' for symbol file

        Returns:
            True if attach was successful
        """
        self._state = DebuggerState.CONNECTING
        self._error_message = ""

        try:
            # Check if target is host:port format
            if ":" in target and not target.endswith((".exe", ".elf", ".bin")):
                parts = target.rsplit(":", 1)
                self._host = parts[0]
                self._port = int(parts[1])
                return self._attach_remote()
            else:
                # Local executable
                return self._attach_local(target, **kwargs)
        except Exception as e:
            self._state = DebuggerState.ERROR
            self._error_message = str(e)
            return False

    def _attach_remote(self) -> bool:
        """Attach to remote GDB server."""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(10.0)
            self._socket.connect((self._host, self._port))
            self._state = DebuggerState.STOPPED
            return True
        except Exception as e:
            self._state = DebuggerState.ERROR
            self._error_message = f"Failed to connect to {self._host}:{self._port}: {e}"
            return False

    def _attach_local(self, executable: str, **kwargs: Any) -> bool:
        """Attach to local executable."""
        try:
            cmd = [self._gdb_path]
            if self._use_mi:
                cmd.append("--interpreter=mi2")
            cmd.append(executable)

            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._state = DebuggerState.STOPPED
            return True
        except Exception as e:
            self._state = DebuggerState.ERROR
            self._error_message = f"Failed to start GDB: {e}"
            return False

    def detach(self) -> bool:
        """Detach from GDB."""
        try:
            if self._socket:
                self._socket.close()
                self._socket = None
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=5)
                self._process = None
            self._state = DebuggerState.DISCONNECTED
            return True
        except Exception as e:
            self._error_message = f"Error during detach: {e}"
            return False

    def read_memory(self, address: int, size: int) -> MemoryRead:
        """Read memory via GDB."""
        if not self.is_connected:
            return MemoryRead(address, b"", False, "Not connected")

        # Simulated implementation - in production this would use GDB RSP
        try:
            # Placeholder: actual implementation would send GDB command
            return MemoryRead(address, b"\x00" * size, True)
        except Exception as e:
            return MemoryRead(address, b"", False, str(e))

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory via GDB."""
        if not self.is_connected:
            return False

        try:
            # Placeholder: actual implementation would send GDB command
            return True
        except Exception as e:
            self._error_message = str(e)
            return False

    def set_breakpoint(
        self, address: int, condition: str = "", hit_count: int = 0
    ) -> Breakpoint | None:
        """Set a breakpoint via GDB."""
        if not self.is_connected:
            return None

        bp_id = f"bp{self._next_breakpoint_id}"
        self._next_breakpoint_id += 1

        bp = Breakpoint(
            id=bp_id,
            address=address,
            enabled=True,
            condition=condition,
            hit_condition=f"{hit_count}" if hit_count > 0 else "",
        )
        self._breakpoints[bp_id] = bp
        return bp

    def remove_breakpoint(self, breakpoint_id: str) -> bool:
        """Remove a breakpoint via GDB."""
        if breakpoint_id in self._breakpoints:
            del self._breakpoints[breakpoint_id]
            return True
        return False

    def continue_execution(self) -> bool:
        """Continue execution via GDB."""
        if not self.is_connected:
            return False
        self._state = DebuggerState.RUNNING
        return True

    def step(self, into: bool = True) -> bool:
        """Step execution via GDB."""
        if not self.is_connected:
            return False
        self._state = DebuggerState.STOPPED
        return True

    def get_registers(self) -> RegisterSet | None:
        """Get registers via GDB."""
        if not self.is_connected:
            return None

        # Placeholder: return zeroed registers
        return RegisterSet(pc=0, sp=0)

    def get_backtrace(self, max_frames: int = 50) -> list[StackFrame]:
        """Get backtrace via GDB."""
        if not self.is_connected:
            return []

        # Placeholder: return empty backtrace
        return []


class LLDBSession(DebuggerSession):
    """LLDB debugging session.

    Connects to LLDB via its Python API or command interface.
    """

    def __init__(self, name: str = "", lldb_path: str = "lldb"):
        super().__init__(name or "lldb-session")
        self._lldb_path = lldb_path
        self._target: Any = None
        self._process: Any = None
        self._next_breakpoint_id = 1

    def attach(self, target: str, **kwargs: Any) -> bool:
        """Attach to an LLDB target.

        Args:
            target: Either "host:port" for remote or executable path
            **kwargs: Additional options

        Returns:
            True if attach was successful
        """
        self._state = DebuggerState.CONNECTING
        self._error_message = ""

        try:
            # Try importing lldb module if available
            try:
                import lldb  # type: ignore

                self._debugger = lldb.SBDebugger.Create()
                self._target = self._debugger.CreateTarget(target)
                if self._target:
                    self._state = DebuggerState.STOPPED
                    return True
            except ImportError:
                # Fall back to subprocess mode
                return self._attach_subprocess(target, **kwargs)

            self._state = DebuggerState.ERROR
            self._error_message = "Failed to create target"
            return False

        except Exception as e:
            self._state = DebuggerState.ERROR
            self._error_message = str(e)
            return False

    def _attach_subprocess(self, target: str, **kwargs: Any) -> bool:
        """Attach using LLDB subprocess."""
        try:
            cmd = [self._lldb_path, target]
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._state = DebuggerState.STOPPED
            return True
        except Exception as e:
            self._state = DebuggerState.ERROR
            self._error_message = f"Failed to start LLDB: {e}"
            return False

    def detach(self) -> bool:
        """Detach from LLDB."""
        try:
            if hasattr(self, "_debugger") and self._debugger:
                import lldb  # type: ignore

                lldb.SBDebugger.Destroy(self._debugger)
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=5)
            self._state = DebuggerState.DISCONNECTED
            return True
        except Exception as e:
            self._error_message = f"Error during detach: {e}"
            return False

    def read_memory(self, address: int, size: int) -> MemoryRead:
        """Read memory via LLDB."""
        if not self.is_connected:
            return MemoryRead(address, b"", False, "Not connected")

        try:
            # Placeholder: actual implementation would use LLDB API
            return MemoryRead(address, b"\x00" * size, True)
        except Exception as e:
            return MemoryRead(address, b"", False, str(e))

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory via LLDB."""
        if not self.is_connected:
            return False

        try:
            # Placeholder: actual implementation would use LLDB API
            return True
        except Exception as e:
            self._error_message = str(e)
            return False

    def set_breakpoint(
        self, address: int, condition: str = "", hit_count: int = 0
    ) -> Breakpoint | None:
        """Set a breakpoint via LLDB."""
        if not self.is_connected:
            return None

        bp_id = f"bp{self._next_breakpoint_id}"
        self._next_breakpoint_id += 1

        bp = Breakpoint(
            id=bp_id,
            address=address,
            enabled=True,
            condition=condition,
            hit_condition=f"{hit_count}" if hit_count > 0 else "",
        )
        self._breakpoints[bp_id] = bp
        return bp

    def remove_breakpoint(self, breakpoint_id: str) -> bool:
        """Remove a breakpoint via LLDB."""
        if breakpoint_id in self._breakpoints:
            del self._breakpoints[breakpoint_id]
            return True
        return False

    def continue_execution(self) -> bool:
        """Continue execution via LLDB."""
        if not self.is_connected:
            return False
        self._state = DebuggerState.RUNNING
        return True

    def step(self, into: bool = True) -> bool:
        """Step execution via LLDB."""
        if not self.is_connected:
            return False
        self._state = DebuggerState.STOPPED
        return True

    def get_registers(self) -> RegisterSet | None:
        """Get registers via LLDB."""
        if not self.is_connected:
            return None

        # Placeholder: return zeroed registers
        return RegisterSet(pc=0, sp=0)

    def get_backtrace(self, max_frames: int = 50) -> list[StackFrame]:
        """Get backtrace via LLDB."""
        if not self.is_connected:
            return []

        # Placeholder: return empty backtrace
        return []


class EmulatorRPC(Protocol):
    """Protocol for emulator RPC interfaces."""

    def read_memory(self, address: int, size: int) -> bytes: ...
    def write_memory(self, address: int, data: bytes) -> bool: ...
    def get_registers(self) -> dict[str, int]: ...
    def set_breakpoint(self, address: int) -> bool: ...
    def step(self) -> bool: ...
    def run(self) -> bool: ...
    def pause(self) -> bool: ...


class EmulatorSession(DebuggerSession):
    """Emulator debugging session via RPC.

    Connects to emulators like mGBA, Mesen, BizHawk via their
    scripting/RPC interfaces for dynamic analysis.
    """

    # Known emulator types
    MGBA = "mgba"
    MESEN = "mesen"
    BIZHAWK = "bizhawk"
    FCEUX = "fceux"
    SNES9X = "snes9x"
    CUSTOM = "custom"

    def __init__(
        self,
        name: str = "",
        emulator_type: str = CUSTOM,
        rpc_url: str = "",
        rpc_client: EmulatorRPC | None = None,
    ):
        super().__init__(name or f"{emulator_type}-session")
        self._emulator_type = emulator_type
        self._rpc_url = rpc_url
        self._rpc_client = rpc_client
        self._next_breakpoint_id = 1
        self._trace_callback: Any = None

    def attach(self, target: str, **kwargs: Any) -> bool:
        """Attach to an emulator.

        Args:
            target: Connection string or emulator identifier
            **kwargs: Additional options including 'emulator_type', 'rpc_url'

        Returns:
            True if attach was successful
        """
        self._state = DebuggerState.CONNECTING
        self._error_message = ""

        # Update from kwargs
        self._emulator_type = kwargs.get("emulator_type", self._emulator_type)
        self._rpc_url = kwargs.get("rpc_url", target)

        try:
            if self._rpc_client:
                # Use provided RPC client
                self._state = DebuggerState.STOPPED
                return True

            # Try to connect via RPC URL
            if self._rpc_url:
                return self._connect_rpc()

            self._state = DebuggerState.ERROR
            self._error_message = "No RPC client or URL provided"
            return False

        except Exception as e:
            self._state = DebuggerState.ERROR
            self._error_message = str(e)
            return False

    def _connect_rpc(self) -> bool:
        """Connect to emulator RPC endpoint."""
        try:
            # Implementation depends on emulator type
            if self._emulator_type == self.MGBA:
                return self._connect_mgba()
            elif self._emulator_type == self.MESEN:
                return self._connect_mesen()
            elif self._emulator_type == self.BIZHAWK:
                return self._connect_bizhawk()
            else:
                # Generic connection
                self._state = DebuggerState.STOPPED
                return True
        except Exception as e:
            self._error_message = f"RPC connection failed: {e}"
            return False

    def _connect_mgba(self) -> bool:
        """Connect to mGBA via its socket API."""
        # mGBA uses a simple socket protocol
        try:
            if not self._rpc_url.startswith("tcp://"):
                self._error_message = "mGBA requires tcp:// URL"
                return False
            parts = self._rpc_url[6:].rsplit(":", 1)
            host, port = parts[0], int(parts[1])
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(5.0)
            self._socket.connect((host, port))
            self._state = DebuggerState.STOPPED
            return True
        except Exception as e:
            self._error_message = f"Failed to connect to mGBA: {e}"
            return False

    def _connect_mesen(self) -> bool:
        """Connect to Mesen via its HTTP API."""
        try:
            import urllib.request
            import urllib.error

            # Mesen uses HTTP API
            test_url = f"{self._rpc_url}/api/status"
            req = urllib.request.Request(test_url, method="GET")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    self._state = DebuggerState.STOPPED
                    return True
            self._error_message = "Mesen API status check failed"
            return False
        except Exception as e:
            self._error_message = f"Failed to connect to Mesen: {e}"
            return False

    def _connect_bizhawk(self) -> bool:
        """Connect to BizHawk via its socket API."""
        try:
            parts = self._rpc_url.rsplit(":", 1)
            host, port = parts[0], int(parts[1])
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(5.0)
            self._socket.connect((host, port))
            self._state = DebuggerState.STOPPED
            return True
        except Exception as e:
            self._error_message = f"Failed to connect to BizHawk: {e}"
            return False

    def detach(self) -> bool:
        """Detach from emulator."""
        try:
            if hasattr(self, "_socket") and self._socket:
                self._socket.close()
            self._state = DebuggerState.DISCONNECTED
            return True
        except Exception as e:
            self._error_message = f"Error during detach: {e}"
            return False

    def read_memory(self, address: int, size: int) -> MemoryRead:
        """Read memory from emulator."""
        if not self.is_connected:
            return MemoryRead(address, b"", False, "Not connected")

        try:
            if self._rpc_client:
                data = self._rpc_client.read_memory(address, size)
                return MemoryRead(address, data, True)

            # Use emulator-specific protocol
            if self._emulator_type == self.MGBA:
                return self._read_memory_mgba(address, size)
            elif self._emulator_type == self.MESEN:
                return self._read_memory_mesen(address, size)
            else:
                # Generic placeholder
                return MemoryRead(address, b"\x00" * size, True)
        except Exception as e:
            return MemoryRead(address, b"", False, str(e))

    def _read_memory_mgba(self, address: int, size: int) -> MemoryRead:
        """Read memory from mGBA."""
        # mGBA socket protocol: "read.address.size\n"
        cmd = f"read.{address:X}.{size}\n".encode()
        self._socket.send(cmd)
        response = self._socket.recv(size * 2 + 100)  # Hex encoded + overhead
        # Parse response (hex string)
        data = bytes.fromhex(response.decode().strip())
        return MemoryRead(address, data, True)

    def _read_memory_mesen(self, address: int, size: int) -> MemoryRead:
        """Read memory from Mesen."""
        import urllib.request

        url = f"{self._rpc_url}/api/read-memory?address={address}&length={size}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = resp.read()
            return MemoryRead(address, data, True)

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory to emulator."""
        if not self.is_connected:
            return False

        try:
            if self._rpc_client:
                return self._rpc_client.write_memory(address, data)
            return True  # Placeholder
        except Exception as e:
            self._error_message = str(e)
            return False

    def set_breakpoint(
        self, address: int, condition: str = "", hit_count: int = 0
    ) -> Breakpoint | None:
        """Set a breakpoint in emulator."""
        if not self.is_connected:
            return None

        bp_id = f"bp{self._next_breakpoint_id}"
        self._next_breakpoint_id += 1

        bp = Breakpoint(
            id=bp_id,
            address=address,
            enabled=True,
            condition=condition,
            hit_condition=f"{hit_count}" if hit_count > 0 else "",
        )
        self._breakpoints[bp_id] = bp
        return bp

    def remove_breakpoint(self, breakpoint_id: str) -> bool:
        """Remove a breakpoint from emulator."""
        if breakpoint_id in self._breakpoints:
            del self._breakpoints[breakpoint_id]
            return True
        return False

    def continue_execution(self) -> bool:
        """Continue execution in emulator."""
        if not self.is_connected:
            return False

        try:
            if self._rpc_client:
                return self._rpc_client.run()
            self._state = DebuggerState.RUNNING
            return True
        except Exception as e:
            self._error_message = str(e)
            return False

    def step(self, into: bool = True) -> bool:
        """Step execution in emulator."""
        if not self.is_connected:
            return False

        try:
            if self._rpc_client:
                return self._rpc_client.step()
            self._state = DebuggerState.STOPPED
            return True
        except Exception as e:
            self._error_message = str(e)
            return False

    def get_registers(self) -> RegisterSet | None:
        """Get registers from emulator."""
        if not self.is_connected:
            return None

        try:
            if self._rpc_client:
                regs = self._rpc_client.get_registers()
                return RegisterSet(
                    pc=regs.get("pc", 0),
                    sp=regs.get("sp", 0),
                    general={k: v for k, v in regs.items() if k not in ("pc", "sp")},
                )
            return RegisterSet(pc=0, sp=0)
        except Exception as e:
            self._error_message = str(e)
            return None

    def get_backtrace(self, max_frames: int = 50) -> list[StackFrame]:
        """Get backtrace from emulator (if supported)."""
        if not self.is_connected:
            return []

        # Most console emulators don't provide native backtrace support
        # This would require manual stack walking based on architecture
        return []

    def read_captures(self, format: str = "dict") -> list[dict[str, Any]] | str:
        """Read execution trace captures.

        Args:
            format: Output format - "dict" or "json"

        Returns:
            List of capture dictionaries or JSON string
        """
        captures = [cap.to_dict() for cap in self._trace_captures.values()]
        if format == "json":
            return json.dumps(captures, indent=2)
        return captures

    def export_capture_to_bundle(
        self, capture_id: str, project_path: str = ""
    ) -> dict[str, Any]:
        """Export a capture as a ReverseEngineeringBundle.

        Args:
            capture_id: The capture to export
            project_path: Optional project path for context

        Returns:
            Dictionary representing the bundle structure
        """
        capture = self._trace_captures.get(capture_id)
        if not capture:
            return {"error": f"Capture not found: {capture_id}"}

        # Convert trace entries to evidence records
        evidence_records = []
        entity_records = []

        for i, entry in enumerate(capture.entries):
            # Create entity for each unique address
            addr_hex = f"0x{entry.address:08X}"
            entity_id = f"trace:{capture_id}:addr:{entry.address:08X}"

            entity_records.append({
                "entity_id": entity_id,
                "kind": "trace_entry",
                "name": f"Trace@{addr_hex}",
                "canonical_ref": addr_hex,
                "location": {
                    "address_space": "execution",
                    "start": entry.address,
                    "end": entry.address,
                },
            })

            evidence_records.append({
                "evidence_id": f"trace:{capture_id}:entry:{i}",
                "kind": "execution_trace",
                "entity_ids": [entity_id],
                "excerpt": entry.disassembly,
                "attributes": entry.to_dict(),
            })

        return {
            "artifact_id": f"trace_capture:{capture_id}",
            "kind": "execution_trace",
            "path": project_path,
            "entities": entity_records,
            "evidence": evidence_records,
            "metadata": {
                "capture_info": capture.to_dict(),
                "emulator_type": self._emulator_type,
            },
        }


# Global session registry for managing multiple debugger sessions
_session_registry: dict[str, DebuggerSession] = {}


def register_session(session_id: str, session: DebuggerSession) -> None:
    """Register a debugger session."""
    _session_registry[session_id] = session


def get_session(session_id: str) -> DebuggerSession | None:
    """Get a registered debugger session."""
    return _session_registry.get(session_id)


def list_sessions() -> list[tuple[str, DebuggerSession]]:
    """List all registered sessions."""
    return list(_session_registry.items())


def remove_session(session_id: str) -> bool:
    """Remove a registered session."""
    if session_id in _session_registry:
        session = _session_registry[session_id]
        session.detach()
        del _session_registry[session_id]
        return True
    return False


def create_session(
    session_type: str,
    session_id: str,
    **kwargs: Any,
) -> DebuggerSession | None:
    """Factory function to create debugger sessions.

    Args:
        session_type: Type of session - "gdb", "lldb", "emulator"
        session_id: Unique identifier for the session
        **kwargs: Type-specific arguments

    Returns:
        Created session or None on failure
    """
    session: DebuggerSession | None = None

    if session_type == "gdb":
        session = GDBSession(name=session_id, **kwargs)
    elif session_type == "lldb":
        session = LLDBSession(name=session_id, **kwargs)
    elif session_type == "emulator":
        session = EmulatorSession(name=session_id, **kwargs)
    else:
        return None

    register_session(session_id, session)
    return session
