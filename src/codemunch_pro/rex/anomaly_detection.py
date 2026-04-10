"""Anomaly detection for unusual code patterns in reverse-engineering analysis.

This module provides statistical analysis and pattern detection for identifying:
- Unusual instruction sequences (anti-debugging)
- High entropy regions (packed/encrypted data)
- Unreachable code (dead code, obfuscation)
- Anti-analysis patterns (timing checks, debugger detection, VM detection)
- Potential bugs (null pointer dereferences, buffer overflows, unchecked returns)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore


class SeverityLevel(Enum):
    """Severity levels for anomaly detection."""

    INFO = 1
    WARNING = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        """Get the label for this severity level."""
        return _SEVERITY_LABELS[self]


_SEVERITY_LABELS = {
    SeverityLevel.INFO: "info",
    SeverityLevel.WARNING: "warning",
    SeverityLevel.CRITICAL: "critical",
}


class AnomalyType(Enum):
    """Types of anomalies that can be detected."""

    # Anti-debugging patterns
    ANTI_DEBUG = "anti_debug"
    TIMING_CHECK = "timing_check"
    DEBUGGER_DETECTION = "debugger_detection"
    VM_DETECTION = "vm_detection"

    # Code structure anomalies
    UNREACHABLE_CODE = "unreachable_code"
    HIGH_ENTROPY = "high_entropy"
    OBFUSCATED_CODE = "obfuscated_code"

    # Potential bugs
    NULL_POINTER_DEREF = "null_pointer_dereference"
    BUFFER_OVERFLOW = "buffer_overflow"
    UNCHECKED_RETURN = "unchecked_return"
    SUSPICIOUS_LOOP = "suspicious_loop"

    # Instruction anomalies
    UNUSUAL_INSTRUCTION = "unusual_instruction"
    RARE_OPCODE = "rare_opcode"


@dataclass(frozen=True, slots=True)
class AnomalyReport:
    """A single anomaly report."""

    anomaly_type: AnomalyType
    severity: SeverityLevel
    address: int
    address_space: str
    description: str
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity.label,
            "address": f"0x{self.address:08X}",
            "address_space": self.address_space,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "details": self.details,
        }


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""

    address_space: str
    total_anomalies: int = 0
    info_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    anomalies: list[AnomalyReport] = field(default_factory=list)

    def add(self, report: AnomalyReport) -> None:
        """Add an anomaly report."""
        self.anomalies.append(report)
        self.total_anomalies += 1
        if report.severity == SeverityLevel.INFO:
            self.info_count += 1
        elif report.severity == SeverityLevel.WARNING:
            self.warning_count += 1
        elif report.severity == SeverityLevel.CRITICAL:
            self.critical_count += 1

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "address_space": self.address_space,
            "total_anomalies": self.total_anomalies,
            "by_severity": {
                SeverityLevel.INFO.label: self.info_count,
                SeverityLevel.WARNING.label: self.warning_count,
                SeverityLevel.CRITICAL.label: self.critical_count,
            },
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


class AnomalyDetector:
    """Detector for unusual code patterns and anomalies.

    Uses statistical analysis and pattern matching to identify:
    - Anti-debugging and anti-analysis techniques
    - Potentially malicious or obfuscated code
    - Common vulnerability patterns
    """

    # Anti-debugging instruction patterns (x86/x64)
    ANTI_DEBUG_PATTERNS: dict[str, tuple[AnomalyType, SeverityLevel, str]] = {
        # RDTSC - timing checks for debugger detection
        r"RDTSC": (
            AnomalyType.TIMING_CHECK,
            SeverityLevel.INFO,
            "Timing check using RDTSC instruction (possible anti-debug)",
        ),
        # INT3 / ICEBP - software breakpoints
        r"\bINT3?\b|\bICEBP\b": (
            AnomalyType.ANTI_DEBUG,
            SeverityLevel.WARNING,
            "Breakpoint instruction detected",
        ),
        # INT 2D - kernel debugger detection
        r"INT\s+2Dh?": (
            AnomalyType.DEBUGGER_DETECTION,
            SeverityLevel.WARNING,
            "Kernel debugger detection (INT 2D)",
        ),
        # CPUID with specific leafs for VM detection
        r"CPUID": (
            AnomalyType.VM_DETECTION,
            SeverityLevel.INFO,
            "CPUID instruction (possible VM detection)",
        ),
        # RDMSR/WRMSR - model-specific registers
        r"\bRDMSR\b|\bWRMSR\b": (
            AnomalyType.ANTI_DEBUG,
            SeverityLevel.WARNING,
            "MSR access (possible anti-debug)",
        ),
        # IN/OUT instructions - hardware access
        r"\bIN\s+|\bOUT\s+": (
            AnomalyType.ANTI_DEBUG,
            SeverityLevel.INFO,
            "Port I/O instruction",
        ),
        # SIDT/SGDT/SLDT - descriptor table access for VM detection
        r"\bSIDT\b|\bSGDT\b|\bSLDT\b": (
            AnomalyType.VM_DETECTION,
            SeverityLevel.WARNING,
            "Descriptor table access (possible VM detection)",
        ),
        # STR - task register access
        r"\bSTR\b": (
            AnomalyType.VM_DETECTION,
            SeverityLevel.WARNING,
            "Task register access (possible VM detection)",
        ),
    }

    # Suspicious instruction sequences
    SUSPICIOUS_SEQUENCES: list[tuple[list[str], SeverityLevel, str]] = [
        # Push/Pop with different values - possible obfuscation
        ([r"PUSH", r"POP"], SeverityLevel.INFO, "Stack manipulation sequence"),
        # Multiple consecutive jumps - obfuscation pattern
        ([r"JMP", r"JMP"], SeverityLevel.WARNING, "Consecutive jumps (possible obfuscation)"),
        # Far jumps - uncommon in normal code
        ([r"JMPF"], SeverityLevel.INFO, "Far jump instruction"),
        # Self-modifying code pattern
        ([r"MOV.*\[.*\].*", r"CALL"], SeverityLevel.WARNING, "Possible self-modifying code pattern"),
    ]

    # Rare opcodes that warrant attention
    RARE_OPCODES: dict[str, tuple[SeverityLevel, str]] = {
        "AAA": (SeverityLevel.INFO, "ASCII adjust after addition (rare)"),
        "AAD": (SeverityLevel.INFO, "ASCII adjust before division (rare)"),
        "AAM": (SeverityLevel.INFO, "ASCII adjust after multiply (rare)"),
        "AAS": (SeverityLevel.INFO, "ASCII adjust after subtraction (rare)"),
        "ARPL": (SeverityLevel.INFO, "Adjust RPL field (rare in user mode)"),
        "BOUND": (SeverityLevel.INFO, "Check array bounds (obsolete)"),
        "DAA": (SeverityLevel.INFO, "Decimal adjust after addition (rare)"),
        "DAS": (SeverityLevel.INFO, "Decimal adjust after subtraction (rare)"),
        "ENTER": (SeverityLevel.INFO, "Create stack frame (uncommon)"),
        "LEAVE": (SeverityLevel.INFO, "Leave stack frame"),
        "SALC": (SeverityLevel.INFO, "Set AL from carry (undocumented)"),
    }

    def __init__(self, entropy_threshold: float = 7.2, min_region_size: int = 256):
        """Initialize the anomaly detector.

        Args:
            entropy_threshold: Threshold for high entropy detection (0-8).
            min_region_size: Minimum size for entropy region reporting.
        """
        self.entropy_threshold = entropy_threshold
        self.min_region_size = min_region_size

    def detect_anomalies(
        self,
        store: ReverseEngineeringStore,
        address_space: str,
        min_severity: SeverityLevel = SeverityLevel.INFO,
    ) -> AnomalyResult:
        """Detect anomalies in an address space.

        Args:
            store: The reverse engineering store to analyze.
            address_space: The address space to analyze.
            min_severity: Minimum severity level to report.

        Returns:
            AnomalyResult containing all detected anomalies.
        """
        result = AnomalyResult(address_space=address_space)

        # Get all entities in the address space
        entities = store.list_entities(address_space=address_space, limit=10000)

        for entity in entities:
            if entity.location is None:
                continue

            # Get evidence/disassembly for this entity
            evidence_list = store.get_evidence_for_entity(entity.entity_id, limit=100)

            for evidence in evidence_list:
                if not evidence.excerpt:
                    continue

                excerpt = evidence.excerpt.upper()
                address = evidence.location.start if evidence.location else 0

                # Check for anti-debug patterns
                for pattern, (anomaly_type, severity, description) in self.ANTI_DEBUG_PATTERNS.items():
                    if severity.value < min_severity.value:
                        continue
                    if re.search(pattern, excerpt, re.IGNORECASE):
                        result.add(
                            AnomalyReport(
                                anomaly_type=anomaly_type,
                                severity=severity,
                                address=address,
                                address_space=address_space,
                                description=description,
                                confidence=0.8,
                                details={
                                    "entity_id": entity.entity_id,
                                    "entity_name": entity.name,
                                    "pattern_matched": pattern,
                                    "excerpt": excerpt[:100],
                                },
                            )
                        )

                # Check for rare opcodes
                for opcode, (severity, description) in self.RARE_OPCODES.items():
                    if severity.value < min_severity.value:
                        continue
                    if re.search(rf"\b{opcode}\b", excerpt):
                        result.add(
                            AnomalyReport(
                                anomaly_type=AnomalyType.RARE_OPCODE,
                                severity=severity,
                                address=address,
                                address_space=address_space,
                                description=description,
                                confidence=0.7,
                                details={
                                    "entity_id": entity.entity_id,
                                    "opcode": opcode,
                                    "excerpt": excerpt[:100],
                                },
                            )
                        )

                # Check for potential bugs
                self._detect_bug_patterns(
                    excerpt, address, address_space, entity, min_severity, result
                )

        # Detect high entropy regions
        self._detect_entropy_anomalies(store, address_space, min_severity, result)

        # Detect unreachable code
        self._detect_unreachable_code(store, address_space, min_severity, result)

        return result

    def _detect_bug_patterns(
        self,
        excerpt: str,
        address: int,
        address_space: str,
        entity: Any,
        min_severity: SeverityLevel,
        result: AnomalyResult,
    ) -> None:
        """Detect potential bug patterns in disassembly."""
        upper_excerpt = excerpt.upper()

        # Null pointer dereference patterns
        null_patterns = [
            (r"MOV\s+\[0+\],", SeverityLevel.CRITICAL, "Write to null address"),
            (r"MOV\s+.*,\s*\[0+\]", SeverityLevel.WARNING, "Read from null address"),
            (r"CALL\s+0+", SeverityLevel.WARNING, "Call to null address"),
            (r"JMP\s+0+", SeverityLevel.WARNING, "Jump to null address"),
        ]

        for pattern, severity, description in null_patterns:
            if severity.value < min_severity.value:
                continue
            if re.search(pattern, upper_excerpt):
                result.add(
                    AnomalyReport(
                        anomaly_type=AnomalyType.NULL_POINTER_DEREF,
                        severity=severity,
                        address=address,
                        address_space=address_space,
                        description=description,
                        confidence=0.75,
                        details={
                            "entity_id": entity.entity_id,
                            "entity_name": entity.name,
                            "pattern": pattern,
                        },
                    )
                )

        # Unchecked return value patterns
        if SeverityLevel.WARNING.value >= min_severity.value:
            unchecked_patterns = [
                r"CALL\s+.*malloc",
                r"CALL\s+.*alloc",
                r"CALL\s+.*fopen",
                r"CALL\s+.*socket",
            ]
            for pattern in unchecked_patterns:
                if re.search(pattern, excerpt, re.IGNORECASE):
                    # Check if followed by null check
                    if not re.search(r"TEST\s+|CMP\s+.*,\s*0|OR\s+.*,\s*.*", upper_excerpt):
                        result.add(
                            AnomalyReport(
                                anomaly_type=AnomalyType.UNCHECKED_RETURN,
                                severity=SeverityLevel.WARNING,
                                address=address,
                                address_space=address_space,
                                description="Possible unchecked return value",
                                confidence=0.6,
                                details={
                                    "entity_id": entity.entity_id,
                                    "call_pattern": pattern,
                                },
                            )
                        )
                        break

        # Suspicious loop patterns (potential buffer overflow)
        if SeverityLevel.WARNING.value >= min_severity.value:
            loop_patterns = [
                (r"LOOP\s+", "LOOP instruction without bounds check"),
                (r"REP\s+MOVSB", "REP MOVSB without length validation"),
                (r"REP\s+MOVSW", "REP MOVSW without length validation"),
                (r"REP\s+STOSB", "REP STOSB without length validation"),
            ]
            for pattern, description in loop_patterns:
                if re.search(pattern, upper_excerpt):
                    result.add(
                        AnomalyReport(
                            anomaly_type=AnomalyType.SUSPICIOUS_LOOP,
                            severity=SeverityLevel.WARNING,
                            address=address,
                            address_space=address_space,
                            description=description,
                            confidence=0.65,
                            details={
                                "entity_id": entity.entity_id,
                                "entity_name": entity.name,
                            },
                        )
                    )

    def _detect_entropy_anomalies(
        self,
        store: ReverseEngineeringStore,
        address_space: str,
        min_severity: SeverityLevel,
        result: AnomalyResult,
    ) -> None:
        """Detect high entropy regions indicating packed/encrypted data."""
        if SeverityLevel.INFO.value < min_severity.value:
            return

        from codemunch_pro.rex.entropy import EntropyAnalyzer

        # Try to reconstruct binary data from evidence
        entities = store.list_entities(address_space=address_space, limit=1000)

        for entity in entities:
            if entity.location is None:
                continue

            # Get evidence for this entity
            evidence_list = store.get_evidence_for_entity(entity.entity_id, limit=50)

            # Collect bytes from evidence
            data_chunks: list[tuple[int, bytes]] = []
            for ev in evidence_list:
                if ev.excerpt and ev.location:
                    # Try to extract hex bytes from disassembly
                    hex_matches = re.findall(r"[0-9A-Fa-f]{2}", ev.excerpt)
                    if len(hex_matches) >= 4:
                        try:
                            data = bytes(int(h, 16) for h in hex_matches[:64])
                            offset = ev.location.start
                            data_chunks.append((offset, data))
                        except ValueError:
                            continue

            if len(data_chunks) >= 3:  # Need multiple chunks for meaningful analysis
                # Analyze entropy
                all_bytes = b"".join(chunk for _, chunk in sorted(data_chunks))
                if len(all_bytes) >= self.min_region_size:
                    analyzer = EntropyAnalyzer(window_size=256)
                    packed_regions = analyzer.detect_packed_regions(
                        all_bytes,
                        threshold=self.entropy_threshold,
                        min_region_size=self.min_region_size,
                    )

                    for region in packed_regions:
                        result.add(
                            AnomalyReport(
                                anomaly_type=AnomalyType.HIGH_ENTROPY,
                                severity=SeverityLevel.INFO,
                                address=entity.location.start + region.start,
                                address_space=address_space,
                                description=f"High entropy region detected (avg: {region.avg_entropy:.2f})",
                                confidence=region.confidence,
                                details={
                                    "entity_id": entity.entity_id,
                                    "region_start": region.start,
                                    "region_end": region.end,
                                    "region_size": region.size,
                                    "avg_entropy": round(region.avg_entropy, 3),
                                    "max_entropy": round(region.max_entropy, 3),
                                },
                            )
                        )

    def _detect_unreachable_code(
        self,
        store: ReverseEngineeringStore,
        address_space: str,
        min_severity: SeverityLevel,
        result: AnomalyResult,
    ) -> None:
        """Detect potentially unreachable code (dead code)."""
        if SeverityLevel.INFO.value < min_severity.value:
            return

        # Get all function entities
        functions = store.list_entities(
            kind="function", address_space=address_space, limit=1000
        )

        for func in functions:
            if func.location is None:
                continue

            # Get evidence/disassembly for this function
            evidence_list = store.get_evidence_for_entity(func.entity_id, limit=100)

            if len(evidence_list) < 2:
                continue

            # Sort by address
            sorted_evidence = sorted(
                evidence_list,
                key=lambda e: e.location.start if e.location else 0,
            )

            # Check for unreachable code patterns
            prev_end = None
            for ev in sorted_evidence:
                if ev.location is None or not ev.excerpt:
                    continue

                current_start = ev.location.start

                if prev_end is not None:
                    gap = current_start - prev_end
                    if gap > 0 and gap <= 16:  # Small gap might be padding
                        # Check if previous instruction was unconditional jump/ret
                        prev_excerpt = sorted_evidence[
                            sorted_evidence.index(ev) - 1
                        ].excerpt.upper()

                        if re.search(r"\b(JMP|RET|RETF|IRET|HLT)\b", prev_excerpt):
                            # Code after unconditional transfer might be unreachable
                            result.add(
                                AnomalyReport(
                                    anomaly_type=AnomalyType.UNREACHABLE_CODE,
                                    severity=SeverityLevel.INFO,
                                    address=current_start,
                                    address_space=address_space,
                                    description=f"Possible unreachable code after unconditional transfer (gap: {gap} bytes)",
                                    confidence=0.5,
                                    details={
                                        "entity_id": func.entity_id,
                                        "function_name": func.name,
                                        "gap_size": gap,
                                        "prev_instruction": prev_excerpt[:50],
                                    },
                                )
                            )

                prev_end = ev.location.end if ev.location else current_start

    def analyze_function_complexity(
        self,
        store: ReverseEngineeringStore,
        function_address: int,
        address_space: str = "",
    ) -> dict[str, Any]:
        """Analyze function for complexity metrics that may indicate obfuscation.

        Args:
            store: The reverse engineering store.
            function_address: Address of the function to analyze.
            address_space: Optional address space filter.

        Returns:
            Dictionary with complexity metrics.
        """
        # Find the function entity
        functions = store.list_entities(
            kind="function", address_space=address_space, limit=10000
        )

        target_func = None
        for func in functions:
            if func.location and func.location.start == function_address:
                target_func = func
                break

        if target_func is None:
            return {
                "error": f"Function not found at address 0x{function_address:08X}",
            }

        # Get evidence for this function
        evidence_list = store.get_evidence_for_entity(target_func.entity_id, limit=200)

        if not evidence_list:
            return {
                "function_address": f"0x{function_address:08X}",
                "function_name": target_func.name,
                "error": "No disassembly evidence found",
            }

        # Calculate metrics
        instruction_count = len(evidence_list)
        unique_mnemonics: set[str] = set()
        jump_count = 0
        call_count = 0

        for ev in evidence_list:
            if not ev.excerpt:
                continue

            excerpt = ev.excerpt.upper()

            # Extract mnemonic
            match = re.match(r"[^:]*:\s*(\w+)", excerpt)
            if match:
                mnemonic = match.group(1)
                unique_mnemonics.add(mnemonic)

            # Count control flow
            if re.search(r"\bJ(MP|NZ|Z|E|NE|A|B|G|L|AE|BE|GE|LE)", excerpt):
                jump_count += 1
            if re.search(r"\bCALL\b", excerpt):
                call_count += 1

        # Calculate cyclomatic complexity approximation
        cyclomatic = 1 + jump_count

        # Detect possible obfuscation
        obfuscation_indicators: list[str] = []
        if jump_count / max(instruction_count, 1) > 0.3:
            obfuscation_indicators.append("High jump density (possible control flow obfuscation)")
        if len(unique_mnemonics) / max(instruction_count, 1) < 0.1:
            obfuscation_indicators.append("Low instruction diversity (possible pattern-based obfuscation)")

        return {
            "function_address": f"0x{function_address:08X}",
            "function_name": target_func.name,
            "instruction_count": instruction_count,
            "unique_mnemonics": len(unique_mnemonics),
            "jump_count": jump_count,
            "call_count": call_count,
            "cyclomatic_complexity": cyclomatic,
            "jump_density": round(jump_count / max(instruction_count, 1), 3),
            "obfuscation_indicators": obfuscation_indicators,
            "possible_obfuscation": len(obfuscation_indicators) > 0,
        }
