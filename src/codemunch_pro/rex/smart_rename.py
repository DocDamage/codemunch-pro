"""Smart rename suggestions for functions and data using heuristics."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from codemunch_pro.rex.storage import ReverseEngineeringStore


@dataclass
class RenameSuggestion:
    """A single rename suggestion with confidence and reasoning."""

    suggested_name: str
    confidence: float  # 0.0 to 1.0
    heuristic: str  # Which heuristic generated this
    reasoning: str  # Human-readable explanation
    platform: str = "generic"  # Platform convention (windows, linux, macos, generic)

    def __post_init__(self):
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")


@dataclass
class RenameResult:
    """Result of a rename suggestion query."""

    entity_id: str
    current_name: str
    suggestions: list[RenameSuggestion] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def best_suggestion(self) -> RenameSuggestion | None:
        """Get the highest confidence suggestion."""
        if not self.suggestions:
            return None
        return max(self.suggestions, key=lambda s: s.confidence)


class RenameSuggester:
    """Generate smart rename suggestions using multiple heuristics."""

    # Known library function signatures and their descriptive names
    LIBRARY_SIGNATURES: dict[str, dict[str, str]] = {
        "memcmp": {"name": "CompareMemory", "platform": "generic"},
        "memset": {"name": "InitializeMemory", "platform": "generic"},
        "memcpy": {"name": "CopyMemory", "platform": "generic"},
        "memmove": {"name": "MoveMemory", "platform": "generic"},
        "strlen": {"name": "GetStringLength", "platform": "generic"},
        "strcpy": {"name": "CopyString", "platform": "generic"},
        "strncpy": {"name": "CopyStringN", "platform": "generic"},
        "strcat": {"name": "ConcatenateString", "platform": "generic"},
        "strncat": {"name": "ConcatenateStringN", "platform": "generic"},
        "strcmp": {"name": "CompareString", "platform": "generic"},
        "strncmp": {"name": "CompareStringN", "platform": "generic"},
        "strchr": {"name": "FindCharInString", "platform": "generic"},
        "strstr": {"name": "FindStringInString", "platform": "generic"},
        "malloc": {"name": "AllocateMemory", "platform": "generic"},
        "calloc": {"name": "AllocateZeroedMemory", "platform": "generic"},
        "realloc": {"name": "ReallocateMemory", "platform": "generic"},
        "free": {"name": "ReleaseMemory", "platform": "generic"},
        "sprintf": {"name": "FormatString", "platform": "generic"},
        "snprintf": {"name": "FormatStringN", "platform": "generic"},
        "sscanf": {"name": "ScanString", "platform": "generic"},
        "atoi": {"name": "StringToInt", "platform": "generic"},
        "atol": {"name": "StringToLong", "platform": "generic"},
        "atof": {"name": "StringToFloat", "platform": "generic"},
        "fopen": {"name": "OpenFile", "platform": "generic"},
        "fclose": {"name": "CloseFile", "platform": "generic"},
        "fread": {"name": "ReadFile", "platform": "generic"},
        "fwrite": {"name": "WriteFile", "platform": "generic"},
        "fseek": {"name": "SeekFile", "platform": "generic"},
        "ftell": {"name": "GetFilePosition", "platform": "generic"},
        "fprintf": {"name": "FormatFileOutput", "platform": "generic"},
        "printf": {"name": "PrintFormatted", "platform": "generic"},
        "puts": {"name": "PrintString", "platform": "generic"},
        "putchar": {"name": "PrintCharacter", "platform": "generic"},
        "getc": {"name": "ReadCharacter", "platform": "generic"},
        "gets": {"name": "ReadString", "platform": "generic"},
        "rand": {"name": "GenerateRandom", "platform": "generic"},
        "srand": {"name": "SeedRandom", "platform": "generic"},
        "time": {"name": "GetCurrentTime", "platform": "generic"},
        "clock": {"name": "GetProcessorTime", "platform": "generic"},
        "exit": {"name": "TerminateProgram", "platform": "generic"},
        "abort": {"name": "AbortProgram", "platform": "generic"},
        "assert": {"name": "AssertCondition", "platform": "generic"},
        "qsort": {"name": "QuickSort", "platform": "generic"},
        "bsearch": {"name": "BinarySearch", "platform": "generic"},
    }

    # Windows-specific naming conventions
    WINDOWS_SIGNATURES: dict[str, dict[str, str]] = {
        "CreateFileA": {"name": "CreateFile", "platform": "windows"},
        "CreateFileW": {"name": "CreateFileWide", "platform": "windows"},
        "ReadFile": {"name": "ReadFile", "platform": "windows"},
        "WriteFile": {"name": "WriteFile", "platform": "windows"},
        "CloseHandle": {"name": "CloseHandle", "platform": "windows"},
        "GetLastError": {"name": "GetLastError", "platform": "windows"},
        "SetLastError": {"name": "SetLastError", "platform": "windows"},
        "LocalAlloc": {"name": "AllocateLocalMemory", "platform": "windows"},
        "LocalFree": {"name": "FreeLocalMemory", "platform": "windows"},
        "GlobalAlloc": {"name": "AllocateGlobalMemory", "platform": "windows"},
        "GlobalFree": {"name": "FreeGlobalMemory", "platform": "windows"},
        "HeapAlloc": {"name": "AllocateHeapMemory", "platform": "windows"},
        "HeapFree": {"name": "FreeHeapMemory", "platform": "windows"},
        "VirtualAlloc": {"name": "AllocateVirtualMemory", "platform": "windows"},
        "VirtualFree": {"name": "FreeVirtualMemory", "platform": "windows"},
        "LoadLibraryA": {"name": "LoadLibrary", "platform": "windows"},
        "LoadLibraryW": {"name": "LoadLibraryWide", "platform": "windows"},
        "GetProcAddress": {"name": "GetProcedureAddress", "platform": "windows"},
        "GetModuleHandleA": {"name": "GetModuleHandle", "platform": "windows"},
        "GetModuleHandleW": {"name": "GetModuleHandleWide", "platform": "windows"},
        "RegOpenKeyExA": {"name": "OpenRegistryKey", "platform": "windows"},
        "RegQueryValueExA": {"name": "QueryRegistryValue", "platform": "windows"},
        "RegCloseKey": {"name": "CloseRegistryKey", "platform": "windows"},
    }

    # Pattern-based heuristics
    GETTER_PATTERNS = [
        (r"^[gs]et[_-]?([a-zA-Z0-9_]+)$", "Get{0}"),
        (r"^is[_-]?([a-zA-Z0-9_]+)$", "Is{0}"),
        (r"^has[_-]?([a-zA-Z0-9_]+)$", "Has{0}"),
        (r"^can[_-]?([a-zA-Z0-9_]+)$", "Can{0}"),
        (r"^should[_-]?([a-zA-Z0-9_]+)$", "Should{0}"),
    ]

    SETTER_PATTERNS = [
        (r"^set[_-]?([a-zA-Z0-9_]+)$", "Set{0}"),
    ]

    INIT_PATTERNS = [
        (r"^init[_-]?([a-zA-Z0-9_]+)$", "Initialize{0}"),
        (r"^init$", "Initialize"),
        (r"^init_([a-zA-Z0-9_]+)$", "Initialize{0}"),
    ]

    CLEANUP_PATTERNS = [
        (r"^cleanup[_-]?([a-zA-Z0-9_]+)$", "Cleanup{0}"),
        (r"^cleanup$", "Cleanup"),
        (r"^deinit[_-]?([a-zA-Z0-9_]+)$", "Deinitialize{0}"),
        (r"^deinit$", "Deinitialize"),
        (r"^fini[_-]?([a-zA-Z0-9_]+)$", "Finalize{0}"),
        (r"^fini$", "Finalize"),
        (r"^destroy[_-]?([a-zA-Z0-9_]+)$", "Destroy{0}"),
        (r"^destroy$", "Destroy"),
        (r"^free_([a-zA-Z0-9_]+)$", "Release{0}"),
    ]

    CREATE_PATTERNS = [
        (r"^create[_-]?([a-zA-Z0-9_]+)$", "Create{0}"),
        (r"^new[_-]?([a-zA-Z0-9_]+)$", "Create{0}"),
        (r"^alloc[_-]?([a-zA-Z0-9_]+)$", "Allocate{0}"),
    ]

    # Common function call patterns that suggest behavior
    CALL_PATTERNS: dict[frozenset[str], tuple[str, str, float]] = {
        # Memory allocation patterns
        frozenset({"malloc", "strcpy"}): ("DuplicateString", "strdup", 0.85),
        frozenset({"calloc", "strcpy"}): ("DuplicateStringSafe", "strdup_safe", 0.80),
        frozenset({"malloc", "memcpy"}): ("DuplicateMemory", "memdup", 0.80),
        frozenset({"malloc", "memset"}): ("AllocateZeroedMemory", "zalloc", 0.75),
        # File operations
        frozenset({"fopen", "fread", "fclose"}): ("ReadFileContents", "read_file", 0.80),
        frozenset({"fopen", "fwrite", "fclose"}): ("WriteFileContents", "write_file", 0.80),
        # String building
        frozenset({"malloc", "strcat", "strcpy"}): ("ConcatenateStrings", "strconcat", 0.75),
        frozenset({"sprintf", "malloc"}): ("FormatAndAllocate", "format_alloc", 0.70),
        # Error handling
        frozenset({"GetLastError", "FormatMessage"}): ("GetErrorMessage", "get_error_msg", 0.85),
        frozenset({"errno", "strerror"}): ("GetErrorString", "get_error_str", 0.85),
        # Resource management
        frozenset({"CreateFile", "CloseHandle"}): ("OpenAndCloseFile", "file_operation", 0.70),
        frozenset({"RegOpenKeyEx", "RegCloseKey"}): ("RegistryOperation", "reg_operation", 0.70),
    }

    # String reference patterns that suggest function purpose
    STRING_PATTERNS: list[tuple[re.Pattern, str, float]] = [
        # Error messages
        (re.compile(r"error|failed|fail|invalid|cannot|can't", re.I), "ErrorHandler", 0.70),
        (re.compile(r"warning|warn", re.I), "WarningHandler", 0.70),
        (re.compile(r"debug|trace|log", re.I), "DebugLogger", 0.65),
        # Resource operations
        (re.compile(r"loading|load.*file|open.*file", re.I), "LoadResource", 0.75),
        (re.compile(r"saving|save.*file|write.*file", re.I), "SaveResource", 0.75),
        (re.compile(r"initializ|setup|prepare", re.I), "Initialize", 0.70),
        (re.compile(r"clean.*up|shutdown|release|free.*memory", re.I), "Cleanup", 0.70),
        # Data operations
        (re.compile(r"parse|decode|deserialize", re.I), "ParseData", 0.75),
        (re.compile(r"serialize|encode", re.I), "SerializeData", 0.75),
        (re.compile(r"validate|verify|check", re.I), "Validate", 0.70),
        (re.compile(r"convert|transform", re.I), "ConvertData", 0.70),
        # UI/Interaction
        (re.compile(r"user.*input|prompt|dialog", re.I), "GetUserInput", 0.65),
        (re.compile(r"display|show.*window|render", re.I), "DisplayOutput", 0.65),
        # Network
        (re.compile(r"connect.*server|network|socket", re.I), "NetworkConnect", 0.70),
        (re.compile(r"send.*data|transmit", re.I), "SendData", 0.70),
        (re.compile(r"receive.*data|recv", re.I), "ReceiveData", 0.70),
    ]

    def __init__(self, platform: str = "generic"):
        """Initialize the suggester with platform preferences.

        Args:
            platform: Target platform naming convention (windows, linux, macos, generic)
        """
        self.platform = platform.lower()
        self._library_sigs = {**self.LIBRARY_SIGNATURES}
        if self.platform == "windows":
            self._library_sigs.update(self.WINDOWS_SIGNATURES)

    def suggest_function_name(self, entity_id: str, store: ReverseEngineeringStore) -> RenameResult:
        """Suggest new names for a function entity.

        Args:
            entity_id: The entity ID to analyze
            store: The reverse engineering store

        Returns:
            RenameResult with suggestions sorted by confidence
        """
        entity = store.get_entity(entity_id)
        if entity is None:
            return RenameResult(
                entity_id=entity_id,
                current_name="",
                suggestions=[],
                metadata={"error": "Entity not found"},
            )

        if entity.kind != "function":
            return RenameResult(
                entity_id=entity_id,
                current_name=entity.name,
                suggestions=[],
                metadata={"error": "Entity is not a function"},
            )

        suggestions: list[RenameSuggestion] = []
        current_name = entity.name

        # Get related evidence and edges for analysis
        evidence = store.get_evidence_for_entity(entity_id)
        edges = store.get_neighbors(entity_id)

        # 1. Check for string references in evidence
        string_suggestions = self._analyze_string_references(evidence)
        suggestions.extend(string_suggestions)

        # 2. Analyze called functions
        call_suggestions = self._analyze_call_patterns(edges, store)
        suggestions.extend(call_suggestions)

        # 3. Check for library signature matches
        sig_suggestions = self._analyze_library_signatures(current_name, edges)
        suggestions.extend(sig_suggestions)

        # 4. Apply pattern recognition
        pattern_suggestions = self._analyze_naming_patterns(current_name)
        suggestions.extend(pattern_suggestions)

        # Sort by confidence descending
        suggestions.sort(key=lambda s: s.confidence, reverse=True)

        return RenameResult(
            entity_id=entity_id,
            current_name=current_name,
            suggestions=suggestions,
            metadata={
                "evidence_count": len(evidence),
                "edge_count": len(edges),
                "platform": self.platform,
            },
        )

    def suggest_data_label(self, entity_id: str, store: ReverseEngineeringStore) -> RenameResult:
        """Suggest new names for a data entity (variable, buffer, etc.).

        Args:
            entity_id: The entity ID to analyze
            store: The reverse engineering store

        Returns:
            RenameResult with suggestions sorted by confidence
        """
        entity = store.get_entity(entity_id)
        if entity is None:
            return RenameResult(
                entity_id=entity_id,
                current_name="",
                suggestions=[],
                metadata={"error": "Entity not found"},
            )

        suggestions: list[RenameSuggestion] = []
        current_name = entity.name

        # Get related evidence
        evidence = store.get_evidence_for_entity(entity_id)

        # Analyze attributes for size/type hints
        attrs = entity.attributes
        size = attrs.get("size", 0)
        data_type = attrs.get("type", "unknown")

        # Suggest based on type and usage
        if data_type == "string":
            suggestions.append(RenameSuggestion(
                suggested_name=f"g_{self._to_camel_case(current_name)}String",
                confidence=0.70,
                heuristic="type_inference",
                reasoning="Entity is used as a string constant",
                platform=self.platform,
            ))
        elif data_type == "buffer" and size > 0:
            size_hint = f"{size}Byte" if size < 1024 else f"{size // 1024}K"
            suggestions.append(RenameSuggestion(
                suggested_name=f"g_{self._to_camel_case(current_name)}Buffer",
                confidence=0.65,
                heuristic="type_inference",
                reasoning=f"Entity is a {size} byte buffer",
                platform=self.platform,
            ))

        # Check string references for semantic hints
        for ev in evidence:
            excerpt = ev.excerpt
            # Look for usage patterns
            if "counter" in excerpt.lower() or "count" in excerpt.lower():
                suggestions.append(RenameSuggestion(
                    suggested_name=f"g_{self._to_camel_case(current_name)}Counter",
                    confidence=0.60,
                    heuristic="usage_pattern",
                    reasoning="Evidence suggests counter usage",
                    platform=self.platform,
                ))
            elif "flag" in excerpt.lower() or "enabled" in excerpt.lower():
                suggestions.append(RenameSuggestion(
                    suggested_name=f"g_b{self._to_camel_case(current_name)}",
                    confidence=0.60,
                    heuristic="usage_pattern",
                    reasoning="Evidence suggests boolean flag usage",
                    platform=self.platform,
                ))

        # Sort by confidence
        suggestions.sort(key=lambda s: s.confidence, reverse=True)

        return RenameResult(
            entity_id=entity_id,
            current_name=current_name,
            suggestions=suggestions,
            metadata={
                "data_type": data_type,
                "size": size,
                "evidence_count": len(evidence),
            },
        )

    def batch_suggest_names(
        self, entity_ids: list[str], store: ReverseEngineeringStore
    ) -> list[RenameResult]:
        """Suggest names for multiple entities.

        Args:
            entity_ids: List of entity IDs to analyze
            store: The reverse engineering store

        Returns:
            List of RenameResult objects
        """
        results = []
        for entity_id in entity_ids:
            entity = store.get_entity(entity_id)
            if entity is None:
                results.append(RenameResult(
                    entity_id=entity_id,
                    current_name="",
                    suggestions=[],
                    metadata={"error": "Entity not found"},
                ))
                continue

            if entity.kind == "function":
                results.append(self.suggest_function_name(entity_id, store))
            else:
                results.append(self.suggest_data_label(entity_id, store))

        return results

    def _analyze_string_references(self, evidence: list) -> list[RenameSuggestion]:
        """Analyze string references in evidence for naming hints."""
        suggestions = []
        seen_patterns: set[str] = set()

        for ev in evidence:
            excerpt = ev.excerpt
            if not excerpt:
                continue

            for pattern, suggested_name, confidence in self.STRING_PATTERNS:
                if pattern.search(excerpt) and suggested_name not in seen_patterns:
                    seen_patterns.add(suggested_name)
                    suggestions.append(RenameSuggestion(
                        suggested_name=suggested_name,
                        confidence=confidence,
                        heuristic="string_reference",
                        reasoning=f"String reference matches pattern: {pattern.pattern[:30]}...",
                        platform=self.platform,
                    ))
                    break  # Only add the first matching pattern per evidence

        return suggestions

    def _analyze_call_patterns(self, edges: list, store: ReverseEngineeringStore) -> list[RenameSuggestion]:
        """Analyze function call patterns for behavior hints."""
        suggestions = []

        # Collect called function names from outgoing edges
        called_functions: set[str] = set()
        for edge in edges:
            if edge.kind in ("calls", "calls_function"):
                target_entity = store.get_entity(edge.target_entity_id)
                if target_entity:
                    called_functions.add(target_entity.name)

        # Check for known patterns
        for pattern_calls, (suggested_name, _, confidence) in self.CALL_PATTERNS.items():
            if pattern_calls.issubset(called_functions):
                suggestions.append(RenameSuggestion(
                    suggested_name=suggested_name,
                    confidence=confidence,
                    heuristic="call_pattern",
                    reasoning=f"Function calls suggest {suggested_name} behavior: {', '.join(pattern_calls)}",
                    platform=self.platform,
                ))

        # Check for library wrapper patterns
        libc_calls = called_functions & set(self.LIBRARY_SIGNATURES.keys())
        if libc_calls and len(called_functions) <= 3:
            # Likely a thin wrapper around libc functions
            for call in libc_calls:
                sig = self.LIBRARY_SIGNATURES[call]
                suggestions.append(RenameSuggestion(
                    suggested_name=f"Wrapper_{sig['name']}",
                    confidence=0.60,
                    heuristic="library_wrapper",
                    reasoning=f"Function appears to wrap {call}",
                    platform=sig["platform"],
                ))

        return suggestions

    def _analyze_library_signatures(self, current_name: str, edges: list) -> list[RenameSuggestion]:
        """Check if current name matches known library signatures."""
        suggestions = []

        # Check for exact or partial matches
        for lib_name, info in self._library_sigs.items():
            if lib_name.lower() in current_name.lower():
                suggestions.append(RenameSuggestion(
                    suggested_name=info["name"],
                    confidence=0.75 if current_name.lower() == lib_name.lower() else 0.55,
                    heuristic="library_signature",
                    reasoning=f"Name matches {lib_name} signature",
                    platform=info["platform"],
                ))

        return suggestions

    def _analyze_naming_patterns(self, name: str) -> list[RenameSuggestion]:
        """Apply pattern recognition heuristics to suggest better names."""
        suggestions = []
        name_lower = name.lower()

        # Check getter patterns
        for pattern, template in self.GETTER_PATTERNS:
            match = re.match(pattern, name_lower)
            if match:
                property_name = self._to_pascal_case(match.group(1))
                suggested = template.format(property_name)
                suggestions.append(RenameSuggestion(
                    suggested_name=suggested,
                    confidence=0.80,
                    heuristic="getter_pattern",
                    reasoning=f"Function follows getter pattern for {property_name}",
                    platform=self.platform,
                ))

        # Check setter patterns
        for pattern, template in self.SETTER_PATTERNS:
            match = re.match(pattern, name_lower)
            if match:
                property_name = self._to_pascal_case(match.group(1))
                suggested = template.format(property_name)
                suggestions.append(RenameSuggestion(
                    suggested_name=suggested,
                    confidence=0.80,
                    heuristic="setter_pattern",
                    reasoning=f"Function follows setter pattern for {property_name}",
                    platform=self.platform,
                ))

        # Check init patterns
        for pattern, template in self.INIT_PATTERNS:
            match = re.match(pattern, name_lower)
            if match:
                if "{0}" in template:
                    component = self._to_pascal_case(match.group(1) if match.lastindex else "")
                    suggested = template.format(component)
                else:
                    suggested = template
                suggestions.append(RenameSuggestion(
                    suggested_name=suggested,
                    confidence=0.75,
                    heuristic="init_pattern",
                    reasoning="Function follows initialization pattern",
                    platform=self.platform,
                ))

        # Check cleanup patterns
        for pattern, template in self.CLEANUP_PATTERNS:
            match = re.match(pattern, name_lower)
            if match:
                if "{0}" in template:
                    component = self._to_pascal_case(match.group(1) if match.lastindex else "")
                    suggested = template.format(component)
                else:
                    suggested = template
                suggestions.append(RenameSuggestion(
                    suggested_name=suggested,
                    confidence=0.75,
                    heuristic="cleanup_pattern",
                    reasoning="Function follows cleanup/finalization pattern",
                    platform=self.platform,
                ))

        # Check create patterns
        for pattern, template in self.CREATE_PATTERNS:
            match = re.match(pattern, name_lower)
            if match:
                object_name = self._to_pascal_case(match.group(1))
                suggested = template.format(object_name)
                suggestions.append(RenameSuggestion(
                    suggested_name=suggested,
                    confidence=0.75,
                    heuristic="factory_pattern",
                    reasoning=f"Function follows factory/creation pattern for {object_name}",
                    platform=self.platform,
                ))

        return suggestions

    def _to_pascal_case(self, s: str) -> str:
        """Convert string to PascalCase."""
        if not s:
            return s
        # Split on common separators
        parts = re.split(r'[_\-\s]+', s)
        return ''.join(part.capitalize() for part in parts if part)

    def _to_camel_case(self, s: str) -> str:
        """Convert string to camelCase."""
        if not s:
            return s
        # If already starts with lowercase, assume it's already camelCase
        if s[0].islower() and s != s.lower():
            return s
        # If already PascalCase, just lowercase first char
        if s[0].isupper():
            return s[0].lower() + s[1:]
        # Otherwise convert to PascalCase first
        pascal = self._to_pascal_case(s)
        if not pascal:
            return s
        return pascal[0].lower() + pascal[1:]

    def _to_snake_case(self, s: str) -> str:
        """Convert string to snake_case."""
        # Insert underscore before capitals
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', s)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
