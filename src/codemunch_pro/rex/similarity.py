"""Function similarity and clone detection using fuzzy hashing.

This module provides tools for detecting similar functions and code clones
using multiple algorithms including fuzzy hashing, n-gram comparison,
and CFG-based similarity.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:

    from codemunch_pro.rex.model import EntityRecord


class SimilarityAlgorithm(Enum):
    """Supported similarity algorithms."""

    FUZZY_HASH = "fuzzy_hash"  # ssdeep-like rolling hash
    NGRAM = "ngram"  # n-gram based similarity
    CFG = "cfg"  # Control flow graph based


@dataclass(frozen=True, slots=True)
class FunctionFingerprint:
    """Fingerprint of a function for similarity comparison.

    Attributes:
        entity_id: The entity ID of the function
        canonical_ref: The canonical reference address
        name: Function name
        fuzzy_hash: Fuzzy hash of the function's instruction sequence
        ngram_hashes: Set of n-gram hashes for partial matching
        cfg_hash: Hash of the control flow graph structure
        instruction_count: Number of instructions in the function
        block_count: Number of basic blocks
        feature_vector: Extracted features for comparison
    """

    entity_id: str
    canonical_ref: str
    name: str
    fuzzy_hash: str = ""
    ngram_hashes: frozenset[str] = field(default_factory=frozenset)
    cfg_hash: str = ""
    instruction_count: int = 0
    block_count: int = 0
    feature_vector: tuple[float, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the fingerprint to a dictionary."""
        return {
            "entity_id": self.entity_id,
            "canonical_ref": self.canonical_ref,
            "name": self.name,
            "fuzzy_hash": self.fuzzy_hash,
            "ngram_hashes": list(self.ngram_hashes),
            "cfg_hash": self.cfg_hash,
            "instruction_count": self.instruction_count,
            "block_count": self.block_count,
            "feature_vector": list(self.feature_vector),
        }


@dataclass(frozen=True, slots=True)
class SimilarityResult:
    """Result of a similarity comparison.

    Attributes:
        source_entity_id: The entity ID of the source function
        target_entity_id: The entity ID of the similar function
        source_name: Name of the source function
        target_name: Name of the similar function
        target_canonical_ref: Canonical reference of the similar function
        similarity_score: Similarity score between 0.0 and 1.0
        algorithm: Algorithm used for comparison
        details: Additional comparison details
    """

    source_entity_id: str
    target_entity_id: str
    source_name: str
    target_name: str
    target_canonical_ref: str
    similarity_score: float
    algorithm: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result to a dictionary."""
        return {
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "source_name": self.source_name,
            "target_name": self.target_name,
            "target_canonical_ref": self.target_canonical_ref,
            "similarity_score": round(self.similarity_score, 4),
            "algorithm": self.algorithm,
            "details": self.details,
        }


class FuzzyHasher:
    """Rolling hash implementation similar to ssdeep.

    Uses a simplified rolling hash algorithm that is resilient to small
    changes like instruction modifications.
    """

    def __init__(self, block_size: int = 3):
        self.block_size = block_size

    def hash(self, data: str | bytes) -> str:
        """Compute a fuzzy hash of the input data.

        Args:
            data: The data to hash (instruction sequence or bytes)

        Returns:
            A fuzzy hash string
        """
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")

        if len(data) < self.block_size:
            return hashlib.md5(data).hexdigest()[:16]

        # Simplified rolling hash using a window
        hashes = []
        window = []
        for i, byte in enumerate(data):
            window.append(byte)
            if len(window) > self.block_size:
                window.pop(0)
            if len(window) == self.block_size:
                # Simple hash of the window
                window_hash = sum((b * (j + 1)) for j, b in enumerate(window)) & 0xFF
                if window_hash % 7 == 0:  # Trigger point
                    chunk = bytes(window)
                    hashes.append(hashlib.md5(chunk).hexdigest()[:4])

        if not hashes:
            # Fallback for small data
            return hashlib.md5(data).hexdigest()[:16]

        return "".join(hashes)

    def compare(self, hash1: str, hash2: str) -> float:
        """Compare two fuzzy hashes and return a similarity score.

        Args:
            hash1: First fuzzy hash
            hash2: Second fuzzy hash

        Returns:
            Similarity score between 0.0 and 1.0
        """
        if not hash1 or not hash2:
            return 0.0
        if hash1 == hash2:
            return 1.0

        # Use edit distance approximation for fuzzy hash comparison
        distance = self._edit_distance(hash1, hash2)
        max_len = max(len(hash1), len(hash2))
        if max_len == 0:
            return 1.0

        return 1.0 - (distance / max_len)

    def _edit_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return self._edit_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost: 0 if same, 1 if different
                cost = 0 if c1 == c2 else 1
                curr_row.append(
                    min(prev_row[j + 1] + 1, curr_row[j] + 1, prev_row[j] + cost)
                )
            prev_row = curr_row

        return prev_row[-1]


class NgramHasher:
    """N-gram based hashing for code similarity."""

    def __init__(self, n: int = 4):
        self.n = n

    def hash(self, instructions: list[str]) -> set[str]:
        """Compute n-gram hashes from a sequence of instructions.

        Args:
            instructions: List of normalized instruction strings

        Returns:
            Set of n-gram hash strings
        """
        if len(instructions) < self.n:
            # Hash individual instructions
            return {hashlib.md5(str(inst).encode()).hexdigest()[:8] for inst in instructions}

        ngrams = set()
        for i in range(len(instructions) - self.n + 1):
            ngram = " ".join(instructions[i : i + self.n])
            hash_val = hashlib.md5(ngram.encode()).hexdigest()[:8]
            ngrams.add(hash_val)

        return ngrams

    def compare(self, ngrams1: frozenset[str], ngrams2: frozenset[str]) -> float:
        """Compare two sets of n-gram hashes using Jaccard similarity.

        Args:
            ngrams1: First set of n-gram hashes
            ngrams2: Second set of n-gram hashes

        Returns:
            Similarity score between 0.0 and 1.0
        """
        if not ngrams1 and not ngrams2:
            return 1.0
        if not ngrams1 or not ngrams2:
            return 0.0

        intersection = len(ngrams1 & ngrams2)
        union = len(ngrams1 | ngrams2)

        return intersection / union if union > 0 else 0.0


class CFGHasher:
    """Control flow graph based similarity."""

    def hash_structure(self, block_count: int, edges: list[tuple[int, int]]) -> str:
        """Create a hash of the CFG structure.

        Args:
            block_count: Number of basic blocks
            edges: List of (source_block, target_block) tuples

        Returns:
            A hash string representing the CFG structure
        """
        edge_str = "|".join(f"{s}->{t}" for s, t in sorted(edges))
        data = f"{block_count}:{edge_str}"
        return hashlib.md5(data.encode()).hexdigest()[:16]

    def compare_structures(
        self,
        blocks1: int,
        edges1: list[tuple[int, int]],
        blocks2: int,
        edges2: list[tuple[int, int]],
    ) -> float:
        """Compare two CFG structures.

        Args:
            blocks1: Number of blocks in first function
            edges1: Edges in first function
            blocks2: Number of blocks in second function
            edges2: Edges in second function

        Returns:
            Similarity score between 0.0 and 1.0
        """
        # Size similarity
        size_sim = min(blocks1, blocks2) / max(blocks1, blocks2) if max(blocks1, blocks2) > 0 else 1.0

        # Edge similarity (Jaccard)
        set1 = set(edges1)
        set2 = set(edges2)
        if set1 or set2:
            edge_sim = len(set1 & set2) / len(set1 | set2)
        else:
            edge_sim = 1.0

        return (size_sim * 0.4) + (edge_sim * 0.6)


class SimilarityStrategy(ABC):
    """Abstract base class for similarity calculation strategies."""

    @abstractmethod
    def calculate(
        self,
        fp1: FunctionFingerprint,
        fp2: FunctionFingerprint,
    ) -> float:
        """Calculate similarity between two fingerprints.

        Returns:
            Similarity score between 0.0 and 1.0
        """
        raise NotImplementedError


class FuzzyHashStrategy(SimilarityStrategy):
    """Similarity based on fuzzy hashing."""

    def __init__(self):
        self.hasher = FuzzyHasher()

    def calculate(self, fp1: FunctionFingerprint, fp2: FunctionFingerprint) -> float:
        return self.hasher.compare(fp1.fuzzy_hash, fp2.fuzzy_hash)


class NgramStrategy(SimilarityStrategy):
    """Similarity based on n-gram comparison."""

    def __init__(self):
        self.hasher = NgramHasher()

    def calculate(self, fp1: FunctionFingerprint, fp2: FunctionFingerprint) -> float:
        return self.hasher.compare(fp1.ngram_hashes, fp2.ngram_hashes)


class CFGStrategy(SimilarityStrategy):
    """Similarity based on control flow graph structure."""

    def __init__(self):
        self.hasher = CFGHasher()

    def calculate(self, fp1: FunctionFingerprint, fp2: FunctionFingerprint) -> float:
        # For CFG comparison, we'd need the actual edge structure
        # Here we use a simplified comparison based on stored hashes
        if fp1.cfg_hash == fp2.cfg_hash:
            return 1.0
        # Size-based approximation
        size_sim = (
            min(fp1.block_count, fp2.block_count) / max(fp1.block_count, fp2.block_count)
            if max(fp1.block_count, fp2.block_count) > 0
            else 1.0
        )
        return size_sim * 0.5  # Reduced weight when only hashes are available


class CombinedStrategy(SimilarityStrategy):
    """Combined similarity using multiple strategies with weighted scoring."""

    def __init__(self, weights: dict[str, float] | None = None):
        self.strategies: dict[str, SimilarityStrategy] = {
            "fuzzy_hash": FuzzyHashStrategy(),
            "ngram": NgramStrategy(),
            "cfg": CFGStrategy(),
        }
        self.weights = weights or {
            "fuzzy_hash": 0.5,
            "ngram": 0.3,
            "cfg": 0.2,
        }

    def calculate(self, fp1: FunctionFingerprint, fp2: FunctionFingerprint) -> float:
        total_score = 0.0
        total_weight = 0.0

        for name, strategy in self.strategies.items():
            weight = self.weights.get(name, 0.0)
            if weight > 0:
                score = strategy.calculate(fp1, fp2)
                total_score += score * weight
                total_weight += weight

        return total_score / total_weight if total_weight > 0 else 0.0


class SimilarityIndex:
    """Index for efficient function similarity search.

    This class maintains an index of function fingerprints and provides
    efficient methods for finding similar functions.
    """

    def __init__(
        self,
        algorithm: SimilarityAlgorithm = SimilarityAlgorithm.FUZZY_HASH,
        threshold: float = 0.7,
    ):
        self.algorithm = algorithm
        self.threshold = threshold
        self._fingerprints: dict[str, FunctionFingerprint] = {}
        self._by_canonical_ref: dict[str, str] = {}  # ref -> entity_id
        self._fuzzy_hasher = FuzzyHasher()
        self._ngram_hasher = NgramHasher()
        self._cfg_hasher = CFGHasher()

        # Select strategy based on algorithm
        if algorithm == SimilarityAlgorithm.FUZZY_HASH:
            self._strategy: SimilarityStrategy = FuzzyHashStrategy()
        elif algorithm == SimilarityAlgorithm.NGRAM:
            self._strategy = NgramStrategy()
        elif algorithm == SimilarityAlgorithm.CFG:
            self._strategy = CFGStrategy()
        else:
            self._strategy = CombinedStrategy()

    def set_threshold(self, threshold: float) -> None:
        """Set the similarity threshold (0.0-1.0)."""
        self.threshold = max(0.0, min(1.0, threshold))

    def add_fingerprint(self, fingerprint: FunctionFingerprint) -> None:
        """Add a function fingerprint to the index."""
        self._fingerprints[fingerprint.entity_id] = fingerprint
        if fingerprint.canonical_ref:
            self._by_canonical_ref[fingerprint.canonical_ref] = fingerprint.entity_id

    def remove_fingerprint(self, entity_id: str) -> None:
        """Remove a function fingerprint from the index."""
        if entity_id in self._fingerprints:
            fp = self._fingerprints[entity_id]
            if fp.canonical_ref in self._by_canonical_ref:
                del self._by_canonical_ref[fp.canonical_ref]
            del self._fingerprints[entity_id]

    def get_fingerprint(self, entity_id: str) -> FunctionFingerprint | None:
        """Get a fingerprint by entity ID."""
        return self._fingerprints.get(entity_id)

    def find_similar(
        self,
        query_fp: FunctionFingerprint,
        top_k: int = 10,
        threshold: float | None = None,
    ) -> list[SimilarityResult]:
        """Find functions similar to the query fingerprint.

        Args:
            query_fp: The query function fingerprint
            top_k: Maximum number of results to return
            threshold: Optional override for similarity threshold

        Returns:
            List of similarity results sorted by score (descending)
        """
        threshold = threshold if threshold is not None else self.threshold
        results: list[SimilarityResult] = []

        for entity_id, fp in self._fingerprints.items():
            if entity_id == query_fp.entity_id:
                continue  # Skip self-comparison

            score = self._strategy.calculate(query_fp, fp)
            if score >= threshold:
                results.append(
                    SimilarityResult(
                        source_entity_id=query_fp.entity_id,
                        target_entity_id=fp.entity_id,
                        source_name=query_fp.name,
                        target_name=fp.name,
                        target_canonical_ref=fp.canonical_ref,
                        similarity_score=score,
                        algorithm=self.algorithm.value,
                        details={
                            "source_instruction_count": query_fp.instruction_count,
                            "target_instruction_count": fp.instruction_count,
                            "source_block_count": query_fp.block_count,
                            "target_block_count": fp.block_count,
                        },
                    )
                )

        # Sort by score descending and return top_k
        results.sort(key=lambda r: r.similarity_score, reverse=True)
        return results[:top_k]

    def find_similar_by_entity_id(
        self,
        entity_id: str,
        top_k: int = 10,
        threshold: float | None = None,
    ) -> list[SimilarityResult]:
        """Find functions similar to a given entity.

        Args:
            entity_id: The entity ID to find similar functions for
            top_k: Maximum number of results to return
            threshold: Optional override for similarity threshold

        Returns:
            List of similarity results sorted by score (descending)
        """
        query_fp = self._fingerprints.get(entity_id)
        if query_fp is None:
            return []
        return self.find_similar(query_fp, top_k, threshold)

    def find_similar_by_address(
        self,
        canonical_ref: str,
        top_k: int = 10,
        threshold: float | None = None,
    ) -> list[SimilarityResult]:
        """Find functions similar to a function at a given address.

        Args:
            canonical_ref: The canonical reference address
            top_k: Maximum number of results to return
            threshold: Optional override for similarity threshold

        Returns:
            List of similarity results sorted by score (descending)
        """
        entity_id = self._by_canonical_ref.get(canonical_ref)
        if entity_id is None:
            return []
        return self.find_similar_by_entity_id(entity_id, top_k, threshold)

    def get_all_fingerprints(self) -> list[FunctionFingerprint]:
        """Get all fingerprints in the index."""
        return list(self._fingerprints.values())

    def clear(self) -> None:
        """Clear all fingerprints from the index."""
        self._fingerprints.clear()
        self._by_canonical_ref.clear()

    def __len__(self) -> int:
        """Return the number of fingerprints in the index."""
        return len(self._fingerprints)


def create_fingerprint_from_entity(
    entity: EntityRecord,
    instruction_sequence: list[str] | None = None,
    block_count: int = 0,
    cfg_edges: list[tuple[int, int]] | None = None,
) -> FunctionFingerprint:
    """Create a function fingerprint from an entity and optional disassembly info.

    Args:
        entity: The entity record (must have kind="function")
        instruction_sequence: Optional list of normalized instruction strings
        block_count: Number of basic blocks
        cfg_edges: Optional list of CFG edges

    Returns:
        A FunctionFingerprint for the entity
    """
    fuzzy_hasher = FuzzyHasher()
    ngram_hasher = NgramHasher()
    cfg_hasher = CFGHasher()

    # Create fuzzy hash from instructions or use canonical_ref as fallback
    if instruction_sequence:
        inst_text = " ".join(instruction_sequence)
        fuzzy_hash = fuzzy_hasher.hash(inst_text)
        ngram_hashes = frozenset(ngram_hasher.hash(instruction_sequence))
        instruction_count = len(instruction_sequence)
    else:
        # Use entity attributes as fallback
        inst_text = entity.canonical_ref or entity.entity_id
        fuzzy_hash = fuzzy_hasher.hash(inst_text)
        ngram_hashes = frozenset(ngram_hasher.hash([inst_text]))
        instruction_count = entity.attributes.get("instruction_count", 0) or 0

    # CFG hash
    if cfg_edges is not None:
        cfg_hash = cfg_hasher.hash_structure(block_count, cfg_edges)
    else:
        cfg_hash = hashlib.md5(str(block_count).encode()).hexdigest()[:16]

    # Create feature vector from attributes
    features = [
        float(instruction_count),
        float(block_count),
        float(entity.attributes.get("cyclomatic_complexity", 0) or 0),
        float(entity.attributes.get("local_var_count", 0) or 0),
        float(entity.attributes.get("parameter_count", 0) or 0),
    ]

    return FunctionFingerprint(
        entity_id=entity.entity_id,
        canonical_ref=entity.canonical_ref,
        name=entity.name,
        fuzzy_hash=fuzzy_hash,
        ngram_hashes=ngram_hashes,
        cfg_hash=cfg_hash,
        instruction_count=instruction_count,
        block_count=block_count or entity.attributes.get("block_count", 0) or 0,
        feature_vector=tuple(features),
    )


def compare_functions(
    fp1: FunctionFingerprint,
    fp2: FunctionFingerprint,
    algorithm: SimilarityAlgorithm = SimilarityAlgorithm.FUZZY_HASH,
) -> float:
    """Compare two function fingerprints and return a similarity score.

    Args:
        fp1: First function fingerprint
        fp2: Second function fingerprint
        algorithm: Algorithm to use for comparison

    Returns:
        Similarity score between 0.0 and 1.0
    """
    if algorithm == SimilarityAlgorithm.FUZZY_HASH:
        strategy = FuzzyHashStrategy()
    elif algorithm == SimilarityAlgorithm.NGRAM:
        strategy = NgramStrategy()
    elif algorithm == SimilarityAlgorithm.CFG:
        strategy = CFGStrategy()
    else:
        strategy = CombinedStrategy()

    return strategy.calculate(fp1, fp2)
