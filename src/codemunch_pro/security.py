"""Security utilities — path traversal prevention, binary detection, secret scanning."""

from __future__ import annotations

import re
from pathlib import Path

# Binary file signatures (magic bytes)
_BINARY_SIGS = [
    b'\x7fELF',       # ELF
    b'MZ',            # PE/DOS
    b'\xca\xfe\xba\xbe',  # Mach-O
    b'\xcf\xfa\xed\xfe',  # Mach-O 64
    b'PK\x03\x04',   # ZIP
    b'\x1f\x8b',      # gzip
    b'\x89PNG',       # PNG
    b'\xff\xd8\xff',  # JPEG
    b'GIF8',          # GIF
    b'%PDF',          # PDF
    b'\x00asm',       # WASM
]

# Extensions that are always binary
_BINARY_EXTENSIONS = frozenset({
    '.pyc', '.pyo', '.so', '.dll', '.dylib', '.o', '.a', '.lib',
    '.exe', '.bin', '.class', '.jar', '.war',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac',
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.wasm', '.woff', '.woff2', '.ttf', '.otf', '.eot',
    '.db', '.sqlite', '.sqlite3',
    '.lock',
})

# Default paths to ignore
DEFAULT_IGNORE_PATTERNS = [
    '.git', '__pycache__', 'node_modules', '.venv', 'venv',
    '.tox', '.mypy_cache', '.pytest_cache', '.ruff_cache',
    'dist', 'build', '.eggs', '*.egg-info',
    '.next', '.nuxt', '.output',
    'target',  # Rust/Java
    'vendor',  # Go
]

# Potential secret patterns
_SECRET_PATTERNS = [
    re.compile(r'(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}', re.I),
    re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),  # AWS key
    re.compile(r'sk-[a-zA-Z0-9]{20,}'),  # OpenAI/Stripe
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),  # GitHub PAT
]

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB


def validate_path(path: str, base_dir: str | None = None) -> Path:
    """Validate and resolve a path, preventing directory traversal.

    Args:
        path: The path to validate.
        base_dir: Optional base directory to restrict access to.

    Returns:
        Resolved absolute Path.

    Raises:
        ValueError: If path is invalid or escapes base_dir.
    """
    resolved = Path(path).resolve()

    if base_dir:
        base = Path(base_dir).resolve()
        if not str(resolved).startswith(str(base)):
            raise ValueError(
                f'Path traversal detected: {path} escapes {base_dir}'
            )

    if not resolved.exists():
        raise ValueError(f'Path does not exist: {resolved}')

    return resolved


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary (not source code)."""
    if file_path.suffix.lower() in _BINARY_EXTENSIONS:
        return True

    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
            if not header:
                return False
            for sig in _BINARY_SIGS:
                if header.startswith(sig):
                    return True
            # Check for null bytes (binary indicator)
            if b'\x00' in header:
                return True
    except (OSError, PermissionError):
        return True

    return False


def is_too_large(file_path: Path, max_size: int = MAX_FILE_SIZE) -> bool:
    """Check if a file exceeds the size limit."""
    try:
        return file_path.stat().st_size > max_size
    except OSError:
        return True


def scan_for_secrets(content: str) -> list[str]:
    """Scan text content for potential secrets. Returns list of warnings."""
    warnings = []
    for pattern in _SECRET_PATTERNS:
        matches = pattern.findall(content)
        if matches:
            # Don't include the actual secret in the warning
            warnings.append(
                f'Potential secret found matching pattern: {pattern.pattern[:40]}...'
            )
    return warnings
