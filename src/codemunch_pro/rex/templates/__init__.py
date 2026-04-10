"""Project templates for CodeMunch Pro REX."""

from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent

AVAILABLE_TEMPLATES = [
    "snes-hirom",
    "snes-lorom",
    "generic",
    "psx-exe",
    "n64-rom",
]


def get_template_path(template_name: str) -> Path:
    """Get the path to a template directory.
    
    Args:
        template_name: Name of the template
        
    Returns:
        Path to the template directory
        
    Raises:
        ValueError: If template doesn't exist
    """
    if template_name not in AVAILABLE_TEMPLATES:
        raise ValueError(
            f"Unknown template: {template_name}. "
            f"Available: {', '.join(AVAILABLE_TEMPLATES)}"
        )
    return TEMPLATES_DIR / template_name
