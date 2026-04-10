"""Project template management for CodeMunch Pro REX.

This module provides functionality for creating new reverse engineering
projects from predefined templates for various platforms.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


# Template directory - relative to this module
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Available template names
AVAILABLE_TEMPLATES = [
    "snes-hirom",
    "snes-lorom",
    "generic",
    "psx-exe",
    "n64-rom",
]


@dataclass
class ProjectTemplate:
    """Represents a project template.
    
    Attributes:
        name: Template identifier (e.g., "snes-hirom")
        description: Human-readable description
        platform: Target platform name
        path: Path to template directory
    """
    name: str
    description: str
    platform: str
    path: Path
    
    def __post_init__(self) -> None:
        """Validate template exists."""
        if not self.path.exists():
            raise ValueError(f"Template directory not found: {self.path}")
    
    @classmethod
    def from_name(cls, name: str) -> ProjectTemplate:
        """Load a template by name.
        
        Args:
            name: Template name (e.g., "snes-hirom")
            
        Returns:
            ProjectTemplate instance
            
        Raises:
            ValueError: If template doesn't exist
        """
        if name not in AVAILABLE_TEMPLATES:
            raise ValueError(
                f"Unknown template: {name}. "
                f"Available: {', '.join(AVAILABLE_TEMPLATES)}"
            )
        
        template_path = TEMPLATES_DIR / name
        
        # Load description from config if available
        config_path = template_path / "config.yml"
        description = f"{name} project template"
        platform = name
        
        if config_path.exists():
            try:
                content = config_path.read_text(encoding="utf-8")
                # Parse platform section
                in_platform = False
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped == "platform:":
                        in_platform = True
                    elif stripped.endswith(":") and not line.startswith(" "):
                        in_platform = False
                    elif in_platform:
                        if stripped.startswith("description:"):
                            description = stripped.split(":", 1)[1].strip().strip('"')
                        elif stripped.startswith("type:"):
                            platform = stripped.split(":", 1)[1].strip().strip('"')
            except Exception:
                pass  # Use defaults if parsing fails
        
        return cls(
            name=name,
            description=description,
            platform=platform,
            path=template_path,
        )
    
    def list_files(self) -> list[Path]:
        """List all files in the template.
        
        Returns:
            List of file paths relative to template root
        """
        files = []
        for item in self.path.rglob("*"):
            if item.is_file():
                files.append(item.relative_to(self.path))
        return sorted(files)


def list_templates() -> list[ProjectTemplate]:
    """List all available templates.
    
    Returns:
        List of ProjectTemplate instances
    """
    return [ProjectTemplate.from_name(name) for name in AVAILABLE_TEMPLATES]


def init_project(
    path: Path | str,
    template_name: str,
    name: str | None = None,
    options: dict[str, Any] | None = None,
) -> Path:
    """Initialize a new project from a template.
    
    Args:
        path: Destination path for the project
        template_name: Name of the template to use
        name: Project name (defaults to directory name)
        options: Additional template options
        
    Returns:
        Path to the created project directory
        
    Raises:
        ValueError: If template doesn't exist
        FileExistsError: If destination already exists and is not empty
    """
    dest_path = Path(path).resolve()
    options = options or {}
    
    # Use directory name as default project name
    if name is None:
        name = dest_path.name
    
    # Load template
    template = ProjectTemplate.from_name(template_name)
    
    # Check if destination exists
    if dest_path.exists():
        if any(dest_path.iterdir()):
            raise FileExistsError(
                f"Destination directory exists and is not empty: {dest_path}"
            )
    else:
        dest_path.mkdir(parents=True)
    
    # Copy template files and directories
    template_files = template.list_files()
    
    # Copy all directories first (to ensure empty dirs are created)
    for item in template.path.rglob("*"):
        if item.is_dir():
            rel_dir = item.relative_to(template.path)
            dest_dir = dest_path / rel_dir
            dest_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy and process files
    for rel_path in template_files:
        src_file = template.path / rel_path
        dest_file = dest_path / rel_path
        
        # Create parent directories
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Read and process file content
        with open(src_file, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Replace template variables
        processed_content = _process_template(content, name, options)
        
        # Write processed file
        with open(dest_file, "w", encoding="utf-8") as f:
            f.write(processed_content)
    
    # Create exports directory if not in template
    exports_dir = dest_path / "exports"
    exports_dir.mkdir(exist_ok=True)
    
    return dest_path


def _process_template(content: str, project_name: str, options: dict[str, Any]) -> str:
    """Process template content, replacing variables.
    
    Args:
        content: Template file content
        project_name: Project name
        options: Additional options
        
    Returns:
        Processed content
    """
    # Standard replacements
    replacements = {
        "{{PROJECT_NAME}}": project_name,
        "{{CREATED_DATE}}": datetime.now().isoformat(),
    }
    
    # Add custom options
    for key, value in options.items():
        replacements[f"{{{{{key.upper()}}}}}"] = str(value)
    
    result = content
    for key, value in replacements.items():
        result = result.replace(key, value)
    
    return result


def init_command(args: argparse.Namespace) -> int:
    """Handle the 'init' CLI command.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success)
    """
    path = Path(args.path) if args.path else Path.cwd() / args.name
    
    try:
        project_path = init_project(
            path=path,
            template_name=args.template,
            name=args.name,
        )
        
        print(f"Created {args.template} project: {project_path}")
        print(f"\nNext steps:")
        print(f"  cd {project_path.name}")
        print(f"  codemunch-pro web  # Start the web interface")
        
        return 0
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except FileExistsError as e:
        print(f"Error: {e}", file=sys.stderr)
        print(f"Use a different path or remove the existing directory.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error creating project: {e}", file=sys.stderr)
        return 1


def list_command(args: argparse.Namespace) -> int:
    """Handle the 'list-templates' CLI command.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success)
    """
    templates = list_templates()
    
    print("Available project templates:\n")
    print(f"{'Name':<15} {'Platform':<15} Description")
    print("-" * 60)
    
    for template in templates:
        print(f"{template.name:<15} {template.platform:<15} {template.description}")
    
    return 0


def add_init_subparser(subparsers: Any) -> None:
    """Add the 'init' subparser to the argument parser.
    
    Args:
        subparsers: argparse subparsers object
    """
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new reverse engineering project",
        description="Create a new project from a template.",
    )
    
    init_parser.add_argument(
        "--template",
        "-t",
        choices=AVAILABLE_TEMPLATES,
        default="generic",
        help="Project template to use (default: generic)",
    )
    
    init_parser.add_argument(
        "--name",
        "-n",
        default="my-project",
        help="Project name (default: my-project)",
    )
    
    init_parser.add_argument(
        "path",
        nargs="?",
        help="Destination path (default: project name in current directory)",
    )
    
    init_parser.set_defaults(func=init_command)


def add_list_subparser(subparsers: Any) -> None:
    """Add the 'list-templates' subparser to the argument parser.
    
    Args:
        subparsers: argparse subparsers object
    """
    list_parser = subparsers.add_parser(
        "list-templates",
        help="List available project templates",
        description="Show all available project templates.",
    )
    
    list_parser.set_defaults(func=list_command)


# Import this at the end to avoid circular imports
__all__ = [
    "AVAILABLE_TEMPLATES",
    "ProjectTemplate",
    "add_init_subparser",
    "add_list_subparser",
    "init_project",
    "list_templates",
]
