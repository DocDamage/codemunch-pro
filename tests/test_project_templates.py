"""Tests for project template functionality."""

import tempfile
from pathlib import Path

import pytest

from codemunch_pro.rex.project_templates import (
    AVAILABLE_TEMPLATES,
    ProjectTemplate,
    init_project,
    list_templates,
    _process_template,
)
from codemunch_pro.rex.templates import get_template_path


class TestProjectTemplate:
    """Tests for ProjectTemplate class."""
    
    def test_from_name_valid(self) -> None:
        """Test loading a valid template."""
        template = ProjectTemplate.from_name("snes-hirom")
        
        assert template.name == "snes-hirom"
        assert template.platform == "snes-hirom"
        assert template.path.exists()
    
    def test_from_name_invalid(self) -> None:
        """Test loading an invalid template raises error."""
        with pytest.raises(ValueError) as exc_info:
            ProjectTemplate.from_name("nonexistent")
        
        assert "nonexistent" in str(exc_info.value)
        assert "generic" in str(exc_info.value)  # Should list available templates
    
    def test_list_files(self) -> None:
        """Test listing template files."""
        template = ProjectTemplate.from_name("generic")
        files = template.list_files()
        
        assert len(files) > 0
        assert any(f.name == "config.yml" for f in files)
        assert any(f.name == "README.md" for f in files)
    
    def test_all_templates_loadable(self) -> None:
        """Test that all available templates can be loaded."""
        for name in AVAILABLE_TEMPLATES:
            template = ProjectTemplate.from_name(name)
            assert template.name == name
            assert template.path.exists()


class TestListTemplates:
    """Tests for list_templates function."""
    
    def test_returns_all_templates(self) -> None:
        """Test that all templates are returned."""
        templates = list_templates()
        
        assert len(templates) == len(AVAILABLE_TEMPLATES)
        names = [t.name for t in templates]
        assert set(names) == set(AVAILABLE_TEMPLATES)


class TestInitProject:
    """Tests for init_project function."""
    
    def test_creates_project_directory(self) -> None:
        """Test that project directory is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "test-project"
            result = init_project(project_path, "generic")
            
            assert result.exists()
            assert result.is_dir()
    
    def test_creates_required_files(self) -> None:
        """Test that all template files are copied."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "test-project"
            init_project(project_path, "generic")
            
            assert (project_path / "config.yml").exists()
            assert (project_path / "README.md").exists()
            assert (project_path / ".gitignore").exists()
    
    def test_creates_required_directories(self) -> None:
        """Test that all directories are created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "test-project"
            init_project(project_path, "snes-hirom")  # Has more defined directories
            
            assert (project_path / "manifests").is_dir()
            assert (project_path / "notes").is_dir()
            assert (project_path / "symbols").is_dir()
            assert (project_path / "exports").is_dir()
    
    def test_processes_template_variables(self) -> None:
        """Test that template variables are replaced."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "MyCoolProject"
            init_project(project_path, "generic", name="MyCoolProject")
            
            readme = project_path / "README.md"
            content = readme.read_text()
            
            assert "MyCoolProject" in content
            assert "{{PROJECT_NAME}}" not in content
    
    def test_uses_directory_name_as_default(self) -> None:
        """Test that directory name is used as project name by default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "auto-named-project"
            init_project(project_path, "generic")  # No name specified
            
            config = project_path / "config.yml"
            content = config.read_text()
            
            assert "auto-named-project" in content
    
    def test_raises_on_existing_nonempty_dir(self) -> None:
        """Test that error is raised if directory exists and is not empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "existing"
            project_path.mkdir()
            (project_path / "some-file.txt").write_text("content")
            
            with pytest.raises(FileExistsError):
                init_project(project_path, "generic")
    
    def test_allows_existing_empty_dir(self) -> None:
        """Test that empty existing directory is allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "empty"
            project_path.mkdir()
            
            result = init_project(project_path, "generic")
            assert result.exists()
    
    def test_all_templates_work(self) -> None:
        """Test that all templates can be used to create projects."""
        for template_name in AVAILABLE_TEMPLATES:
            with tempfile.TemporaryDirectory() as tmpdir:
                project_path = Path(tmpdir) / f"test-{template_name}"
                result = init_project(project_path, template_name)
                
                assert result.exists()
                assert (result / "config.yml").exists()


class TestProcessTemplate:
    """Tests for _process_template function."""
    
    def test_replaces_project_name(self) -> None:
        """Test that project name is replaced."""
        content = "Project: {{PROJECT_NAME}}"
        result = _process_template(content, "MyProject", {})
        
        assert result == "Project: MyProject"
    
    def test_replaces_date(self) -> None:
        """Test that date is replaced with ISO format."""
        content = "Created: {{CREATED_DATE}}"
        result = _process_template(content, "MyProject", {})
        
        # Should contain an ISO date (starts with year)
        assert "{{CREATED_DATE}}" not in result
        assert "20" in result  # Year prefix
    
    def test_replaces_custom_options(self) -> None:
        """Test that custom options are replaced."""
        content = "Author: {{AUTHOR}}, Version: {{VERSION}}"
        result = _process_template(content, "MyProject", {
            "author": "John Doe",
            "version": "1.0",
        })
        
        assert "Author: John Doe, Version: 1.0" == result
    
    def test_preserves_unmatched_variables(self) -> None:
        """Test that unmatched variables are preserved."""
        content = "{{UNKNOWN_VAR}}"
        result = _process_template(content, "MyProject", {})
        
        assert result == "{{UNKNOWN_VAR}}"


class TestTemplatesPackage:
    """Tests for the templates package."""
    
    def test_available_templates_list(self) -> None:
        """Test that AVAILABLE_TEMPLATES is correctly defined."""
        expected = ["snes-hirom", "snes-lorom", "generic", "psx-exe", "n64-rom"]
        assert sorted(AVAILABLE_TEMPLATES) == sorted(expected)
    
    def test_get_template_path_valid(self) -> None:
        """Test getting path for valid template."""
        path = get_template_path("generic")
        
        assert path.exists()
        assert path.is_dir()
        assert path.name == "generic"
    
    def test_get_template_path_invalid(self) -> None:
        """Test getting path for invalid template raises error."""
        with pytest.raises(ValueError) as exc_info:
            get_template_path("nonexistent")
        
        assert "nonexistent" in str(exc_info.value)


class TestSnesHiRomTemplate:
    """Specific tests for SNES HiROM template."""
    
    def test_config_content(self) -> None:
        """Test that HiROM config has correct values."""
        template = ProjectTemplate.from_name("snes-hirom")
        config_path = template.path / "config.yml"
        content = config_path.read_text()
        
        assert "snes-hirom" in content
        assert "0xC00000" in content  # Base address
        assert "W65C816S" in content  # CPU type


class TestSnesLoRomTemplate:
    """Specific tests for SNES LoROM template."""
    
    def test_config_content(self) -> None:
        """Test that LoROM config has correct values."""
        template = ProjectTemplate.from_name("snes-lorom")
        config_path = template.path / "config.yml"
        content = config_path.read_text()
        
        assert "snes-lorom" in content
        assert "0x8000" in content  # Base address
        assert "0x7FC0" in content  # Header address


class TestPsxExeTemplate:
    """Specific tests for PSX EXE template."""
    
    def test_config_content(self) -> None:
        """Test that PSX config has correct values."""
        template = ProjectTemplate.from_name("psx-exe")
        config_path = template.path / "config.yml"
        content = config_path.read_text()
        
        assert "psx-exe" in content
        assert "R3000A" in content  # CPU type
        assert "mips" in content  # Architecture
        assert "0x80010000" in content  # Base address


class TestN64RomTemplate:
    """Specific tests for N64 ROM template."""
    
    def test_config_content(self) -> None:
        """Test that N64 config has correct values."""
        template = ProjectTemplate.from_name("n64-rom")
        config_path = template.path / "config.yml"
        content = config_path.read_text()
        
        assert "n64-rom" in content
        assert "VR4300" in content  # CPU type
        assert "mips64" in content  # Architecture
        assert "0x80000000" in content  # Base address


class TestGitignoreFiles:
    """Tests for .gitignore files in templates."""
    
    def test_gitignore_blocks_roms(self) -> None:
        """Test that ROM files are gitignored."""
        template = ProjectTemplate.from_name("snes-hirom")
        gitignore_path = template.path / ".gitignore"
        content = gitignore_path.read_text()
        
        assert "*.sfc" in content
        assert "*.smc" in content
    
    def test_gitignore_blocks_databases(self) -> None:
        """Test that database files are gitignored."""
        template = ProjectTemplate.from_name("generic")
        gitignore_path = template.path / ".gitignore"
        content = gitignore_path.read_text()
        
        assert ".rex_db/" in content
        assert "*.db" in content
