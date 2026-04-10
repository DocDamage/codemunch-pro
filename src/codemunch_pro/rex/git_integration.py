"""Git integration for tracking reverse-engineering project changes.

This module provides a wrapper around git operations specifically designed
for RE projects, with support for tracking manifests, labels, notes, and symbols.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class GitCommit:
    """Represents a git commit."""

    hash: str
    author: str
    email: str
    date: datetime
    message: str
    files_changed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize commit to dictionary."""
        return {
            "hash": self.hash,
            "author": self.author,
            "email": self.email,
            "date": self.date.isoformat(),
            "message": self.message,
            "files_changed": self.files_changed,
        }


@dataclass
class ArtifactChange:
    """Represents a change to an artifact."""

    path: str
    change_type: str  # 'added', 'modified', 'deleted'
    old_content: str | None = None
    new_content: str | None = None
    diff: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize change to dictionary."""
        return {
            "path": self.path,
            "change_type": self.change_type,
            "old_content": self.old_content,
            "new_content": self.new_content,
            "diff": self.diff,
        }


@dataclass
class EntityHistory:
    """Represents the history of an entity across commits."""

    entity_id: str
    commits: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize history to dictionary."""
        return {
            "entity_id": self.entity_id,
            "commits": self.commits,
        }


@dataclass
class BlameLine:
    """Represents a single line from git blame output."""

    commit_hash: str
    author: str
    date: datetime
    line_num: int
    content: str
    original_line_num: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize blame line to dictionary."""
        return {
            "commit_hash": self.commit_hash,
            "author": self.author,
            "date": self.date.isoformat(),
            "line_num": self.line_num,
            "content": self.content,
            "original_line_num": self.original_line_num,
        }


class GitError(Exception):
    """Raised when a git operation fails."""

    pass


class REProjectRepo:
    """Git repository wrapper for reverse-engineering projects.

    Provides specialized methods for tracking and diffing RE artifacts
    including manifests, labels, notes, and symbols.
    """

    # Common RE artifact patterns
    ARTIFACT_PATTERNS = {
        "manifest": ["*.json", "*.yaml", "*.yml", "manifest*"],
        "label": ["*.labels", "labels/*", "symbols/*", "*.sym"],
        "note": ["*.md", "notes/*", "docs/*", "*.txt"],
        "symbol": ["*.asm", "*.s", "disasm/*", "*.inc"],
    }

    def __init__(self, project_path: str | Path) -> None:
        """Initialize the repo wrapper.

        Args:
            project_path: Path to the git repository root.

        Raises:
            GitError: If the path is not a valid git repository.
        """
        self.project_path = Path(project_path).resolve()
        if not self._is_git_repo():
            raise GitError(f"Not a git repository: {project_path}")

    def _is_git_repo(self) -> bool:
        """Check if the project path is a valid git repository."""
        git_dir = self.project_path / ".git"
        return git_dir.exists() or (self.project_path / ".git").is_file()

    def _run_git(
        self,
        args: list[str],
        cwd: Path | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run a git command.

        Args:
            args: Git command arguments.
            cwd: Working directory (defaults to project_path).
            check: Whether to raise on non-zero exit.

        Returns:
            CompletedProcess with stdout/stderr.

        Raises:
            GitError: If the command fails and check=True.
        """
        cmd = ["git"] + args
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd or self.project_path,
                capture_output=True,
                text=True,
                check=False,
            )
            if check and result.returncode != 0:
                raise GitError(f"Git command failed: {result.stderr}")
            return result
        except FileNotFoundError as e:
            raise GitError("Git executable not found") from e

    def _parse_git_date(self, date_str: str) -> datetime:
        """Parse git date string to datetime."""
        # Git dates are in ISO 8601 format
        date_str = date_str.strip()
        # Handle timezone offset
        if "+" in date_str or date_str.count("-") > 2:
            # Remove timezone for simplicity
            date_str = re.sub(r"[+-]\d{4}$", "", date_str)
        try:
            return datetime.fromisoformat(date_str)
        except ValueError:
            return datetime.now()

    def _get_artifact_type(self, path: str) -> str:
        """Determine artifact type from path."""
        path_lower = path.lower()
        for art_type, patterns in self.ARTIFACT_PATTERNS.items():
            for pattern in patterns:
                if self._match_pattern(path_lower, pattern):
                    return art_type
        return "other"

    def _match_pattern(self, path: str, pattern: str) -> bool:
        """Match a path against a glob pattern."""
        import fnmatch

        return fnmatch.fnmatch(path, pattern.lower()) or fnmatch.fnmatch(
            Path(path).name, pattern.lower()
        )

    def _is_re_artifact(self, path: str) -> bool:
        """Check if a path is an RE artifact."""
        return self._get_artifact_type(path) != "other"

    def diff_rex_project(
        self,
        commit_a: str,
        commit_b: str,
        artifact_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Compare RE artifacts between two commits.

        Args:
            commit_a: First commit hash or ref.
            commit_b: Second commit hash or ref.
            artifact_types: Optional list of artifact types to filter
                (manifest, label, note, symbol).

        Returns:
            Dictionary with diff results including added, modified, and
            deleted artifacts with human-readable diffs.
        """
        # Get changed files between commits
        result = self._run_git(
            ["diff", "--name-status", f"{commit_a}...{commit_b}"]
        )

        changes: list[ArtifactChange] = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue

            status, path = parts[0], parts[1]
            art_type = self._get_artifact_type(path)

            # Filter by artifact type if specified
            if artifact_types and art_type not in artifact_types:
                continue

            # Skip non-RE artifacts
            if not self._is_re_artifact(path):
                continue

            change_type = {
                "A": "added",
                "M": "modified",
                "D": "deleted",
                "R": "renamed",
                "C": "copied",
            }.get(status[0], "modified")

            change = ArtifactChange(
                path=path,
                change_type=change_type,
            )

            # Get diff content for modified files
            if change_type in ("modified", "added"):
                try:
                    diff_result = self._run_git(
                        ["diff", f"{commit_a}...{commit_b}", "--", path],
                        check=False,
                    )
                    if diff_result.returncode == 0:
                        change.diff = diff_result.stdout
                except GitError:
                    pass

            # Get file content at each commit
            if change_type != "deleted":
                try:
                    content_result = self._run_git(
                        ["show", f"{commit_b}:{path}"],
                        check=False,
                    )
                    if content_result.returncode == 0:
                        change.new_content = content_result.stdout
                except GitError:
                    pass

            if change_type != "added":
                try:
                    content_result = self._run_git(
                        ["show", f"{commit_a}:{path}"],
                        check=False,
                    )
                    if content_result.returncode == 0:
                        change.old_content = content_result.stdout
                except GitError:
                    pass

            changes.append(change)

        # Group changes by artifact type
        by_type: dict[str, list[dict[str, Any]]] = {
            "manifest": [],
            "label": [],
            "note": [],
            "symbol": [],
            "other": [],
        }

        for change in changes:
            art_type = self._get_artifact_type(change.path)
            by_type[art_type].append(change.to_dict())

        # Generate summary statistics
        summary = {
            "total_changes": len(changes),
            "added": len([c for c in changes if c.change_type == "added"]),
            "modified": len([c for c in changes if c.change_type == "modified"]),
            "deleted": len([c for c in changes if c.change_type == "deleted"]),
            "by_type": {
                art_type: len(items) for art_type, items in by_type.items() if items
            },
        }

        return {
            "commit_a": commit_a,
            "commit_b": commit_b,
            "changes": [c.to_dict() for c in changes],
            "by_type": by_type,
            "summary": summary,
        }

    def blame_artifact(
        self,
        artifact_path: str,
        line_start: int | None = None,
        line_end: int | None = None,
    ) -> dict[str, Any]:
        """Show who last modified each line of an artifact.

        Args:
            artifact_path: Path to the artifact (relative to project root).
            line_start: Optional starting line number.
            line_end: Optional ending line number.

        Returns:
            Dictionary with blame information per line.
        """
        full_path = self.project_path / artifact_path
        if not full_path.exists():
            return {"error": f"Artifact not found: {artifact_path}"}

        # Build blame command
        args = ["blame", "--porcelain"]
        if line_start is not None:
            args.extend(["-L", f"{line_start},{line_end or line_start}"])
        args.append(artifact_path)

        result = self._run_git(args)

        lines: list[BlameLine] = []
        current_commit: dict[str, str] = {}
        line_num = 0

        for line in result.stdout.split("\n"):
            if not line:
                continue

            # Porcelain format: each commit header starts with 40-char hash
            if len(line) >= 40 and line[40:41] == " ":
                parts = line.split(" ")
                commit_hash = parts[0]
                original_line = parts[1] if len(parts) > 1 else "0"
                final_line = parts[2] if len(parts) > 2 else "0"

                current_commit = {"hash": commit_hash}
                line_num = int(final_line) if final_line.isdigit() else 0
            elif line.startswith("author "):
                current_commit["author"] = line[7:]
            elif line.startswith("author-mail "):
                current_commit["email"] = line[12:].strip("<>")
            elif line.startswith("author-time "):
                timestamp = int(line[12:])
                current_commit["date"] = datetime.fromtimestamp(timestamp).isoformat()
            elif line.startswith("\t"):
                # Content line (starts with tab)
                content = line[1:]
                blame_line = BlameLine(
                    commit_hash=current_commit.get("hash", "?"),
                    author=current_commit.get("author", "Unknown"),
                    date=datetime.fromisoformat(
                        current_commit.get("date", datetime.now().isoformat())
                    ),
                    line_num=line_num,
                    content=content,
                )
                lines.append(blame_line)

        # Aggregate by commit for summary
        by_commit: dict[str, dict[str, Any]] = {}
        for blame_line in lines:
            h = blame_line.commit_hash
            if h not in by_commit:
                by_commit[h] = {
                    "hash": h,
                    "author": blame_line.author,
                    "date": blame_line.date.isoformat(),
                    "line_count": 0,
                    "lines": [],
                }
            by_commit[h]["line_count"] += 1
            by_commit[h]["lines"].append(blame_line.line_num)

        return {
            "artifact": artifact_path,
            "lines": [line.to_dict() for line in lines],
            "by_commit": list(by_commit.values()),
            "total_lines": len(lines),
        }

    def log_entity(
        self,
        entity_id: str,
        artifact_pattern: str = "*",
        max_commits: int = 50,
    ) -> dict[str, Any]:
        """Get the commit history for an entity.

        Searches commits for mentions of the entity ID in commit messages
        and file changes.

        Args:
            entity_id: The entity ID to search for.
            artifact_pattern: Glob pattern for artifacts to search.
            max_commits: Maximum number of commits to search.

        Returns:
            Dictionary with commit history and entity mentions.
        """
        # Search git log for commits mentioning this entity
        result = self._run_git(
            [
                "log",
                f"--max-count={max_commits}",
                "--format=%H|%an|%ae|%ad|%s",
                "--date=iso",
                "--all",
                "-S",
                entity_id,
                "--",
                artifact_pattern,
            ],
            check=False,
        )

        commits: list[GitCommit] = []
        for line in result.stdout.strip().split("\n"):
            if not line or "|" not in line:
                continue

            parts = line.split("|", 4)
            if len(parts) < 5:
                continue

            commit_hash, author, email, date_str, message = parts

            # Get files changed in this commit
            files_result = self._run_git(
                ["diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash],
                check=False,
            )
            files = [
                f for f in files_result.stdout.strip().split("\n") if f
            ]

            # Filter to RE artifacts
            re_files = [f for f in files if self._is_re_artifact(f)]

            commit = GitCommit(
                hash=commit_hash,
                author=author,
                email=email,
                date=self._parse_git_date(date_str),
                message=message,
                files_changed=re_files,
            )
            commits.append(commit)

        # Also search commit messages
        message_result = self._run_git(
            [
                "log",
                f"--max-count={max_commits}",
                "--format=%H|%an|%ae|%ad|%s",
                "--date=iso",
                "--all",
                "--grep",
                entity_id,
            ],
            check=False,
        )

        seen_hashes = {c.hash for c in commits}
        for line in message_result.stdout.strip().split("\n"):
            if not line or "|" not in line:
                continue

            parts = line.split("|", 4)
            if len(parts) < 5:
                continue

            commit_hash = parts[0]
            if commit_hash in seen_hashes:
                continue

            _, author, email, date_str, message = parts

            # Get files changed
            files_result = self._run_git(
                ["diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash],
                check=False,
            )
            files = [
                f for f in files_result.stdout.strip().split("\n") if f
            ]
            re_files = [f for f in files if self._is_re_artifact(f)]

            commit = GitCommit(
                hash=commit_hash,
                author=author,
                email=email,
                date=self._parse_git_date(date_str),
                message=message,
                files_changed=re_files,
            )
            commits.append(commit)

        # Sort by date descending
        commits.sort(key=lambda c: c.date, reverse=True)

        # Build entity history
        history = EntityHistory(entity_id=entity_id)
        for commit in commits[:max_commits]:
            history.commits.append({
                "hash": commit.hash,
                "author": commit.author,
                "date": commit.date.isoformat(),
                "message": commit.message,
                "files_changed": commit.files_changed,
            })

        return {
            "entity_id": entity_id,
            "history": history.to_dict(),
            "commit_count": len(history.commits),
            "authors": list(set(c.author for c in commits)),
        }

    def commit_artifacts(
        self,
        message: str,
        artifacts: list[str] | None = None,
        allow_empty: bool = False,
    ) -> dict[str, Any]:
        """Commit specific artifacts to the repository.

        Args:
            message: Commit message.
            artifacts: Optional list of artifact paths to commit.
                If None, commits all staged changes.
            allow_empty: Whether to allow empty commits.

        Returns:
            Dictionary with commit result.
        """
        if artifacts:
            # Stage specific artifacts
            for artifact in artifacts:
                self._run_git(["add", artifact])
        else:
            # Stage all changes to RE artifacts
            for art_type, patterns in self.ARTIFACT_PATTERNS.items():
                for pattern in patterns:
                    try:
                        self._run_git(["add", "--", pattern], check=False)
                    except GitError:
                        pass

        # Build commit command
        args = ["commit", "-m", message]
        if allow_empty:
            args.append("--allow-empty")
        if artifacts:
            args.extend(["--"] + artifacts)

        result = self._run_git(args, check=False)

        if result.returncode != 0:
            # Check if nothing to commit
            if "nothing to commit" in result.stdout.lower():
                return {
                    "success": False,
                    "message": "Nothing to commit",
                    "committed": False,
                }
            return {
                "success": False,
                "error": result.stderr,
                "committed": False,
            }

        # Get the new commit hash
        hash_result = self._run_git(["rev-parse", "HEAD"])
        commit_hash = hash_result.stdout.strip()

        return {
            "success": True,
            "commit_hash": commit_hash,
            "message": message,
            "artifacts_committed": artifacts or [],
            "committed": True,
        }

    def get_re_artifacts(
        self,
        artifact_type: str = "",
        include_untracked: bool = False,
    ) -> dict[str, Any]:
        """List all RE artifacts in the repository.

        Args:
            artifact_type: Optional filter by type
                (manifest, label, note, symbol).
            include_untracked: Whether to include untracked files.

        Returns:
            Dictionary with artifact lists by type.
        """
        artifacts_by_type: dict[str, list[str]] = {
            "manifest": [],
            "label": [],
            "note": [],
            "symbol": [],
            "other": [],
        }

        # Get tracked files
        result = self._run_git(["ls-files"], check=False)
        tracked_files = [f for f in result.stdout.strip().split("\n") if f]

        # Get untracked files if requested
        untracked_files: list[str] = []
        if include_untracked:
            untracked_result = self._run_git(
                ["ls-files", "--others", "--exclude-standard"],
                check=False,
            )
            untracked_files = [
                f for f in untracked_result.stdout.strip().split("\n") if f
            ]

        all_files = tracked_files + untracked_files

        for file_path in all_files:
            art_type = self._get_artifact_type(file_path)
            if art_type in artifacts_by_type:
                artifacts_by_type[art_type].append(file_path)

        # Filter by type if specified
        if artifact_type:
            return {
                "artifact_type": artifact_type,
                "artifacts": artifacts_by_type.get(artifact_type, []),
                "count": len(artifacts_by_type.get(artifact_type, [])),
            }

        return {
            "artifacts_by_type": artifacts_by_type,
            "total": sum(len(v) for v in artifacts_by_type.values()),
            "by_type_count": {
                k: len(v) for k, v in artifacts_by_type.items()
            },
        }

    def generate_human_readable_diff(
        self,
        commit_a: str,
        commit_b: str,
        artifact_path: str | None = None,
    ) -> str:
        """Generate a human-readable diff summary for RE artifacts.

        Args:
            commit_a: First commit hash or ref.
            commit_b: Second commit hash or ref.
            artifact_path: Optional specific artifact to diff.

        Returns:
            Human-readable diff string.
        """
        lines: list[str] = []
        lines.append(f"RE Project Diff: {commit_a}..{commit_b}")
        lines.append("=" * 60)
        lines.append("")

        diff_data = self.diff_rex_project(commit_a, commit_b)

        # Summary
        summary = diff_data.get("summary", {})
        lines.append("Summary:")
        lines.append(f"  Total changes: {summary.get('total_changes', 0)}")
        lines.append(f"  Added: {summary.get('added', 0)}")
        lines.append(f"  Modified: {summary.get('modified', 0)}")
        lines.append(f"  Deleted: {summary.get('deleted', 0)}")
        lines.append("")

        # Changes by type
        by_type = diff_data.get("by_type", {})
        for art_type, changes in by_type.items():
            if not changes:
                continue

            if artifact_path:
                changes = [c for c in changes if c.get("path") == artifact_path]
                if not changes:
                    continue

            lines.append(f"{art_type.upper()} Changes:")
            lines.append("-" * 40)

            for change in changes:
                path = change.get("path", "unknown")
                change_type = change.get("change_type", "unknown")
                lines.append(f"  [{change_type.upper()}] {path}")

                # Add excerpt of diff if available
                diff_content = change.get("diff", "")
                if diff_content:
                    diff_lines = diff_content.split("\n")[:10]  # First 10 lines
                    for dl in diff_lines:
                        lines.append(f"    {dl}")
                    if len(diff_content.split("\n")) > 10:
                        lines.append("    ... (truncated)")

            lines.append("")

        return "\n".join(lines)


def get_repo(project_path: str | Path) -> REProjectRepo | None:
    """Get a REProjectRepo instance if the path is a valid git repo.

    Args:
        project_path: Path to check.

    Returns:
        REProjectRepo instance or None if not a valid repo.
    """
    try:
        return REProjectRepo(project_path)
    except GitError:
        return None
