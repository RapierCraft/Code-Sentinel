"""
Git integration for Code Sentinel.

Provides:
- File history and blame information
- Changed file detection
- Commit context for findings
- PR diff analysis
"""

import subprocess
import re
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class BlameInfo:
    """Blame information for a line of code."""
    commit_hash: str
    author: str
    author_email: str
    timestamp: datetime
    line_num: int
    content: str


@dataclass
class CommitInfo:
    """Information about a git commit."""
    hash: str
    short_hash: str
    author: str
    author_email: str
    date: datetime
    message: str
    files_changed: list[str]


@dataclass
class FileChange:
    """A file change in a diff."""
    path: str
    status: str  # A=added, M=modified, D=deleted, R=renamed
    old_path: Optional[str] = None  # For renames
    additions: int = 0
    deletions: int = 0


class GitIntegration:
    """Git integration for code history and context."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self._verify_repo()

    def _verify_repo(self) -> None:
        """Verify this is a git repository."""
        git_dir = self.repo_path / ".git"
        if not git_dir.exists():
            raise ValueError(f"Not a git repository: {self.repo_path}")

    def _run_git(self, *args, check: bool = True) -> subprocess.CompletedProcess:
        """Run a git command."""
        return subprocess.run(
            ["git", *args],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=check
        )

    def get_changed_files(self, since: Optional[str] = None, staged: bool = False) -> list[FileChange]:
        """
        Get list of changed files.

        Args:
            since: Commit hash or ref to compare against (default: HEAD)
            staged: If True, only return staged changes

        Returns:
            List of FileChange objects
        """
        changes = []

        if staged:
            result = self._run_git("diff", "--cached", "--name-status")
        elif since:
            result = self._run_git("diff", "--name-status", since)
        else:
            result = self._run_git("diff", "--name-status", "HEAD")

        for line in result.stdout.strip().split("\n"):
            if not line:
                continue

            parts = line.split("\t")
            status = parts[0][0]  # First char is status

            if status == "R":
                # Rename: R100\told_path\tnew_path
                changes.append(FileChange(
                    path=parts[2] if len(parts) > 2 else parts[1],
                    status=status,
                    old_path=parts[1]
                ))
            else:
                changes.append(FileChange(
                    path=parts[1] if len(parts) > 1 else "",
                    status=status
                ))

        return changes

    def get_blame(self, file_path: str, line_start: int, line_end: int) -> list[BlameInfo]:
        """
        Get blame information for specific lines.

        Args:
            file_path: Relative path to file
            line_start: Starting line number
            line_end: Ending line number

        Returns:
            List of BlameInfo for each line
        """
        blame_info = []

        try:
            result = self._run_git(
                "blame",
                "-L", f"{line_start},{line_end}",
                "--porcelain",
                file_path
            )
        except subprocess.CalledProcessError:
            return blame_info

        # Parse porcelain blame output
        current_commit = None
        author = None
        author_email = None
        timestamp = None
        line_num = line_start

        for line in result.stdout.split("\n"):
            if re.match(r'^[0-9a-f]{40}', line):
                current_commit = line.split()[0]
            elif line.startswith("author "):
                author = line[7:]
            elif line.startswith("author-mail "):
                author_email = line[12:].strip("<>")
            elif line.startswith("author-time "):
                timestamp = datetime.fromtimestamp(int(line[12:]))
            elif line.startswith("\t"):
                # This is the actual code line
                if current_commit and author:
                    blame_info.append(BlameInfo(
                        commit_hash=current_commit,
                        author=author,
                        author_email=author_email or "",
                        timestamp=timestamp or datetime.now(),
                        line_num=line_num,
                        content=line[1:]  # Remove leading tab
                    ))
                    line_num += 1

        return blame_info

    def get_file_history(self, file_path: str, limit: int = 10) -> list[CommitInfo]:
        """
        Get commit history for a specific file.

        Args:
            file_path: Relative path to file
            limit: Maximum number of commits to return

        Returns:
            List of CommitInfo objects
        """
        commits = []

        result = self._run_git(
            "log",
            f"-n{limit}",
            "--format=%H|%h|%an|%ae|%at|%s",
            "--",
            file_path,
            check=False
        )

        for line in result.stdout.strip().split("\n"):
            if not line:
                continue

            parts = line.split("|")
            if len(parts) >= 6:
                commits.append(CommitInfo(
                    hash=parts[0],
                    short_hash=parts[1],
                    author=parts[2],
                    author_email=parts[3],
                    date=datetime.fromtimestamp(int(parts[4])),
                    message=parts[5],
                    files_changed=[file_path]
                ))

        return commits

    def get_commit_context(self, file_path: str, line_num: int) -> Optional[CommitInfo]:
        """
        Get the commit that last modified a specific line.

        Args:
            file_path: Relative path to file
            line_num: Line number

        Returns:
            CommitInfo for the commit, or None if not found
        """
        blame = self.get_blame(file_path, line_num, line_num)
        if not blame:
            return None

        commit_hash = blame[0].commit_hash

        result = self._run_git(
            "show",
            "-s",
            "--format=%H|%h|%an|%ae|%at|%s",
            commit_hash,
            check=False
        )

        parts = result.stdout.strip().split("|")
        if len(parts) >= 6:
            return CommitInfo(
                hash=parts[0],
                short_hash=parts[1],
                author=parts[2],
                author_email=parts[3],
                date=datetime.fromtimestamp(int(parts[4])),
                message=parts[5],
                files_changed=[]
            )

        return None

    def get_pr_context(self, base: str = "main") -> dict:
        """
        Get context for a PR (branch comparison).

        Args:
            base: Base branch to compare against

        Returns:
            Dictionary with PR context information
        """
        context = {
            "base": base,
            "commits": [],
            "files_changed": [],
            "stats": {"additions": 0, "deletions": 0, "files": 0}
        }

        # Get current branch
        result = self._run_git("branch", "--show-current")
        context["branch"] = result.stdout.strip()

        # Get commits between base and HEAD
        result = self._run_git(
            "log",
            f"{base}..HEAD",
            "--format=%H|%h|%an|%s",
            check=False
        )

        for line in result.stdout.strip().split("\n"):
            if line:
                parts = line.split("|")
                if len(parts) >= 4:
                    context["commits"].append({
                        "hash": parts[0],
                        "short_hash": parts[1],
                        "author": parts[2],
                        "message": parts[3]
                    })

        # Get file changes
        context["files_changed"] = self.get_changed_files(since=base)
        context["stats"]["files"] = len(context["files_changed"])

        # Get diff stats
        result = self._run_git("diff", "--stat", base, check=False)
        stat_match = re.search(r'(\d+) insertions?\(\+\), (\d+) deletions?\(-\)', result.stdout)
        if stat_match:
            context["stats"]["additions"] = int(stat_match.group(1))
            context["stats"]["deletions"] = int(stat_match.group(2))

        return context

    def get_staged_diff(self) -> str:
        """Get the full diff of staged changes."""
        result = self._run_git("diff", "--cached", check=False)
        return result.stdout

    def get_uncommitted_files(self) -> list[str]:
        """Get list of all uncommitted files (staged + unstaged)."""
        files = set()

        # Staged files
        result = self._run_git("diff", "--cached", "--name-only", check=False)
        files.update(f for f in result.stdout.strip().split("\n") if f)

        # Unstaged modified files
        result = self._run_git("diff", "--name-only", check=False)
        files.update(f for f in result.stdout.strip().split("\n") if f)

        # Untracked files
        result = self._run_git("ls-files", "--others", "--exclude-standard", check=False)
        files.update(f for f in result.stdout.strip().split("\n") if f)

        return list(files)

    def is_file_tracked(self, file_path: str) -> bool:
        """Check if a file is tracked by git."""
        result = self._run_git("ls-files", file_path, check=False)
        return bool(result.stdout.strip())

    def get_root(self) -> Path:
        """Get the root of the git repository."""
        result = self._run_git("rev-parse", "--show-toplevel")
        return Path(result.stdout.strip())
