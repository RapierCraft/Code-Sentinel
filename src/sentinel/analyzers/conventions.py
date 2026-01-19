"""
Team conventions analyzer.

Reads conventions from .sentinel/conventions.md and enforces them.
Supports both AI-powered and pattern-based convention checking.
"""

import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from ..core.memory import Finding, Severity, Category


@dataclass
class Convention:
    """A team convention rule."""
    id: str
    name: str
    description: str
    pattern: Optional[str] = None  # Regex pattern to detect violations
    file_pattern: Optional[str] = None  # Glob pattern for applicable files
    severity: Severity = Severity.P2
    suggestion: Optional[str] = None


class ConventionsAnalyzer:
    """Analyzer that enforces team conventions."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.conventions: list[Convention] = []
        self._load_conventions()

    def _load_conventions(self) -> None:
        """Load conventions from .sentinel/conventions.md."""
        conventions_path = self.project_root / ".sentinel" / "conventions.md"

        if not conventions_path.exists():
            return

        content = conventions_path.read_text()
        self.conventions = self._parse_conventions(content)

    def _parse_conventions(self, content: str) -> list[Convention]:
        """
        Parse conventions from markdown format.

        Expected format:
        ## Convention Name
        Description of the convention

        - Pattern: `regex_pattern`
        - Files: `*.py`
        - Severity: P1
        - Suggestion: How to fix
        """
        conventions = []
        current = None
        convention_id = 0

        lines = content.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]

            # New convention header
            if line.startswith("## ") and not line.startswith("## Add your"):
                if current:
                    conventions.append(current)

                convention_id += 1
                current = Convention(
                    id=f"CONV-{convention_id:03d}",
                    name=line[3:].strip(),
                    description=""
                )

            elif current:
                # Parse convention attributes
                if line.startswith("- Pattern:"):
                    match = re.search(r'`([^`]+)`', line)
                    if match:
                        current.pattern = match.group(1)

                elif line.startswith("- Files:"):
                    match = re.search(r'`([^`]+)`', line)
                    if match:
                        current.file_pattern = match.group(1)

                elif line.startswith("- Severity:"):
                    severity_str = line.split(":")[1].strip().upper()
                    if severity_str in ("P0", "P1", "P2", "P3"):
                        current.severity = Severity(severity_str)

                elif line.startswith("- Suggestion:"):
                    current.suggestion = line.split(":", 1)[1].strip()

                elif line.strip() and not line.startswith("-") and not line.startswith("#"):
                    # Description line
                    if current.description:
                        current.description += " "
                    current.description += line.strip()

            i += 1

        if current:
            conventions.append(current)

        # Add built-in conventions that are common
        conventions.extend(self._get_builtin_conventions())

        return conventions

    def _get_builtin_conventions(self) -> list[Convention]:
        """Get built-in common conventions."""
        return [
            Convention(
                id="BUILTIN-001",
                name="Function Length",
                description="Functions should be under 50 lines for readability.",
                pattern=None,  # Handled specially
                severity=Severity.P3,
                suggestion="Split into smaller functions."
            ),
            Convention(
                id="BUILTIN-002",
                name="TODO Without Owner",
                description="TODO comments should have an owner or ticket reference.",
                pattern=r'#\s*TODO[^:]',
                severity=Severity.P3,
                suggestion="Add owner: # TODO(name): or # TODO: JIRA-123"
            ),
            Convention(
                id="BUILTIN-003",
                name="Magic Numbers",
                description="Avoid magic numbers; use named constants.",
                pattern=r'(?<!["\'])\b(?:86400|3600|60|1000|1024|255)\b(?!["\'])',
                file_pattern="*.py",
                severity=Severity.P3,
                suggestion="Define as a named constant (e.g., SECONDS_PER_DAY = 86400)"
            ),
            Convention(
                id="BUILTIN-004",
                name="Print Statement in Production",
                description="Use logging instead of print() in production code.",
                pattern=r'^[^#]*\bprint\s*\(',
                file_pattern="*.py",
                severity=Severity.P3,
                suggestion="Use logging.info() or logging.debug() instead."
            ),
            Convention(
                id="BUILTIN-005",
                name="Broad Exception",
                description="Avoid catching broad Exception; be specific.",
                pattern=r'except\s+Exception\s*:',
                file_pattern="*.py",
                severity=Severity.P2,
                suggestion="Catch specific exceptions (e.g., ValueError, KeyError)."
            ),
        ]

    def analyze(self, file_path: str, content: str) -> list[Finding]:
        """Analyze file for convention violations."""
        findings = []
        lines = content.split("\n")

        for convention in self.conventions:
            # Check file pattern match
            if convention.file_pattern:
                from fnmatch import fnmatch
                if not fnmatch(file_path, convention.file_pattern):
                    continue

            # Pattern-based check
            if convention.pattern:
                findings.extend(self._check_pattern(
                    file_path, content, lines, convention
                ))

            # Special checks
            if convention.id == "BUILTIN-001":
                findings.extend(self._check_function_length(
                    file_path, content, lines
                ))

        return findings

    def _check_pattern(
        self,
        file_path: str,
        content: str,
        lines: list[str],
        convention: Convention
    ) -> list[Finding]:
        """Check for pattern violations."""
        findings = []

        try:
            for match in re.finditer(convention.pattern, content, re.MULTILINE):
                line_num = content[:match.start()].count("\n") + 1

                findings.append(Finding(
                    id=None,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    severity=convention.severity,
                    category=Category.CONVENTION,
                    title=f"Convention: {convention.name}",
                    description=convention.description,
                    suggestion=convention.suggestion or "See team conventions.",
                    code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                    detected_by="conventions-analyzer",
                    confidence=0.85
                ))
        except re.error:
            pass  # Invalid regex in convention

        return findings

    def _check_function_length(
        self,
        file_path: str,
        content: str,
        lines: list[str]
    ) -> list[Finding]:
        """Check for functions that are too long."""
        findings = []
        max_lines = 50

        if file_path.endswith(".py"):
            # Find Python functions
            for match in re.finditer(r'^(\s*)def\s+(\w+)\s*\(', content, re.MULTILINE):
                indent = len(match.group(1))
                func_name = match.group(2)
                start_line = content[:match.start()].count("\n")

                # Find function end
                end_line = start_line + 1
                for i in range(start_line + 1, len(lines)):
                    line = lines[i]
                    if line.strip() and not line.startswith(" " * (indent + 1)):
                        if re.match(r"^\s*(def|class|@)", line):
                            end_line = i
                            break
                    end_line = i + 1

                func_length = end_line - start_line
                if func_length > max_lines:
                    findings.append(Finding(
                        id=None,
                        file_path=file_path,
                        line_start=start_line + 1,
                        line_end=end_line,
                        severity=Severity.P3,
                        category=Category.CONVENTION,
                        title=f"Function Too Long: {func_name}",
                        description=f"Function '{func_name}' is {func_length} lines (max: {max_lines}).",
                        suggestion="Split into smaller, focused functions.",
                        code_snippet=f"def {func_name}(...)  # {func_length} lines",
                        detected_by="conventions-analyzer",
                        confidence=0.95
                    ))

        return findings

    def reload(self) -> None:
        """Reload conventions from file."""
        self._load_conventions()

    def get_conventions(self) -> list[Convention]:
        """Get all loaded conventions."""
        return self.conventions

    def add_convention(self, convention: Convention) -> None:
        """Add a new convention programmatically."""
        self.conventions.append(convention)

    def to_markdown(self) -> str:
        """Export conventions to markdown format."""
        lines = ["# Team Conventions\n"]

        for conv in self.conventions:
            if conv.id.startswith("BUILTIN"):
                continue  # Skip built-ins

            lines.append(f"## {conv.name}")
            lines.append(conv.description)
            lines.append("")

            if conv.pattern:
                lines.append(f"- Pattern: `{conv.pattern}`")
            if conv.file_pattern:
                lines.append(f"- Files: `{conv.file_pattern}`")
            lines.append(f"- Severity: {conv.severity.value}")
            if conv.suggestion:
                lines.append(f"- Suggestion: {conv.suggestion}")
            lines.append("")

        return "\n".join(lines)
