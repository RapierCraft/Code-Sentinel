"""
Dead code analyzer.

Detects:
- Unused imports
- Unused variables
- Unused functions/classes
- Unreachable code
- Empty exception handlers
"""

import re
from pathlib import Path
from typing import Optional

from ..core.memory import Finding, Severity, Category


class DeadCodeAnalyzer:
    """Analyzer for detecting dead/unused code."""

    def __init__(self):
        self.findings = []

    def analyze(self, file_path: str, content: str) -> list[Finding]:
        """Analyze file for dead code patterns."""
        findings = []
        lines = content.split("\n")

        # Detect based on file type
        if file_path.endswith(".py"):
            findings.extend(self._analyze_python(file_path, content, lines))
        elif file_path.endswith((".js", ".ts", ".tsx", ".jsx")):
            findings.extend(self._analyze_javascript(file_path, content, lines))

        return findings

    def _analyze_python(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        """Analyze Python file for dead code."""
        findings = []

        # Find all imports
        imports = self._extract_python_imports(content)

        # Check for unused imports
        for imp_name, line_num in imports:
            # Count usages (excluding the import line itself)
            pattern = rf'\b{re.escape(imp_name)}\b'
            matches = list(re.finditer(pattern, content))

            # Filter out matches on the import line
            usages = [m for m in matches if content[:m.start()].count('\n') + 1 != line_num]

            if not usages:
                findings.append(Finding(
                    id=None,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.P3,
                    category=Category.DEAD_CODE,
                    title="Unused Import",
                    description=f"'{imp_name}' is imported but never used.",
                    suggestion=f"Remove unused import: {imp_name}",
                    code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                    detected_by="dead-code-analyzer",
                    confidence=0.85
                ))

        # Check for unused variables (assigned but never read)
        findings.extend(self._find_unused_python_vars(file_path, content, lines))

        # Check for unreachable code after return/raise
        findings.extend(self._find_unreachable_code(file_path, content, lines))

        # Check for empty except blocks
        findings.extend(self._find_empty_except(file_path, content, lines))

        # Check for pass in non-abstract methods
        findings.extend(self._find_pass_statements(file_path, content, lines))

        return findings

    def _extract_python_imports(self, content: str) -> list[tuple[str, int]]:
        """Extract imported names and their line numbers."""
        imports = []

        # import x, y
        for match in re.finditer(r'^import\s+(.+)$', content, re.MULTILINE):
            line_num = content[:match.start()].count('\n') + 1
            for name in match.group(1).split(','):
                name = name.strip()
                if ' as ' in name:
                    name = name.split(' as ')[1].strip()
                imports.append((name.split('.')[0], line_num))

        # from x import y, z
        for match in re.finditer(r'^from\s+[\w.]+\s+import\s+(.+)$', content, re.MULTILINE):
            line_num = content[:match.start()].count('\n') + 1
            names_str = match.group(1)

            # Handle multiline imports
            if '(' in names_str and ')' not in names_str:
                continue  # Skip multiline for now

            for name in names_str.split(','):
                name = name.strip()
                if name == '*':
                    continue
                if ' as ' in name:
                    name = name.split(' as ')[1].strip()
                if name and name not in (')', '('):
                    imports.append((name, line_num))

        return imports

    def _find_unused_python_vars(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        """Find variables that are assigned but never used."""
        findings = []

        # Find all assignments
        assignments = []
        for match in re.finditer(r'^(\s*)(\w+)\s*=\s*(?!.*=)', content, re.MULTILINE):
            var_name = match.group(2)
            line_num = content[:match.start()].count('\n') + 1

            # Skip special cases
            if var_name.startswith('_') or var_name.isupper():
                continue
            if var_name in ('self', 'cls', 'args', 'kwargs'):
                continue

            assignments.append((var_name, line_num))

        # Check usage (simplified - only checks basic references)
        for var_name, line_num in assignments:
            pattern = rf'\b{re.escape(var_name)}\b'
            matches = list(re.finditer(pattern, content))

            # Filter out the assignment itself and count remaining
            usages = [m for m in matches if content[:m.start()].count('\n') + 1 != line_num]

            if not usages:
                findings.append(Finding(
                    id=None,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.P3,
                    category=Category.DEAD_CODE,
                    title="Potentially Unused Variable",
                    description=f"Variable '{var_name}' may be assigned but never used.",
                    suggestion=f"Remove unused variable or use it: {var_name}",
                    code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                    detected_by="dead-code-analyzer",
                    confidence=0.6  # Lower confidence - could be false positive
                ))

        return findings

    def _find_unreachable_code(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        """Find code after return/raise/break/continue."""
        findings = []

        for match in re.finditer(r'^(\s*)(return|raise|break|continue)\b[^\n]*\n(\1\s+\S)', content, re.MULTILINE):
            line_num = content[:match.start()].count('\n') + 1
            keyword = match.group(2)

            findings.append(Finding(
                id=None,
                file_path=file_path,
                line_start=line_num + 1,
                line_end=line_num + 1,
                severity=Severity.P2,
                category=Category.DEAD_CODE,
                title="Unreachable Code",
                description=f"Code after '{keyword}' will never execute.",
                suggestion="Remove unreachable code or fix control flow.",
                code_snippet="\n".join(lines[line_num - 1:line_num + 2]) if line_num <= len(lines) else "",
                detected_by="dead-code-analyzer",
                confidence=0.9
            ))

        return findings

    def _find_empty_except(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        """Find empty except blocks."""
        findings = []

        for match in re.finditer(r'except[^:]*:\s*\n(\s*)pass\s*$', content, re.MULTILINE):
            line_num = content[:match.start()].count('\n') + 1

            findings.append(Finding(
                id=None,
                file_path=file_path,
                line_start=line_num,
                line_end=line_num + 1,
                severity=Severity.P2,
                category=Category.CODE_SMELL,
                title="Empty Exception Handler",
                description="Exception is caught but ignored. This can hide bugs.",
                suggestion="Log the exception or handle it properly. At minimum: logging.exception('...')",
                code_snippet="\n".join(lines[line_num - 1:line_num + 2]) if line_num <= len(lines) else "",
                detected_by="dead-code-analyzer",
                confidence=0.95
            ))

        return findings

    def _find_pass_statements(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        """Find pass statements that might indicate incomplete code."""
        findings = []

        # Find pass in function bodies (not abstract methods or protocols)
        for match in re.finditer(r'^(\s*)def\s+(\w+)[^:]+:\s*\n\1\s+(["\'].*["\'])?\s*\n?\1\s+pass\s*$', content, re.MULTILINE):
            func_name = match.group(2)
            line_num = content[:match.start()].count('\n') + 1

            # Skip likely abstract methods
            if func_name.startswith('_'):
                continue

            findings.append(Finding(
                id=None,
                file_path=file_path,
                line_start=line_num,
                line_end=line_num + 2,
                severity=Severity.P3,
                category=Category.DEAD_CODE,
                title="Empty Function",
                description=f"Function '{func_name}' has only pass statement.",
                suggestion="Implement the function or mark as abstract/TODO.",
                code_snippet="\n".join(lines[line_num - 1:line_num + 3]) if line_num <= len(lines) else "",
                detected_by="dead-code-analyzer",
                confidence=0.7
            ))

        return findings

    def _analyze_javascript(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        """Analyze JavaScript/TypeScript file for dead code."""
        findings = []

        # Find unused imports
        imports = self._extract_js_imports(content)

        for imp_name, line_num in imports:
            pattern = rf'\b{re.escape(imp_name)}\b'
            matches = list(re.finditer(pattern, content))

            # Filter out the import line
            usages = [m for m in matches if content[:m.start()].count('\n') + 1 != line_num]

            if not usages:
                findings.append(Finding(
                    id=None,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.P3,
                    category=Category.DEAD_CODE,
                    title="Unused Import",
                    description=f"'{imp_name}' is imported but never used.",
                    suggestion=f"Remove unused import: {imp_name}",
                    code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                    detected_by="dead-code-analyzer",
                    confidence=0.85
                ))

        # Check for console.log in production code
        for match in re.finditer(r'console\.(log|debug|info)\s*\(', content):
            line_num = content[:match.start()].count('\n') + 1

            findings.append(Finding(
                id=None,
                file_path=file_path,
                line_start=line_num,
                line_end=line_num,
                severity=Severity.P3,
                category=Category.CODE_SMELL,
                title="Console Statement",
                description="console.log() left in code. May be debug statement.",
                suggestion="Remove console.log() or use proper logging.",
                code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                detected_by="dead-code-analyzer",
                confidence=0.7
            ))

        return findings

    def _extract_js_imports(self, content: str) -> list[tuple[str, int]]:
        """Extract JavaScript/TypeScript import names."""
        imports = []

        # import { x, y } from 'module'
        for match in re.finditer(r'import\s*\{([^}]+)\}\s*from', content):
            line_num = content[:match.start()].count('\n') + 1
            for name in match.group(1).split(','):
                name = name.strip()
                if ' as ' in name:
                    name = name.split(' as ')[1].strip()
                if name:
                    imports.append((name, line_num))

        # import x from 'module'
        for match in re.finditer(r'import\s+(\w+)\s+from', content):
            line_num = content[:match.start()].count('\n') + 1
            imports.append((match.group(1), line_num))

        # import * as x from 'module'
        for match in re.finditer(r'import\s+\*\s+as\s+(\w+)\s+from', content):
            line_num = content[:match.start()].count('\n') + 1
            imports.append((match.group(1), line_num))

        return imports
