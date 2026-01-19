"""
Core scanning engine for Code Sentinel.

Combines multiple analysis strategies:
- AI-powered analysis (Claude)
- Pattern matching (regex-based detection)
- AST analysis (tree-sitter)
- Security scanning (bandit, secrets)
"""

import os
import re
import hashlib
import subprocess
import fnmatch
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Config
from .memory import Memory, Finding, Severity, Category, Status


# Common security patterns
SECURITY_PATTERNS = [
    # Hardcoded secrets
    (r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*[=:]\s*["\'][^"\']{8,}["\']',
     "Potential hardcoded secret", Severity.P0, Category.SECURITY),

    # SQL Injection
    (r'(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\'].*%s.*["\']',
     "Potential SQL injection (string formatting)", Severity.P0, Category.SECURITY),

    # Dangerous functions
    (r'\beval\s*\(', "Use of eval() - code injection risk", Severity.P1, Category.SECURITY),
    (r'\bexec\s*\(', "Use of exec() - code injection risk", Severity.P1, Category.SECURITY),
    (r'pickle\.loads?\s*\(', "Unsafe pickle deserialization", Severity.P1, Category.SECURITY),
    (r'yaml\.load\s*\([^)]*\)\s*(?!.*Loader)', "Unsafe YAML load without Loader", Severity.P1, Category.SECURITY),

    # XSS patterns
    (r'innerHTML\s*=', "Direct innerHTML assignment - XSS risk", Severity.P1, Category.SECURITY),
    (r'dangerouslySetInnerHTML', "dangerouslySetInnerHTML usage", Severity.P2, Category.SECURITY),

    # Command injection
    (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
     "Shell=True in subprocess - command injection risk", Severity.P1, Category.SECURITY),
    (r'os\.system\s*\(', "os.system() usage - prefer subprocess", Severity.P2, Category.SECURITY),
]

# Code smell patterns
CODE_SMELL_PATTERNS = [
    # TODO/FIXME
    (r'#\s*(TODO|FIXME|HACK|XXX|BUG)[\s:]+(.{10,})',
     "TODO/FIXME comment", Severity.P3, Category.TECH_DEBT),

    # Empty except
    (r'except\s*:\s*(?:pass|\.\.\.)\s*$',
     "Empty except clause - silently swallowing errors", Severity.P2, Category.BUG),

    # Broad exception (only flag bare Exception, not Exception as e which is often intentional)
    (r'except\s+Exception\s*:',
     "Bare except Exception - consider specific exceptions", Severity.P3, Category.STYLE),

    # Console/debug statements
    (r'console\.log\s*\(', "console.log left in code", Severity.P3, Category.TECH_DEBT),
]

# Dead code patterns
DEAD_CODE_PATTERNS = [
    (r'^\s*#.*\n\s*#.*\n\s*#.*code',
     "Commented out code block", Severity.P3, Category.DEAD_CODE),
    (r'if\s+(?:False|0)\s*:', "Dead code: if False", Severity.P2, Category.DEAD_CODE),
    (r'if\s+__name__\s*==\s*["\']__main__["\']\s*:\s*pass',
     "Empty main block", Severity.P3, Category.DEAD_CODE),
]


@dataclass
class FileAnalysis:
    """Result of analyzing a single file."""

    file_path: str
    content_hash: str
    findings: list[Finding]
    error: Optional[str] = None


class Scanner:
    """Main scanning engine."""

    def __init__(self, config: Config, memory: Memory):
        self.config = config
        self.memory = memory
        self.ai_client = None

    def scan_directory(
        self,
        directory: Optional[Path] = None,
        incremental: bool = True,
        trigger: str = "manual"
    ) -> list[Finding]:
        """
        Scan a directory for issues.

        Args:
            directory: Directory to scan (default: project root)
            incremental: Only scan changed files
            trigger: What triggered this scan (manual, watch, ci)

        Returns:
            List of new findings
        """
        directory = directory or self.config.project_root

        # Start scan record
        scan_id = self.memory.start_scan(
            mode="incremental" if incremental else "full",
            trigger=trigger
        )

        start_time = __import__("time").time()
        all_findings = []
        files_scanned = 0

        # Get files to scan
        files = list(self._get_scannable_files(directory))

        if incremental:
            files = [f for f in files if self._file_changed(f)]

        # Scan files in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.scan_file, f): f
                for f in files[:self.config.scan.max_files_per_scan]
            }

            for future in as_completed(futures):
                result = future.result()
                if result and not result.error:
                    files_scanned += 1
                    for finding in result.findings:
                        # Check if suppressed
                        if not self.memory.is_suppressed(
                            finding.file_path,
                            finding.line_start,
                            finding.category.value
                        ):
                            finding_id = self.memory.add_finding(finding)
                            finding.id = finding_id
                            all_findings.append(finding)

                    # Update file hash
                    self.memory.update_file_hash(
                        result.file_path,
                        result.content_hash,
                        len(result.findings)
                    )

        # Complete scan record
        duration = __import__("time").time() - start_time
        self.memory.complete_scan(
            scan_id=scan_id,
            files_scanned=files_scanned,
            findings_new=len(all_findings),
            findings_fixed=0,  # TODO: detect fixed findings
            issues_created=0,
            duration_seconds=duration
        )

        return all_findings

    def scan_file(self, file_path: Path) -> Optional[FileAnalysis]:
        """Scan a single file for issues."""
        try:
            # Check file size
            if file_path.stat().st_size > self.config.scan.max_file_size_kb * 1024:
                return None

            content = file_path.read_text(errors="ignore")
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            findings = []
            rel_path = str(file_path.relative_to(self.config.project_root))

            # Skip if file matches exclude patterns (self-exclusion)
            if any(fnmatch.fnmatch(rel_path, pat) for pat in self.config.scan.exclude_patterns):
                return FileAnalysis(
                    file_path=rel_path,
                    content_hash=content_hash,
                    findings=[]
                )

            # Run pattern-based analysis
            findings.extend(self._scan_patterns(rel_path, content))

            # Run security scanning if enabled
            if self.config.scan.security_enabled:
                findings.extend(self._scan_security(rel_path, content, file_path))

            return FileAnalysis(
                file_path=rel_path,
                content_hash=content_hash,
                findings=findings
            )

        except Exception as e:
            return FileAnalysis(
                file_path=str(file_path),
                content_hash="",
                findings=[],
                error=str(e)
            )

    def scan_with_ai(
        self,
        file_path: Path,
        focus: Optional[str] = None
    ) -> list[Finding]:
        """
        Scan a file using AI analysis.

        Args:
            file_path: Path to file
            focus: Optional focus area (security, performance, etc.)

        Returns:
            List of AI-detected findings
        """
        content = file_path.read_text(errors="ignore")
        rel_path = str(file_path.relative_to(self.config.project_root))

        # Load conventions if available
        conventions = self._load_conventions()

        prompt = self._build_ai_prompt(rel_path, content, focus, conventions)

        # Call Claude (via Claude Code CLI or direct API)
        response = self._call_ai(prompt)

        # Parse response into findings
        return self._parse_ai_response(response, rel_path)

    def _get_scannable_files(self, directory: Path) -> Generator[Path, None, None]:
        """Get all files that should be scanned."""
        # Determine which directories to scan
        scan_roots = []
        if self.config.scan.include_dirs:
            for include_dir in self.config.scan.include_dirs:
                include_path = directory / include_dir
                if include_path.exists():
                    scan_roots.append(include_path)

        # If no include_dirs match, fall back to scanning entire directory
        if not scan_roots:
            scan_roots = [directory]

        for scan_root in scan_roots:
            for root, dirs, files in os.walk(scan_root):
                # Filter out excluded directories
                dirs[:] = [
                    d for d in dirs
                    if not any(
                        fnmatch.fnmatch(d, pat.split("/")[0])
                        for pat in self.config.scan.exclude_patterns
                    )
                ]

                for file in files:
                    file_path = Path(root) / file

                    # Check extension
                    if file_path.suffix not in self.config.scan.extensions:
                        continue

                    # Check exclude patterns
                    rel_path = str(file_path.relative_to(directory))
                    if any(fnmatch.fnmatch(rel_path, pat) for pat in self.config.scan.exclude_patterns):
                        continue

                    yield file_path

    def _file_changed(self, file_path: Path) -> bool:
        """Check if file has changed since last scan."""
        try:
            content = file_path.read_text(errors="ignore")
            current_hash = hashlib.sha256(content.encode()).hexdigest()
            stored_hash = self.memory.get_file_hash(
                str(file_path.relative_to(self.config.project_root))
            )
            return current_hash != stored_hash
        except Exception:
            return True

    def _scan_patterns(self, file_path: str, content: str) -> list[Finding]:
        """Scan content using regex patterns."""
        findings = []
        lines = content.split("\n")

        all_patterns = SECURITY_PATTERNS + CODE_SMELL_PATTERNS + DEAD_CODE_PATTERNS

        for pattern, title, severity, category in all_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                # Find line number
                line_num = content[:match.start()].count("\n") + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                # Skip false positives: pattern definitions in strings
                if self._is_pattern_definition(line_content, match.group()):
                    continue

                # Get code snippet
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 2)
                snippet = "\n".join(lines[start_line:end_line])

                findings.append(Finding(
                    id=None,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    severity=severity,
                    category=category,
                    title=title,
                    description=f"Pattern match: {match.group()[:100]}",
                    suggestion=None,
                    code_snippet=snippet,
                    detected_by="pattern"
                ))

        return findings

    def _is_pattern_definition(self, line: str, match_text: str) -> bool:
        """Check if a match is inside a pattern/regex definition (false positive)."""
        # Skip if line is a regex pattern definition (starts with pattern syntax)
        stripped = line.strip()
        if stripped.startswith("(r'") or stripped.startswith('(r"'):
            return True
        if stripped.startswith("r'") or stripped.startswith('r"'):
            return True
        # Skip if match is inside a raw string (common for patterns)
        if re.search(r"r['\"].*" + re.escape(match_text[:20]), line):
            return True
        # Skip comment lines that are documenting patterns
        if stripped.startswith("#") and ("pattern" in stripped.lower() or "regex" in stripped.lower()):
            return True
        # Skip if line contains "pattern" variable assignment
        if re.match(r"^\s*\w*[Pp]attern", stripped):
            return True
        return False

    def _scan_security(
        self,
        file_path: str,
        content: str,
        abs_path: Path
    ) -> list[Finding]:
        """Run security-specific scans."""
        findings = []

        # Secret scanning
        if self.config.scan.secret_scanning:
            findings.extend(self._scan_secrets(file_path, content))

        # Python-specific: bandit
        if abs_path.suffix == ".py":
            findings.extend(self._run_bandit(file_path, abs_path))

        return findings

    def _scan_secrets(self, file_path: str, content: str) -> list[Finding]:
        """Scan for hardcoded secrets."""
        findings = []

        secret_patterns = [
            (r'(?i)aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\s*[=:]\s*["\']?[\w/+=]{20,}',
             "AWS credentials"),
            (r'(?i)github[_-]?(?:token|pat)\s*[=:]\s*["\']?(?:ghp_|gho_|ghu_|ghs_|ghr_)[\w]{36,}',
             "GitHub token"),
            (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\'][\w-]{20,}["\']',
             "API key"),
            (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
             "Private key"),
            (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
             "Hardcoded password"),
        ]

        lines = content.split("\n")
        for pattern, secret_type in secret_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1

                findings.append(Finding(
                    id=None,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.P0,
                    category=Category.SECURITY,
                    title=f"Potential {secret_type} exposed",
                    description="Secrets should not be hardcoded. Use environment variables or a secrets manager.",
                    suggestion="Move to environment variable or secrets manager",
                    code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                    detected_by="secret-scanner"
                ))

        return findings

    def _run_bandit(self, file_path: str, abs_path: Path) -> list[Finding]:
        """Run bandit security scanner on Python files."""
        findings = []

        try:
            result = subprocess.run(
                ["bandit", "-f", "json", "-q", str(abs_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.stdout:
                import json
                data = json.loads(result.stdout)

                for issue in data.get("results", []):
                    severity_map = {
                        "HIGH": Severity.P0,
                        "MEDIUM": Severity.P1,
                        "LOW": Severity.P2,
                    }

                    findings.append(Finding(
                        id=None,
                        file_path=file_path,
                        line_start=issue.get("line_number", 1),
                        line_end=issue.get("line_number", 1),
                        severity=severity_map.get(issue.get("issue_severity", "LOW"), Severity.P2),
                        category=Category.SECURITY,
                        title=issue.get("issue_text", "Security issue"),
                        description=issue.get("more_info", ""),
                        suggestion=None,
                        code_snippet=issue.get("code", ""),
                        detected_by="bandit"
                    ))

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass  # Bandit not installed or failed

        return findings

    def _load_conventions(self) -> str:
        """Load team conventions file if it exists."""
        conv_path = self.config.project_root / self.config.conventions_file
        if conv_path.exists():
            return conv_path.read_text()
        return ""

    def _build_ai_prompt(
        self,
        file_path: str,
        content: str,
        focus: Optional[str],
        conventions: str
    ) -> str:
        """Build prompt for AI analysis."""
        prompt = f"""Analyze this code file for issues. Report findings in JSON format.

File: {file_path}

```
{content[:8000]}  # Truncate for context limits
```

"""
        if conventions:
            prompt += f"""
Team conventions to enforce:
{conventions}

"""

        if focus:
            prompt += f"Focus particularly on: {focus}\n\n"

        prompt += """
Return findings as JSON array:
[
  {
    "line": <line_number>,
    "severity": "P0|P1|P2|P3",
    "category": "security|bug|performance|tech_debt|style|architecture",
    "title": "<short title>",
    "description": "<detailed description>",
    "suggestion": "<how to fix>"
  }
]

Only report real issues, not style preferences. Be specific with line numbers.
If no issues found, return empty array: []
"""
        return prompt

    def _call_ai(self, prompt: str) -> str:
        """Call AI for analysis."""
        if self.config.ai.use_claude_code:
            # Use Claude Code CLI
            try:
                result = subprocess.run(
                    ["claude", "--dangerously-skip-permissions", "-p", prompt],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=str(self.config.project_root)
                )
                return result.stdout
            except Exception as e:
                return f"Error: {e}"
        else:
            # Direct API call
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=self.config.ai.api_key)
                response = client.messages.create(
                    model=self.config.ai.model,
                    max_tokens=self.config.ai.max_tokens,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            except Exception as e:
                return f"Error: {e}"

    def _parse_ai_response(self, response: str, file_path: str) -> list[Finding]:
        """Parse AI response into findings."""
        findings = []

        # Try to extract JSON from response
        import json

        try:
            # Find JSON array in response
            match = re.search(r'\[[\s\S]*\]', response)
            if match:
                data = json.loads(match.group())

                for item in data:
                    severity_map = {
                        "P0": Severity.P0, "P1": Severity.P1,
                        "P2": Severity.P2, "P3": Severity.P3
                    }
                    category_map = {
                        "security": Category.SECURITY,
                        "bug": Category.BUG,
                        "performance": Category.PERFORMANCE,
                        "tech_debt": Category.TECH_DEBT,
                        "style": Category.STYLE,
                        "architecture": Category.ARCHITECTURE,
                    }

                    findings.append(Finding(
                        id=None,
                        file_path=file_path,
                        line_start=item.get("line", 1),
                        line_end=item.get("line", 1),
                        severity=severity_map.get(item.get("severity", "P2"), Severity.P2),
                        category=category_map.get(item.get("category", "style"), Category.STYLE),
                        title=item.get("title", "Issue detected"),
                        description=item.get("description", ""),
                        suggestion=item.get("suggestion"),
                        code_snippet=None,
                        detected_by="ai"
                    ))

        except (json.JSONDecodeError, KeyError):
            pass

        return findings
