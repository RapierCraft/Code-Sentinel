"""
Security-focused code analyzer.

Detects:
- OWASP Top 10 vulnerabilities
- Hardcoded secrets
- Insecure cryptography
- Injection risks
- Insecure dependencies
"""

import re
from pathlib import Path
from typing import Optional

from ..core.memory import Finding, Severity, Category


class SecurityAnalyzer:
    """Analyzer focused on security vulnerabilities."""

    # OWASP patterns by category
    INJECTION_PATTERNS = [
        # SQL Injection
        (r'(?i)(?:execute|query|cursor\.execute)\s*\(\s*[f"\'].*(?:\{|\%s|\+).*["\']',
         "SQL Injection Risk", "String interpolation in SQL query. Use parameterized queries."),

        # Command Injection
        (r'(?i)os\.system\s*\(\s*[f"\']',
         "Command Injection Risk", "User input in os.system(). Use subprocess with list args."),
        (r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True',
         "Shell Injection Risk", "shell=True allows command injection. Use list of arguments."),

        # LDAP Injection
        (r'(?i)ldap\.(?:search|modify)\s*\([^)]*[f"\'].*\{',
         "LDAP Injection Risk", "User input in LDAP query."),

        # XPath Injection
        (r'(?i)\.xpath\s*\(\s*[f"\'].*\{',
         "XPath Injection Risk", "User input in XPath query."),
    ]

    XSS_PATTERNS = [
        (r'innerHTML\s*=\s*(?![\'"]\s*[\'"])',
         "XSS Risk", "Direct innerHTML assignment. Sanitize input or use textContent."),
        (r'document\.write\s*\(',
         "XSS Risk", "document.write() is dangerous. Use DOM manipulation."),
        (r'dangerouslySetInnerHTML',
         "Potential XSS", "Review that input is properly sanitized."),
        (r'v-html\s*=',
         "Potential XSS (Vue)", "v-html can execute scripts. Ensure input is sanitized."),
    ]

    CRYPTO_PATTERNS = [
        (r'(?i)md5\s*\(|hashlib\.md5',
         "Weak Cryptography", "MD5 is cryptographically broken. Use SHA-256 or better."),
        (r'(?i)sha1\s*\(|hashlib\.sha1',
         "Weak Cryptography", "SHA1 is deprecated. Use SHA-256 or better."),
        (r'(?i)DES\s*\(|from\s+Crypto\.Cipher\s+import\s+DES',
         "Weak Cryptography", "DES is insecure. Use AES-256."),
        (r'(?i)random\.(random|randint|choice)\s*\(',
         "Insecure Randomness", "random module is not cryptographically secure. Use secrets module."),
    ]

    SECRET_PATTERNS = [
        (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
         "Hardcoded Password", "Passwords should not be in code. Use environment variables."),
        (r'(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*["\'][^"\']{16,}["\']',
         "Hardcoded API Key", "API keys should not be in code. Use environment variables."),
        (r'(?i)(?:aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?[A-Z0-9]{20}',
         "AWS Access Key", "AWS credentials detected. Use IAM roles or environment variables."),
        (r'(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}',
         "AWS Secret Key", "AWS credentials detected. Use IAM roles or environment variables."),
        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
         "Private Key Exposed", "Private keys should never be in code."),
        (r'ghp_[A-Za-z0-9]{36}',
         "GitHub Token", "GitHub personal access token detected."),
        (r'sk-[A-Za-z0-9]{48}',
         "OpenAI API Key", "OpenAI API key detected."),
    ]

    AUTH_PATTERNS = [
        (r'(?i)verify\s*=\s*False',
         "SSL Verification Disabled", "Disabling SSL verification allows MITM attacks."),
        (r'(?i)(?:password|pwd)\s*==\s*["\']',
         "Hardcoded Password Check", "Don't compare passwords directly. Use secure comparison."),
        (r'(?i)jwt\.decode\s*\([^)]*verify\s*=\s*False',
         "JWT Verification Disabled", "JWT tokens should always be verified."),
    ]

    DESERIALIZATION_PATTERNS = [
        (r'pickle\.loads?\s*\(',
         "Unsafe Deserialization", "pickle can execute arbitrary code. Use JSON for untrusted data."),
        (r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)',
         "Unsafe YAML Load", "yaml.load() is unsafe. Use yaml.safe_load()."),
        (r'eval\s*\(',
         "Code Injection Risk", "eval() executes arbitrary code. Avoid or use ast.literal_eval()."),
        (r'exec\s*\(',
         "Code Injection Risk", "exec() executes arbitrary code. Find an alternative."),
    ]

    def __init__(self):
        self.all_patterns = (
            [(p, t, d, Severity.P0) for p, t, d in self.INJECTION_PATTERNS] +
            [(p, t, d, Severity.P1) for p, t, d in self.XSS_PATTERNS] +
            [(p, t, d, Severity.P1) for p, t, d in self.CRYPTO_PATTERNS] +
            [(p, t, d, Severity.P0) for p, t, d in self.SECRET_PATTERNS] +
            [(p, t, d, Severity.P1) for p, t, d in self.AUTH_PATTERNS] +
            [(p, t, d, Severity.P0) for p, t, d in self.DESERIALIZATION_PATTERNS]
        )

    def analyze(self, file_path: str, content: str) -> list[Finding]:
        """Analyze file content for security issues."""
        findings = []
        lines = content.split("\n")

        for pattern, title, description, severity in self.all_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                line_num = content[:match.start()].count("\n") + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                # Skip false positives: pattern definitions in strings/regexes
                if self._is_false_positive(line_content, match.group()):
                    continue

                # Get context
                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 2)
                snippet = "\n".join(lines[start:end])

                findings.append(Finding(
                    id=None,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    severity=severity,
                    category=Category.SECURITY,
                    title=title,
                    description=description,
                    suggestion=description,
                    code_snippet=snippet,
                    detected_by="security-analyzer",
                    confidence=0.9
                ))

        return findings

    def _is_false_positive(self, line: str, match_text: str) -> bool:
        """Check if a match is a false positive (inside pattern definition)."""
        stripped = line.strip()
        # Skip regex pattern definitions
        if stripped.startswith("(r'") or stripped.startswith('(r"'):
            return True
        if stripped.startswith("r'") or stripped.startswith('r"'):
            return True
        # Skip if inside a raw string pattern
        if re.search(r"r['\"].*" + re.escape(match_text[:15] if len(match_text) > 15 else match_text), line):
            return True
        # Skip pattern variable assignments
        if re.match(r"^\s*\w*[Pp]attern", stripped):
            return True
        # Skip lines that are clearly pattern lists
        if "_PATTERNS" in line or "PATTERNS =" in line:
            return True
        return False

    def scan_dependencies(self, project_root: Path) -> list[Finding]:
        """Scan for vulnerable dependencies."""
        findings = []

        # Check Python requirements
        req_files = list(project_root.glob("**/requirements*.txt"))
        for req_file in req_files:
            # TODO: Check against vulnerability databases
            pass

        # Check package.json
        pkg_files = list(project_root.glob("**/package.json"))
        for pkg_file in pkg_files:
            # TODO: Check against npm audit
            pass

        return findings
