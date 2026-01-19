"""
Duplicate code analyzer.

Detects:
- Duplicate functions/methods
- Copy-pasted code blocks
- Similar patterns that could be abstracted
"""

import re
import hashlib
from pathlib import Path
from dataclasses import dataclass
from collections import defaultdict

from ..core.memory import Finding, Severity, Category


@dataclass
class CodeBlock:
    """A block of code for comparison."""
    file_path: str
    line_start: int
    line_end: int
    content: str
    normalized: str  # Whitespace-normalized for comparison
    hash: str


class DuplicateAnalyzer:
    """Analyzer for detecting duplicate/similar code."""

    MIN_LINES = 5  # Minimum lines for a duplicate block
    SIMILARITY_THRESHOLD = 0.85  # 85% similarity = duplicate

    def __init__(self):
        self.blocks: list[CodeBlock] = []
        self.function_hashes: dict[str, list[tuple[str, int, str]]] = defaultdict(list)

    def analyze(self, file_path: str, content: str) -> list[Finding]:
        """Analyze a single file for internal duplicates."""
        findings = []
        lines = content.split("\n")

        # Find duplicate code blocks within file
        findings.extend(self._find_internal_duplicates(file_path, content, lines))

        # Find repeated patterns
        findings.extend(self._find_repeated_patterns(file_path, content, lines))

        return findings

    def analyze_codebase(self, files: dict[str, str]) -> list[Finding]:
        """Analyze entire codebase for cross-file duplicates."""
        findings = []

        # Extract all function bodies
        all_functions = []
        for file_path, content in files.items():
            if file_path.endswith(".py"):
                all_functions.extend(self._extract_python_functions(file_path, content))
            elif file_path.endswith((".js", ".ts", ".tsx", ".jsx")):
                all_functions.extend(self._extract_js_functions(file_path, content))

        # Group by normalized hash
        function_groups = defaultdict(list)
        for func in all_functions:
            function_groups[func.hash].append(func)

        # Report duplicates
        for hash_val, group in function_groups.items():
            if len(group) > 1:
                # Multiple functions with same hash = duplicates
                first = group[0]
                for dup in group[1:]:
                    findings.append(Finding(
                        id=None,
                        file_path=dup.file_path,
                        line_start=dup.line_start,
                        line_end=dup.line_end,
                        severity=Severity.P2,
                        category=Category.DUPLICATION,
                        title="Duplicate Function",
                        description=f"This function is identical to one in {first.file_path}:{first.line_start}",
                        suggestion="Extract common code into a shared utility function.",
                        code_snippet=dup.content[:200] + "..." if len(dup.content) > 200 else dup.content,
                        detected_by="duplicate-analyzer",
                        confidence=0.95
                    ))

        # Find similar (but not identical) code blocks
        findings.extend(self._find_similar_blocks(all_functions))

        return findings

    def _find_internal_duplicates(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        """Find duplicate blocks within a single file."""
        findings = []

        # Split into chunks and hash them
        chunk_size = self.MIN_LINES
        chunk_hashes = {}

        for i in range(len(lines) - chunk_size + 1):
            chunk = "\n".join(lines[i:i + chunk_size])
            normalized = self._normalize(chunk)

            if not normalized.strip():
                continue

            chunk_hash = hashlib.md5(normalized.encode()).hexdigest()

            if chunk_hash in chunk_hashes:
                # Found duplicate
                original_line = chunk_hashes[chunk_hash]
                if abs(i - original_line) > chunk_size:  # Not overlapping
                    findings.append(Finding(
                        id=None,
                        file_path=file_path,
                        line_start=i + 1,
                        line_end=i + chunk_size,
                        severity=Severity.P3,
                        category=Category.DUPLICATION,
                        title="Duplicate Code Block",
                        description=f"This code block is duplicated from lines {original_line + 1}-{original_line + chunk_size}",
                        suggestion="Extract into a function or remove duplication.",
                        code_snippet=chunk[:150] + "..." if len(chunk) > 150 else chunk,
                        detected_by="duplicate-analyzer",
                        confidence=0.8
                    ))
            else:
                chunk_hashes[chunk_hash] = i

        return findings

    def _find_repeated_patterns(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        """Find repeated patterns that could be abstracted."""
        findings = []

        # Look for repeated similar lines (common anti-pattern)
        line_patterns = defaultdict(list)

        for i, line in enumerate(lines):
            normalized = self._normalize(line)
            if len(normalized) > 20:  # Significant lines only
                pattern = self._extract_pattern(normalized)
                if pattern:
                    line_patterns[pattern].append(i + 1)

        # Report patterns that repeat too much
        for pattern, line_nums in line_patterns.items():
            if len(line_nums) >= 4:  # 4+ similar lines
                findings.append(Finding(
                    id=None,
                    file_path=file_path,
                    line_start=line_nums[0],
                    line_end=line_nums[-1],
                    severity=Severity.P3,
                    category=Category.DUPLICATION,
                    title="Repeated Pattern",
                    description=f"Similar pattern appears {len(line_nums)} times (lines: {', '.join(map(str, line_nums[:5]))}{'...' if len(line_nums) > 5 else ''})",
                    suggestion="Consider using a loop, list comprehension, or helper function.",
                    code_snippet=lines[line_nums[0] - 1] if line_nums else "",
                    detected_by="duplicate-analyzer",
                    confidence=0.6
                ))

        return findings

    def _extract_python_functions(self, file_path: str, content: str) -> list[CodeBlock]:
        """Extract Python function bodies as code blocks."""
        blocks = []
        lines = content.split("\n")

        for match in re.finditer(r'^(\s*)def\s+\w+\s*\([^)]*\)\s*(?:->.*)?:', content, re.MULTILINE):
            indent = len(match.group(1))
            start_line = content[:match.start()].count('\n')

            # Find end of function
            end_line = start_line + 1
            for i in range(start_line + 1, len(lines)):
                line = lines[i]
                if line.strip() and not line.startswith(' ' * (indent + 1)):
                    if re.match(r'^(\s*)(def|class|@)', line):
                        end_line = i
                        break
                end_line = i + 1

            if end_line - start_line >= self.MIN_LINES:
                func_content = "\n".join(lines[start_line:end_line])
                normalized = self._normalize(func_content)

                blocks.append(CodeBlock(
                    file_path=file_path,
                    line_start=start_line + 1,
                    line_end=end_line,
                    content=func_content,
                    normalized=normalized,
                    hash=hashlib.md5(normalized.encode()).hexdigest()
                ))

        return blocks

    def _extract_js_functions(self, file_path: str, content: str) -> list[CodeBlock]:
        """Extract JavaScript/TypeScript function bodies."""
        blocks = []
        lines = content.split("\n")

        # Match function declarations and arrow functions
        patterns = [
            r'(?:export\s+)?(?:async\s+)?function\s+\w+\s*\([^)]*\)\s*\{',
            r'(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{',
            r'(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?function\s*\([^)]*\)\s*\{',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content):
                start_line = content[:match.start()].count('\n')

                # Find matching closing brace (simplified)
                brace_count = 1
                end_pos = match.end()

                while brace_count > 0 and end_pos < len(content):
                    if content[end_pos] == '{':
                        brace_count += 1
                    elif content[end_pos] == '}':
                        brace_count -= 1
                    end_pos += 1

                end_line = content[:end_pos].count('\n') + 1

                if end_line - start_line >= self.MIN_LINES:
                    func_content = "\n".join(lines[start_line:end_line])
                    normalized = self._normalize(func_content)

                    blocks.append(CodeBlock(
                        file_path=file_path,
                        line_start=start_line + 1,
                        line_end=end_line,
                        content=func_content,
                        normalized=normalized,
                        hash=hashlib.md5(normalized.encode()).hexdigest()
                    ))

        return blocks

    def _find_similar_blocks(self, blocks: list[CodeBlock]) -> list[Finding]:
        """Find blocks that are similar but not identical."""
        findings = []
        reported_pairs = set()

        for i, block1 in enumerate(blocks):
            for block2 in blocks[i + 1:]:
                # Skip same file nearby blocks
                if block1.file_path == block2.file_path:
                    if abs(block1.line_start - block2.line_start) < max(
                        block1.line_end - block1.line_start,
                        block2.line_end - block2.line_start
                    ):
                        continue

                # Skip if already reported identical
                if block1.hash == block2.hash:
                    continue

                # Calculate similarity
                similarity = self._calculate_similarity(block1.normalized, block2.normalized)

                if similarity >= self.SIMILARITY_THRESHOLD:
                    pair_key = tuple(sorted([
                        f"{block1.file_path}:{block1.line_start}",
                        f"{block2.file_path}:{block2.line_start}"
                    ]))

                    if pair_key not in reported_pairs:
                        reported_pairs.add(pair_key)

                        findings.append(Finding(
                            id=None,
                            file_path=block2.file_path,
                            line_start=block2.line_start,
                            line_end=block2.line_end,
                            severity=Severity.P3,
                            category=Category.DUPLICATION,
                            title="Similar Code Block",
                            description=f"{similarity*100:.0f}% similar to {block1.file_path}:{block1.line_start}",
                            suggestion="Consider extracting common logic into a shared function.",
                            code_snippet=block2.content[:150] + "..." if len(block2.content) > 150 else block2.content,
                            detected_by="duplicate-analyzer",
                            confidence=similarity
                        ))

        return findings

    def _normalize(self, code: str) -> str:
        """Normalize code for comparison."""
        # Remove comments
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)  # Python
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)  # JS
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # Multi-line

        # Remove string literals (replace with placeholder)
        code = re.sub(r'(["\'])(?:(?!\1)[^\\]|\\.)*\1', 'STR', code)

        # Normalize whitespace
        code = re.sub(r'\s+', ' ', code)

        # Remove leading/trailing whitespace
        code = code.strip()

        return code

    def _extract_pattern(self, line: str) -> str:
        """Extract a pattern from a line for grouping similar lines."""
        # Replace variable names with placeholders
        pattern = re.sub(r'\b[a-z_][a-z0-9_]*\b', 'VAR', line, flags=re.IGNORECASE)

        # Replace numbers
        pattern = re.sub(r'\b\d+\b', 'NUM', pattern)

        return pattern

    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity ratio between two strings."""
        if not s1 or not s2:
            return 0.0

        # Use simple Jaccard similarity on tokens
        tokens1 = set(s1.split())
        tokens2 = set(s2.split())

        if not tokens1 or not tokens2:
            return 0.0

        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)

        return intersection / union if union > 0 else 0.0
