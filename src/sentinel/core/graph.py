"""
Codebase graph for dependency tracking and impact analysis.

Tracks:
- File dependencies (imports)
- Function/class definitions and usages
- Module relationships
- Change impact radius
"""

import re
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


@dataclass
class Symbol:
    """A code symbol (function, class, variable)."""

    name: str
    kind: str  # function, class, variable, constant
    file_path: str
    line_start: int
    line_end: int
    docstring: Optional[str] = None


@dataclass
class Import:
    """An import statement."""

    module: str
    names: list[str]
    file_path: str
    line: int
    is_relative: bool = False


@dataclass
class FileNode:
    """A file in the codebase graph."""

    path: str
    symbols: list[Symbol] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    lines_of_code: int = 0
    last_modified: Optional[str] = None


class CodeGraph:
    """
    Graph representation of codebase dependencies.

    Enables:
    - Finding unused code (no incoming edges)
    - Impact analysis (what breaks if I change X)
    - Circular dependency detection
    - Module coupling metrics
    """

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.files: dict[str, FileNode] = {}
        self.symbol_index: dict[str, list[Symbol]] = defaultdict(list)

        if HAS_NETWORKX:
            self.graph = nx.DiGraph()
        else:
            self.graph = None
            self._edges: dict[str, set[str]] = defaultdict(set)

    def build(self, files: Optional[list[Path]] = None) -> None:
        """
        Build the codebase graph.

        Args:
            files: Specific files to analyze, or None for all
        """
        if files is None:
            files = self._discover_files()

        for file_path in files:
            self._analyze_file(file_path)

        self._build_dependency_graph()

    def _discover_files(self) -> list[Path]:
        """Discover all source files in the project."""
        extensions = {".py", ".js", ".ts", ".tsx", ".jsx"}
        exclude = {"node_modules", "__pycache__", ".git", "venv", ".venv", "dist", "build"}

        files = []
        for root, dirs, filenames in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in exclude]

            for filename in filenames:
                path = Path(root) / filename
                if path.suffix in extensions:
                    files.append(path)

        return files

    def _analyze_file(self, file_path: Path) -> None:
        """Analyze a single file and extract symbols/imports."""
        try:
            content = file_path.read_text(errors="ignore")
            rel_path = str(file_path.relative_to(self.project_root))

            node = FileNode(
                path=rel_path,
                lines_of_code=len(content.splitlines())
            )

            # Extract based on file type
            if file_path.suffix == ".py":
                node.symbols = self._extract_python_symbols(rel_path, content)
                node.imports = self._extract_python_imports(rel_path, content)
            elif file_path.suffix in {".js", ".ts", ".tsx", ".jsx"}:
                node.symbols = self._extract_js_symbols(rel_path, content)
                node.imports = self._extract_js_imports(rel_path, content)

            self.files[rel_path] = node

            # Index symbols
            for symbol in node.symbols:
                self.symbol_index[symbol.name].append(symbol)

        except Exception:
            pass

    def _extract_python_symbols(self, file_path: str, content: str) -> list[Symbol]:
        """Extract Python function and class definitions."""
        symbols = []
        lines = content.splitlines()

        # Function definitions
        for match in re.finditer(r'^(\s*)def\s+(\w+)\s*\(', content, re.MULTILINE):
            indent = len(match.group(1))
            name = match.group(2)
            line_num = content[:match.start()].count('\n') + 1

            # Find end of function (next definition at same or lower indent, or EOF)
            end_line = len(lines)
            for i in range(line_num, len(lines)):
                if lines[i].strip() and not lines[i].startswith(' ' * (indent + 1)):
                    if re.match(r'^(\s*)(def|class|@)', lines[i]):
                        end_line = i
                        break

            symbols.append(Symbol(
                name=name,
                kind="function",
                file_path=file_path,
                line_start=line_num,
                line_end=end_line
            ))

        # Class definitions
        for match in re.finditer(r'^(\s*)class\s+(\w+)', content, re.MULTILINE):
            name = match.group(2)
            line_num = content[:match.start()].count('\n') + 1

            symbols.append(Symbol(
                name=name,
                kind="class",
                file_path=file_path,
                line_start=line_num,
                line_end=line_num  # Simplified
            ))

        return symbols

    def _extract_python_imports(self, file_path: str, content: str) -> list[Import]:
        """Extract Python import statements."""
        imports = []

        # import module
        for match in re.finditer(r'^import\s+([\w.]+)', content, re.MULTILINE):
            imports.append(Import(
                module=match.group(1),
                names=[match.group(1).split('.')[-1]],
                file_path=file_path,
                line=content[:match.start()].count('\n') + 1
            ))

        # from module import names
        for match in re.finditer(r'^from\s+(\.*)?([\w.]*)\s+import\s+(.+)$', content, re.MULTILINE):
            dots = match.group(1) or ""
            module = match.group(2)
            names_str = match.group(3)

            # Parse names (handle 'as' aliases)
            names = []
            for part in names_str.split(','):
                part = part.strip()
                if ' as ' in part:
                    part = part.split(' as ')[0].strip()
                if part and part != '*':
                    names.append(part)

            imports.append(Import(
                module=module,
                names=names,
                file_path=file_path,
                line=content[:match.start()].count('\n') + 1,
                is_relative=bool(dots)
            ))

        return imports

    def _extract_js_symbols(self, file_path: str, content: str) -> list[Symbol]:
        """Extract JavaScript/TypeScript function and class definitions."""
        symbols = []

        # Function declarations
        for match in re.finditer(r'(?:export\s+)?(?:async\s+)?function\s+(\w+)', content):
            line_num = content[:match.start()].count('\n') + 1
            symbols.append(Symbol(
                name=match.group(1),
                kind="function",
                file_path=file_path,
                line_start=line_num,
                line_end=line_num
            ))

        # Arrow functions assigned to const/let
        for match in re.finditer(r'(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?\(', content):
            line_num = content[:match.start()].count('\n') + 1
            symbols.append(Symbol(
                name=match.group(1),
                kind="function",
                file_path=file_path,
                line_start=line_num,
                line_end=line_num
            ))

        # Class declarations
        for match in re.finditer(r'(?:export\s+)?class\s+(\w+)', content):
            line_num = content[:match.start()].count('\n') + 1
            symbols.append(Symbol(
                name=match.group(1),
                kind="class",
                file_path=file_path,
                line_start=line_num,
                line_end=line_num
            ))

        return symbols

    def _extract_js_imports(self, file_path: str, content: str) -> list[Import]:
        """Extract JavaScript/TypeScript import statements."""
        imports = []

        # import { x, y } from 'module'
        for match in re.finditer(r'import\s*\{([^}]+)\}\s*from\s*[\'"]([^\'"]+)[\'"]', content):
            names = [n.strip().split(' as ')[0].strip() for n in match.group(1).split(',')]
            imports.append(Import(
                module=match.group(2),
                names=names,
                file_path=file_path,
                line=content[:match.start()].count('\n') + 1,
                is_relative=match.group(2).startswith('.')
            ))

        # import x from 'module'
        for match in re.finditer(r'import\s+(\w+)\s+from\s*[\'"]([^\'"]+)[\'"]', content):
            imports.append(Import(
                module=match.group(2),
                names=[match.group(1)],
                file_path=file_path,
                line=content[:match.start()].count('\n') + 1,
                is_relative=match.group(2).startswith('.')
            ))

        return imports

    def _build_dependency_graph(self) -> None:
        """Build the dependency graph from extracted data."""
        for file_path, node in self.files.items():
            # Add file as node
            if self.graph is not None:
                self.graph.add_node(file_path, **{"loc": node.lines_of_code})
            else:
                self._edges[file_path]  # Ensure node exists

            # Add edges for imports
            for imp in node.imports:
                # Try to resolve import to a file
                target = self._resolve_import(file_path, imp)
                if target and target in self.files:
                    if self.graph is not None:
                        self.graph.add_edge(file_path, target)
                    else:
                        self._edges[file_path].add(target)

    def _resolve_import(self, from_file: str, imp: Import) -> Optional[str]:
        """Try to resolve an import to a file path."""
        if imp.is_relative:
            # Relative import
            base_dir = str(Path(from_file).parent)
            module_path = imp.module.replace('.', '/')
            candidates = [
                f"{base_dir}/{module_path}.py",
                f"{base_dir}/{module_path}/index.py",
                f"{base_dir}/{module_path}.ts",
                f"{base_dir}/{module_path}.tsx",
                f"{base_dir}/{module_path}/index.ts",
            ]
        else:
            # Absolute import
            module_path = imp.module.replace('.', '/')
            candidates = [
                f"{module_path}.py",
                f"{module_path}/__init__.py",
                f"src/{module_path}.py",
                f"src/{module_path}/index.ts",
                f"app/{module_path}.py",
            ]

        for candidate in candidates:
            if candidate in self.files:
                return candidate

        return None

    # === Analysis Methods ===

    def get_dependents(self, file_path: str) -> list[str]:
        """Get files that depend on (import) this file."""
        if self.graph is not None:
            return list(self.graph.predecessors(file_path))
        else:
            return [f for f, deps in self._edges.items() if file_path in deps]

    def get_dependencies(self, file_path: str) -> list[str]:
        """Get files that this file depends on (imports)."""
        if self.graph is not None:
            return list(self.graph.successors(file_path))
        else:
            return list(self._edges.get(file_path, set()))

    def get_impact_radius(self, file_path: str, depth: int = 3) -> set[str]:
        """
        Get all files that could be affected by changes to this file.

        Args:
            file_path: The file being changed
            depth: How many levels of dependents to include

        Returns:
            Set of file paths that could be affected
        """
        affected = set()
        current_level = {file_path}

        for _ in range(depth):
            next_level = set()
            for f in current_level:
                dependents = self.get_dependents(f)
                next_level.update(dependents)
            affected.update(next_level)
            current_level = next_level

            if not current_level:
                break

        return affected

    def find_unused_symbols(self) -> list[Symbol]:
        """Find symbols that are defined but never used."""
        # Get all symbol usages across the codebase
        all_content = ""
        for file_path, node in self.files.items():
            try:
                full_path = self.project_root / file_path
                all_content += full_path.read_text(errors="ignore") + "\n"
            except Exception:
                pass

        unused = []
        for name, symbols in self.symbol_index.items():
            # Skip private/dunder methods
            if name.startswith('_'):
                continue

            # Count occurrences (minus definitions)
            pattern = rf'\b{re.escape(name)}\b'
            occurrences = len(re.findall(pattern, all_content))

            # Each symbol is at least defined once
            if occurrences <= len(symbols):
                unused.extend(symbols)

        return unused

    def find_circular_dependencies(self) -> list[list[str]]:
        """Find circular dependency chains."""
        if self.graph is not None and HAS_NETWORKX:
            try:
                cycles = list(nx.simple_cycles(self.graph))
                return [c for c in cycles if len(c) > 1]
            except Exception:
                return []
        else:
            # Simple cycle detection without networkx
            cycles = []
            visited = set()

            def dfs(node: str, path: list[str]) -> None:
                if node in path:
                    cycle_start = path.index(node)
                    cycles.append(path[cycle_start:] + [node])
                    return
                if node in visited:
                    return

                visited.add(node)
                path.append(node)

                for neighbor in self._edges.get(node, set()):
                    dfs(neighbor, path.copy())

            for node in self._edges:
                dfs(node, [])

            return cycles

    def get_coupling_metrics(self) -> dict:
        """Get module coupling metrics."""
        metrics = {
            "total_files": len(self.files),
            "total_symbols": sum(len(n.symbols) for n in self.files.values()),
            "total_imports": sum(len(n.imports) for n in self.files.values()),
            "avg_dependencies": 0,
            "max_dependencies": 0,
            "orphan_files": 0,  # Files with no incoming or outgoing edges
        }

        dep_counts = []
        for file_path in self.files:
            deps = len(self.get_dependencies(file_path))
            dependents = len(self.get_dependents(file_path))
            dep_counts.append(deps)

            if deps == 0 and dependents == 0:
                metrics["orphan_files"] += 1

        if dep_counts:
            metrics["avg_dependencies"] = sum(dep_counts) / len(dep_counts)
            metrics["max_dependencies"] = max(dep_counts)

        return metrics
