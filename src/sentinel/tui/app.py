"""
Code Sentinel TUI - Dashboard-style interface.

A professional code analysis dashboard with:
- Real-time metrics and health scores
- File browser with issue indicators
- Findings panel with filtering
- Live scan visualization
- Keyboard-driven navigation
"""

import asyncio
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import deque
import random

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, Grid, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, Button, DataTable, ProgressBar,
    Tree, TabbedContent, TabPane, Label, Sparkline, Rule, Input, RichLog
)
from textual.binding import Binding
from textual.reactive import reactive
from textual.timer import Timer
from textual import events
from rich.text import Text
from rich.style import Style
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from io import StringIO

from ..core.config import Config
from ..core.memory import Memory, Severity, Status
from ..core.scanner import Scanner


# Severity colors
SEV_COLORS = {
    "P0": "#ff4444",
    "P1": "#ffaa00",
    "P2": "#4488ff",
    "P3": "#44aa44",
}

SEV_ICONS = {
    "P0": "●",
    "P1": "●",
    "P2": "●",
    "P3": "●",
}


class HealthGauge(Static):
    """Visual health score gauge."""

    score = reactive(100)

    def __init__(self, label: str = "Health", **kwargs):
        super().__init__(**kwargs)
        self.label = label

    def render(self) -> Text:
        # Determine color based on score
        if self.score >= 90:
            color = "#44ff44"
            status = "EXCELLENT"
        elif self.score >= 70:
            color = "#88ff44"
            status = "GOOD"
        elif self.score >= 50:
            color = "#ffff44"
            status = "FAIR"
        elif self.score >= 30:
            color = "#ffaa44"
            status = "POOR"
        else:
            color = "#ff4444"
            status = "CRITICAL"

        # Build gauge
        filled = int(self.score / 5)
        empty = 20 - filled

        gauge = f"[{color}]{'█' * filled}[/][#333]{'░' * empty}[/]"

        return Text.from_markup(
            f"[bold]{self.label}[/]\n"
            f"{gauge} [{color}]{self.score}%[/]\n"
            f"[dim]{status}[/]"
        )


class SeverityBar(Static):
    """Horizontal bar showing severity distribution."""

    def __init__(self, p0: int = 0, p1: int = 0, p2: int = 0, p3: int = 0, **kwargs):
        super().__init__(**kwargs)
        self.p0 = p0
        self.p1 = p1
        self.p2 = p2
        self.p3 = p3

    def update_counts(self, p0: int, p1: int, p2: int, p3: int) -> None:
        self.p0, self.p1, self.p2, self.p3 = p0, p1, p2, p3
        self.refresh()

    def render(self) -> Text:
        total = self.p0 + self.p1 + self.p2 + self.p3
        if total == 0:
            return Text.from_markup("[dim]No issues found[/]")

        width = 40
        p0_w = max(1, int(self.p0 / total * width)) if self.p0 else 0
        p1_w = max(1, int(self.p1 / total * width)) if self.p1 else 0
        p2_w = max(1, int(self.p2 / total * width)) if self.p2 else 0
        p3_w = width - p0_w - p1_w - p2_w

        bar = (
            f"[{SEV_COLORS['P0']}]{'█' * p0_w}[/]"
            f"[{SEV_COLORS['P1']}]{'█' * p1_w}[/]"
            f"[{SEV_COLORS['P2']}]{'█' * p2_w}[/]"
            f"[{SEV_COLORS['P3']}]{'█' * p3_w}[/]"
        )

        legend = (
            f"[{SEV_COLORS['P0']}]● P0:{self.p0}[/]  "
            f"[{SEV_COLORS['P1']}]● P1:{self.p1}[/]  "
            f"[{SEV_COLORS['P2']}]● P2:{self.p2}[/]  "
            f"[{SEV_COLORS['P3']}]● P3:{self.p3}[/]"
        )

        return Text.from_markup(f"{bar}\n{legend}")


class MetricCard(Static):
    """Single metric display card."""

    value = reactive("0")

    def __init__(self, label: str, icon: str = "◆", color: str = "cyan", **kwargs):
        super().__init__(**kwargs)
        self.label = label
        self.icon = icon
        self.color = color

    def render(self) -> Text:
        return Text.from_markup(
            f"[{self.color}]{self.icon}[/] [{self.color} bold]{self.value}[/]\n"
            f"[dim]{self.label}[/]"
        )


class ScanProgress(Static):
    """Animated scan progress indicator."""

    progress = reactive(0)
    status = reactive("Idle")
    is_scanning = reactive(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.animation_frame = 0
        self.scan_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def render(self) -> Text:
        if self.is_scanning:
            self.animation_frame = (self.animation_frame + 1) % len(self.scan_frames)
            spinner = self.scan_frames[self.animation_frame]
            bar_filled = int(self.progress / 2.5)
            bar_empty = 40 - bar_filled
            bar = f"[cyan]{'━' * bar_filled}[/][#333]{'─' * bar_empty}[/]"
            return Text.from_markup(
                f"[cyan]{spinner}[/] [bold]SCANNING[/] {self.progress}%\n"
                f"{bar}\n"
                f"[dim]{self.status}[/]"
            )
        else:
            return Text.from_markup(
                f"[green]✓[/] [bold]READY[/]\n"
                f"[#333]{'─' * 40}[/]\n"
                f"[dim]Press [bold]s[/] to scan[/]"
            )


class FileHealthTree(Tree):
    """File tree with lazy loading - loads children when expanded."""

    SKIP_DIRS = {"node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".next", "site-packages", ".git"}
    CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".c", ".cpp", ".h"}

    def __init__(self, project_root: Path, **kwargs):
        super().__init__(str(project_root.name), **kwargs)
        self.project_root = project_root
        self.file_issues = {}  # path -> issue count
        # Store path data on root
        self.root.data = {"path": project_root, "loaded": False}

    def set_file_issues(self, issues: dict) -> None:
        self.file_issues = issues
        self.refresh()

    def build_tree(self, include_dirs: list[str] = None) -> None:
        """Initialize tree with top-level directories."""
        self.clear()
        self.root.data = {"path": self.project_root, "loaded": False}

        # If include_dirs specified, add those as top level
        if include_dirs:
            found_any = False
            for dir_name in include_dirs:
                dir_path = self.project_root / dir_name
                if dir_path.exists() and dir_path.is_dir():
                    self._add_directory_node(self.root, dir_path)
                    found_any = True
            if found_any:
                self.root.data["loaded"] = True
                self.root.expand()
                return

        # Otherwise load root contents
        self._load_children(self.root)
        self.root.expand()

    def _add_directory_node(self, parent, path: Path) -> None:
        """Add a directory node (lazy - children loaded on expand)."""
        name = path.name
        rel_path = self._get_rel_path(path)

        dir_issues = sum(
            count for p, count in self.file_issues.items()
            if p.startswith(rel_path + "/") or p == rel_path
        )

        if dir_issues > 0:
            icon = f"[{SEV_COLORS['P1']}]📁[/]"
            label = f"{icon} {name} [dim]({dir_issues})[/]"
        else:
            label = f"[cyan]📁[/] {name}"

        # Add as expandable node with path data
        node = parent.add(label, data={"path": path, "loaded": False})

    def _add_file_node(self, parent, path: Path) -> None:
        """Add a file leaf node."""
        rel_path = self._get_rel_path(path)
        issues = self.file_issues.get(rel_path, 0)

        if issues > 0:
            color = SEV_COLORS["P0"] if issues > 5 else SEV_COLORS["P1"] if issues > 2 else SEV_COLORS["P3"]
            parent.add_leaf(f"[{color}]●[/] {path.name} [dim]({issues})[/]", data={"path": path})
        else:
            parent.add_leaf(f"[green]●[/] {path.name}", data={"path": path})

    def _get_rel_path(self, path: Path) -> str:
        """Get relative path string."""
        try:
            return str(path.relative_to(self.project_root))
        except ValueError:
            return path.name

    def _load_children(self, node) -> None:
        """Load children of a directory node."""
        if not node.data or node.data.get("loaded"):
            return

        path = node.data.get("path")
        if not path or not path.is_dir():
            return

        try:
            items = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            for item in items:
                if item.name.startswith("."):
                    continue
                if item.name in self.SKIP_DIRS:
                    continue

                if item.is_dir():
                    self._add_directory_node(node, item)
                elif item.suffix in self.CODE_EXTENSIONS:
                    self._add_file_node(node, item)

            node.data["loaded"] = True
        except PermissionError:
            pass

    def on_tree_node_expanded(self, event: Tree.NodeExpanded) -> None:
        """Lazy load children when node is expanded."""
        node = event.node
        if node.data and not node.data.get("loaded"):
            self._load_children(node)


class FindingsTable(DataTable):
    """Interactive findings table."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True

    def setup(self) -> None:
        self.add_column("", key="sev", width=3)
        self.add_column("Title", key="title", width=35)
        self.add_column("File", key="file", width=30)
        self.add_column("Line", key="line", width=6)

    def load_findings(self, findings: list) -> None:
        self.clear()
        for f in findings:
            sev_color = SEV_COLORS.get(f.severity.value, "white")
            self.add_row(
                Text(SEV_ICONS.get(f.severity.value, "●"), style=sev_color),
                Text(f.title[:33] + "…" if len(f.title) > 35 else f.title),
                Text(f.file_path.split("/")[-1][:28], style="dim"),
                Text(str(f.line_start), style="cyan"),
                key=str(f.id)
            )


class FindingDetail(Static):
    """Detailed view of a single finding."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.finding = None

    def show_finding(self, finding) -> None:
        self.finding = finding
        self.refresh()

    def render(self) -> Text:
        if not self.finding:
            return Text.from_markup("[dim]Select a finding to view details[/]")

        f = self.finding
        sev_color = SEV_COLORS.get(f.severity.value, "white")

        content = f"""[bold {sev_color}]{f.severity.value}[/] [bold]{f.title}[/]

[dim]Category:[/] {f.category.value}
[dim]File:[/] {f.file_path}
[dim]Line:[/] {f.line_start}
[dim]Detected by:[/] {f.detected_by}

[bold]Description[/]
{f.description}

[bold]Suggestion[/]
{f.suggestion or 'No suggestion available'}"""

        if f.code_snippet:
            content += f"\n\n[bold]Code[/]\n[on #1a1a1a]{f.code_snippet}[/]"

        return Text.from_markup(content)


class ChatLog(RichLog):
    """Chat log with better text handling and markdown support."""

    def __init__(self, **kwargs):
        super().__init__(highlight=True, markup=True, wrap=True, **kwargs)
        self.last_message = ""

    def _md_to_rich(self, text: str) -> str:
        """Convert markdown to Rich markup."""
        import re

        # Process line by line for headers and lists
        lines = text.split('\n')
        result = []
        in_code_block = False

        for line in lines:
            # Code blocks
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                if in_code_block:
                    result.append('[on #1a1a2e]')
                else:
                    result.append('[/on #1a1a2e]')
                continue

            if in_code_block:
                result.append(f'[cyan]{line}[/cyan]')
                continue

            # Headers
            if line.startswith('### '):
                result.append(f'[bold cyan]{line[4:]}[/bold cyan]')
                continue
            elif line.startswith('## '):
                result.append(f'[bold yellow]{line[3:]}[/bold yellow]')
                continue
            elif line.startswith('# '):
                result.append(f'[bold magenta]{line[2:]}[/bold magenta]')
                continue

            # Bullet points
            if line.strip().startswith('- '):
                line = '  • ' + line.strip()[2:]
            elif line.strip().startswith('* '):
                line = '  • ' + line.strip()[2:]

            # Bold **text**
            line = re.sub(r'\*\*(.+?)\*\*', r'[bold]\1[/bold]', line)

            # Italic *text* (but not inside bold)
            line = re.sub(r'(?<!\*)\*([^*]+?)\*(?!\*)', r'[italic]\1[/italic]', line)

            # Inline code `text`
            line = re.sub(r'`([^`]+)`', r'[cyan on #1a1a2e]\1[/cyan on #1a1a2e]', line)

            result.append(line)

        return '\n'.join(result)

    def add_message(self, content: str, is_user: bool = False) -> None:
        prefix = "[cyan bold]You:[/cyan bold] " if is_user else "[green bold]Sentinel:[/green bold] "
        formatted = self._md_to_rich(content) if not is_user else content
        self.write(Text.from_markup(f"{prefix}{formatted}"))
        self.write("")  # Add spacing
        self.last_message = content

    def clear_chat(self) -> None:
        self.clear()


class ThinkingIndicator(Static):
    """Animated thinking indicator with queue status."""

    SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.frame_index = 0
        self.is_thinking = False
        self.queue_count = 0

    def on_mount(self) -> None:
        """Start animation timer on mount."""
        self.set_interval(0.1, self._tick)

    def _tick(self) -> None:
        """Animation tick - always runs."""
        if self.is_thinking:
            self.frame_index = (self.frame_index + 1) % len(self.SPINNER_FRAMES)
        self.update(self._render_content())

    def set_thinking(self, thinking: bool) -> None:
        """Set thinking state."""
        self.is_thinking = thinking
        self.update(self._render_content())

    def set_queue(self, count: int) -> None:
        """Set queue count."""
        self.queue_count = count
        self.update(self._render_content())

    def _render_content(self) -> Text:
        if not self.is_thinking and self.queue_count == 0:
            return Text.from_markup("[dim]Ready[/dim]")

        parts = []

        if self.is_thinking:
            spinner = self.SPINNER_FRAMES[self.frame_index]
            parts.append(f"[cyan bold]{spinner} Processing...[/cyan bold]")

        if self.queue_count > 0:
            parts.append(f"[yellow]({self.queue_count} queued)[/yellow]")

        return Text.from_markup(" ".join(parts))


class LogPanel(VerticalScroll):
    """Activity log panel."""

    def add_log(self, message: str, level: str = "info") -> None:
        colors = {"info": "cyan", "warn": "yellow", "error": "red", "success": "green"}
        color = colors.get(level, "white")
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.mount(Static(
            Text.from_markup(f"[dim]{timestamp}[/] [{color}]●[/] {message}")
        ))
        self.scroll_end(animate=False)


class SentinelApp(App):
    """Code Sentinel Dashboard TUI."""

    CSS = """
    Screen {
        background: #0a0a0a;
    }

    #main-container {
        height: 100%;
        padding: 1;
    }

    #top-row {
        height: auto;
        layout: horizontal;
        margin-bottom: 1;
    }

    #health-section {
        width: 1fr;
        height: auto;
        border: round #333;
        padding: 1;
    }

    #metrics-section {
        width: 2fr;
        height: auto;
        border: round #333;
        padding: 1;
        layout: horizontal;
        margin: 0 1;
    }

    #scan-section {
        width: 1fr;
        height: auto;
        border: round #333;
        padding: 1;
    }

    MetricCard {
        width: 1fr;
        height: auto;
        padding: 0 1;
    }

    #panels-row {
        height: 1fr;
        layout: horizontal;
    }

    #left-panel {
        width: 1fr;
        border: round #333;
        height: 100%;
    }

    #center-panel {
        width: 1fr;
        border: round #333;
        height: 100%;
        margin: 0 1;
    }

    #right-panel {
        width: 2fr;
        border: round #333;
        height: 100%;
    }

    .panel-title {
        dock: top;
        background: #1a1a1a;
        padding: 0 1;
        text-style: bold;
        color: #888;
    }

    FindingsTable {
        height: 1fr;
    }

    FindingDetail {
        height: auto;
        max-height: 50%;
        padding: 1;
        border-bottom: solid #333;
    }

    ChatLog {
        height: 1fr;
        padding: 1;
    }

    FileHealthTree {
        height: 1fr;
    }

    SeverityBar {
        margin-top: 1;
    }

    HealthGauge {
        text-align: center;
    }

    #chat-input-container {
        dock: bottom;
        height: auto;
        padding: 1;
        background: #111;
    }

    #chat-input {
        width: 100%;
    }

    #copy-hint {
        text-align: right;
        color: #555;
        height: 1;
        margin-bottom: 0;
    }

    #thinking-indicator {
        height: 1;
        padding: 0 1;
        background: #0a0a0a;
    }

    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "scan", "Scan"),
        Binding("r", "refresh", "Refresh"),
        Binding("f", "focus_findings", "Findings"),
        Binding("d", "show_detail", "Detail"),
        Binding("g", "run_graph", "Graph"),
        Binding("?", "help", "Help"),
        Binding("c", "copy_last", "Copy"),
        Binding("escape", "quit", "Quit"),
    ]

    def __init__(self, project_root: Path = None):
        super().__init__()
        self.project_root = project_root or Path.cwd()
        self.config = None
        self.memory = None
        self.scanner = None
        self.scan_timer: Optional[Timer] = None
        self.message_queue: deque = deque()
        self.is_processing = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Vertical(id="main-container"):
            # Top row - metrics
            with Horizontal(id="top-row"):
                with Container(id="health-section"):
                    yield HealthGauge(label="Code Health", id="health-gauge")

                with Container(id="metrics-section"):
                    yield MetricCard("Files", icon="📁", color="cyan", id="metric-files")
                    yield MetricCard("Issues", icon="⚠", color="yellow", id="metric-findings")
                    yield MetricCard("Fixed", icon="✓", color="green", id="metric-fixed")
                    yield MetricCard("Scans", icon="↻", color="blue", id="metric-scans")

                with Container(id="scan-section"):
                    yield ScanProgress(id="scan-progress")

            # Main panels row
            with Horizontal(id="panels-row"):
                with Container(id="left-panel"):
                    yield Static("FILES", classes="panel-title")
                    yield FileHealthTree(self.project_root, id="file-tree")

                with Container(id="center-panel"):
                    yield Static("FINDINGS", classes="panel-title")
                    yield FindingsTable(id="findings-table")
                    yield SeverityBar(id="severity-bar")

                with Container(id="right-panel"):
                    yield Static("SENTINEL AI", classes="panel-title")
                    yield FindingDetail(id="finding-detail")
                    yield ChatLog(id="chat-panel")
                    yield ThinkingIndicator(id="thinking-indicator")

            # Chat input at bottom
            with Container(id="chat-input-container"):
                yield Static("[dim]Shift+drag to select text[/]", id="copy-hint")
                yield Input(
                    placeholder="Ask Sentinel anything... (or :scan, :help, :clear)",
                    id="chat-input"
                )

        yield Footer()

    def on_mount(self) -> None:
        self.title = "Code Sentinel"
        self.sub_title = str(self.project_root.name)

        # Run startup checks FIRST (before anything else)
        self.run_startup_checks()

        # Initialize sentinel components
        try:
            self.config = Config.load(self.project_root)
            self.config.ensure_dirs()
            self.memory = Memory(self.project_root / ".sentinel" / "memory.db")
            self.scanner = Scanner(self.config, self.memory)

            # Setup components
            table = self.query_one("#findings-table", FindingsTable)
            table.setup()

            # Build file tree
            tree = self.query_one("#file-tree", FileHealthTree)
            tree.build_tree(self.config.scan.include_dirs)

            # Load initial data
            self.refresh_data()

        except Exception as e:
            self.log_message(f"Init error: {e}", "error")
            # Still build file tree even without config
            try:
                tree = self.query_one("#file-tree", FileHealthTree)
                tree.build_tree()
            except Exception:
                pass

        # Welcome message in chat
        chat = self.query_one("#chat-panel", ChatLog)
        chat.add_message(
            "Hey! I'm Sentinel. Ask me anything about your code, "
            "or type [cyan]:scan[/] to find issues. [dim]:help for commands[/]"
        )

        # Animate scan progress
        self.set_interval(0.1, self.animate_scan)

        # Focus chat input
        self.query_one("#chat-input").focus()

    def _find_git_root(self) -> Optional[Path]:
        """Find .git by searching: current dir, parent dirs, then child dirs."""
        root = self.project_root.resolve()

        # 1. Check current directory
        if (root / ".git").exists():
            return root

        # 2. Search UP parent directories
        current = root.parent
        while current != current.parent:
            if (current / ".git").exists():
                return current
            current = current.parent

        # 3. Search DOWN immediate child directories (1 level)
        try:
            for child in root.iterdir():
                if child.is_dir() and not child.name.startswith("."):
                    if (child / ".git").exists():
                        return child
        except PermissionError:
            pass

        # 4. Search DOWN 2 levels deep
        try:
            for child in root.iterdir():
                if child.is_dir() and not child.name.startswith("."):
                    for grandchild in child.iterdir():
                        if grandchild.is_dir() and not grandchild.name.startswith("."):
                            if (grandchild / ".git").exists():
                                return grandchild
        except PermissionError:
            pass

        return None

    def run_startup_checks(self) -> None:
        """Run startup checks and display warnings."""
        warnings = []
        successes = []

        # Check if git is initialized (search up directory tree)
        git_root = self._find_git_root()
        if not git_root:
            warnings.append(("⚠ Git not initialized", "Run 'git init' to enable git integration (blame, history)", "warn"))
        elif git_root != self.project_root:
            # Git found but in parent directory
            successes.append(f"✓ Git found (root: {git_root.name})")
        else:
            successes.append("✓ Git initialized")

        # Check if gh CLI is installed
        if not shutil.which("gh"):
            warnings.append(("⚠ GitHub CLI not found", "Install 'gh' CLI to auto-create issues from findings", "warn"))
        else:
            # Check if gh is authenticated (quick check, no timeout issues)
            try:
                result = subprocess.run(
                    ["gh", "auth", "status"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode != 0:
                    warnings.append(("⚠ GitHub CLI not authenticated", "Run 'gh auth login' to enable auto-issue creation", "warn"))
                else:
                    successes.append("✓ GitHub CLI ready")
            except Exception:
                pass  # Skip if check fails - not critical

        # Check if claude CLI is available (for AI features)
        if not shutil.which("claude"):
            warnings.append(("ℹ Claude CLI not found", "Install Claude Code CLI for AI-powered analysis", "info"))
        else:
            successes.append("✓ Claude CLI ready")

        # Check if .sentinel is initialized
        sentinel_dir = self.project_root / ".sentinel"
        if not sentinel_dir.exists():
            warnings.append(("⚠ Sentinel not initialized", "Press 's' to run first scan and initialize", "warn"))
        else:
            successes.append("✓ Sentinel initialized")

        # Display successes as notification
        if successes:
            self.notify(" | ".join(successes), severity="information", timeout=4)
            self.sub_title = " | ".join(successes)

        # Display warnings as notifications
        if warnings:
            for title, desc, level in warnings:
                self.notify(f"{title}: {desc}", severity="warning" if level == "warn" else "information", timeout=5)

    def refresh_data(self) -> None:
        """Refresh all data displays."""
        if not self.memory:
            return

        stats = self.memory.get_stats()

        # Update metrics
        self.query_one("#metric-files", MetricCard).value = str(stats.get("files_scanned", 0))
        self.query_one("#metric-findings", MetricCard).value = str(stats["total_open"])
        self.query_one("#metric-fixed", MetricCard).value = str(stats["total_fixed"])
        self.query_one("#metric-scans", MetricCard).value = str(stats["total_scans"])

        # Update health gauge
        health = self.query_one("#health-gauge", HealthGauge)
        total_issues = stats["total_open"]
        p0_weight = stats["open_p0"] * 25
        p1_weight = stats["open_p1"] * 10
        p2_weight = stats["open_p2"] * 3
        p3_weight = stats["open_p3"] * 1
        penalty = min(100, p0_weight + p1_weight + p2_weight + p3_weight)
        health.score = max(0, 100 - penalty)

        # Update severity bar
        severity_bar = self.query_one("#severity-bar", SeverityBar)
        severity_bar.update_counts(
            stats["open_p0"], stats["open_p1"],
            stats["open_p2"], stats["open_p3"]
        )

        # Load findings into table
        findings = self.memory.get_findings(
            status=[Status.DETECTED, Status.REPORTED, Status.ACKNOWLEDGED],
            limit=50
        )
        table = self.query_one("#findings-table", FindingsTable)
        table.load_findings(findings)

        # Update file tree with issue counts
        file_issues = {}
        for f in findings:
            file_issues[f.file_path] = file_issues.get(f.file_path, 0) + 1

        tree = self.query_one("#file-tree", FileHealthTree)
        tree.set_file_issues(file_issues)

    def animate_scan(self) -> None:
        """Animate the scan progress indicator."""
        progress = self.query_one("#scan-progress", ScanProgress)
        if progress.is_scanning:
            progress.refresh()

    async def action_scan(self) -> None:
        """Run a full scan."""
        if not self.scanner:
            self.log_message("Scanner not initialized", "error")
            return

        progress = self.query_one("#scan-progress", ScanProgress)
        progress.is_scanning = True
        progress.progress = 0
        progress.status = "Starting scan..."

        self.log_message("Starting full scan...", "info")

        # Run scan in background
        try:
            # Simulate progress updates
            for i in range(0, 101, 10):
                progress.progress = i
                progress.status = f"Scanning... ({i}%)"
                await asyncio.sleep(0.1)

            # Actually run scan
            findings = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.scanner.scan_directory(incremental=False)
            )

            progress.progress = 100
            progress.status = "Complete!"
            await asyncio.sleep(0.5)

            self.log_message(f"Scan complete: {len(findings)} findings", "success")
            self.refresh_data()

        except Exception as e:
            self.log_message(f"Scan error: {e}", "error")

        finally:
            progress.is_scanning = False

    def action_refresh(self) -> None:
        """Refresh data."""
        self.refresh_data()
        self.log_message("Data refreshed", "info")

    def action_focus_findings(self) -> None:
        """Focus the findings table."""
        self.query_one("#findings-table").focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle finding selection."""
        if not self.memory or not event.row_key:
            return

        try:
            finding_id = int(str(event.row_key.value))
            finding = self.memory.get_finding(finding_id)
            if finding:
                detail = self.query_one("#finding-detail", FindingDetail)
                detail.show_finding(finding)
        except (ValueError, AttributeError):
            pass

    def action_run_graph(self) -> None:
        """Run graph analysis."""
        self.log_message("Building dependency graph...", "info")
        # TODO: Implement graph view

    def action_help(self) -> None:
        """Show help."""
        chat = self.query_one("#chat-panel", ChatLog)
        help_text = """[bold]Commands:[/]
:scan - Run full scan
:quick - Quick incremental scan
:clear - Clear chat
:help - Show this help

[bold]Keys:[/]
s - Scan  r - Refresh  c - Copy  f - Findings  q - Quit

[bold]Copy text:[/]
Hold [bold]Shift[/] + drag mouse to select & copy

[dim]Or just ask me anything about your code![/]"""
        chat.add_message(help_text)

    def action_copy_last(self) -> None:
        """Copy last chat message to clipboard."""
        try:
            chat = self.query_one("#chat-panel", ChatLog)
            if chat.last_message:
                content = chat.last_message

                # Try to copy to clipboard
                try:
                    import pyperclip
                    pyperclip.copy(content)
                    self.notify("Copied to clipboard!", severity="information", timeout=2)
                except ImportError:
                    # Fallback: write to temp file
                    tmp_file = Path("/tmp/sentinel_copy.txt")
                    tmp_file.write_text(content)
                    self.notify(f"Saved to {tmp_file}", severity="information", timeout=2)
            else:
                self.notify("No messages to copy", severity="information", timeout=2)
        except Exception as e:
            self.notify(f"Copy failed: {e}", severity="error")

    def log_message(self, message: str, level: str = "info") -> None:
        """Add message to log."""
        self.sub_title = message

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle chat input with message queuing."""
        user_input = event.value.strip()
        if not user_input:
            return

        event.input.value = ""
        chat = self.query_one("#chat-panel", ChatLog)
        thinking = self.query_one("#thinking-indicator", ThinkingIndicator)

        # Handle commands immediately
        if user_input.startswith(":"):
            await self.handle_chat_command(user_input)
            return

        # Show user message
        chat.add_message(user_input, is_user=True)

        # Queue the message
        self.message_queue.append(user_input)
        thinking.set_queue(len(self.message_queue))

        # Start processing if not already
        if not self.is_processing:
            asyncio.create_task(self.process_message_queue())

    async def process_message_queue(self) -> None:
        """Process queued messages sequentially."""
        if self.is_processing:
            return

        self.is_processing = True
        thinking = self.query_one("#thinking-indicator", ThinkingIndicator)

        while self.message_queue:
            question = self.message_queue.popleft()
            thinking.set_queue(len(self.message_queue))
            thinking.set_thinking(True)

            await self.ask_claude(question)

            thinking.set_thinking(False)

        self.is_processing = False

    async def handle_chat_command(self, command: str) -> None:
        """Handle chat commands."""
        chat = self.query_one("#chat-panel", ChatLog)
        cmd = command.lower()

        if cmd == ":clear":
            chat.clear_chat()
            chat.add_message("Chat cleared. How can I help?")
        elif cmd == ":help":
            self.action_help()
        elif cmd == ":scan":
            chat.add_message("Starting full scan...", is_user=False)
            await self.action_scan()
        elif cmd == ":quick":
            chat.add_message("Starting quick scan...", is_user=False)
            await self.run_quick_scan()
        else:
            chat.add_message(f"Unknown command: {cmd}. Try :help")

    async def run_quick_scan(self) -> None:
        """Run incremental scan."""
        if not self.scanner:
            return

        progress = self.query_one("#scan-progress", ScanProgress)
        progress.is_scanning = True
        progress.status = "Quick scan..."

        try:
            findings = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.scanner.scan_directory(incremental=True)
            )
            self.refresh_data()

            chat = self.query_one("#chat-panel", ChatLog)
            if findings:
                chat.add_message(f"Found {len(findings)} new issues.")
            else:
                chat.add_message("No new issues found!")

        except Exception as e:
            self.log_message(f"Scan error: {e}", "error")
        finally:
            progress.is_scanning = False

    async def ask_claude(self, question: str) -> None:
        """Ask Claude Code about the codebase."""
        chat = self.query_one("#chat-panel", ChatLog)

        try:
            # Build context-aware prompt
            stats = self.memory.get_stats() if self.memory else {}

            prompt = f"""You are Code Sentinel, an AI code auditor assistant.
Project: {self.project_root}
Open issues: {stats.get('total_open', 0)} (P0:{stats.get('open_p0', 0)}, P1:{stats.get('open_p1', 0)}, P2:{stats.get('open_p2', 0)}, P3:{stats.get('open_p3', 0)})

User question: {question}

Be helpful and concise. If they ask to fix something, provide specific code changes. If they ask about the codebase, analyze relevant files."""

            # Call Claude Code CLI (-p for print mode, prompt as positional arg)
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["claude", "--print", "--dangerously-skip-permissions", prompt],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=str(self.project_root)
                )
            )

            if result.returncode == 0 and result.stdout.strip():
                # Truncate very long responses for TUI
                response = result.stdout.strip()
                if len(response) > 2000:
                    response = response[:2000] + "\n\n[dim]... (truncated)[/]"
                chat.add_message(response)
            else:
                error = result.stderr.strip() if result.stderr else "No response"
                chat.add_message(f"[yellow]Claude returned no output. Error: {error[:200]}[/]")

        except subprocess.TimeoutExpired:
            chat.add_message("[yellow]Request timed out. Try a simpler question.[/]")
        except FileNotFoundError:
            chat.add_message("[red]Claude CLI not found.[/] Install with: npm install -g @anthropic-ai/claude-code")
        except Exception as e:
            chat.add_message(f"[red]Error: {str(e)[:100]}[/]")


def run_tui(project_root: Path = None) -> None:
    """Run the TUI application."""
    app = SentinelApp(project_root=project_root)
    app.run()
