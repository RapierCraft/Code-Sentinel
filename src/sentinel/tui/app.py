"""Main TUI application for Code Sentinel."""

import asyncio
import subprocess
from pathlib import Path
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, VerticalScroll
from textual.widgets import Header, Footer, Static, Input, Button
from textual.binding import Binding
from rich.text import Text
from rich.panel import Panel
from rich.markdown import Markdown

from ..core.config import Config
from ..core.memory import Memory
from ..core.scanner import Scanner


MASCOT = """
    [cyan]▄▄▄▄▄▄▄[/]
   [cyan]█[/][white]░░░░░[/][cyan]█[/]
   [cyan]█[/][bright_white]●[/] [white]░[/] [bright_white]●[/][cyan]█[/]
   [cyan]█[/][white]░[/][yellow]▄▄▄[/][white]░[/][cyan]█[/]
   [cyan]█[/][white]░░░░░[/][cyan]█[/]
   [cyan]▀▀▀▀▀▀▀[/]
  [dim]Sentinel[/]
"""

WELCOME_MSG = """
[bold cyan]Code Sentinel[/] - AI-powered code auditor

[dim]Commands:[/]
  [cyan]/scan[/]      - Scan codebase for issues
  [cyan]/status[/]    - Show findings summary
  [cyan]/findings[/]  - List all findings
  [cyan]/watch[/]     - Watch for changes
  [cyan]/graph[/]     - Analyze dependencies
  [cyan]/help[/]      - Show all commands
  [cyan]/quit[/]      - Exit

[dim]Or just ask me anything about your code![/]
"""


class MessageBubble(Static):
    """A chat message bubble."""

    def __init__(self, content: str, is_user: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.content = content
        self.is_user = is_user

    def compose(self) -> ComposeResult:
        yield Static(self.content)

    def on_mount(self) -> None:
        if self.is_user:
            self.styles.background = "#1a3a5c"
            self.styles.border = ("round", "#3a7ca5")
        else:
            self.styles.background = "#2d2d2d"
            self.styles.border = ("round", "#4a4a4a")
        self.styles.padding = (0, 1)
        self.styles.margin = (0, 0, 1, 0)


class ThinkingIndicator(Static):
    """Animated thinking indicator."""

    def __init__(self, **kwargs):
        super().__init__("", **kwargs)
        self.dots = 0
        self.messages = [
            "Analyzing",
            "Scanning patterns",
            "Checking security",
            "Processing",
        ]
        self.msg_idx = 0

    def on_mount(self) -> None:
        self.styles.color = "cyan"
        self.set_interval(0.3, self.animate)

    def animate(self) -> None:
        self.dots = (self.dots + 1) % 4
        if self.dots == 0:
            self.msg_idx = (self.msg_idx + 1) % len(self.messages)
        self.update(f"[cyan]{self.messages[self.msg_idx]}{'.' * self.dots}[/]")


class ChatArea(VerticalScroll):
    """Scrollable chat area."""

    def add_message(self, content: str, is_user: bool = False) -> None:
        bubble = MessageBubble(content, is_user=is_user)
        self.mount(bubble)
        self.scroll_end(animate=False)

    def add_thinking(self) -> ThinkingIndicator:
        indicator = ThinkingIndicator(id="thinking")
        self.mount(indicator)
        self.scroll_end(animate=False)
        return indicator

    def remove_thinking(self) -> None:
        try:
            thinking = self.query_one("#thinking")
            thinking.remove()
        except Exception:
            pass


class SentinelApp(App):
    """Code Sentinel TUI Application."""

    CSS = """
    Screen {
        background: #000;
    }

    #main-container {
        height: 100%;
        padding: 1;
    }

    #chat-area {
        height: 1fr;
        border: round #333;
        padding: 1;
    }

    #input-container {
        height: auto;
        margin-top: 1;
    }

    #chat-input {
        width: 100%;
    }

    MessageBubble {
        width: 100%;
        margin-bottom: 1;
    }

    #welcome {
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+q", "quit", "Quit"),
        Binding("escape", "quit", "Quit"),
    ]

    def __init__(self, project_root: Path = None):
        super().__init__()
        self.project_root = project_root or Path.cwd()
        self.config = None
        self.memory = None
        self.scanner = None
        self.show_welcome = True

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="main-container"):
            with ChatArea(id="chat-area"):
                if self.show_welcome:
                    yield Static(MASCOT, id="mascot")
                    yield Static(WELCOME_MSG, id="welcome")
            with Container(id="input-container"):
                yield Input(placeholder="Ask about your code or type /command...", id="chat-input")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Code Sentinel"
        self.sub_title = str(self.project_root)

        # Initialize components
        try:
            self.config = Config.load(self.project_root)
            self.config.ensure_dirs()
            self.memory = Memory(self.project_root / ".sentinel" / "memory.db")
            self.scanner = Scanner(self.config, self.memory)
        except Exception as e:
            self.add_response(f"[red]Error initializing: {e}[/]\nRun [cyan]sentinel init[/] first.")

        # Focus input
        self.query_one("#chat-input").focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle user input."""
        user_input = event.value.strip()
        if not user_input:
            return

        # Clear input
        event.input.value = ""

        # Remove welcome if shown
        if self.show_welcome:
            self.show_welcome = False
            try:
                self.query_one("#mascot").remove()
                self.query_one("#welcome").remove()
            except Exception:
                pass

        # Add user message
        chat_area = self.query_one("#chat-area", ChatArea)
        chat_area.add_message(user_input, is_user=True)

        # Process command or message
        await self.process_input(user_input)

    async def process_input(self, user_input: str) -> None:
        """Process user input - commands or questions."""
        chat_area = self.query_one("#chat-area", ChatArea)

        # Handle commands
        if user_input.startswith("/"):
            await self.handle_command(user_input)
            return

        # For non-commands, use AI or show help
        chat_area.add_thinking()

        try:
            response = await self.ask_ai(user_input)
            chat_area.remove_thinking()
            chat_area.add_message(response)
        except Exception as e:
            chat_area.remove_thinking()
            chat_area.add_message(f"[red]Error: {e}[/]")

    async def handle_command(self, command: str) -> None:
        """Handle slash commands."""
        chat_area = self.query_one("#chat-area", ChatArea)
        cmd = command.lower().split()[0]
        args = command.split()[1:] if len(command.split()) > 1 else []

        if cmd in ("/quit", "/exit", "/q"):
            self.exit()
            return

        if cmd == "/help":
            help_text = """[bold]Available Commands:[/]

[cyan]/scan[/]           - Full codebase scan
[cyan]/scan --quick[/]   - Incremental scan (changed files)
[cyan]/scan -f FILE[/]   - Scan specific file
[cyan]/status[/]         - Show findings summary
[cyan]/findings[/]       - List all findings
[cyan]/fix ID[/]         - Get help fixing finding #ID
[cyan]/watch[/]          - Watch mode (continuous scanning)
[cyan]/graph[/]          - Analyze codebase dependencies
[cyan]/impact FILE[/]    - Show what's affected by changing FILE
[cyan]/clear[/]          - Clear chat
[cyan]/quit[/]           - Exit"""
            chat_area.add_message(help_text)
            return

        if cmd == "/clear":
            for child in list(chat_area.children):
                child.remove()
            return

        if cmd == "/status":
            chat_area.add_thinking()
            await asyncio.sleep(0.1)
            chat_area.remove_thinking()

            if self.memory:
                stats = self.memory.get_stats()
                status = f"""[bold cyan]Sentinel Status[/]

[bold]Open Findings:[/]
  [red]P0 (Critical):[/] {stats['open_p0']}
  [yellow]P1 (High):[/]     {stats['open_p1']}
  [blue]P2 (Medium):[/]   {stats['open_p2']}
  [green]P3 (Low):[/]      {stats['open_p3']}

[bold]Summary:[/]
  Total Open:  {stats['total_open']}
  Total Fixed: {stats['total_fixed']}
  Total Scans: {stats['total_scans']}"""
                chat_area.add_message(status)
            else:
                chat_area.add_message("[red]Not initialized. Run /scan first.[/]")
            return

        if cmd == "/scan":
            chat_area.add_thinking()
            await asyncio.sleep(0.1)

            try:
                if "-f" in args:
                    idx = args.index("-f")
                    if idx + 1 < len(args):
                        file_path = self.project_root / args[idx + 1]
                        result = self.scanner.scan_file(file_path)
                        findings = result.findings if result else []
                    else:
                        chat_area.remove_thinking()
                        chat_area.add_message("[red]Usage: /scan -f FILEPATH[/]")
                        return
                else:
                    incremental = "--quick" in args or "-q" in args
                    findings = self.scanner.scan_directory(incremental=incremental)

                chat_area.remove_thinking()

                if findings:
                    result = f"[yellow]Found {len(findings)} issues:[/]\n\n"
                    for f in findings[:10]:
                        sev_color = {"P0": "red", "P1": "yellow", "P2": "blue", "P3": "green"}.get(f.severity.value, "white")
                        result += f"[{sev_color}]{f.severity.value}[/] {f.title}\n"
                        result += f"  [dim]{f.file_path}:{f.line_start}[/]\n"
                    if len(findings) > 10:
                        result += f"\n[dim]... and {len(findings) - 10} more[/]"
                    chat_area.add_message(result)
                else:
                    chat_area.add_message("[green]No issues found![/]")

            except Exception as e:
                chat_area.remove_thinking()
                chat_area.add_message(f"[red]Scan error: {e}[/]")
            return

        if cmd == "/findings":
            if self.memory:
                from ..core.memory import Status
                findings = self.memory.get_findings(
                    status=[Status.DETECTED, Status.REPORTED, Status.ACKNOWLEDGED],
                    limit=20
                )
                if findings:
                    result = "[bold]Recent Findings:[/]\n\n"
                    for f in findings:
                        sev_color = {"P0": "red", "P1": "yellow", "P2": "blue", "P3": "green"}.get(f.severity.value, "white")
                        result += f"[{sev_color}]#{f.id} {f.severity.value}[/] {f.title}\n"
                        result += f"  [dim]{f.file_path}:{f.line_start}[/]\n"
                    chat_area.add_message(result)
                else:
                    chat_area.add_message("[dim]No findings yet. Run /scan first.[/]")
            return

        if cmd == "/fix":
            if args and self.memory:
                try:
                    finding_id = int(args[0])
                    finding = self.memory.get_finding(finding_id)
                    if finding:
                        result = f"""[bold]Finding #{finding_id}[/]

[bold]{finding.title}[/]
[dim]File:[/] {finding.file_path}:{finding.line_start}
[dim]Severity:[/] {finding.severity.value}
[dim]Category:[/] {finding.category.value}

[bold]Description:[/]
{finding.description}

[bold]Suggestion:[/]
{finding.suggestion or 'No suggestion available'}"""
                        if finding.code_snippet:
                            result += f"\n\n[bold]Code:[/]\n```\n{finding.code_snippet}\n```"
                        chat_area.add_message(result)
                    else:
                        chat_area.add_message(f"[red]Finding #{finding_id} not found[/]")
                except ValueError:
                    chat_area.add_message("[red]Usage: /fix <id>[/]")
            else:
                chat_area.add_message("[red]Usage: /fix <id>[/]")
            return

        if cmd == "/graph":
            chat_area.add_thinking()
            await asyncio.sleep(0.1)

            try:
                from ..core.graph import CodeGraph
                graph = CodeGraph(self.project_root)
                graph.build()
                metrics = graph.get_coupling_metrics()

                chat_area.remove_thinking()
                result = f"""[bold cyan]Codebase Analysis[/]

[bold]Metrics:[/]
  Files:        {metrics['total_files']}
  Symbols:      {metrics['total_symbols']}
  Imports:      {metrics['total_imports']}
  Avg Deps:     {metrics['avg_dependencies']:.1f}
  Max Deps:     {metrics['max_dependencies']}
  Orphan Files: {metrics['orphan_files']}"""
                chat_area.add_message(result)
            except Exception as e:
                chat_area.remove_thinking()
                chat_area.add_message(f"[red]Graph error: {e}[/]")
            return

        if cmd == "/impact":
            if args:
                chat_area.add_thinking()
                await asyncio.sleep(0.1)

                try:
                    from ..core.graph import CodeGraph
                    graph = CodeGraph(self.project_root)
                    graph.build()
                    affected = graph.get_impact_radius(args[0])

                    chat_area.remove_thinking()
                    if affected:
                        result = f"[bold]Changing {args[0]} may affect:[/]\n\n"
                        for f in sorted(affected)[:15]:
                            result += f"  - {f}\n"
                        if len(affected) > 15:
                            result += f"\n[dim]... and {len(affected) - 15} more[/]"
                        chat_area.add_message(result)
                    else:
                        chat_area.add_message(f"[green]No files depend on {args[0]}[/]")
                except Exception as e:
                    chat_area.remove_thinking()
                    chat_area.add_message(f"[red]Impact error: {e}[/]")
            else:
                chat_area.add_message("[red]Usage: /impact <filepath>[/]")
            return

        # Unknown command
        chat_area.add_message(f"[red]Unknown command: {cmd}[/]\nType [cyan]/help[/] for available commands.")

    async def ask_ai(self, question: str) -> str:
        """Ask AI about the codebase."""
        # Try Claude Code CLI
        try:
            prompt = f"""You are Code Sentinel, an AI code auditor.
Answer this question about the codebase at {self.project_root}:

{question}

Be concise and helpful. If you need to see specific files, mention which ones."""

            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["claude", "--dangerously-skip-permissions", "-p", prompt],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    cwd=str(self.project_root)
                )
            )

            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            else:
                return "[dim]AI not available. Use /commands or set up Claude Code CLI.[/]"

        except FileNotFoundError:
            return "[dim]Claude Code CLI not found. Install it for AI features.\nUse /commands for available actions.[/]"
        except subprocess.TimeoutExpired:
            return "[yellow]AI request timed out. Try a simpler question.[/]"
        except Exception as e:
            return f"[red]AI error: {e}[/]"

    def add_response(self, content: str) -> None:
        """Add a response message."""
        chat_area = self.query_one("#chat-area", ChatArea)
        chat_area.add_message(content)


def run_tui(project_root: Path = None) -> None:
    """Run the TUI application."""
    app = SentinelApp(project_root=project_root)
    app.run()
