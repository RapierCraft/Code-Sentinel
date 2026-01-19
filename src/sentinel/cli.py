"""
Command-line interface for Code Sentinel.

Usage:
    sentinel init          Initialize Sentinel in current directory
    sentinel scan          Run full codebase scan
    sentinel scan --quick  Run incremental scan (changed files only)
    sentinel watch         Watch for changes and scan automatically
    sentinel review        Review staged changes (git diff)
    sentinel status        Show findings summary
    sentinel findings      List all findings
    sentinel fix <id>      Get help fixing a specific finding
    sentinel explain <file>  Explain what a file does
    sentinel impact <file>   Show what would be affected by changing a file
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint

from .core.config import Config
from .core.memory import Memory, Severity, Status
from .core.scanner import Scanner
from .core.graph import CodeGraph


console = Console()


def get_sentinel(ctx: click.Context) -> tuple[Config, Memory, Scanner]:
    """Get or create Sentinel components."""
    project_root = Path(ctx.obj.get("project_root", ".")).resolve()
    config = Config.load(project_root)
    config.ensure_dirs()

    memory = Memory(project_root / ".sentinel" / "memory.db")
    scanner = Scanner(config, memory)

    return config, memory, scanner


@click.group(invoke_without_command=True)
@click.option("--project", "-p", default=".", help="Project root directory")
@click.pass_context
def main(ctx: click.Context, project: str) -> None:
    """Code Sentinel - AI-powered code auditor that lives in your codebase."""
    ctx.ensure_object(dict)
    ctx.obj["project_root"] = project

    # If no command specified, launch TUI
    if ctx.invoked_subcommand is None:
        from .tui import SentinelApp
        project_root = Path(project).resolve()
        app = SentinelApp(project_root=project_root)
        app.run()


@main.command()
@click.pass_context
def init(ctx: click.Context) -> None:
    """Initialize Code Sentinel in the current directory."""
    project_root = Path(ctx.obj.get("project_root", ".")).resolve()

    console.print(f"[cyan]Initializing Code Sentinel in {project_root}[/]")

    # Create .sentinel directory
    sentinel_dir = project_root / ".sentinel"
    sentinel_dir.mkdir(exist_ok=True)
    (sentinel_dir / "logs").mkdir(exist_ok=True)

    # Create default config
    config = Config(project_root=project_root)
    config.save()

    # Create conventions template
    conventions_path = sentinel_dir / "conventions.md"
    if not conventions_path.exists():
        conventions_path.write_text("""# Team Conventions

## Code Style
- Use descriptive variable names
- Keep functions under 50 lines
- Add docstrings to public functions

## Security
- Never hardcode secrets
- Always validate user input
- Use parameterized queries for SQL

## Architecture
- Keep business logic in services, not routes
- Use dependency injection for testability

## Add your team's conventions below:

""")

    # Initialize database
    Memory(sentinel_dir / "memory.db").close()

    # Add to .gitignore
    gitignore = project_root / ".gitignore"
    sentinel_ignore = "\n# Code Sentinel\n.sentinel/memory.db\n.sentinel/logs/\n"

    if gitignore.exists():
        content = gitignore.read_text()
        if ".sentinel" not in content:
            gitignore.write_text(content + sentinel_ignore)
    else:
        gitignore.write_text(sentinel_ignore)

    console.print("[green]✓ Code Sentinel initialized![/]")
    console.print("\nNext steps:")
    console.print("  1. Edit [cyan].sentinel/conventions.md[/] with your team's rules")
    console.print("  2. Run [cyan]sentinel scan[/] to analyze your codebase")
    console.print("  3. Run [cyan]sentinel watch[/] to monitor for issues")


@main.command()
@click.option("--quick", "-q", is_flag=True, help="Only scan changed files")
@click.option("--file", "-f", "file_path", help="Scan a specific file")
@click.option("--ai", is_flag=True, help="Use AI for deeper analysis")
@click.option("--focus", help="Focus area for AI (security, performance, etc.)")
@click.pass_context
def scan(
    ctx: click.Context,
    quick: bool,
    file_path: Optional[str],
    ai: bool,
    focus: Optional[str]
) -> None:
    """Scan codebase for issues."""
    config, memory, scanner = get_sentinel(ctx)

    if file_path:
        # Scan single file
        console.print(f"[cyan]Scanning {file_path}...[/]")
        target = config.project_root / file_path

        if ai:
            findings = scanner.scan_with_ai(target, focus)
        else:
            result = scanner.scan_file(target)
            findings = result.findings if result else []

        for finding in findings:
            memory.add_finding(finding)

    else:
        # Full or incremental scan
        mode = "incremental" if quick else "full"
        console.print(f"[cyan]Running {mode} scan...[/]")

        with console.status("[bold cyan]Scanning..."):
            findings = scanner.scan_directory(
                incremental=quick,
                trigger="manual"
            )

    # Display results
    if findings:
        _display_findings(findings)
        console.print(f"\n[yellow]Found {len(findings)} issues[/]")
    else:
        console.print("[green]✓ No new issues found[/]")

    # Show stats
    stats = memory.get_stats()
    console.print(f"\n[dim]Total open: {stats['total_open']} | Fixed: {stats['total_fixed']}[/]")

    memory.close()


@main.command()
@click.pass_context
def watch(ctx: click.Context) -> None:
    """Watch for file changes and scan automatically."""
    config, memory, scanner = get_sentinel(ctx)

    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        console.print("[red]watchdog not installed. Run: pip install watchdog[/]")
        return

    class ScanHandler(FileSystemEventHandler):
        def __init__(self):
            self.pending_files = set()
            self.last_scan = 0

        def on_modified(self, event):
            if event.is_directory:
                return

            path = Path(event.src_path)
            if path.suffix in config.scan.extensions:
                rel_path = str(path.relative_to(config.project_root))

                # Skip excluded
                if any(p in rel_path for p in ["node_modules", "__pycache__", ".git"]):
                    return

                console.print(f"[dim]Change detected: {rel_path}[/]")

                # Scan the file
                result = scanner.scan_file(path)
                if result and result.findings:
                    for finding in result.findings:
                        if not memory.is_suppressed(finding.file_path, finding.line_start, finding.category.value):
                            memory.add_finding(finding)
                            _print_finding(finding)

    handler = ScanHandler()
    observer = Observer()
    observer.schedule(handler, str(config.project_root), recursive=True)
    observer.start()

    console.print(f"[cyan]Watching {config.project_root} for changes...[/]")
    console.print("[dim]Press Ctrl+C to stop[/]\n")

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        console.print("\n[yellow]Stopped watching[/]")

    observer.join()
    memory.close()


@main.command()
@click.pass_context
def review(ctx: click.Context) -> None:
    """Review staged git changes."""
    import subprocess

    config, memory, scanner = get_sentinel(ctx)

    # Get staged diff
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        cwd=config.project_root
    )

    if result.returncode != 0:
        console.print("[red]Not a git repository or git error[/]")
        return

    changed_files = [f for f in result.stdout.strip().split("\n") if f]

    if not changed_files:
        console.print("[yellow]No staged changes to review[/]")
        return

    console.print(f"[cyan]Reviewing {len(changed_files)} staged files...[/]")

    all_findings = []
    for file_path in changed_files:
        full_path = config.project_root / file_path
        if full_path.exists() and full_path.suffix in config.scan.extensions:
            result = scanner.scan_file(full_path)
            if result:
                all_findings.extend(result.findings)

    if all_findings:
        _display_findings(all_findings)
        console.print(f"\n[yellow]Found {len(all_findings)} issues in staged changes[/]")
    else:
        console.print("[green]✓ No issues found in staged changes[/]")

    memory.close()


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show findings summary."""
    config, memory, _ = get_sentinel(ctx)

    stats = memory.get_stats()

    console.print(Panel.fit(
        f"""[bold cyan]Code Sentinel Status[/]

[bold]Open Findings:[/]
  [red]P0 (Critical):[/] {stats['open_p0']}
  [yellow]P1 (High):[/]     {stats['open_p1']}
  [blue]P2 (Medium):[/]   {stats['open_p2']}
  [green]P3 (Low):[/]      {stats['open_p3']}

[bold]Summary:[/]
  Total Open:    {stats['total_open']}
  Total Fixed:   {stats['total_fixed']}
  Issues Created: {stats['issues_created']}
  Total Scans:   {stats['total_scans']}
""",
        title="Sentinel Status"
    ))

    memory.close()


@main.command()
@click.option("--severity", "-s", help="Filter by severity (P0, P1, P2, P3)")
@click.option("--category", "-c", help="Filter by category")
@click.option("--file", "-f", "file_path", help="Filter by file path")
@click.option("--limit", "-n", default=20, help="Number of findings to show")
@click.pass_context
def findings(
    ctx: click.Context,
    severity: Optional[str],
    category: Optional[str],
    file_path: Optional[str],
    limit: int
) -> None:
    """List all findings."""
    config, memory, _ = get_sentinel(ctx)

    # Parse filters
    severity_filter = [Severity(severity)] if severity else None
    status_filter = [Status.DETECTED, Status.REPORTED, Status.ACKNOWLEDGED]

    results = memory.get_findings(
        status=status_filter,
        severity=severity_filter,
        file_path=file_path,
        limit=limit
    )

    if results:
        _display_findings(results)
    else:
        console.print("[dim]No findings match the criteria[/]")

    memory.close()


@main.command()
@click.argument("finding_id", type=int)
@click.pass_context
def fix(ctx: click.Context, finding_id: int) -> None:
    """Get help fixing a specific finding."""
    config, memory, scanner = get_sentinel(ctx)

    finding = memory.get_finding(finding_id)
    if not finding:
        console.print(f"[red]Finding #{finding_id} not found[/]")
        return

    console.print(Panel.fit(
        f"""[bold]{finding.title}[/]

[bold]File:[/] {finding.file_path}:{finding.line_start}
[bold]Severity:[/] {finding.severity.value}
[bold]Category:[/] {finding.category.value}

[bold]Description:[/]
{finding.description}

[bold]Suggestion:[/]
{finding.suggestion or 'No suggestion available'}
""",
        title=f"Finding #{finding_id}"
    ))

    # Show code snippet
    if finding.code_snippet:
        console.print("\n[bold]Code:[/]")
        syntax = Syntax(finding.code_snippet, "python", line_numbers=True, start_line=max(1, finding.line_start - 2))
        console.print(syntax)

    memory.close()


@main.command()
@click.argument("file_path")
@click.pass_context
def impact(ctx: click.Context, file_path: str) -> None:
    """Show what would be affected by changing a file."""
    config, memory, _ = get_sentinel(ctx)

    console.print(f"[cyan]Building dependency graph...[/]")

    graph = CodeGraph(config.project_root)
    graph.build()

    affected = graph.get_impact_radius(file_path)

    if affected:
        console.print(f"\n[bold]Changing {file_path} may affect:[/]")
        for f in sorted(affected):
            console.print(f"  - {f}")
        console.print(f"\n[yellow]Total: {len(affected)} files[/]")
    else:
        console.print(f"[green]No other files depend on {file_path}[/]")

    # Show metrics
    metrics = graph.get_coupling_metrics()
    console.print(f"\n[dim]Codebase: {metrics['total_files']} files, {metrics['total_symbols']} symbols[/]")

    memory.close()


@main.command()
@click.pass_context
def graph(ctx: click.Context) -> None:
    """Analyze codebase structure and dependencies."""
    config, memory, _ = get_sentinel(ctx)

    console.print("[cyan]Building codebase graph...[/]")

    cg = CodeGraph(config.project_root)
    cg.build()

    # Find issues
    unused = cg.find_unused_symbols()
    cycles = cg.find_circular_dependencies()
    metrics = cg.get_coupling_metrics()

    console.print(Panel.fit(
        f"""[bold cyan]Codebase Analysis[/]

[bold]Metrics:[/]
  Files:          {metrics['total_files']}
  Symbols:        {metrics['total_symbols']}
  Imports:        {metrics['total_imports']}
  Avg Deps:       {metrics['avg_dependencies']:.1f}
  Max Deps:       {metrics['max_dependencies']}
  Orphan Files:   {metrics['orphan_files']}

[bold]Issues Found:[/]
  Unused Symbols: {len(unused)}
  Circular Deps:  {len(cycles)}
""",
        title="Codebase Graph"
    ))

    if unused:
        console.print("\n[bold]Potentially Unused Symbols:[/]")
        for symbol in unused[:10]:
            console.print(f"  - {symbol.name} ({symbol.kind}) in {symbol.file_path}:{symbol.line_start}")

    if cycles:
        console.print("\n[bold yellow]Circular Dependencies:[/]")
        for cycle in cycles[:5]:
            console.print(f"  - {' -> '.join(cycle)}")

    memory.close()


def _display_findings(findings: list) -> None:
    """Display findings in a table."""
    table = Table(title="Findings")
    table.add_column("ID", style="dim")
    table.add_column("Sev", style="bold")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("File")

    severity_colors = {
        Severity.P0: "red",
        Severity.P1: "yellow",
        Severity.P2: "blue",
        Severity.P3: "green",
    }

    for f in findings:
        color = severity_colors.get(f.severity, "white")
        table.add_row(
            str(f.id or "-"),
            f"[{color}]{f.severity.value}[/]",
            f.category.value,
            f.title[:40],
            f"{f.file_path}:{f.line_start}"
        )

    console.print(table)


def _print_finding(finding) -> None:
    """Print a single finding."""
    severity_colors = {
        Severity.P0: "red",
        Severity.P1: "yellow",
        Severity.P2: "blue",
        Severity.P3: "green",
    }
    color = severity_colors.get(finding.severity, "white")

    console.print(f"[{color}]{finding.severity.value}[/] [{finding.category.value}] {finding.title}")
    console.print(f"  [dim]{finding.file_path}:{finding.line_start}[/]")


if __name__ == "__main__":
    main()
