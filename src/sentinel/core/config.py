"""Configuration management for Code Sentinel."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import yaml


@dataclass
class ScanConfig:
    """Configuration for scanning behavior."""

    # Directories to scan
    include_dirs: list[str] = field(default_factory=lambda: ["src", "app", "lib"])

    # Patterns to exclude
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/.git/**",
        "**/dist/**",
        "**/build/**",
        "**/.next/**",
        "**/venv/**",
        "**/.venv/**",
        "**/test_*.py",
        "**/*_test.py",
        "**/tests/**",
        "**/site-packages/**",
        "**/sentinel/**",  # Exclude sentinel's own source to avoid false positives
    ])

    # File extensions to analyze
    extensions: list[str] = field(default_factory=lambda: [
        ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb"
    ])

    # Security scanning
    security_enabled: bool = True
    secret_scanning: bool = True
    dependency_check: bool = True

    # Severity thresholds
    auto_issue_threshold: str = "P1"  # Auto-create GitHub issues for P0, P1

    # Performance
    max_file_size_kb: int = 500
    max_files_per_scan: int = 1000


@dataclass
class AIConfig:
    """Configuration for AI/LLM settings."""

    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.0

    # Use Claude Code CLI as backend (uses existing auth)
    use_claude_code: bool = True

    # Or use direct API (requires ANTHROPIC_API_KEY)
    api_key: Optional[str] = None


@dataclass
class Config:
    """Main configuration for Code Sentinel."""

    # Project root (auto-detected or specified)
    project_root: Path = field(default_factory=Path.cwd)

    # Sentinel data directory
    sentinel_dir: Path = field(default_factory=lambda: Path(".sentinel"))

    # Sub-configs
    scan: ScanConfig = field(default_factory=ScanConfig)
    ai: AIConfig = field(default_factory=AIConfig)

    # Team conventions file
    conventions_file: Path = field(default_factory=lambda: Path(".sentinel/conventions.md"))

    # GitHub integration
    github_auto_issues: bool = True
    github_labels: list[str] = field(default_factory=lambda: ["sentinel", "auto-detected"])

    @classmethod
    def load(cls, project_root: Optional[Path] = None) -> "Config":
        """Load configuration from .sentinel/config.yaml or defaults."""
        root = project_root or Path.cwd()
        config_file = root / ".sentinel" / "config.yaml"

        config = cls(project_root=root)

        if config_file.exists():
            with open(config_file) as f:
                data = yaml.safe_load(f) or {}

            # Update scan config
            if "scan" in data:
                for key, value in data["scan"].items():
                    if hasattr(config.scan, key):
                        setattr(config.scan, key, value)

            # Update AI config
            if "ai" in data:
                for key, value in data["ai"].items():
                    if hasattr(config.ai, key):
                        setattr(config.ai, key, value)

            # Update top-level config
            for key in ["github_auto_issues", "github_labels"]:
                if key in data:
                    setattr(config, key, data[key])

        # Check for API key in environment
        if not config.ai.api_key:
            config.ai.api_key = os.environ.get("ANTHROPIC_API_KEY")

        return config

    def save(self) -> None:
        """Save configuration to .sentinel/config.yaml."""
        config_file = self.project_root / ".sentinel" / "config.yaml"
        config_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "scan": {
                "include_dirs": self.scan.include_dirs,
                "exclude_patterns": self.scan.exclude_patterns,
                "extensions": self.scan.extensions,
                "security_enabled": self.scan.security_enabled,
                "auto_issue_threshold": self.scan.auto_issue_threshold,
            },
            "ai": {
                "model": self.ai.model,
                "use_claude_code": self.ai.use_claude_code,
            },
            "github_auto_issues": self.github_auto_issues,
            "github_labels": self.github_labels,
        }

        with open(config_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False)

    def ensure_dirs(self) -> None:
        """Ensure .sentinel directories exist."""
        sentinel_path = self.project_root / self.sentinel_dir
        sentinel_path.mkdir(parents=True, exist_ok=True)
        (sentinel_path / "logs").mkdir(exist_ok=True)
