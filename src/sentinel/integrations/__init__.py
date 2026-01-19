"""Integration modules for external tools and services."""

from .git import GitIntegration
from .github import GitHubIntegration

__all__ = ["GitIntegration", "GitHubIntegration"]
