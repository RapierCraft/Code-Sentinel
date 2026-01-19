# Contributing to Code Sentinel

Thank you for your interest in contributing to Code Sentinel! This document provides guidelines and information for contributors.

## Code of Conduct

Be respectful, inclusive, and constructive. We want Code Sentinel to be a welcoming project for everyone.

## Getting Started

### Prerequisites

- Python 3.10+
- Poetry (for dependency management)
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/rapiercraft/code-sentinel.git
cd code-sentinel

# Install dependencies
poetry install

# Install pre-commit hooks
poetry run pre-commit install

# Run tests
poetry run pytest

# Run the CLI
poetry run sentinel --help
```

## Project Structure

```
code-sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py
│       ├── cli.py              # CLI interface
│       ├── core/
│       │   ├── config.py       # Configuration management
│       │   ├── memory.py       # SQLite persistence
│       │   ├── scanner.py      # Core scanning engine
│       │   └── graph.py        # Codebase dependency graph
│       ├── analyzers/
│       │   ├── security.py     # Security vulnerability detection
│       │   ├── dead_code.py    # Dead code detection
│       │   ├── duplicates.py   # Duplicate code detection
│       │   └── conventions.py  # Team conventions enforcement
│       └── integrations/
│           ├── git.py          # Git integration
│           └── github.py       # GitHub integration
├── tests/
├── pyproject.toml
├── README.md
├── LICENSE
└── CONTRIBUTING.md
```

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Python version
   - OS and version
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

### Suggesting Features

1. Check existing issues and discussions
2. Use the feature request template
3. Explain the use case and why it would benefit users

### Submitting Code

1. **Fork the repository** and create a feature branch
2. **Write tests** for new functionality
3. **Follow code style** (we use Black and isort)
4. **Update documentation** if needed
5. **Create a pull request** with a clear description

## Code Style

We follow Python best practices:

```bash
# Format code
poetry run black src/ tests/

# Sort imports
poetry run isort src/ tests/

# Type checking
poetry run mypy src/
```

### Guidelines

- Use type hints
- Write docstrings for public functions
- Keep functions focused and under 50 lines
- Use meaningful variable names
- Add comments for complex logic

## Adding New Analyzers

To add a new analyzer:

1. Create a new file in `src/sentinel/analyzers/`
2. Implement the analyzer class with an `analyze(file_path, content)` method
3. Return a list of `Finding` objects
4. Export in `analyzers/__init__.py`
5. Add tests in `tests/analyzers/`

Example:

```python
from ..core.memory import Finding, Severity, Category

class MyAnalyzer:
    def analyze(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        # Your detection logic here
        return findings
```

## Adding New Integrations

To add a new integration:

1. Create a new file in `src/sentinel/integrations/`
2. Implement the integration class
3. Export in `integrations/__init__.py`
4. Add tests

## Testing

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=sentinel

# Run specific test file
poetry run pytest tests/test_scanner.py

# Run tests matching a pattern
poetry run pytest -k "test_security"
```

### Writing Tests

- Use pytest fixtures for common setup
- Test both happy paths and edge cases
- Mock external dependencies (git, filesystem, etc.)
- Aim for >80% coverage for new code

## Pull Request Process

1. Update the README.md if you're adding features
2. Update tests to cover your changes
3. Ensure all tests pass
4. Request review from maintainers
5. Address review feedback
6. Squash commits before merge (if requested)

### PR Checklist

- [ ] Tests pass
- [ ] Code is formatted (black, isort)
- [ ] Type hints added
- [ ] Documentation updated
- [ ] No breaking changes (or documented)

## Release Process

Releases are automated via GitHub Actions when a tag is pushed:

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create a git tag: `git tag v0.1.0`
4. Push the tag: `git push origin v0.1.0`

## Getting Help

- Open an issue for bugs or features
- Start a discussion for questions
- Join our Discord (coming soon)

## Recognition

Contributors are recognized in:
- The README contributors section
- Release notes
- Our website (coming soon)

Thank you for helping make Code Sentinel better!
