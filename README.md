# Code Sentinel

**AI-powered code auditor that lives in your codebase.**

Code Sentinel is a local-first, privacy-focused code analysis tool that continuously monitors your codebase for security vulnerabilities, code smells, dead code, and team convention violations. Unlike cloud-based alternatives, your code never leaves your machine.

## Key Features

- **Local-First, Zero Data Leakage** - All analysis happens on your machine. Code never touches external servers.
- **Persistent Memory** - SQLite-based memory remembers findings across sessions, tracks fix status, and learns from your codebase.
- **Proactive Scanning** - Watch mode continuously monitors file changes. Don't wait for PR reviews.
- **Team Conventions** - Define your team's rules in `.sentinel/conventions.md` and enforce them automatically.
- **Security-First** - Detects OWASP Top 10 vulnerabilities, hardcoded secrets, insecure crypto, and more.
- **Impact Analysis** - Understand what could break when you change a file.
- **GitHub Integration** - Create issues, add PR comments, and report check runs.
- **Git-Aware** - Uses blame and history for context. Know who introduced issues and when.

## Installation

```bash
pip install code-sentinel
```

Or with poetry:

```bash
poetry add code-sentinel
```

## Quick Start

```bash
# Initialize Sentinel in your project
cd your-project
sentinel init

# Run a full scan
sentinel scan

# Watch for changes (real-time scanning)
sentinel watch

# Review staged changes before commit
sentinel review

# See what files would be affected by changing a file
sentinel impact src/core/auth.py

# Get help fixing a finding
sentinel fix 42
```

## Commands

| Command | Description |
|---------|-------------|
| `sentinel init` | Initialize Sentinel in current directory |
| `sentinel scan` | Run full codebase scan |
| `sentinel scan --quick` | Incremental scan (changed files only) |
| `sentinel scan --ai` | Use AI for deeper analysis |
| `sentinel watch` | Watch for changes and scan automatically |
| `sentinel review` | Review staged git changes |
| `sentinel status` | Show findings summary |
| `sentinel findings` | List all findings |
| `sentinel fix <id>` | Get help fixing a specific finding |
| `sentinel impact <file>` | Show what would be affected by changing a file |
| `sentinel graph` | Analyze codebase structure and dependencies |

## Configuration

After running `sentinel init`, edit `.sentinel/config.yaml`:

```yaml
scan:
  include_dirs:
    - src
    - app
  exclude_patterns:
    - "**/node_modules/**"
    - "**/__pycache__/**"
    - "**/test_*.py"
  extensions:
    - .py
    - .js
    - .ts
    - .tsx

security:
  scan_secrets: true
  scan_dependencies: true

ai:
  enabled: false  # Enable for AI-powered analysis
  focus: null     # security, performance, quality
```

## Team Conventions

Define your team's coding standards in `.sentinel/conventions.md`:

```markdown
# Team Conventions

## No Print Statements
Use logging instead of print() in production code.

- Pattern: `^[^#]*\bprint\s*\(`
- Files: `*.py`
- Severity: P3
- Suggestion: Use logging.info() or logging.debug() instead.

## Function Docstrings Required
All public functions must have docstrings.

- Pattern: `^def [^_][^(]+\([^)]*\):\s*\n\s+[^"\']`
- Files: `*.py`
- Severity: P2
- Suggestion: Add a docstring describing the function's purpose.
```

## Severity Levels

| Level | Description |
|-------|-------------|
| **P0** | Critical - Security vulnerabilities, data loss risks |
| **P1** | High - Bugs, significant issues |
| **P2** | Medium - Code smells, maintainability issues |
| **P3** | Low - Style issues, minor improvements |

## What Sentinel Detects

### Security
- SQL, Command, LDAP, XPath injection
- Cross-site scripting (XSS)
- Hardcoded secrets (passwords, API keys, tokens)
- Weak cryptography (MD5, SHA1, DES)
- Insecure deserialization (pickle, eval, exec)
- Disabled SSL verification
- Exposed private keys

### Code Quality
- Dead code (unused imports, variables, functions)
- Duplicate code blocks
- Functions that are too long
- Empty exception handlers
- Unreachable code

### Conventions
- Custom team rules from `.sentinel/conventions.md`
- TODO comments without owners
- Magic numbers
- Print statements in production

## Privacy & Security

Code Sentinel is designed with privacy as a core principle:

- **100% Local** - All analysis runs on your machine
- **No Telemetry** - We don't collect any usage data
- **No Cloud** - Your code is never uploaded anywhere
- **Open Source** - Audit the code yourself

When AI analysis is enabled, you can use your own API keys or the Claude Code CLI with your existing subscription.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Comparison with Alternatives

| Feature | Code Sentinel | CodeRabbit | Greptile | GitHub Copilot |
|---------|---------------|------------|----------|----------------|
| Local-first | ✅ | ❌ | ❌ | ❌ |
| Zero data leakage | ✅ | ❌ | ❌ | ❌ |
| Persistent memory | ✅ | ❌ | ❌ | ❌ |
| Team conventions | ✅ | ❌ | ❌ | ❌ |
| Proactive scanning | ✅ | ❌ | ❌ | ❌ |
| Impact analysis | ✅ | ❌ | ✅ | ❌ |
| Free tier | ✅ Unlimited | Limited | Limited | Limited |
| Per-seat pricing | ❌ | ✅ | ✅ | ✅ |

---

Built with ❤️ for developers who care about code quality and privacy.
