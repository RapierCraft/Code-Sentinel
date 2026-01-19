"""
Persistent memory system for Code Sentinel.

Tracks findings, scan history, suppressions, and learns from past reviews.
"""

import sqlite3
import json
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    P0 = "P0"  # Critical - security vulnerability, data loss risk
    P1 = "P1"  # High - bugs, significant issues
    P2 = "P2"  # Medium - code smells, maintainability
    P3 = "P3"  # Low - style, minor improvements


class Category(str, Enum):
    SECURITY = "security"
    BUG = "bug"
    PERFORMANCE = "performance"
    TECH_DEBT = "tech_debt"
    DEAD_CODE = "dead_code"
    DUPLICATE = "duplicate"
    STYLE = "style"
    ARCHITECTURE = "architecture"


class Status(str, Enum):
    DETECTED = "detected"      # Just found
    REPORTED = "reported"      # GitHub issue created
    ACKNOWLEDGED = "acknowledged"  # Dev saw it
    IN_PROGRESS = "in_progress"   # Being fixed
    FIXED = "fixed"            # Resolved
    WONT_FIX = "wont_fix"      # Intentional/accepted
    FALSE_POSITIVE = "false_positive"  # Incorrect detection


@dataclass
class Finding:
    """A detected issue in the codebase."""

    id: Optional[int]
    file_path: str
    line_start: int
    line_end: int
    severity: Severity
    category: Category
    title: str
    description: str
    suggestion: Optional[str]
    code_snippet: Optional[str]
    status: Status = Status.DETECTED
    issue_number: Optional[int] = None
    fingerprint: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    detected_by: str = "sentinel"
    confidence: float = 1.0

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def _compute_fingerprint(self) -> str:
        """Create unique fingerprint for deduplication."""
        content = f"{self.file_path}:{self.line_start}:{self.category}:{self.title}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class ScanRun:
    """Record of a scan execution."""

    id: Optional[int]
    started_at: str
    completed_at: Optional[str]
    mode: str  # full, incremental, file, pr
    trigger: str  # manual, watch, ci, hook
    files_scanned: int = 0
    findings_new: int = 0
    findings_fixed: int = 0
    issues_created: int = 0
    duration_seconds: float = 0.0


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    suggestion TEXT,
    code_snippet TEXT,
    status TEXT DEFAULT 'detected',
    issue_number INTEGER,
    fingerprint TEXT UNIQUE,
    created_at TEXT,
    updated_at TEXT,
    detected_by TEXT DEFAULT 'sentinel',
    confidence REAL DEFAULT 1.0
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    mode TEXT NOT NULL,
    trigger TEXT NOT NULL,
    files_scanned INTEGER DEFAULT 0,
    findings_new INTEGER DEFAULT 0,
    findings_fixed INTEGER DEFAULT 0,
    issues_created INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS file_hashes (
    file_path TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    last_scanned TEXT NOT NULL,
    findings_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT,
    line_number INTEGER,
    category TEXT,
    reason TEXT,
    created_at TEXT,
    created_by TEXT
);

CREATE TABLE IF NOT EXISTS conventions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    rule TEXT NOT NULL,
    description TEXT,
    severity TEXT DEFAULT 'P2',
    enabled INTEGER DEFAULT 1,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    total_findings INTEGER,
    p0_count INTEGER,
    p1_count INTEGER,
    p2_count INTEGER,
    p3_count INTEGER,
    fixed_count INTEGER,
    new_count INTEGER,
    tech_debt_hours REAL
);

CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
"""


class Memory:
    """Persistent memory for Code Sentinel."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Initialize database schema."""
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        """Close database connection."""
        self.conn.close()

    # === Findings ===

    def add_finding(self, finding: Finding) -> int:
        """Add a new finding, or return existing if duplicate."""
        # Check for duplicate by fingerprint
        existing = self.conn.execute(
            "SELECT id FROM findings WHERE fingerprint = ?",
            (finding.fingerprint,)
        ).fetchone()

        if existing:
            return existing["id"]

        cursor = self.conn.execute(
            """
            INSERT INTO findings (
                file_path, line_start, line_end, severity, category,
                title, description, suggestion, code_snippet, status,
                issue_number, fingerprint, created_at, updated_at,
                detected_by, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.file_path, finding.line_start, finding.line_end,
                finding.severity.value, finding.category.value,
                finding.title, finding.description, finding.suggestion,
                finding.code_snippet, finding.status.value,
                finding.issue_number, finding.fingerprint,
                finding.created_at, finding.updated_at,
                finding.detected_by, finding.confidence
            )
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_finding(self, finding_id: int) -> Optional[Finding]:
        """Get a finding by ID."""
        row = self.conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()

        if not row:
            return None

        return self._row_to_finding(row)

    def get_findings(
        self,
        status: Optional[list[Status]] = None,
        severity: Optional[list[Severity]] = None,
        category: Optional[list[Category]] = None,
        file_path: Optional[str] = None,
        limit: int = 100
    ) -> list[Finding]:
        """Get findings with optional filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if status:
            placeholders = ",".join("?" * len(status))
            query += f" AND status IN ({placeholders})"
            params.extend([s.value for s in status])

        if severity:
            placeholders = ",".join("?" * len(severity))
            query += f" AND severity IN ({placeholders})"
            params.extend([s.value for s in severity])

        if category:
            placeholders = ",".join("?" * len(category))
            query += f" AND category IN ({placeholders})"
            params.extend([c.value for c in category])

        if file_path:
            query += " AND file_path LIKE ?"
            params.append(f"%{file_path}%")

        query += " ORDER BY severity, created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def update_finding_status(
        self,
        finding_id: int,
        status: Status,
        issue_number: Optional[int] = None
    ) -> None:
        """Update finding status."""
        self.conn.execute(
            """
            UPDATE findings
            SET status = ?, issue_number = COALESCE(?, issue_number),
                updated_at = ?
            WHERE id = ?
            """,
            (status.value, issue_number, datetime.utcnow().isoformat(), finding_id)
        )
        self.conn.commit()

    def mark_fixed_by_file(self, file_path: str) -> int:
        """Mark all findings in a file as potentially fixed (needs verification)."""
        cursor = self.conn.execute(
            """
            UPDATE findings
            SET status = 'fixed', updated_at = ?
            WHERE file_path = ? AND status IN ('detected', 'reported', 'acknowledged')
            """,
            (datetime.utcnow().isoformat(), file_path)
        )
        self.conn.commit()
        return cursor.rowcount

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        """Convert database row to Finding object."""
        return Finding(
            id=row["id"],
            file_path=row["file_path"],
            line_start=row["line_start"],
            line_end=row["line_end"],
            severity=Severity(row["severity"]),
            category=Category(row["category"]),
            title=row["title"],
            description=row["description"],
            suggestion=row["suggestion"],
            code_snippet=row["code_snippet"],
            status=Status(row["status"]),
            issue_number=row["issue_number"],
            fingerprint=row["fingerprint"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            detected_by=row["detected_by"],
            confidence=row["confidence"]
        )

    # === Scan Runs ===

    def start_scan(self, mode: str, trigger: str) -> int:
        """Record start of a scan run."""
        cursor = self.conn.execute(
            "INSERT INTO scan_runs (started_at, mode, trigger) VALUES (?, ?, ?)",
            (datetime.utcnow().isoformat(), mode, trigger)
        )
        self.conn.commit()
        return cursor.lastrowid

    def complete_scan(
        self,
        scan_id: int,
        files_scanned: int,
        findings_new: int,
        findings_fixed: int,
        issues_created: int,
        duration_seconds: float
    ) -> None:
        """Record completion of a scan run."""
        self.conn.execute(
            """
            UPDATE scan_runs SET
                completed_at = ?,
                files_scanned = ?,
                findings_new = ?,
                findings_fixed = ?,
                issues_created = ?,
                duration_seconds = ?
            WHERE id = ?
            """,
            (
                datetime.utcnow().isoformat(),
                files_scanned, findings_new, findings_fixed,
                issues_created, duration_seconds, scan_id
            )
        )
        self.conn.commit()

    # === File Tracking ===

    def update_file_hash(self, file_path: str, content_hash: str, findings_count: int) -> None:
        """Update or insert file hash for incremental scanning."""
        self.conn.execute(
            """
            INSERT OR REPLACE INTO file_hashes (file_path, content_hash, last_scanned, findings_count)
            VALUES (?, ?, ?, ?)
            """,
            (file_path, content_hash, datetime.utcnow().isoformat(), findings_count)
        )
        self.conn.commit()

    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Get stored hash for a file."""
        row = self.conn.execute(
            "SELECT content_hash FROM file_hashes WHERE file_path = ?",
            (file_path,)
        ).fetchone()
        return row["content_hash"] if row else None

    # === Suppressions ===

    def add_suppression(
        self,
        file_path: Optional[str],
        line_number: Optional[int],
        category: Optional[str],
        reason: str,
        created_by: str = "user"
    ) -> int:
        """Add a suppression rule."""
        cursor = self.conn.execute(
            """
            INSERT INTO suppressions (file_path, line_number, category, reason, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (file_path, line_number, category, reason, datetime.utcnow().isoformat(), created_by)
        )
        self.conn.commit()
        return cursor.lastrowid

    def is_suppressed(self, file_path: str, line_number: int, category: str) -> bool:
        """Check if a finding should be suppressed."""
        row = self.conn.execute(
            """
            SELECT 1 FROM suppressions
            WHERE (file_path IS NULL OR file_path = ?)
              AND (line_number IS NULL OR line_number = ?)
              AND (category IS NULL OR category = ?)
            LIMIT 1
            """,
            (file_path, line_number, category)
        ).fetchone()
        return row is not None

    # === Statistics ===

    def get_stats(self) -> dict:
        """Get summary statistics."""
        stats = {}

        # Open findings by severity
        for severity in Severity:
            count = self.conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = ? AND status IN ('detected', 'reported', 'acknowledged')",
                (severity.value,)
            ).fetchone()[0]
            stats[f"open_{severity.value.lower()}"] = count

        # Total counts
        stats["total_open"] = self.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE status IN ('detected', 'reported', 'acknowledged')"
        ).fetchone()[0]

        stats["total_fixed"] = self.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE status = 'fixed'"
        ).fetchone()[0]

        stats["total_scans"] = self.conn.execute(
            "SELECT COUNT(*) FROM scan_runs"
        ).fetchone()[0]

        stats["issues_created"] = self.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE issue_number IS NOT NULL"
        ).fetchone()[0]

        return stats

    def record_daily_metrics(self) -> None:
        """Record daily metrics snapshot for trend tracking."""
        today = datetime.utcnow().date().isoformat()

        # Check if already recorded today
        existing = self.conn.execute(
            "SELECT 1 FROM metrics WHERE date = ?", (today,)
        ).fetchone()

        if existing:
            return

        stats = self.get_stats()
        self.conn.execute(
            """
            INSERT INTO metrics (date, total_findings, p0_count, p1_count, p2_count, p3_count, fixed_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                today,
                stats["total_open"],
                stats["open_p0"],
                stats["open_p1"],
                stats["open_p2"],
                stats["open_p3"],
                stats["total_fixed"]
            )
        )
        self.conn.commit()
