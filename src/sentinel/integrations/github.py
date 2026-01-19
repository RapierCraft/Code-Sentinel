"""
GitHub integration for Code Sentinel.

Provides:
- Issue creation for findings
- PR comment integration
- Check run reporting
- Repository webhooks
"""

import subprocess
import json
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class GitHubIssue:
    """A GitHub issue."""
    number: int
    title: str
    body: str
    state: str
    url: str
    labels: list[str]
    created_at: datetime


@dataclass
class GitHubPR:
    """A GitHub pull request."""
    number: int
    title: str
    body: str
    state: str
    url: str
    base_branch: str
    head_branch: str
    author: str
    created_at: datetime


class GitHubIntegration:
    """
    GitHub integration using the gh CLI.

    Requires: gh CLI installed and authenticated
    """

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self._verify_gh()
        self.repo_info = self._get_repo_info()

    def _verify_gh(self) -> None:
        """Verify gh CLI is available and authenticated."""
        try:
            result = subprocess.run(
                ["gh", "auth", "status"],
                capture_output=True,
                text=True,
                cwd=self.repo_path
            )
            if result.returncode != 0:
                raise ValueError("GitHub CLI not authenticated. Run: gh auth login")
        except FileNotFoundError:
            raise ValueError("GitHub CLI (gh) not found. Install from: https://cli.github.com")

    def _get_repo_info(self) -> dict:
        """Get repository owner and name."""
        result = subprocess.run(
            ["gh", "repo", "view", "--json", "owner,name,url"],
            capture_output=True,
            text=True,
            cwd=self.repo_path
        )

        if result.returncode == 0:
            return json.loads(result.stdout)
        return {}

    def _run_gh(self, *args, check: bool = True) -> subprocess.CompletedProcess:
        """Run a gh command."""
        return subprocess.run(
            ["gh", *args],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=check
        )

    def create_issue(
        self,
        title: str,
        body: str,
        labels: Optional[list[str]] = None
    ) -> Optional[GitHubIssue]:
        """
        Create a GitHub issue for a finding.

        Args:
            title: Issue title
            body: Issue body (markdown)
            labels: Labels to apply

        Returns:
            Created issue or None if failed
        """
        args = ["issue", "create", "--title", title, "--body", body]

        if labels:
            for label in labels:
                args.extend(["--label", label])

        try:
            result = self._run_gh(*args)
            # Parse issue URL from output
            url = result.stdout.strip()

            # Get issue details
            issue_num = url.split("/")[-1]
            details = self._run_gh("issue", "view", issue_num, "--json",
                                   "number,title,body,state,url,labels,createdAt")
            data = json.loads(details.stdout)

            return GitHubIssue(
                number=data["number"],
                title=data["title"],
                body=data["body"],
                state=data["state"],
                url=data["url"],
                labels=[l["name"] for l in data.get("labels", [])],
                created_at=datetime.fromisoformat(data["createdAt"].replace("Z", "+00:00"))
            )
        except subprocess.CalledProcessError:
            return None

    def create_issue_from_finding(self, finding) -> Optional[GitHubIssue]:
        """
        Create a GitHub issue from a Sentinel finding.

        Args:
            finding: Finding object from Sentinel

        Returns:
            Created issue or None
        """
        # Format issue body
        body = f"""## {finding.category.value} Issue

**Severity:** {finding.severity.value}
**File:** `{finding.file_path}`
**Lines:** {finding.line_start}-{finding.line_end}

### Description
{finding.description}

### Suggestion
{finding.suggestion or 'No suggestion available'}

### Code
```
{finding.code_snippet or 'No snippet available'}
```

---
*Detected by Code Sentinel ({finding.detected_by})*
"""

        # Determine labels
        labels = ["sentinel"]
        if finding.severity.value == "P0":
            labels.append("critical")
        elif finding.severity.value == "P1":
            labels.append("high-priority")

        if finding.category.value == "security":
            labels.append("security")

        return self.create_issue(
            title=f"[Sentinel] {finding.title}",
            body=body,
            labels=labels
        )

    def add_pr_comment(
        self,
        pr_number: int,
        body: str,
        file_path: Optional[str] = None,
        line: Optional[int] = None
    ) -> bool:
        """
        Add a comment to a PR.

        Args:
            pr_number: PR number
            body: Comment body
            file_path: If provided, add as review comment on specific file
            line: If provided with file_path, comment on specific line

        Returns:
            True if successful
        """
        try:
            if file_path and line:
                # Line-specific review comment
                result = self._run_gh(
                    "api",
                    f"/repos/{self.repo_info.get('owner', {}).get('login', '')}/{self.repo_info.get('name', '')}/pulls/{pr_number}/comments",
                    "-f", f"body={body}",
                    "-f", f"path={file_path}",
                    "-f", f"line={line}",
                    "-f", "side=RIGHT",
                    "-X", "POST",
                    check=False
                )
            else:
                # General PR comment
                result = self._run_gh(
                    "pr", "comment", str(pr_number),
                    "--body", body,
                    check=False
                )

            return result.returncode == 0
        except Exception:
            return False

    def add_review_comments(self, pr_number: int, findings: list) -> int:
        """
        Add review comments for multiple findings on a PR.

        Args:
            pr_number: PR number
            findings: List of Finding objects

        Returns:
            Number of comments successfully added
        """
        success_count = 0

        for finding in findings:
            comment = f"""**{finding.severity.value} - {finding.title}**

{finding.description}

**Suggestion:** {finding.suggestion or 'N/A'}

---
*Code Sentinel*"""

            if self.add_pr_comment(
                pr_number,
                comment,
                file_path=finding.file_path,
                line=finding.line_start
            ):
                success_count += 1

        return success_count

    def get_pr(self, pr_number: int) -> Optional[GitHubPR]:
        """Get PR details."""
        try:
            result = self._run_gh(
                "pr", "view", str(pr_number),
                "--json", "number,title,body,state,url,baseRefName,headRefName,author,createdAt"
            )
            data = json.loads(result.stdout)

            return GitHubPR(
                number=data["number"],
                title=data["title"],
                body=data["body"],
                state=data["state"],
                url=data["url"],
                base_branch=data["baseRefName"],
                head_branch=data["headRefName"],
                author=data["author"]["login"],
                created_at=datetime.fromisoformat(data["createdAt"].replace("Z", "+00:00"))
            )
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError):
            return None

    def get_open_prs(self) -> list[GitHubPR]:
        """Get list of open PRs."""
        prs = []

        try:
            result = self._run_gh(
                "pr", "list",
                "--json", "number,title,body,state,url,baseRefName,headRefName,author,createdAt"
            )
            data = json.loads(result.stdout)

            for pr_data in data:
                prs.append(GitHubPR(
                    number=pr_data["number"],
                    title=pr_data["title"],
                    body=pr_data.get("body", ""),
                    state=pr_data["state"],
                    url=pr_data["url"],
                    base_branch=pr_data["baseRefName"],
                    head_branch=pr_data["headRefName"],
                    author=pr_data["author"]["login"],
                    created_at=datetime.fromisoformat(pr_data["createdAt"].replace("Z", "+00:00"))
                ))
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass

        return prs

    def get_pr_files(self, pr_number: int) -> list[str]:
        """Get list of files changed in a PR."""
        try:
            result = self._run_gh(
                "pr", "view", str(pr_number),
                "--json", "files"
            )
            data = json.loads(result.stdout)
            return [f["path"] for f in data.get("files", [])]
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []

    def create_check_run(self, findings: list, sha: str) -> bool:
        """
        Create a GitHub check run with findings summary.

        Args:
            findings: List of findings
            sha: Commit SHA to attach check to

        Returns:
            True if successful
        """
        # Count by severity
        p0_count = sum(1 for f in findings if f.severity.value == "P0")
        p1_count = sum(1 for f in findings if f.severity.value == "P1")
        p2_count = sum(1 for f in findings if f.severity.value == "P2")
        p3_count = sum(1 for f in findings if f.severity.value == "P3")

        conclusion = "success"
        if p0_count > 0:
            conclusion = "failure"
        elif p1_count > 0:
            conclusion = "failure"
        elif p2_count > 5:
            conclusion = "neutral"

        summary = f"""## Code Sentinel Analysis

| Severity | Count |
|----------|-------|
| P0 (Critical) | {p0_count} |
| P1 (High) | {p1_count} |
| P2 (Medium) | {p2_count} |
| P3 (Low) | {p3_count} |

**Total: {len(findings)} issues**
"""

        # Build annotations
        annotations = []
        for finding in findings[:50]:  # GitHub limits to 50
            annotations.append({
                "path": finding.file_path,
                "start_line": finding.line_start,
                "end_line": finding.line_end,
                "annotation_level": "failure" if finding.severity.value in ("P0", "P1") else "warning",
                "message": finding.description,
                "title": finding.title
            })

        try:
            owner = self.repo_info.get("owner", {}).get("login", "")
            repo = self.repo_info.get("name", "")

            # Create check run via API
            payload = {
                "name": "Code Sentinel",
                "head_sha": sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": f"Code Sentinel: {len(findings)} issues found",
                    "summary": summary,
                    "annotations": annotations
                }
            }

            result = subprocess.run(
                ["gh", "api", f"/repos/{owner}/{repo}/check-runs",
                 "-X", "POST", "--input", "-"],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                cwd=self.repo_path
            )

            return result.returncode == 0
        except Exception:
            return False

    def find_existing_issue(self, finding) -> Optional[GitHubIssue]:
        """Check if an issue already exists for a finding."""
        try:
            search_query = f"[Sentinel] {finding.title} in:title is:issue"
            result = self._run_gh(
                "issue", "list",
                "--search", search_query,
                "--json", "number,title,body,state,url,labels,createdAt",
                "--limit", "1"
            )

            data = json.loads(result.stdout)
            if data:
                issue = data[0]
                return GitHubIssue(
                    number=issue["number"],
                    title=issue["title"],
                    body=issue["body"],
                    state=issue["state"],
                    url=issue["url"],
                    labels=[l["name"] for l in issue.get("labels", [])],
                    created_at=datetime.fromisoformat(issue["createdAt"].replace("Z", "+00:00"))
                )
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass

        return None
