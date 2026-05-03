#!/usr/bin/env python3
"""Read-only GitHub repository monitor for pyEzvizApi.

The script borrows the safe parts of maintainer bots like ClawSweeper:
collect live repository state, write durable records, and publish a compact
dashboard. It deliberately does not mutate GitHub.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

GITHUB_API = "https://api.github.com"
DEFAULT_REPO = "RenierM26/pyEzvizApi"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True)
class Finding:
    kind: str
    item: str
    title: str
    url: str
    severity: str
    action: str
    evidence: list[str]


class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        self.token = token

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        query = f"?{urlencode(params)}" if params else ""
        url = f"{GITHUB_API}{path}{query}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "pyEzvizApi-repo-watch",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API request failed: {exc.code} {url}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"GitHub API request failed: {url}: {exc}") from exc


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def utc_now() -> datetime:
    return datetime.now(UTC)


def stable_hash(payload: Any) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fetch_repo_state(client: GitHubClient, repo: str, limit: int) -> dict[str, Any]:
    owner_repo = f"/repos/{repo}"
    repo_info = client.get(owner_repo)
    issues = client.get(
        f"{owner_repo}/issues",
        {"state": "open", "per_page": limit, "sort": "updated", "direction": "desc"},
    )
    pulls = client.get(
        f"{owner_repo}/pulls",
        {"state": "open", "per_page": limit, "sort": "updated", "direction": "desc"},
    )
    runs = client.get(
        f"{owner_repo}/actions/runs",
        {"per_page": limit, "status": "completed"},
    )
    return {
        "repo": repo_info,
        "issues": [item for item in issues if "pull_request" not in item],
        "pulls": pulls,
        "workflow_runs": runs.get("workflow_runs", []),
    }


def classify_issues(issues: list[dict[str, Any]], now: datetime) -> list[Finding]:
    findings: list[Finding] = []
    stale_after = now - timedelta(days=90)

    for issue in issues:
        labels = {label["name"].lower() for label in issue.get("labels", [])}
        updated_at = parse_timestamp(issue["updated_at"])
        evidence: list[str] = []
        severity = "info"
        action = "keep_open"

        if "bug" in labels and issue.get("comments", 0) == 0:
            severity = "medium"
            action = "needs_human"
            evidence.append("Open bug report has no comments yet.")

        if updated_at < stale_after and not labels.intersection({"pinned", "security"}):
            severity = "low" if severity == "info" else severity
            action = "needs_human" if action == "keep_open" else action
            evidence.append(f"No activity since {updated_at.date().isoformat()}.")

        if not evidence:
            continue

        findings.append(
            Finding(
                kind="issue",
                item=f"#{issue['number']}",
                title=issue["title"],
                url=issue["html_url"],
                severity=severity,
                action=action,
                evidence=evidence,
            )
        )

    return findings


def classify_pulls(
    pulls: list[dict[str, Any]], workflow_runs: list[dict[str, Any]]
) -> list[Finding]:
    findings: list[Finding] = []
    failed_heads = {
        run["head_sha"]
        for run in workflow_runs
        if run.get("conclusion") in {"failure", "timed_out", "cancelled", "action_required"}
    }

    for pull in pulls:
        labels = {label["name"].lower() for label in pull.get("labels", [])}
        evidence: list[str] = []
        severity = "info"
        action = "keep_open"
        head_sha = pull.get("head", {}).get("sha")

        if pull.get("draft"):
            evidence.append("PR is currently marked as draft.")
            action = "keep_open"

        if head_sha in failed_heads:
            evidence.append("Latest observed workflow run for this head SHA did not pass.")
            severity = "high"
            action = "ci_failure_summary"

        if not labels and not pull.get("draft"):
            evidence.append("PR has no labels.")
            severity = "low" if severity == "info" else severity
            action = "needs_human" if action == "keep_open" else action

        if not evidence:
            continue

        findings.append(
            Finding(
                kind="pull_request",
                item=f"#{pull['number']}",
                title=pull["title"],
                url=pull["html_url"],
                severity=severity,
                action=action,
                evidence=evidence,
            )
        )

    return findings


def summarize_workflows(workflow_runs: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for run in workflow_runs:
        conclusion = run.get("conclusion")
        if conclusion not in {"failure", "timed_out", "cancelled", "action_required"}:
            continue

        findings.append(
            Finding(
                kind="workflow_run",
                item=f"run {run['id']}",
                title=run.get("display_title") or run.get("name") or "Workflow run",
                url=run["html_url"],
                severity="high" if conclusion == "failure" else "medium",
                action="needs_human",
                evidence=[
                    f"Workflow `{run.get('name', 'unknown')}` concluded with `{conclusion}`.",
                    f"Head branch `{run.get('head_branch')}` at `{run.get('head_sha', '')[:12]}`.",
                ],
            )
        )
    return findings


def record_payload(
    repo: str, generated_at: str, finding: Finding, source_hash: str
) -> dict[str, Any]:
    return {
        "repo": repo,
        "generated_at": generated_at,
        "kind": finding.kind,
        "item": finding.item,
        "title": finding.title,
        "url": finding.url,
        "severity": finding.severity,
        "action": finding.action,
        "confidence": "medium",
        "source_hash": source_hash,
        "evidence": finding.evidence,
        "allowed_mutation": "none",
    }


def write_records(
    output: Path, repo: str, generated_at: str, findings: list[Finding], state: dict[str, Any]
) -> None:
    source_hash = stable_hash(state)
    records_dir = output / "records" / repo.replace("/", "__")
    records_dir.mkdir(parents=True, exist_ok=True)

    for finding in findings:
        item_slug = finding.item.replace("#", "issue-").replace(" ", "-")
        record = record_payload(repo, generated_at, finding, source_hash)
        write_json(records_dir / f"{finding.kind}-{item_slug}.json", record)


def render_dashboard(
    repo: str, generated_at: str, findings: list[Finding], state: dict[str, Any]
) -> str:
    repo_info = state["repo"]
    issue_count = len(state["issues"])
    pull_count = len(state["pulls"])
    failed_runs = [
        run
        for run in state["workflow_runs"]
        if run.get("conclusion") in {"failure", "timed_out", "cancelled", "action_required"}
    ]

    lines = [
        f"# Repository Watch Dashboard: {repo}",
        "",
        f"- Generated: `{generated_at}`",
        f"- Repository: [{repo}]({repo_info['html_url']})",
        f"- Default branch: `{repo_info.get('default_branch', 'unknown')}`",
        f"- Open issues sampled: `{issue_count}`",
        f"- Open PRs sampled: `{pull_count}`",
        f"- Recent failed/problem workflow runs: `{len(failed_runs)}`",
        f"- Findings: `{len(findings)}`",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No monitor findings in the sampled repository state.")
    else:
        for finding in sorted(findings, key=lambda item: SEVERITY_ORDER[item.severity]):
            lines.extend(
                [
                    f"### {finding.severity.upper()} {finding.kind} {finding.item}: {finding.title}",
                    "",
                    f"- Action: `{finding.action}`",
                    f"- URL: {finding.url}",
                    "- Evidence:",
                ]
            )
            lines.extend(f"  - {evidence}" for evidence in finding.evidence)
            lines.append("")

    lines.extend(
        [
            "## Operating Rules",
            "",
            "- This monitor is read-only.",
            "- Review records are durable evidence, not automatic GitHub actions.",
            "- Any future write mode should re-fetch live state and edit one marker-backed comment per item.",
        ]
    )
    return "\n".join(lines) + "\n"


def run(repo: str, output: Path, limit: int) -> int:
    generated_at = utc_now().isoformat(timespec="seconds")
    token = os.environ.get("GITHUB_TOKEN")
    client = GitHubClient(token=token)
    state = fetch_repo_state(client, repo, limit)

    findings = [
        *classify_issues(state["issues"], utc_now()),
        *classify_pulls(state["pulls"], state["workflow_runs"]),
        *summarize_workflows(state["workflow_runs"]),
    ]

    write_json(output / "state" / "latest.json", state)
    write_records(output, repo, generated_at, findings, state)
    dashboard = render_dashboard(repo, generated_at, findings, state)
    dashboard_path = output / "dashboard.md"
    dashboard_path.parent.mkdir(parents=True, exist_ok=True)
    dashboard_path.write_text(dashboard, encoding="utf-8")

    print(f"Wrote {dashboard_path} with {len(findings)} findings.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=DEFAULT_REPO, help="Repository in owner/name form.")
    parser.add_argument("--output", default=".repo-watch", type=Path, help="Output directory.")
    parser.add_argument("--limit", default=50, type=int, help="Maximum issues/PRs/runs to sample.")
    args = parser.parse_args(argv)

    try:
        return run(args.repo, args.output, args.limit)
    except RuntimeError as exc:
        print(f"repo-watch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
