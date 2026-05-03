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
DEFAULT_CONFIG_PATH = Path("config/repo-watch.json")


@dataclass(frozen=True)
class MonitorConfig:
    stale_issue_days: int = 90
    ignored_stale_labels: tuple[str, ...] = ("pinned", "security")
    uncommented_bug_labels: tuple[str, ...] = ("bug",)
    require_pr_labels: bool = True
    problem_workflow_conclusions: tuple[str, ...] = (
        "failure",
        "timed_out",
        "cancelled",
        "action_required",
    )
    digest_min_severity: str = "medium"
    digest_max_items: int = 10


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


def load_config(path: Path) -> MonitorConfig:
    if not path.exists():
        return MonitorConfig()

    raw = json.loads(path.read_text(encoding="utf-8"))
    config = MonitorConfig(
        stale_issue_days=int(raw.get("stale_issue_days", MonitorConfig.stale_issue_days)),
        ignored_stale_labels=tuple(
            label.lower()
            for label in raw.get("ignored_stale_labels", MonitorConfig.ignored_stale_labels)
        ),
        uncommented_bug_labels=tuple(
            label.lower()
            for label in raw.get("uncommented_bug_labels", MonitorConfig.uncommented_bug_labels)
        ),
        require_pr_labels=bool(raw.get("require_pr_labels", MonitorConfig.require_pr_labels)),
        problem_workflow_conclusions=tuple(
            raw.get("problem_workflow_conclusions", MonitorConfig.problem_workflow_conclusions)
        ),
        digest_min_severity=str(raw.get("digest_min_severity", MonitorConfig.digest_min_severity)),
        digest_max_items=int(raw.get("digest_max_items", MonitorConfig.digest_max_items)),
    )

    if config.stale_issue_days < 1:
        raise RuntimeError("repo-watch config `stale_issue_days` must be at least 1.")
    if config.digest_min_severity not in SEVERITY_ORDER:
        raise RuntimeError(
            "repo-watch config `digest_min_severity` must be one of: " + ", ".join(SEVERITY_ORDER)
        )
    if config.digest_max_items < 1:
        raise RuntimeError("repo-watch config `digest_max_items` must be at least 1.")

    return config


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
    recent_runs = client.get(
        f"{owner_repo}/actions/runs",
        {"per_page": limit, "status": "completed"},
    )
    workflow_runs_by_head: dict[str, list[dict[str, Any]]] = {}
    for pull in pulls:
        head_sha = pull.get("head", {}).get("sha")
        if not head_sha:
            continue
        runs = client.get(
            f"{owner_repo}/actions/runs",
            {"head_sha": head_sha, "per_page": limit, "status": "completed"},
        )
        workflow_runs_by_head[head_sha] = runs.get("workflow_runs", [])

    return {
        "repo": repo_info,
        "issues": [item for item in issues if "pull_request" not in item],
        "pulls": pulls,
        "workflow_runs": recent_runs.get("workflow_runs", []),
        "workflow_runs_by_head": workflow_runs_by_head,
    }


def classify_issues(
    issues: list[dict[str, Any]], now: datetime, config: MonitorConfig
) -> list[Finding]:
    findings: list[Finding] = []
    stale_after = now - timedelta(days=config.stale_issue_days)

    for issue in issues:
        labels = {label["name"].lower() for label in issue.get("labels", [])}
        updated_at = parse_timestamp(issue["updated_at"])
        evidence: list[str] = []
        severity = "info"
        action = "keep_open"

        if labels.intersection(config.uncommented_bug_labels) and issue.get("comments", 0) == 0:
            severity = "medium"
            action = "needs_human"
            evidence.append("Open bug report has no comments yet.")

        if updated_at < stale_after and not labels.intersection(config.ignored_stale_labels):
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
    pulls: list[dict[str, Any]],
    workflow_runs_by_head: dict[str, list[dict[str, Any]]],
    config: MonitorConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    for pull in pulls:
        labels = {label["name"].lower() for label in pull.get("labels", [])}
        evidence: list[str] = []
        severity = "info"
        action = "keep_open"
        head_sha = pull.get("head", {}).get("sha")
        latest_runs_by_workflow: dict[str, dict[str, Any]] = {}
        for run in workflow_runs_by_head.get(head_sha, []) if head_sha else []:
            workflow_id = str(run.get("workflow_id") or run["id"])
            current = latest_runs_by_workflow.get(workflow_id)
            if current is None or parse_timestamp(run["updated_at"]) > parse_timestamp(
                current["updated_at"]
            ):
                latest_runs_by_workflow[workflow_id] = run
        latest_runs = list(latest_runs_by_workflow.values())
        failing_runs = [
            run
            for run in latest_runs
            if run.get("conclusion") in config.problem_workflow_conclusions
        ]

        if pull.get("draft"):
            evidence.append("PR is currently marked as draft.")
            action = "keep_open"

        if failing_runs:
            evidence.append(
                "Latest observed workflow runs for this head SHA did not all pass: "
                + ", ".join(
                    f"`{run.get('name', 'unknown')}` concluded with `{run['conclusion']}`"
                    for run in sorted(failing_runs, key=lambda item: item.get("name") or "")
                )
                + "."
            )
            severity = "high"
            action = "ci_failure_summary"

        if config.require_pr_labels and not labels and not pull.get("draft"):
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


def summarize_workflows(
    workflow_runs: list[dict[str, Any]], config: MonitorConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for run in workflow_runs:
        conclusion = run.get("conclusion")
        if conclusion not in config.problem_workflow_conclusions:
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
    repo: str,
    generated_at: str,
    findings: list[Finding],
    state: dict[str, Any],
    config: MonitorConfig,
) -> str:
    repo_info = state["repo"]
    issue_count = len(state["issues"])
    pull_count = len(state["pulls"])
    failed_runs = [
        run
        for run in state["workflow_runs"]
        if run.get("conclusion") in config.problem_workflow_conclusions
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


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {
        severity: sum(1 for finding in findings if finding.severity == severity)
        for severity in SEVERITY_ORDER
    }


def attention_findings(findings: list[Finding], config: MonitorConfig) -> list[Finding]:
    threshold = SEVERITY_ORDER[config.digest_min_severity]
    attention = [finding for finding in findings if SEVERITY_ORDER[finding.severity] <= threshold]
    return sorted(attention, key=lambda item: SEVERITY_ORDER[item.severity])[
        : config.digest_max_items
    ]


def render_openclaw_digest(
    repo: str,
    generated_at: str,
    findings: list[Finding],
    state: dict[str, Any],
    config: MonitorConfig,
) -> str:
    counts = severity_counts(findings)
    attention = attention_findings(findings, config)
    repo_url = state["repo"]["html_url"]

    lines = [
        f"# OpenClaw Repository Digest: {repo}",
        "",
        f"- Generated: `{generated_at}`",
        f"- Repository: [{repo}]({repo_url})",
        f"- Open issues sampled: `{len(state['issues'])}`",
        f"- Open PRs sampled: `{len(state['pulls'])}`",
        "- Findings: " + ", ".join(f"`{severity}: {count}`" for severity, count in counts.items()),
        "",
        "## Attention",
        "",
    ]

    if not attention:
        lines.append(f"No findings at `{config.digest_min_severity}` severity or higher.")
    else:
        for finding in attention:
            first_evidence = finding.evidence[0] if finding.evidence else "No evidence recorded."
            lines.extend(
                [
                    f"- **{finding.severity.upper()}** {finding.kind} {finding.item}: "
                    f"[{finding.title}]({finding.url})",
                    f"  - Action: `{finding.action}`",
                    f"  - Evidence: {first_evidence}",
                ]
            )

    lines.extend(
        [
            "",
            "## Next",
            "",
            "- Use this digest for OpenClaw notifications.",
            "- Inspect `.repo-watch/dashboard.md` for the full finding list.",
            "- The monitor is still read-only.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_digest_json(
    path: Path,
    repo: str,
    generated_at: str,
    findings: list[Finding],
    state: dict[str, Any],
    config: MonitorConfig,
) -> None:
    attention = attention_findings(findings, config)
    write_json(
        path,
        {
            "repo": repo,
            "repo_url": state["repo"]["html_url"],
            "generated_at": generated_at,
            "sampled": {
                "open_issues": len(state["issues"]),
                "open_pulls": len(state["pulls"]),
            },
            "counts": severity_counts(findings),
            "digest_min_severity": config.digest_min_severity,
            "attention": [
                {
                    "kind": finding.kind,
                    "item": finding.item,
                    "title": finding.title,
                    "url": finding.url,
                    "severity": finding.severity,
                    "action": finding.action,
                    "evidence": finding.evidence,
                }
                for finding in attention
            ],
        },
    )


def run(repo: str, output: Path, limit: int, config_path: Path) -> int:
    generated_at = utc_now().isoformat(timespec="seconds")
    config = load_config(config_path)
    token = os.environ.get("GITHUB_TOKEN")
    client = GitHubClient(token=token)
    state = fetch_repo_state(client, repo, limit)

    findings = [
        *classify_issues(state["issues"], utc_now(), config),
        *classify_pulls(state["pulls"], state["workflow_runs_by_head"], config),
        *summarize_workflows(state["workflow_runs"], config),
    ]

    write_json(output / "state" / "config.json", config.__dict__)
    write_json(output / "state" / "latest.json", state)
    write_records(output, repo, generated_at, findings, state)
    dashboard = render_dashboard(repo, generated_at, findings, state, config)
    dashboard_path = output / "dashboard.md"
    dashboard_path.parent.mkdir(parents=True, exist_ok=True)
    dashboard_path.write_text(dashboard, encoding="utf-8")
    digest = render_openclaw_digest(repo, generated_at, findings, state, config)
    digest_path = output / "openclaw-digest.md"
    digest_path.write_text(digest, encoding="utf-8")
    write_digest_json(output / "openclaw-digest.json", repo, generated_at, findings, state, config)

    print(f"Wrote {dashboard_path} and {digest_path} with {len(findings)} findings.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=DEFAULT_REPO, help="Repository in owner/name form.")
    parser.add_argument("--output", default=".repo-watch", type=Path, help="Output directory.")
    parser.add_argument("--limit", default=50, type=int, help="Maximum issues/PRs/runs to sample.")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        type=Path,
        help="Path to the repository watch JSON config.",
    )
    args = parser.parse_args(argv)

    try:
        return run(args.repo, args.output, args.limit, args.config)
    except RuntimeError as exc:
        print(f"repo-watch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
