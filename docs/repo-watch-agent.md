# Repository Watch Agent

This repository includes a small read-only monitor inspired by ClawSweeper's
operating model: collect live GitHub state, write durable records, and publish a
dashboard before any mutation is considered.

The first version intentionally does not comment, label, close, merge, or push.
It is a trust-building layer for maintainer attention.

## Run Locally

```bash
python tools/repo_watch.py --repo RenierM26/pyEzvizApi --output .repo-watch
```

For higher rate limits, set `GITHUB_TOKEN` first. The token only needs read
access for this version.

Outputs:

- `.repo-watch/state/latest.json` stores the sampled GitHub state.
- `.repo-watch/records/RenierM26__pyEzvizApi/*.json` stores durable finding
  records.
- `.repo-watch/dashboard.md` stores the human-readable dashboard.

## What It Watches

- Open issues with no activity or bug reports that have not received a comment.
- Open PRs with failed recent workflow runs, no labels, or draft state.
- Recent workflow runs that failed, timed out, were cancelled, or need action.

The action vocabulary is deliberately narrow:

- `keep_open`
- `needs_human`
- `ci_failure_summary`

## GitHub Actions

`.github/workflows/repo-watch.yml` runs the monitor on a schedule and uploads the
generated dashboard/records as an artifact.

The workflow uses read-only permissions:

```yaml
permissions:
  contents: read
  actions: read
  issues: read
  pull-requests: read
```

## Promotion Path

Keep the sequence conservative:

1. Run read-only and inspect dashboard quality.
2. Add marker-backed comments for high-signal CI failure summaries only.
3. Add labels only after the comment mode is reliable.
4. Consider close/merge actions last, and only with explicit opt-in labels.

Future write mode should be a separate apply lane. It should re-fetch live
GitHub state, compare the stored source hash/snapshot, and refuse to mutate when
the item changed after review.
