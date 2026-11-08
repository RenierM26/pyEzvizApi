"""Validate repository documentation without running examples or contacting devices."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import re
import shlex
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'!?\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)')


def prose_and_commands(text: str) -> tuple[list[str], list[tuple[int, str]]]:
    """Retain prose line numbers, and collect only explicit executable CLI lines."""
    prose = []
    commands = []
    fence = None
    shell = False
    pending = ""
    first = 0
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        match = re.match(r"^(`{3,}|~{3,})(.*)$", stripped)
        if match:
            marker, language = match.groups()
            if fence is None:
                fence, shell = marker[0], language.strip() in {"bash", "sh", "shell", "console"}
            elif marker[0] == fence:
                fence, shell = None, False
            prose.append("")
            continue
        if fence:
            prose.append("")
            if shell:
                if not pending and stripped.startswith("pyezvizapi "):
                    first = number
                    pending = stripped
                elif pending:
                    pending += " " + stripped
                if pending.endswith("\\"):
                    pending = pending[:-1]
                elif pending:
                    commands.append((first, pending))
                    pending = ""
        else:
            prose.append(line)
    return prose, commands


def anchors(lines: list[str]) -> set[str]:
    found = set()
    used: dict[str, int] = {}
    for line in lines:
        match = re.match(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if match:
            value = re.sub(r"<[^>]+>", "", match[1]).lower()
            value = re.sub(r"[^\w\- ]", "", value).replace(" ", "-")
            count = used.get(value, 0)
            used[value] = count + 1
            found.add(f"{value}-{count}" if count else value)
        found.update(re.findall(r'<a\s+(?:id|name)=["\x27]([^"\x27]+)', line))
    return found


def check_links(
    root: Path, path: Path, prose: list[str], headings: dict[Path, set[str]]
) -> list[str]:
    label = path.relative_to(root)
    errors = []
    for line_no, line in enumerate(prose, 1):
        for raw in LINK.findall(line):
            target = unquote(raw.strip("<>"))
            parts = urlsplit(target)
            prefix = "/RenierM26/pyEzvizApi/blob/main/"
            if parts.netloc == "github.com" and parts.path.startswith(prefix):
                parts = parts._replace(scheme="", netloc="", path="/" + parts.path[len(prefix) :])
            if parts.scheme or parts.netloc:
                continue
            dest = (
                (
                    root / parts.path.lstrip("/")
                    if parts.path.startswith("/")
                    else path.parent / parts.path
                ).resolve()
                if parts.path
                else path
            )
            if not dest.exists():
                errors.append(f"{label}:{line_no}: missing target {raw}")
            elif (
                parts.fragment
                and dest.suffix == ".md"
                and unquote(parts.fragment) not in headings.get(dest, set())
            ):
                errors.append(f"{label}:{line_no}: missing heading {raw}")
    return errors


def check_commands(
    parser: argparse.ArgumentParser, commands: list[tuple[int, str]], label: Path
) -> tuple[list[str], int]:
    errors = []
    checked = 0
    for line_no, command in commands:
        try:
            tokens = shlex.split(command, comments=True)[1:]
            cut = next(
                (i for i, t in enumerate(tokens) if t in {"|", ">", ">>", "2>"}),
                len(tokens),
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    parser.parse_args(tokens[:cut])
                except SystemExit as exc:
                    if exc.code:
                        raise ValueError("arguments rejected by current parser") from exc
            checked += 1
        except ValueError as exc:
            errors.append(f"{label}:{line_no}: {exc}: {command}")
    return errors, checked


def check(root: Path, *, cli: bool) -> tuple[list[str], int, int]:
    files = sorted(root.rglob("*.md"))
    # Only tracked/source Markdown, not an operator's local environments/builds.
    files = [
        p
        for p in files
        if not any(
            (part.startswith(".") and part != ".github")
            or part in {"build", "dist", "node_modules"}
            for part in p.relative_to(root).parts
        )
    ]
    parsed = {p.resolve(): prose_and_commands(p.read_text(encoding="utf-8")) for p in files}
    headings = {p: anchors(prose) for p, (prose, _) in parsed.items()}
    errors = []
    checked = 0
    parser = None
    if cli:
        sys.path.insert(0, str(root))
        from pyezvizapi.cli.arguments import build_parser  # noqa: PLC0415

        parser = build_parser()
    for path, (prose, commands) in parsed.items():
        errors.extend(check_links(root, path, prose, headings))
        if parser is not None:
            cli_errors, count = check_commands(parser, commands, path.relative_to(root))
            errors.extend(cli_errors)
            checked += count
    changelog = root / "CHANGELOG.md"
    if changelog.exists():
        sections = re.findall(r"^## Unreleased.*$", changelog.read_text(), re.M)
        if sections != ["## Unreleased"]:
            errors.append("CHANGELOG.md: require one exact '## Unreleased' heading")
    return errors, len(files), checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--links-only",
        action="store_true",
        help="Skip CLI syntax checks; no library installation needed",
    )
    args = parser.parse_args()
    errors, files, commands = check(ROOT, cli=not args.links_only)
    for error in errors:
        print(error, file=sys.stderr)
    print(
        f"Checked {files} Markdown files and {commands} CLI examples; {len(errors)} errors. No examples executed; external URLs not checked."
    )
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
