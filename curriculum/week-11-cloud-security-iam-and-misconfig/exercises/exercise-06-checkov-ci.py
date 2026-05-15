#!/usr/bin/env python3
"""Exercise 6 — Drive Checkov from CI, Gate Builds.

AUTHORIZED USE ONLY.  This script wraps Checkov; Checkov itself reads
text on disk and does not call any cloud API.  No credentials are
required.  See the week README banner for the broader policy on running
security tooling.

This script is a small wrapper around the ``checkov`` command-line tool
that adds three behaviours a real CI pipeline needs:

  1. Pinned configuration: invoke Checkov with explicit framework,
     output-format, and skip-check arguments, so the CI run does not
     drift as the upstream defaults change.
  2. Severity gating: parse Checkov's JSON output, compute the count
     of failing checks at or above a configurable severity threshold,
     and exit non-zero when that count is positive.
  3. Pull-request comment generation: emit a markdown summary of the
     scan suitable for posting back to a GitHub PR via ``gh pr comment``.

USAGE
-----
    python3 exercise-06-checkov-ci.py --directory ./terraform
    python3 exercise-06-checkov-ci.py --directory ./terraform --fail-on HIGH
    python3 exercise-06-checkov-ci.py --directory ./terraform --emit-markdown out.md
    python3 exercise-06-checkov-ci.py --directory ./terraform --skip-check CKV_AWS_50,CKV_AWS_79
    python3 exercise-06-checkov-ci.py --directory ./terraform --use-existing-report report.json

REQUIREMENTS
------------
    - Python 3.11 or later.
    - Checkov 3.x on PATH (``pipx install checkov``) when running a live scan.
    - No external Python packages.  Standard library only.

REFERENCE
---------
    Checkov docs        — https://www.checkov.io/
    Checkov GitHub      — https://github.com/bridgecrewio/checkov
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Checkov ships severities both lower- and upper-cased depending on
# the source of the check; normalise on upper.
SEVERITY_ALIASES: dict[str, str] = {
    "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
    "INFORMATIONAL": "INFO",
}

DEFAULT_FRAMEWORKS: tuple[str, ...] = (
    "terraform",
    "cloudformation",
    "kubernetes",
    "dockerfile",
    "github_actions",
)

EXIT_OK: int = 0
EXIT_BAD_INPUT: int = 1
EXIT_FINDINGS_OVER_THRESHOLD: int = 2
EXIT_CHECKOV_MISSING: int = 3
EXIT_CHECKOV_CRASHED: int = 4


# ---------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class CheckResult:
    """One Checkov finding (a failed or skipped check)."""

    check_id: str
    check_name: str
    severity: str
    severity_rank: int
    resource: str
    file_path: str
    file_line_range: tuple[int, int]
    guideline: str
    framework: str


@dataclass
class ScanSummary:
    """Aggregated scan result."""

    passed: int = 0
    failed: int = 0
    skipped: int = 0
    parsing_errors: int = 0
    failed_by_severity: dict[str, int] = field(default_factory=dict)
    failed_checks: list[CheckResult] = field(default_factory=list)


# ---------------------------------------------------------------------
# Running Checkov
# ---------------------------------------------------------------------


def _normalise_severity(value: str | None) -> str:
    if not value:
        return "INFO"
    upper: str = value.upper()
    return SEVERITY_ALIASES.get(value, upper)


def _check_checkov_available() -> str | None:
    """Return the path to ``checkov`` if installed, else None."""
    return shutil.which("checkov")


def run_checkov(
    directory: Path,
    frameworks: Iterable[str],
    skip_checks: Iterable[str],
    output_file: Path,
) -> int:
    """Invoke ``checkov`` and write its JSON output to `output_file`.

    Returns Checkov's exit code.  Checkov returns non-zero whenever any
    check fails, which is the documented behaviour; we treat that as
    normal and use the JSON output to drive our own gating.
    """
    checkov_path: str | None = _check_checkov_available()
    if checkov_path is None:
        print(
            "error: `checkov` is not on PATH.  Install with `pipx install checkov`.",
            file=sys.stderr,
        )
        return EXIT_CHECKOV_MISSING

    cmd: list[str] = [
        checkov_path,
        "--directory",
        str(directory),
        "--output",
        "json",
        "--output-file-path",
        str(output_file.parent),
        "--quiet",
        "--compact",
    ]
    for framework in frameworks:
        cmd.extend(["--framework", framework])
    for check in skip_checks:
        cmd.extend(["--skip-check", check])

    try:
        completed = subprocess.run(  # noqa: S603 — argv list, not shell
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        print(f"error: failed to invoke checkov: {exc}", file=sys.stderr)
        return EXIT_CHECKOV_CRASHED

    # Checkov writes the JSON to <output-file-path>/results_json.json by
    # default.  Move it into the canonical location for our parser.
    candidate: Path = output_file.parent / "results_json.json"
    if candidate.exists() and candidate != output_file:
        candidate.replace(output_file)

    if completed.returncode not in (0, 1):
        # Exit code 1 is "checks failed"; anything else is a tool error.
        print(completed.stdout, file=sys.stdout)
        print(completed.stderr, file=sys.stderr)
        return EXIT_CHECKOV_CRASHED

    return completed.returncode


# ---------------------------------------------------------------------
# Parsing the JSON output
# ---------------------------------------------------------------------


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_failed_check(entry: dict[str, Any], framework: str) -> CheckResult:
    severity_raw: str = str(entry.get("severity") or "INFO")
    severity: str = _normalise_severity(severity_raw)
    severity_rank: int = SEVERITY_ORDER.get(severity, 0)

    file_line_raw: list[Any] = entry.get("file_line_range") or [0, 0]
    if isinstance(file_line_raw, list) and len(file_line_raw) >= 2:
        line_start: int = _to_int(file_line_raw[0])
        line_end: int = _to_int(file_line_raw[1])
    else:
        line_start = 0
        line_end = 0

    return CheckResult(
        check_id=str(entry.get("check_id", "")),
        check_name=str(entry.get("check_name", "")),
        severity=severity,
        severity_rank=severity_rank,
        resource=str(entry.get("resource", "")),
        file_path=str(entry.get("file_path", "")),
        file_line_range=(line_start, line_end),
        guideline=str(entry.get("guideline", "")),
        framework=framework,
    )


def parse_checkov_report(report_path: Path) -> ScanSummary:
    """Read a Checkov JSON report and produce a ScanSummary."""
    if not report_path.exists():
        raise FileNotFoundError(f"Checkov report not found: {report_path}")

    raw: str = report_path.read_text(encoding="utf-8")
    if not raw.strip():
        return ScanSummary()

    parsed: Any = json.loads(raw)
    summary = ScanSummary()
    summary.failed_by_severity = {key: 0 for key in SEVERITY_ORDER}

    # Checkov emits either a single object (when one framework ran) or a
    # list of objects (when multiple ran).  Normalise to a list.
    if isinstance(parsed, dict):
        frameworks_results: list[dict[str, Any]] = [parsed]
    elif isinstance(parsed, list):
        frameworks_results = [x for x in parsed if isinstance(x, dict)]
    else:
        raise ValueError(
            f"Unexpected top-level shape in Checkov report: "
            f"{type(parsed).__name__}"
        )

    for framework_block in frameworks_results:
        framework: str = str(framework_block.get("check_type", "unknown"))
        results: dict[str, Any] = framework_block.get("results") or {}
        summary_block: dict[str, Any] = framework_block.get("summary") or {}

        summary.passed += _to_int(summary_block.get("passed"))
        summary.failed += _to_int(summary_block.get("failed"))
        summary.skipped += _to_int(summary_block.get("skipped"))
        summary.parsing_errors += _to_int(summary_block.get("parsing_errors"))

        failed_checks: list[dict[str, Any]] = list(
            results.get("failed_checks") or []
        )
        for entry in failed_checks:
            if not isinstance(entry, dict):
                continue
            result: CheckResult = parse_failed_check(entry, framework)
            summary.failed_checks.append(result)
            summary.failed_by_severity[result.severity] = (
                summary.failed_by_severity.get(result.severity, 0) + 1
            )

    return summary


# ---------------------------------------------------------------------
# Gating logic
# ---------------------------------------------------------------------


def gating_decision(summary: ScanSummary, fail_on: str) -> tuple[bool, int]:
    """Return ``(should_fail, count_at_or_above_threshold)``."""
    threshold: int = SEVERITY_ORDER.get(fail_on.upper(), 0)
    count: int = sum(
        1 for c in summary.failed_checks if c.severity_rank >= threshold
    )
    return (count > 0, count)


# ---------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------


def render_text(summary: ScanSummary, fail_on: str) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("CHECKOV SCAN SUMMARY")
    lines.append("=" * 72)
    lines.append(f"Passed         : {summary.passed}")
    lines.append(f"Failed         : {summary.failed}")
    lines.append(f"Skipped        : {summary.skipped}")
    lines.append(f"Parsing errors : {summary.parsing_errors}")
    lines.append("")

    lines.append("Failed checks by severity:")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count: int = summary.failed_by_severity.get(severity, 0)
        lines.append(f"  {severity:<10} {count:>5}")
    lines.append("")

    sorted_failures: list[CheckResult] = sorted(
        summary.failed_checks,
        key=lambda c: (-c.severity_rank, c.check_id, c.file_path),
    )
    lines.append(f"Failed checks at or above {fail_on}:")
    threshold: int = SEVERITY_ORDER.get(fail_on.upper(), 0)
    over_threshold: list[CheckResult] = [
        c for c in sorted_failures if c.severity_rank >= threshold
    ]
    if not over_threshold:
        lines.append("  (none)")
    for check in over_threshold:
        start, end = check.file_line_range
        location: str = (
            f"{check.file_path}:{start}-{end}" if start else check.file_path
        )
        lines.append(f"  [{check.severity:<8}] {check.check_id}")
        lines.append(f"             {check.check_name}")
        lines.append(f"             Resource : {check.resource}")
        lines.append(f"             File     : {location}")
        if check.guideline:
            lines.append(f"             Guideline: {check.guideline}")
        lines.append("")

    return "\n".join(lines)


def render_markdown(summary: ScanSummary, fail_on: str) -> str:
    lines: list[str] = []
    lines.append("# Checkov Scan Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|------:|")
    lines.append(f"| Passed | {summary.passed} |")
    lines.append(f"| Failed | {summary.failed} |")
    lines.append(f"| Skipped | {summary.skipped} |")
    lines.append(f"| Parsing errors | {summary.parsing_errors} |")
    lines.append("")

    lines.append("## Failed checks by severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count: int = summary.failed_by_severity.get(severity, 0)
        lines.append(f"| {severity} | {count} |")
    lines.append("")

    threshold: int = SEVERITY_ORDER.get(fail_on.upper(), 0)
    over_threshold: list[CheckResult] = sorted(
        [c for c in summary.failed_checks if c.severity_rank >= threshold],
        key=lambda c: (-c.severity_rank, c.check_id, c.file_path),
    )
    lines.append(f"## Failed checks at or above {fail_on}")
    lines.append("")
    if not over_threshold:
        lines.append("_None._")
    for check in over_threshold:
        start, end = check.file_line_range
        location: str = (
            f"`{check.file_path}:{start}-{end}`" if start else f"`{check.file_path}`"
        )
        lines.append(f"### `{check.check_id}` — {check.severity}")
        lines.append("")
        lines.append(f"**Check.** {check.check_name}")
        lines.append("")
        lines.append(f"**Resource.** `{check.resource}`")
        lines.append("")
        lines.append(f"**File.** {location}")
        lines.append("")
        if check.guideline:
            lines.append(f"**Guideline.** {check.guideline}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Drive Checkov from CI: pinned configuration, severity gating, "
            "and pull-request comment output."
        ),
    )
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path("."),
        help="Directory to scan (default: cwd).",
    )
    parser.add_argument(
        "--framework",
        action="append",
        default=None,
        help=(
            "Framework to enable (repeatable).  Defaults to: "
            + ", ".join(DEFAULT_FRAMEWORKS)
        ),
    )
    parser.add_argument(
        "--skip-check",
        action="append",
        default=None,
        help=(
            "Check ID to skip (repeatable, or comma-separated).  Use "
            "sparingly; every skip should have a justification in code."
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER.keys()),
        default="HIGH",
        help="Severity at or above which a failing check fails the build.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./checkov-results.json"),
        help="Path for Checkov's JSON output (default: ./checkov-results.json).",
    )
    parser.add_argument(
        "--emit-markdown",
        type=Path,
        default=None,
        help="Write a markdown summary to this path.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "markdown"),
        default="text",
        help="Console output format (default: text).",
    )
    parser.add_argument(
        "--use-existing-report",
        type=Path,
        default=None,
        help=(
            "Skip the Checkov invocation and parse an existing JSON "
            "report at this path.  Useful for unit testing this script."
        ),
    )
    return parser


def _flatten_csv(values: list[str] | None) -> list[str]:
    if not values:
        return []
    flat: list[str] = []
    for value in values:
        for part in value.split(","):
            cleaned: str = part.strip()
            if cleaned:
                flat.append(cleaned)
    return flat


def main(argv: list[str] | None = None) -> int:
    parser: argparse.ArgumentParser = build_parser()
    args: argparse.Namespace = parser.parse_args(argv)

    frameworks: tuple[str, ...] = (
        tuple(args.framework) if args.framework else DEFAULT_FRAMEWORKS
    )
    skip_checks: list[str] = _flatten_csv(args.skip_check)

    if args.use_existing_report is not None:
        report_path: Path = args.use_existing_report
    else:
        if not args.directory.exists():
            print(
                f"error: directory not found: {args.directory}",
                file=sys.stderr,
            )
            return EXIT_BAD_INPUT
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rc: int = run_checkov(
            directory=args.directory,
            frameworks=frameworks,
            skip_checks=skip_checks,
            output_file=args.output,
        )
        if rc == EXIT_CHECKOV_MISSING or rc == EXIT_CHECKOV_CRASHED:
            return rc
        report_path = args.output

    try:
        summary: ScanSummary = parse_checkov_report(report_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if args.format == "text":
        print(render_text(summary, args.fail_on))
    else:
        print(render_markdown(summary, args.fail_on))

    if args.emit_markdown is not None:
        args.emit_markdown.parent.mkdir(parents=True, exist_ok=True)
        args.emit_markdown.write_text(
            render_markdown(summary, args.fail_on),
            encoding="utf-8",
        )

    should_fail, count = gating_decision(summary, args.fail_on)
    if should_fail:
        print(
            f"\nFAIL: {count} Checkov finding(s) at or above {args.fail_on} "
            f"severity.",
            file=sys.stderr,
        )
        return EXIT_FINDINGS_OVER_THRESHOLD

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
