#!/usr/bin/env python3
"""Exercise 5 — Prowler Triage.

AUTHORIZED USE ONLY.  This script reads a Prowler JSON-ASFF output file
that you produced from a scan of an AWS account you own or for which you
hold written authorisation.  See the week README banner.

This script ingests a Prowler JSON-ASFF report and produces a triage
summary suitable for a weekly review meeting or a pull-request comment.
It does NOT call any AWS API.  It does not need any AWS credentials.

USAGE
-----
    python3 exercise-05-prowler-triage.py REPORT.asff.json
    python3 exercise-05-prowler-triage.py REPORT.asff.json --format markdown
    python3 exercise-05-prowler-triage.py REPORT.asff.json --min-severity HIGH
    python3 exercise-05-prowler-triage.py REPORT.asff.json --top 25
    python3 exercise-05-prowler-triage.py REPORT.asff.json --by-service

The input file is a JSON document whose top level is a list of ASFF
finding objects.  See:

    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

REQUIREMENTS
------------
    - Python 3.11 or later.
    - No external Python packages.  Standard library only.

REFERENCE
---------
    Prowler docs        — https://docs.prowler.com/
    ASFF schema         — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

EXIT_OK: int = 0
EXIT_BAD_INPUT: int = 1
EXIT_FINDINGS_OVER_THRESHOLD: int = 2


# ---------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One ASFF finding, normalised to the fields this triage tool uses."""

    check_id: str
    title: str
    severity: str
    severity_rank: int
    status: str
    resource_id: str
    resource_type: str
    region: str
    account_id: str
    description: str
    remediation: str
    compliance_frameworks: tuple[str, ...]

    @property
    def is_failing(self) -> bool:
        return self.status.upper() in {"FAILED", "FAIL", "WARNING"}


@dataclass
class TriageReport:
    """The output of a triage run."""

    total_findings: int
    failing_findings: int
    by_severity: Counter[str]
    by_service: Counter[str]
    by_check: Counter[str]
    top_failing_findings: list[Finding]
    compliance_failure_counts: Counter[str]


# ---------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------


def _service_from_check_id(check_id: str) -> str:
    """Extract the service name from a Prowler check ID.

    Prowler check IDs are conventionally `<service>_<short_name>`, e.g.,
    `iam_no_root_access_key`, `s3_bucket_public_access`,
    `cloudtrail_multi_region_enabled`.  We split on the first underscore.
    """
    if not check_id:
        return "unknown"
    parts = check_id.split("_", 1)
    return parts[0] if parts else "unknown"


def _safe_get(d: dict[str, Any], *keys: str, default: Any = "") -> Any:
    """Walk a dict path with `.get`; return `default` if any step missing."""
    cur: Any = d
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def parse_finding(asff: dict[str, Any]) -> Finding:
    """Normalise one ASFF JSON object into a Finding dataclass."""
    generator_id: str = str(_safe_get(asff, "GeneratorId", default=""))
    # Prowler 4.x sets GeneratorId to `prowler-<check_id>`; older lines
    # set the bare check_id.  Strip the prefix if present.
    if generator_id.startswith("prowler-"):
        check_id = generator_id[len("prowler-"):]
    else:
        check_id = generator_id

    title: str = str(_safe_get(asff, "Title", default=""))
    severity_label: str = str(
        _safe_get(asff, "Severity", "Label", default="INFORMATIONAL")
    ).upper()
    severity_rank: int = SEVERITY_ORDER.get(severity_label, 0)
    status: str = str(_safe_get(asff, "Compliance", "Status", default="UNKNOWN"))

    resources: list[dict[str, Any]] = list(_safe_get(asff, "Resources", default=[]))
    if resources and isinstance(resources[0], dict):
        resource_id = str(resources[0].get("Id", ""))
        resource_type = str(resources[0].get("Type", ""))
        region = str(resources[0].get("Region", ""))
    else:
        resource_id = ""
        resource_type = ""
        region = ""

    account_id: str = str(_safe_get(asff, "AwsAccountId", default=""))
    description: str = str(_safe_get(asff, "Description", default=""))
    remediation: str = str(
        _safe_get(asff, "Remediation", "Recommendation", "Text", default="")
    )

    frameworks_raw: list[Any] = list(
        _safe_get(asff, "Compliance", "RelatedRequirements", default=[])
    )
    frameworks: tuple[str, ...] = tuple(str(f) for f in frameworks_raw)

    return Finding(
        check_id=check_id,
        title=title,
        severity=severity_label,
        severity_rank=severity_rank,
        status=status,
        resource_id=resource_id,
        resource_type=resource_type,
        region=region,
        account_id=account_id,
        description=description,
        remediation=remediation,
        compliance_frameworks=frameworks,
    )


def load_findings(report_path: Path) -> list[Finding]:
    """Load and parse every finding in `report_path`."""
    if not report_path.exists():
        raise FileNotFoundError(f"Report not found: {report_path}")

    raw_text: str = report_path.read_text(encoding="utf-8")
    if not raw_text.strip():
        return []

    parsed: Any = json.loads(raw_text)
    if isinstance(parsed, dict):
        # Some Prowler versions wrap the list in a top-level object.
        # Accept both shapes.
        if "findings" in parsed:
            parsed = parsed["findings"]
        elif "Findings" in parsed:
            parsed = parsed["Findings"]
        else:
            raise ValueError(
                "Top-level JSON is an object without a recognised "
                "`findings` key; expected a list of ASFF findings."
            )

    if not isinstance(parsed, list):
        raise ValueError(
            f"Expected a list of findings; got {type(parsed).__name__}."
        )

    findings: list[Finding] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        findings.append(parse_finding(entry))
    return findings


# ---------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------


def filter_by_min_severity(
    findings: Iterable[Finding], min_severity: str
) -> list[Finding]:
    """Return only findings at or above `min_severity`."""
    threshold: int = SEVERITY_ORDER.get(min_severity.upper(), 0)
    return [f for f in findings if f.severity_rank >= threshold]


def build_report(findings: list[Finding], top_n: int) -> TriageReport:
    """Aggregate findings into a TriageReport."""
    failing: list[Finding] = [f for f in findings if f.is_failing]

    by_severity: Counter[str] = Counter(f.severity for f in failing)
    by_service: Counter[str] = Counter(
        _service_from_check_id(f.check_id) for f in failing
    )
    by_check: Counter[str] = Counter(f.check_id for f in failing)

    compliance_counts: Counter[str] = Counter()
    for finding in failing:
        for fw in finding.compliance_frameworks:
            # Frameworks come through as "CIS-AWS-Foundations-1.4", etc.
            # Aggregate by the framework family (before the last dash).
            family: str = fw.rsplit("-", 1)[0] if "-" in fw else fw
            compliance_counts[family] += 1

    # Sort failing findings by severity desc, then by check_id for stability.
    failing_sorted: list[Finding] = sorted(
        failing,
        key=lambda f: (-f.severity_rank, f.check_id, f.resource_id),
    )
    top_failing: list[Finding] = failing_sorted[:top_n]

    return TriageReport(
        total_findings=len(findings),
        failing_findings=len(failing),
        by_severity=by_severity,
        by_service=by_service,
        by_check=by_check,
        top_failing_findings=top_failing,
        compliance_failure_counts=compliance_counts,
    )


# ---------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------


def render_text(report: TriageReport) -> str:
    """Plain-text triage summary."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("PROWLER TRIAGE SUMMARY")
    lines.append("=" * 72)
    lines.append(f"Total findings ingested : {report.total_findings}")
    lines.append(f"Failing findings        : {report.failing_findings}")
    lines.append("")

    lines.append("Failing findings by severity:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        count: int = report.by_severity.get(severity, 0)
        lines.append(f"  {severity:<14} {count:>5}")
    lines.append("")

    lines.append("Failing findings by service (top 10):")
    for service, count in report.by_service.most_common(10):
        lines.append(f"  {service:<20} {count:>5}")
    lines.append("")

    lines.append("Failing findings by check (top 10):")
    for check, count in report.by_check.most_common(10):
        lines.append(f"  {check:<48} {count:>5}")
    lines.append("")

    lines.append("Compliance failure aggregates (top 10):")
    for framework, count in report.compliance_failure_counts.most_common(10):
        lines.append(f"  {framework:<48} {count:>5}")
    lines.append("")

    lines.append("Top failing findings (severity-ordered):")
    for finding in report.top_failing_findings:
        lines.append(f"  [{finding.severity:<8}] {finding.check_id}")
        lines.append(f"             Title    : {finding.title}")
        lines.append(f"             Resource : {finding.resource_id}")
        lines.append(f"             Region   : {finding.region or '(global)'}")
        lines.append("")

    return "\n".join(lines)


def render_markdown(report: TriageReport) -> str:
    """Markdown triage summary for pull-request comments."""
    lines: list[str] = []
    lines.append("# Prowler Triage Summary")
    lines.append("")
    lines.append(f"- Total findings ingested: **{report.total_findings}**")
    lines.append(f"- Failing findings: **{report.failing_findings}**")
    lines.append("")

    lines.append("## Failing findings by severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        count: int = report.by_severity.get(severity, 0)
        lines.append(f"| {severity} | {count} |")
    lines.append("")

    lines.append("## Failing findings by service (top 10)")
    lines.append("")
    lines.append("| Service | Count |")
    lines.append("|---------|------:|")
    for service, count in report.by_service.most_common(10):
        lines.append(f"| `{service}` | {count} |")
    lines.append("")

    lines.append("## Top failing findings")
    lines.append("")
    for finding in report.top_failing_findings:
        lines.append(f"### `{finding.check_id}` — {finding.severity}")
        lines.append("")
        lines.append(f"**Title.** {finding.title}")
        lines.append("")
        lines.append(f"**Resource.** `{finding.resource_id}`")
        lines.append("")
        if finding.region:
            lines.append(f"**Region.** `{finding.region}`")
            lines.append("")
        if finding.description:
            lines.append(f"**Description.** {finding.description}")
            lines.append("")
        if finding.remediation:
            lines.append(f"**Remediation.** {finding.remediation}")
            lines.append("")
        if finding.compliance_frameworks:
            joined: str = ", ".join(
                f"`{fw}`" for fw in finding.compliance_frameworks
            )
            lines.append(f"**Compliance.** {joined}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------
# By-service detail
# ---------------------------------------------------------------------


def render_by_service(findings: list[Finding]) -> str:
    """Group findings by service and emit a per-service detail block."""
    by_service: defaultdict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if not finding.is_failing:
            continue
        by_service[_service_from_check_id(finding.check_id)].append(finding)

    lines: list[str] = []
    for service in sorted(by_service.keys()):
        service_findings: list[Finding] = by_service[service]
        lines.append("")
        lines.append(f"### Service: {service} ({len(service_findings)} failing)")
        lines.append("-" * 72)
        for finding in sorted(
            service_findings,
            key=lambda f: (-f.severity_rank, f.check_id),
        ):
            lines.append(
                f"  [{finding.severity:<8}] {finding.check_id:<48} "
                f"{finding.resource_id}"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Triage a Prowler JSON-ASFF report.",
    )
    parser.add_argument(
        "report",
        type=Path,
        help="Path to the Prowler JSON-ASFF file.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--min-severity",
        choices=tuple(SEVERITY_ORDER.keys()),
        default="LOW",
        help="Minimum severity to include in the triage (default: LOW).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=15,
        help="How many top-failing findings to render (default: 15).",
    )
    parser.add_argument(
        "--by-service",
        action="store_true",
        help="Emit a per-service detail block in addition to the summary.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER.keys()),
        default=None,
        help=(
            "Exit non-zero when at least one failing finding at or above "
            "this severity is present.  Use in CI to gate builds."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser: argparse.ArgumentParser = build_parser()
    args: argparse.Namespace = parser.parse_args(argv)

    try:
        findings: list[Finding] = load_findings(args.report)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    filtered: list[Finding] = filter_by_min_severity(findings, args.min_severity)
    report: TriageReport = build_report(filtered, top_n=args.top)

    if args.format == "text":
        print(render_text(report))
        if args.by_service:
            print(render_by_service(filtered))
    else:
        print(render_markdown(report))

    if args.fail_on is not None:
        threshold: int = SEVERITY_ORDER[args.fail_on]
        offending: list[Finding] = [
            f for f in filtered if f.is_failing and f.severity_rank >= threshold
        ]
        if offending:
            print(
                f"\nFAIL: {len(offending)} finding(s) at or above "
                f"{args.fail_on} severity.",
                file=sys.stderr,
            )
            return EXIT_FINDINGS_OVER_THRESHOLD

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
