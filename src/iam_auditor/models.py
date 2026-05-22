"""
models.py
---------
Core data structures for the IAM Auditor.
All checks produce Finding objects. The engine collects them into an AuditResult.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Finding severity levels, ordered low → critical."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other


# Maps each severity to a Rich markup color tag
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "orange1",
    Severity.CRITICAL: "red",
}


@dataclass
class Finding:
    """
    A single security finding produced by a check.

    Attributes:
        check_id:     Short machine-readable identifier, e.g. "IAM-001".
        check_name:   Human-readable check name.
        severity:     One of LOW / MEDIUM / HIGH / CRITICAL.
        resource:     The AWS resource ARN or name this finding applies to.
        detail:       What was found — specific, factual, no fluff.
        remediation:  Concise action the operator should take.
        region:       AWS region (default "global" for IAM).
        cis_control:  CIS AWS Benchmark control reference, e.g. "CIS 1.5".
    """
    check_id: str
    check_name: str
    severity: Severity
    resource: str
    detail: str
    remediation: str
    region: str = "global"
    cis_control: str = ""        # e.g. "CIS 1.5", empty if not mapped

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary."""
        d = asdict(self)
        d["severity"] = self.severity.value  # enum → string
        return d


@dataclass
class AuditResult:
    """
    Aggregated output of a full audit run.

    Attributes:
        account_id:     AWS account ID audited.
        run_at:         ISO-8601 timestamp of when the audit ran.
        findings:       All findings collected across every check.
        check_timings:  Per-check execution time in milliseconds.
    """
    account_id: str
    run_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    findings: list[Finding] = field(default_factory=list)
    check_timings: dict[str, float] = field(default_factory=dict)  # label → ms

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def summary(self) -> dict[str, int]:
        """Return a count per severity level."""
        return {s.value: len(self.by_severity(s)) for s in Severity}

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted critical → low."""
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(self.findings, key=lambda f: order[f.severity])

    def total_duration_ms(self) -> float:
        """Sum of all check durations in milliseconds."""
        return sum(self.check_timings.values())

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "run_at": self.run_at,
            "summary": self.summary(),
            "total_findings": len(self.findings),
            "check_timings": self.check_timings,
            "total_duration_ms": round(self.total_duration_ms(), 2),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class CheckResult:
    """
    Wraps the output of a single check with execution metadata.

    Attributes:
        label:        Human-readable check name, e.g. "MFA Checks".
        findings:     All findings produced by this check.
        duration_ms:  How long the check took in milliseconds.
        error:        Set if the check failed with an unhandled exception.
    """
    label: str
    findings: list[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    error: str | None = None

    @property
    def failed(self) -> bool:
        return self.error is not None