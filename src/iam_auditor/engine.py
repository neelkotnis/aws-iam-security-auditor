"""
engine.py
---------
Orchestrates the audit:
  1. Resolves the AWS account ID
  2. Runs all checks concurrently via ThreadPoolExecutor
  3. Aggregates findings into a single AuditResult
  4. Applies an optional severity filter before returning

Check modules are imported explicitly — no dynamic discovery — keeping
the dependency graph obvious and the code easy to follow.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import boto3

from iam_auditor.checks import access_keys, mfa, permissions
from iam_auditor.models import AuditResult, Finding, Severity

logger = logging.getLogger(__name__)

# Each entry is a (label, callable) pair.
# The callable receives a boto3.Session and returns list[Finding].
CHECKS: list[tuple[str, Callable[[boto3.Session], list[Finding]]]] = [
    ("MFA Checks", mfa.run),
    ("Permission Checks", permissions.run),
    ("Access Key Checks", access_keys.run),
]


def _resolve_account_id(session: boto3.Session) -> str:
    """Return the AWS account ID for the active session."""
    try:
        sts = session.client("sts")
        return sts.get_caller_identity()["Account"]
    except Exception as exc:
        logger.warning("Could not resolve account ID: %s", exc)
        return "unknown"


def _run_check(
    label: str,
    check_fn: Callable[[boto3.Session], list[Finding]],
    session: boto3.Session,
) -> tuple[str, list[Finding]]:
    """
    Wrapper that runs a single check function and captures exceptions
    so one failing check never aborts the whole audit.
    """
    try:
        logger.debug("Starting: %s", label)
        findings = check_fn(session)
        logger.debug("Finished: %s — %d finding(s)", label, len(findings))
        return label, findings
    except Exception as exc:
        logger.error("Check '%s' failed with unhandled error: %s", label, exc)
        return label, []


def run_audit(
    session: boto3.Session,
    min_severity: Severity = Severity.LOW,
    max_workers: int = 4,
) -> AuditResult:
    """
    Run all registered checks concurrently and return an AuditResult.

    Args:
        session:      An authenticated boto3.Session.
        min_severity: Filter out findings below this level.
        max_workers:  Thread pool size (IAM API calls are I/O-bound).

    Returns:
        AuditResult with all findings at or above min_severity.
    """
    account_id = _resolve_account_id(session)
    result = AuditResult(account_id=account_id)

    logger.info(
        "Starting audit for account %s with %d check(s), min severity: %s",
        account_id,
        len(CHECKS),
        min_severity.value,
    )

    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_index = severity_order.index(min_severity)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_run_check, label, fn, session): label
            for label, fn in CHECKS
        }

        for future in as_completed(futures):
            label, findings = future.result()

            # Apply severity filter
            filtered = [
                f for f in findings
                if severity_order.index(f.severity) >= min_index
            ]

            result.extend(filtered)
            logger.info(
                "%-25s  total=%-3d  kept=%-3d",
                label,
                len(findings),
                len(filtered),
            )

    logger.info(
        "Audit complete. %d finding(s) across %d check(s). Summary: %s",
        len(result.findings),
        len(CHECKS),
        result.summary(),
    )

    return result
