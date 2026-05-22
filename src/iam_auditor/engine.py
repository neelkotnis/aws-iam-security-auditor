"""
engine.py
---------
Orchestrates the audit:
  1. Resolves the AWS account ID
  2. Runs selected checks concurrently via ThreadPoolExecutor
  3. Times each check with millisecond precision
  4. Aggregates findings into a single AuditResult
  5. Applies severity filter before returning
  6. Returns exit code 2 if CRITICAL findings exist (CI/CD friendly)
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import boto3

from iam_auditor.checks import access_keys, mfa, permissions, unused_users
from iam_auditor.models import AuditResult, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Registry: (label, check_key, callable)
# check_key is what the user passes to --checks flag, e.g. --checks mfa,permissions
CHECKS: list[tuple[str, str, Callable[[boto3.Session], list[Finding]]]] = [
    ("MFA Checks",          "mfa",          mfa.run),
    ("Permission Checks",   "permissions",  permissions.run),
    ("Access Key Checks",   "access_keys",  access_keys.run),
    ("Unused User Checks",  "unused_users", unused_users.run),
]

# Convenience: all valid --checks keys for CLI validation
ALL_CHECK_KEYS: list[str] = [key for _, key, _ in CHECKS]


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
) -> CheckResult:
    """
    Run a single check, capture its duration, and return a CheckResult.
    Exceptions are caught here so one bad check never kills the audit.
    """
    start = time.perf_counter()
    try:
        logger.debug("Starting: %s", label)
        findings = check_fn(session)
        duration_ms = (time.perf_counter() - start) * 1000
        logger.debug("Finished: %s — %d finding(s) in %.0fms", label, len(findings), duration_ms)
        return CheckResult(label=label, findings=findings, duration_ms=duration_ms)
    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000
        logger.error("Check '%s' failed: %s", label, exc)
        return CheckResult(label=label, duration_ms=duration_ms, error=str(exc))


def _filter_checks(selected_keys: list[str] | None) -> list[tuple[str, str, Callable]]:
    """
    Return the subset of CHECKS matching selected_keys.
    If selected_keys is None or empty, return all checks.
    """
    if not selected_keys:
        return CHECKS
    selected = {k.strip().lower() for k in selected_keys}
    return [(label, key, fn) for label, key, fn in CHECKS if key in selected]


def run_audit(
    session: boto3.Session,
    min_severity: Severity = Severity.LOW,
    max_workers: int = 4,
    selected_checks: list[str] | None = None,
) -> tuple[AuditResult, int]:
    """
    Run all registered checks concurrently and return an AuditResult.

    Args:
        session:          An authenticated boto3.Session.
        min_severity:     Filter out findings below this level.
        max_workers:      Thread pool size (IAM calls are I/O-bound).
        selected_checks:  List of check keys to run. None = run all.

    Returns:
        Tuple of (AuditResult, exit_code) where:
          exit_code 0 = success, no findings
          exit_code 1 = success, findings below CRITICAL
          exit_code 2 = CRITICAL findings found (CI/CD pipelines act on this)
    """
    account_id = _resolve_account_id(session)
    result = AuditResult(account_id=account_id)

    checks_to_run = _filter_checks(selected_checks)

    logger.info(
        "Starting audit — account: %s, checks: %d, min severity: %s",
        account_id,
        len(checks_to_run),
        min_severity.value,
    )

    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_index = severity_order.index(min_severity)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_run_check, label, fn, session): label
            for label, _, fn in checks_to_run
        }

        for future in as_completed(futures):
            check_result: CheckResult = future.result()

            # Record timing regardless of success/failure
            result.check_timings[check_result.label] = round(check_result.duration_ms, 2)

            if check_result.failed:
                logger.error(
                    "%-25s  FAILED in %6.0fms — %s",
                    check_result.label,
                    check_result.duration_ms,
                    check_result.error,
                )
                continue

            # Apply severity filter
            filtered = [
                f for f in check_result.findings
                if severity_order.index(f.severity) >= min_index
            ]

            result.extend(filtered)

            logger.info(
                "%-25s  total=%-3d  kept=%-3d  duration=%6.0fms",
                check_result.label,
                len(check_result.findings),
                len(filtered),
                check_result.duration_ms,
            )

    # Determine exit code
    has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
    has_any = len(result.findings) > 0
    exit_code = 2 if has_critical else (1 if has_any else 0)

    logger.info(
        "Audit complete — %d finding(s), %.0fms total, exit code %d",
        len(result.findings),
        result.total_duration_ms(),
        exit_code,
    )

    return result, exit_code