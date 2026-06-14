"""
engine.py
---------
Orchestrates the audit:
  1. Resolves the AWS account ID
  2. Runs selected checks concurrently via ThreadPoolExecutor
  3. Times each check with millisecond precision
  4. Stamps account_id on every finding
  5. Aggregates findings into a single AuditResult
  6. Applies severity filter before returning
  7. Returns exit code 2 if CRITICAL findings exist (CI/CD friendly)
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import boto3

from iam_auditor.checks import access_keys, mfa, permissions, unused_users, iam_advanced
from iam_auditor.models import AuditResult, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Registry: (label, check_key, callable)
CHECKS: list[tuple[str, str, Callable[[boto3.Session], list[Finding]]]] = [
    ("MFA Checks",          "mfa",          mfa.run),
    ("Permission Checks",   "permissions",  permissions.run),
    ("Access Key Checks",   "access_keys",  access_keys.run),
    ("Unused User Checks",  "unused_users", unused_users.run),
    ("IAM Advanced Checks", "iam_advanced", iam_advanced.run),
]

ALL_CHECK_KEYS: list[str] = [key for _, key, _ in CHECKS]


def _resolve_account_id(session: boto3.Session) -> str:
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
    start = time.perf_counter()
    try:
        logger.debug("Starting: %s", label)
        findings = check_fn(session)
        duration_ms = (time.perf_counter() - start) * 1000
        logger.debug("Finished: %s - %d finding(s) in %.0fms", label, len(findings), duration_ms)
        return CheckResult(label=label, findings=findings, duration_ms=duration_ms)
    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000
        logger.error("Check '%s' failed: %s", label, exc)
        return CheckResult(label=label, duration_ms=duration_ms, error=str(exc))


def _filter_checks(selected_keys: list[str] | None) -> list[tuple[str, str, Callable]]:
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
          exit_code 0 = no findings
          exit_code 1 = findings below CRITICAL
          exit_code 2 = CRITICAL findings found
    """
    account_id = _resolve_account_id(session)
    result = AuditResult(account_id=account_id)

    checks_to_run = _filter_checks(selected_checks)

    logger.info(
        "Starting audit - account: %s, checks: %d, min severity: %s",
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

            result.check_timings[check_result.label] = round(check_result.duration_ms, 2)

            if check_result.failed:
                logger.error(
                    "%-25s  FAILED in %6.0fms - %s",
                    check_result.label,
                    check_result.duration_ms,
                    check_result.error,
                )
                continue

            # Stamp account_id on every finding
            for f in check_result.findings:
                if f.account_id == "unknown":
                    f.account_id = account_id

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

    has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
    has_any = len(result.findings) > 0
    exit_code = 2 if has_critical else (1 if has_any else 0)

    logger.info(
        "Audit complete - %d finding(s), %.0fms total, exit code %d",
        len(result.findings),
        result.total_duration_ms(),
        exit_code,
    )

    return result, exit_code
