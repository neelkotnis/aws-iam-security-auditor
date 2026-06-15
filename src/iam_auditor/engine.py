"""
engine.py
---------
Orchestrates the audit across all check modules.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import boto3

from iam_auditor.checks import (
    access_keys, cloudtrail, cloudwatch_alarms, ec2, ecr,
    guardduty, iam_advanced, kms, mfa, permissions,
    rds, s3, secrets_manager, securityhub, unused_users,
)
from iam_auditor.models import AuditResult, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

CHECKS: list[tuple[str, str, Callable[[boto3.Session], list[Finding]]]] = [
    ("MFA Checks",              "mfa",                mfa.run),
    ("Permission Checks",       "permissions",        permissions.run),
    ("Access Key Checks",       "access_keys",        access_keys.run),
    ("Unused User Checks",      "unused_users",       unused_users.run),
    ("IAM Advanced Checks",     "iam_advanced",       iam_advanced.run),
    ("CloudTrail Checks",       "cloudtrail",         cloudtrail.run),
    ("S3 Checks",               "s3",                 s3.run),
    ("EC2 / VPC Checks",        "ec2",                ec2.run),
    ("KMS Checks",              "kms",                kms.run),
    ("GuardDuty Checks",        "guardduty",          guardduty.run),
    ("Security Hub Checks",     "securityhub",        securityhub.run),
    ("RDS / DynamoDB Checks",   "rds",                rds.run),
    ("Secrets Manager Checks",  "secrets_manager",    secrets_manager.run),
    ("ECR Checks",              "ecr",                ecr.run),
    ("CloudWatch Alarm Checks", "cloudwatch_alarms",  cloudwatch_alarms.run),
]

ALL_CHECK_KEYS: list[str] = [key for _, key, _ in CHECKS]


def _resolve_account_id(session: boto3.Session) -> str:
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except Exception as exc:
        logger.warning("Could not resolve account ID: %s", exc)
        return "unknown"


def _run_check(label, check_fn, session):
    start = time.perf_counter()
    try:
        findings    = check_fn(session)
        duration_ms = (time.perf_counter() - start) * 1000
        return CheckResult(label=label, findings=findings, duration_ms=duration_ms)
    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000
        logger.error("Check '%s' failed: %s", label, exc)
        return CheckResult(label=label, duration_ms=duration_ms, error=str(exc))


def _filter_checks(selected_keys):
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
    account_id    = _resolve_account_id(session)
    result        = AuditResult(account_id=account_id)
    checks_to_run = _filter_checks(selected_checks)

    logger.info("Starting audit — account: %s, checks: %d", account_id, len(checks_to_run))

    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_index      = severity_order.index(min_severity)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_run_check, label, fn, session): label
            for label, _, fn in checks_to_run
        }
        for future in as_completed(futures):
            check_result: CheckResult = future.result()
            result.check_timings[check_result.label] = round(check_result.duration_ms, 2)

            if check_result.failed:
                logger.error("%-25s FAILED %.0fms — %s",
                             check_result.label, check_result.duration_ms, check_result.error)
                continue

            for f in check_result.findings:
                if f.account_id == "unknown":
                    f.account_id = account_id

            filtered = [f for f in check_result.findings
                        if severity_order.index(f.severity) >= min_index]
            result.extend(filtered)

            logger.info("%-25s total=%-3d kept=%-3d %.0fms",
                        check_result.label, len(check_result.findings),
                        len(filtered), check_result.duration_ms)

    has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
    exit_code    = 2 if has_critical else (1 if result.findings else 0)
    return result, exit_code
