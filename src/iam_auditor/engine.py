"""
engine.py
---------
Orchestrates the audit across all check modules, with multi-region support
for regional checks (EC2, KMS, GuardDuty, RDS, etc).

Global checks (IAM, CloudTrail, S3) run once regardless of region selection,
since those services are account-wide, not regional.
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

# Registry: (label, check_key, is_global, callable)
# is_global=True  -> runs once, regardless of --regions (IAM, CloudTrail, S3)
# is_global=False -> runs once PER region in scope (EC2, KMS, GuardDuty, etc)
CHECKS: list[tuple[str, str, bool, Callable]] = [
    ("MFA Checks",              "mfa",                True,  mfa.run),
    ("Permission Checks",       "permissions",        True,  permissions.run),
    ("Access Key Checks",       "access_keys",        True,  access_keys.run),
    ("Unused User Checks",      "unused_users",       True,  unused_users.run),
    ("IAM Advanced Checks",     "iam_advanced",       True,  iam_advanced.run),
    ("CloudTrail Checks",       "cloudtrail",         True,  cloudtrail.run),
    ("S3 Checks",               "s3",                 True,  s3.run),
    ("EC2 / VPC Checks",        "ec2",                False, ec2.run),
    ("KMS Checks",              "kms",                False, kms.run),
    ("GuardDuty Checks",        "guardduty",          False, guardduty.run),
    ("Security Hub Checks",     "securityhub",        False, securityhub.run),
    ("RDS / DynamoDB Checks",   "rds",                False, rds.run),
    ("Secrets Manager Checks",  "secrets_manager",    False, secrets_manager.run),
    ("ECR Checks",              "ecr",                False, ecr.run),
    ("CloudWatch Alarm Checks", "cloudwatch_alarms",  False, cloudwatch_alarms.run),
]

ALL_CHECK_KEYS: list[str] = [key for _, key, _, _ in CHECKS]

DEFAULT_REGION = "us-east-1"


def _resolve_account_id(session: boto3.Session) -> str:
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except Exception as exc:
        logger.warning("Could not resolve account ID: %s", exc)
        return "unknown"


def get_enabled_regions(session: boto3.Session) -> list[str]:
    """
    Discover all AWS regions enabled for this account.
    Used by --all-regions. Falls back to [DEFAULT_REGION] on failure.
    """
    try:
        ec2_client = session.client("ec2", region_name=DEFAULT_REGION)
        resp = ec2_client.describe_regions(
            Filters=[{"Name": "opt-in-status",
                      "Values": ["opt-in-not-required", "opted-in"]}]
        )
        regions = sorted(r["RegionName"] for r in resp["Regions"])
        logger.info("Discovered %d enabled region(s): %s", len(regions), regions)
        return regions
    except Exception as exc:
        logger.warning("Could not list regions, defaulting to %s: %s", DEFAULT_REGION, exc)
        return [DEFAULT_REGION]


def _run_check(label: str, check_fn: Callable, session: boto3.Session, region: str | None):
    """
    Run a single check. If region is provided, build a region-scoped session
    so the check's internal session.region_name resolves correctly.
    """
    start = time.perf_counter()
    try:
        if region:
            # Create a region-bound session by cloning credentials with new region
            regional_session = boto3.Session(
                aws_access_key_id=session.get_credentials().access_key,
                aws_secret_access_key=session.get_credentials().secret_key,
                aws_session_token=session.get_credentials().token,
                region_name=region,
            )
            findings = check_fn(regional_session)
        else:
            findings = check_fn(session)
        duration_ms = (time.perf_counter() - start) * 1000
        return CheckResult(label=label, findings=findings, duration_ms=duration_ms)
    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000
        logger.error("Check '%s' [%s] failed: %s", label, region or "global", exc)
        return CheckResult(label=label, duration_ms=duration_ms, error=str(exc))


def _filter_checks(selected_keys: list[str] | None) -> list[tuple[str, str, bool, Callable]]:
    if not selected_keys:
        return CHECKS
    selected = {k.strip().lower() for k in selected_keys}
    return [(label, key, is_global, fn) for label, key, is_global, fn in CHECKS if key in selected]


def run_audit(
    session: boto3.Session,
    min_severity: Severity = Severity.LOW,
    max_workers: int = 8,
    selected_checks: list[str] | None = None,
    regions: list[str] | None = None,
    all_regions: bool = False,
) -> tuple[AuditResult, int]:
    """
    Run all registered checks concurrently and return an AuditResult.

    Args:
        session:          An authenticated boto3.Session.
        min_severity:     Filter out findings below this level.
        max_workers:      Thread pool size.
        selected_checks:  List of check keys to run. None = run all.
        regions:          Explicit list of regions for regional checks.
                           Ignored if all_regions=True.
        all_regions:      If True, auto-discover and scan every enabled region.

    Returns:
        Tuple of (AuditResult, exit_code).
    """
    account_id    = _resolve_account_id(session)
    checks_to_run = _filter_checks(selected_checks)

    # Resolve which regions regional checks will run against
    if all_regions:
        target_regions = get_enabled_regions(session)
    elif regions:
        target_regions = regions
    else:
        target_regions = [session.region_name or DEFAULT_REGION]

    result = AuditResult(account_id=account_id)

    logger.info(
        "Starting audit — account: %s, checks: %d, regions: %s",
        account_id, len(checks_to_run), target_regions,
    )

    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_index      = severity_order.index(min_severity)

    # Build the full work list: global checks run once, regional checks run per-region
    work_items: list[tuple[str, Callable, str | None]] = []
    for label, _, is_global, fn in checks_to_run:
        if is_global:
            work_items.append((label, fn, None))
        else:
            for region in target_regions:
                region_label = f"{label} [{region}]"
                work_items.append((region_label, fn, region))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_run_check, label, fn, session, region): label
            for label, fn, region in work_items
        }
        for future in as_completed(futures):
            check_result: CheckResult = future.result()
            result.check_timings[check_result.label] = round(check_result.duration_ms, 2)

            if check_result.failed:
                logger.error("%-40s FAILED %.0fms — %s",
                             check_result.label, check_result.duration_ms, check_result.error)
                continue

            for f in check_result.findings:
                if f.account_id == "unknown":
                    f.account_id = account_id

            filtered = [f for f in check_result.findings
                        if severity_order.index(f.severity) >= min_index]
            result.extend(filtered)

            logger.info("%-40s total=%-3d kept=%-3d %.0fms",
                        check_result.label, len(check_result.findings),
                        len(filtered), check_result.duration_ms)

    has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
    exit_code    = 2 if has_critical else (1 if result.findings else 0)
    return result, exit_code