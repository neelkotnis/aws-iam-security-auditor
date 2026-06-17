"""
checks/unused_users.py
----------------------
Checks:
  IAM-009  IAM user with no activity in >90 days     -> MEDIUM
  IAM-010  IAM user that has never logged in          -> LOW
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import boto3

from iam_auditor.checks._credential_report import get_credential_report_rows
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)

INACTIVE_THRESHOLD_DAYS = 90


def _days_since(dt_str: str) -> int | None:
    """
    Parse an ISO-8601 date string from the credential report and return
    days elapsed. Returns None if the value is 'N/A' or unparseable.
    """
    if not dt_str or dt_str.strip().upper() in ("N/A", "NO_INFORMATION", ""):
        return None
    try:
        dt = datetime.fromisoformat(dt_str.strip())
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


def check_unused_users(iam_client) -> list[Finding]:
    """
    Use the shared IAM credential report to find users with no recent activity.
    Does not fetch its own copy of the report - reuses the one mfa.py
    already triggered earlier in the same scan run.
    """
    findings: list[Finding] = []
    rows = get_credential_report_rows(iam_client)

    for row in rows:
        username = row.get("user", "")
        arn = row.get("arn", "")

        if username == "<root_account>":
            continue

        password_last_used = row.get("password_last_used", "N/A")
        key1_last_used      = row.get("access_key_1_last_used_date", "N/A")
        key2_last_used       = row.get("access_key_2_last_used_date", "N/A")
        user_creation_time   = row.get("user_creation_time", "")

        days_pw   = _days_since(password_last_used)
        days_key1 = _days_since(key1_last_used)
        days_key2 = _days_since(key2_last_used)

        activity_days = [d for d in [days_pw, days_key1, days_key2] if d is not None]

        if not activity_days:
            days_old = _days_since(user_creation_time)
            age_str = f"{days_old} days old" if days_old is not None else "age unknown"
            findings.append(Finding(
                check_id="IAM-010",
                check_name="IAM User Never Used",
                severity=Severity.LOW,
                resource=arn,
                detail=(
                    f"User '{username}' has never logged in or used an access key "
                    f"({age_str}). No activity has ever been recorded."
                ),
                remediation=(
                    "Verify this user is still required. If it was provisioned for "
                    "a person or service that never onboarded, delete it to reduce "
                    "your attack surface."
                ),
                cis_control="CIS 1.12",
            ))
            continue

        most_recent = min(activity_days)
        if most_recent > INACTIVE_THRESHOLD_DAYS:
            findings.append(Finding(
                check_id="IAM-009",
                check_name="IAM User Inactive",
                severity=Severity.MEDIUM,
                resource=arn,
                detail=(
                    f"User '{username}' has had no console or API activity "
                    f"for {most_recent} days (threshold: {INACTIVE_THRESHOLD_DAYS} days)."
                ),
                remediation=(
                    "Disable this user's console access and deactivate their access keys. "
                    "If confirmed unnecessary after a grace period, delete the user entirely."
                ),
                cis_control="CIS 1.12",
            ))

    logger.info("Unused user check produced %d finding(s)", len(findings))
    return findings


def run(session: boto3.Session) -> list[Finding]:
    """Entry point called by the engine."""
    iam = session.client("iam")
    return check_unused_users(iam)
