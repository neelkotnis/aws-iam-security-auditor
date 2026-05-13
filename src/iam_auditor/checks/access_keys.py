"""
checks/access_keys.py
---------------------
Checks:
  IAM-005  Access key inactive (never used or unused >90 days)  → MEDIUM
  IAM-006  Access key older than 90 days (rotation overdue)     → HIGH
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import boto3

from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)

# Thresholds (days)
KEY_ROTATION_THRESHOLD_DAYS = 90
KEY_INACTIVE_THRESHOLD_DAYS = 90


def _days_since(dt: datetime) -> int:
    """Return the number of whole days between a datetime and now (UTC)."""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


def _paginate_users(iam_client) -> list[dict]:
    paginator = iam_client.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page.get("Users", []))
    return users


def check_access_keys(iam_client) -> list[Finding]:
    """
    For every IAM user, inspect their access keys for:
      - Keys that are Active but have never been used
      - Keys that are Active but haven't been used in >90 days
      - Keys that are older than 90 days (rotation due regardless of usage)

    Key last-used data comes from get_access_key_last_used, which is a
    separate call per key — this is unavoidable given the AWS API design.
    """
    findings: list[Finding] = []

    try:
        users = _paginate_users(iam_client)
    except Exception as exc:
        logger.error("Failed to list IAM users: %s", exc)
        return findings

    for user in users:
        username = user["UserName"]
        user_arn = user["Arn"]

        try:
            keys_resp = iam_client.list_access_keys(UserName=username)
            keys = keys_resp.get("AccessKeyMetadata", [])
        except Exception as exc:
            logger.warning("Could not list keys for user %s: %s", username, exc)
            continue

        for key in keys:
            key_id = key["AccessKeyId"]
            key_status = key["Status"]           # "Active" | "Inactive"
            key_created = key["CreateDate"]
            key_age_days = _days_since(key_created)

            # --- Check 1: Key rotation (age threshold) ---
            if key_status == "Active" and key_age_days > KEY_ROTATION_THRESHOLD_DAYS:
                findings.append(Finding(
                    check_id="IAM-006",
                    check_name="Access Key Rotation Overdue",
                    severity=Severity.HIGH,
                    resource=user_arn,
                    detail=(
                        f"Access key '{key_id}' for user '{username}' is "
                        f"{key_age_days} days old (threshold: {KEY_ROTATION_THRESHOLD_DAYS} days). "
                        "Long-lived keys increase the blast radius of credential leakage."
                    ),
                    remediation=(
                        "Rotate this access key. Create a new key, update all consumers, "
                        "then deactivate and delete the old key. "
                        "Consider using IAM roles instead of long-term access keys."
                    ),
                ))

            # --- Check 2: Inactive / never-used keys ---
            try:
                last_used_resp = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                last_used_info = last_used_resp.get("AccessKeyLastUsed", {})
                last_used_date = last_used_info.get("LastUsedDate")
            except Exception as exc:
                logger.warning("Could not get last-used for key %s: %s", key_id, exc)
                continue

            if key_status == "Active" and last_used_date is None:
                # Key has never been used
                findings.append(Finding(
                    check_id="IAM-005",
                    check_name="Access Key Never Used",
                    severity=Severity.MEDIUM,
                    resource=user_arn,
                    detail=(
                        f"Access key '{key_id}' for user '{username}' is Active "
                        f"but has never been used (created {key_age_days} days ago)."
                    ),
                    remediation=(
                        "Determine if this key is needed. If not, deactivate and delete it. "
                        "Unused credentials are unnecessary attack surface."
                    ),
                ))

            elif key_status == "Active" and last_used_date is not None:
                days_since_used = _days_since(last_used_date)
                if days_since_used > KEY_INACTIVE_THRESHOLD_DAYS:
                    findings.append(Finding(
                        check_id="IAM-005",
                        check_name="Access Key Inactive",
                        severity=Severity.MEDIUM,
                        resource=user_arn,
                        detail=(
                            f"Access key '{key_id}' for user '{username}' has not been used "
                            f"in {days_since_used} days (last used: {last_used_date.date()})."
                        ),
                        remediation=(
                            "Deactivate this key to test that no systems rely on it, "
                            "then delete it after a grace period."
                        ),
                    ))

    logger.info("Access key checks produced %d finding(s)", len(findings))
    return findings


def run(session: boto3.Session) -> list[Finding]:
    """Entry point called by the engine."""
    iam = session.client("iam")
    return check_access_keys(iam)
