"""
checks/mfa.py
-------------
Checks:
  IAM-001  Users without MFA enabled → HIGH
  IAM-002  Root account MFA not enabled → CRITICAL
  IAM-007  Root access keys enabled → CRITICAL
"""

from __future__ import annotations

import csv
import logging
from io import StringIO

import boto3

from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)


def check_users_without_mfa(iam_client) -> list[Finding]:
    """
    Identify IAM users with console access enabled but no MFA configured.

    Uses the IAM credential report for efficient bulk analysis instead of
    making separate MFA API calls per user.
    """
    findings: list[Finding] = []

    try:
        iam_client.generate_credential_report()
        response = iam_client.get_credential_report()

        report_csv = response["Content"].decode("utf-8")

    except Exception as exc:
        logger.error("Failed to retrieve credential report: %s", exc)
        return findings

    try:
        reader = csv.DictReader(StringIO(report_csv))

        for row in reader:
            username = row.get("user", "")
            arn = row.get("arn", "")
            mfa_active = row.get("mfa_active", "").strip().lower()
            password_enabled = row.get("password_enabled", "").strip().lower()

            # Root account handled separately
            if username == "<root_account>":
                continue

            # Ignore users without console access
            if password_enabled != "true":
                continue

            if mfa_active != "true":
                findings.append(Finding(
                    check_id="IAM-001",
                    check_name="IAM User Without MFA",
                    severity=Severity.HIGH,
                    resource=arn,
                    detail=(
                        f"User '{username}' has console access enabled "
                        "but no MFA device configured."
                    ),
                    remediation=(
                        "Enable MFA for this user and enforce MFA usage "
                        "through IAM policy conditions where possible."
                    ),
                ))

    except Exception as exc:
        logger.error("Failed parsing credential report: %s", exc)

    logger.info(
        "MFA user check completed with %d finding(s)",
        len(findings),
    )

    return findings


def check_root_security(iam_client) -> list[Finding]:
    """
    Validate root account security posture.
    """
    findings: list[Finding] = []

    try:
        response = iam_client.get_account_summary()
        summary = response.get("SummaryMap", {})

    except Exception as exc:
        logger.error("Failed to retrieve account summary: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Root MFA check
    # ------------------------------------------------------------------

    if summary.get("AccountMFAEnabled", 0) != 1:
        findings.append(Finding(
            check_id="IAM-002",
            check_name="Root Account MFA Disabled",
            severity=Severity.CRITICAL,
            resource="root-account",
            detail=(
                "The AWS root account does not have MFA enabled."
            ),
            remediation=(
                "Enable hardware or virtual MFA on the AWS root account "
                "immediately."
            ),
        ))

    # ------------------------------------------------------------------
    # Root access key check
    # ------------------------------------------------------------------

    if summary.get("AccountAccessKeysPresent", 0) == 1:
        findings.append(Finding(
            check_id="IAM-007",
            check_name="Root Access Keys Enabled",
            severity=Severity.CRITICAL,
            resource="root-account",
            detail=(
                "The AWS root account has active access keys configured."
            ),
            remediation=(
                "Delete all root access keys immediately and replace usage "
                "with IAM users or roles following least-privilege principles."
            ),
        ))

    logger.info(
        "Root account security checks completed with %d finding(s)",
        len(findings),
    )

    return findings


def run(session: boto3.Session) -> list[Finding]:
    """
    Entry point used by the audit engine.
    """
    iam_client = session.client("iam")

    findings: list[Finding] = []

    findings.extend(check_users_without_mfa(iam_client))
    findings.extend(check_root_security(iam_client))

    return findings