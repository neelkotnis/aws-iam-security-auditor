"""
checks/mfa.py
-------------
Checks:
  IAM-001  IAM users without MFA enabled          → HIGH     (CIS 1.10)
  IAM-002  Root account MFA disabled               → CRITICAL (CIS 1.5)
  IAM-007  Root account access keys present        → CRITICAL (CIS 1.4)
  IAM-008  Account password policy too weak        → MEDIUM   (CIS 1.8)
"""

from __future__ import annotations

import csv
import logging
from io import StringIO

import boto3

from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)

# CIS 1.8 minimum password policy requirements
MIN_PASSWORD_LENGTH = 14
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_SYMBOLS = True
REQUIRE_NUMBERS = True
MAX_PASSWORD_AGE = 90


def check_users_without_mfa(iam_client) -> list[Finding]:
    """
    Identify IAM users with console access enabled but no MFA configured.
    Uses the IAM credential report for efficient bulk analysis.
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

            if username == "<root_account>":
                continue
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
                    cis_control="CIS 1.10",
                ))
    except Exception as exc:
        logger.error("Failed parsing credential report: %s", exc)

    logger.info("MFA user check completed with %d finding(s)", len(findings))
    return findings


def check_root_security(iam_client) -> list[Finding]:
    """
    Validate root account security: MFA status and access key presence.
    """
    findings: list[Finding] = []

    try:
        response = iam_client.get_account_summary()
        summary = response.get("SummaryMap", {})
    except Exception as exc:
        logger.error("Failed to retrieve account summary: %s", exc)
        return findings

    if summary.get("AccountMFAEnabled", 0) != 1:
        findings.append(Finding(
            check_id="IAM-002",
            check_name="Root Account MFA Disabled",
            severity=Severity.CRITICAL,
            resource="root-account",
            detail="The AWS root account does not have MFA enabled.",
            remediation=(
                "Enable hardware or virtual MFA on the AWS root account immediately."
            ),
            cis_control="CIS 1.5",
        ))

    if summary.get("AccountAccessKeysPresent", 0) == 1:
        findings.append(Finding(
            check_id="IAM-007",
            check_name="Root Access Keys Present",
            severity=Severity.CRITICAL,
            resource="root-account",
            detail="The AWS root account has active access keys configured.",
            remediation=(
                "Delete all root access keys immediately. Use IAM roles or "
                "users with least-privilege permissions instead."
            ),
            cis_control="CIS 1.4",
        ))

    logger.info("Root account checks completed with %d finding(s)", len(findings))
    return findings


def check_password_policy(iam_client) -> list[Finding]:
    """
    Verify the account password policy meets CIS AWS Foundations Benchmark
    minimum requirements (CIS 1.8 — 1.11).
    """
    findings: list[Finding] = []

    try:
        response = iam_client.get_account_password_policy()
        policy = response.get("PasswordPolicy", {})
    except iam_client.exceptions.NoSuchEntityException:
        # No password policy set at all — this is the worst case
        findings.append(Finding(
            check_id="IAM-008",
            check_name="No IAM Password Policy",
            severity=Severity.HIGH,
            resource="account-password-policy",
            detail=(
                "No IAM account password policy is configured. "
                "AWS applies no password complexity or rotation requirements."
            ),
            remediation=(
                "Create a password policy requiring minimum 14 characters, "
                "uppercase, lowercase, numbers, symbols, and 90-day rotation."
            ),
            cis_control="CIS 1.8",
        ))
        return findings
    except Exception as exc:
        logger.error("Failed to retrieve password policy: %s", exc)
        return findings

    issues: list[str] = []

    if policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH:
        issues.append(
            f"minimum length is {policy.get('MinimumPasswordLength', 0)} "
            f"(required: {MIN_PASSWORD_LENGTH})"
        )
    if REQUIRE_UPPERCASE and not policy.get("RequireUppercaseCharacters", False):
        issues.append("uppercase characters not required")
    if REQUIRE_LOWERCASE and not policy.get("RequireLowercaseCharacters", False):
        issues.append("lowercase characters not required")
    if REQUIRE_SYMBOLS and not policy.get("RequireSymbols", False):
        issues.append("symbols not required")
    if REQUIRE_NUMBERS and not policy.get("RequireNumbers", False):
        issues.append("numbers not required")

    max_age = policy.get("MaxPasswordAge")
    if max_age is None or max_age > MAX_PASSWORD_AGE:
        age_str = str(max_age) if max_age else "not set"
        issues.append(
            f"password expiry is {age_str} days (required: ≤{MAX_PASSWORD_AGE})"
        )

    if issues:
        findings.append(Finding(
            check_id="IAM-008",
            check_name="Weak IAM Password Policy",
            severity=Severity.MEDIUM,
            resource="account-password-policy",
            detail=(
                "Account password policy does not meet CIS requirements: "
                + "; ".join(issues) + "."
            ),
            remediation=(
                "Update the IAM password policy to require at least 14 characters, "
                "uppercase, lowercase, numbers, symbols, and ≤90 day rotation."
            ),
            cis_control="CIS 1.8",
        ))

    logger.info("Password policy check completed with %d finding(s)", len(findings))
    return findings


def run(session: boto3.Session) -> list[Finding]:
    """Entry point used by the audit engine."""
    iam_client = session.client("iam")
    findings: list[Finding] = []
    findings.extend(check_users_without_mfa(iam_client))
    findings.extend(check_root_security(iam_client))
    findings.extend(check_password_policy(iam_client))
    return findings