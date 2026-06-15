"""
checks/secrets_manager.py
-------------------------
Checks:
  SM-001  Secret rotation not enabled    -> HIGH
  SM-002  Secret unused >90 days         -> MEDIUM
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)
UNUSED_DAYS = 90


def _days_since(dt):
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


def run(session: boto3.Session) -> list[Finding]:
    region = session.region_name or "us-east-1"
    sm     = session.client("secretsmanager", region_name=region)
    aid    = session.client("sts").get_caller_identity()["Account"]
    findings = []

    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                arn  = secret.get("ARN", secret.get("Name"))
                name = secret.get("Name", arn)

                # SM-001: rotation
                if not secret.get("RotationEnabled"):
                    findings.append(Finding(
                        check_id="SM-001",
                        check_name="Secret Rotation Not Enabled",
                        severity=Severity.HIGH,
                        resource=arn,
                        account_id=aid, region=region,
                        detail=f"Secret '{name}' does not have automatic rotation enabled.",
                        remediation="Enable automatic rotation with a Lambda rotation function.",
                        cis_control=get_cis("SM-001"),
                        compliance_controls=get_controls("SM-001"),
                    ))

                # SM-002: unused
                last_accessed = secret.get("LastAccessedDate")
                created       = secret.get("CreatedDate")
                days = _days_since(last_accessed) if last_accessed else _days_since(created)
                if days is not None and days > UNUSED_DAYS:
                    findings.append(Finding(
                        check_id="SM-002",
                        check_name="Secret Unused >90 Days",
                        severity=Severity.MEDIUM,
                        resource=arn,
                        account_id=aid, region=region,
                        detail=(
                            f"Secret '{name}' has not been accessed in {days} days. "
                            "Unused secrets are unnecessary attack surface."
                        ),
                        remediation=(
                            f"aws secretsmanager delete-secret --secret-id {name} "
                            "--recovery-window-in-days 7 if no longer needed."
                        ),
                        cis_control=get_cis("SM-002"),
                        compliance_controls=get_controls("SM-002"),
                    ))
    except Exception as e:
        logger.error("SM failed [%s]: %s", region, e)

    logger.info("SM [%s]: %d finding(s)", region, len(findings))
    return findings
