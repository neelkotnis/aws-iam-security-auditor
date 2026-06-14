"""
checks/secrets_manager.py
--------------------------
Checks:
  SM-001  Secret without automatic rotation enabled     → HIGH
  SM-002  Secret unused for >90 days                    → MEDIUM
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)
UNUSED_DAYS = 90


def _days_since(dt):
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


def _list_secrets(sm):
    try:
        paginator = sm.get_paginator("list_secrets")
        secrets = []
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))
        return secrets
    except Exception as e:
        logger.error("list_secrets failed: %s", e)
        return []


def check_rotation_enabled(sm, account_id, region):
    findings = []
    for secret in _list_secrets(sm):
        if not secret.get("RotationEnabled"):
            arn = secret.get("ARN", secret.get("Name"))
            findings.append(Finding(
                check_id="SM-001", check_name="Secret Rotation Not Enabled",
                severity=Severity.HIGH,
                resource=arn,
                account_id=account_id, region=region,
                detail=(f"Secret '{secret.get('Name')}' does not have automatic rotation enabled. "
                        "Long-lived static secrets increase blast radius if leaked."),
                remediation=("Enable automatic rotation with a Lambda rotation function. "
                             "AWS provides managed rotation functions for RDS, Redshift, "
                             "DocumentDB, and other services."),
                cis_control=get_cis("SM-001"), compliance_controls=get_controls("SM-001")))
    logger.info("SM-001 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_unused_secrets(sm, account_id, region):
    findings = []
    for secret in _list_secrets(sm):
        last_accessed = secret.get("LastAccessedDate")
        created = secret.get("CreatedDate")
        days = _days_since(last_accessed) if last_accessed else _days_since(created)
        if days is not None and days > UNUSED_DAYS:
            arn = secret.get("ARN", secret.get("Name"))
            findings.append(Finding(
                check_id="SM-002", check_name="Secret Unused for >90 Days",
                severity=Severity.MEDIUM,
                resource=arn,
                account_id=account_id, region=region,
                detail=(f"Secret '{secret.get('Name')}' has not been accessed in {days} days "
                        f"(last accessed: {last_accessed or 'never'}). "
                        "Unused secrets are unnecessary attack surface."),
                remediation=("Verify if this secret is still needed. If not, delete it: "
                             f"aws secretsmanager delete-secret --secret-id {secret.get('Name')} "
                             "--recovery-window-in-days 7"),
                cis_control=get_cis("SM-002"), compliance_controls=get_controls("SM-002")))
    logger.info("SM-002 [%s]: %d finding(s)", region, len(findings))
    return findings


def _run(ctx: ScanContext):
    sm = ctx.client("secretsmanager")
    aid, reg = ctx.account_id, ctx.region
    return check_rotation_enabled(sm, aid, reg) + check_unused_secrets(sm, aid, reg)


CHECKS: list = [
    ("Secrets Manager Checks", "secrets_manager", False, _run),
]
