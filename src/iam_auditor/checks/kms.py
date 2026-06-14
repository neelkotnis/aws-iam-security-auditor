"""
checks/kms.py
-------------
Checks:
  KMS-001  CMK automatic rotation not enabled           → MEDIUM
  KMS-002  KMS key policy allows Principal: '*'         → CRITICAL
  KMS-003  KMS keys pending deletion                    → HIGH
  KMS-004  KMS grants with external principals          → HIGH
"""
from __future__ import annotations
import json
import logging
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)


def _list_customer_keys(kms):
    """Return all customer-managed CMKs (excludes AWS-managed and AWS-owned)."""
    try:
        paginator = kms.get_paginator("list_keys")
        keys = []
        for page in paginator.paginate():
            keys.extend(page.get("Keys", []))
        result = []
        for k in keys:
            try:
                meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") not in ("PendingDeletion",):
                    result.append(meta)
            except Exception:
                pass
        return result
    except Exception as e:
        logger.error("list_keys failed: %s", e)
        return []


def check_key_rotation(kms, account_id, region):
    findings = []
    for key in _list_customer_keys(kms):
        kid = key["KeyId"]
        try:
            resp = kms.get_key_rotation_status(KeyId=kid)
            if not resp.get("KeyRotationEnabled", False):
                findings.append(Finding(
                    check_id="KMS-001", check_name="KMS CMK Rotation Not Enabled",
                    severity=Severity.MEDIUM,
                    resource=key.get("Arn", kid),
                    account_id=account_id, region=region,
                    detail=(f"KMS key '{kid}' (alias: {key.get('Description', 'no description')}) "
                            "does not have automatic annual rotation enabled."),
                    remediation=f"aws kms enable-key-rotation --key-id {kid}",
                    cis_control=get_cis("KMS-001"), compliance_controls=get_controls("KMS-001")))
        except Exception as e:
            logger.warning("KMS-001 key %s: %s", kid, e)
    logger.info("KMS-001 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_key_policy(kms, account_id, region):
    findings = []
    for key in _list_customer_keys(kms):
        kid = key["KeyId"]
        try:
            policy = json.loads(kms.get_key_policy(KeyId=kid, PolicyName="default")["Policy"])
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                is_star = (principal == "*" or
                           (isinstance(principal, dict) and
                            (principal.get("AWS") == "*" or principal.get("AWS") == ["*"])))
                if is_star:
                    findings.append(Finding(
                        check_id="KMS-002", check_name="KMS Key Policy Allows Principal: *",
                        severity=Severity.CRITICAL,
                        resource=key.get("Arn", kid),
                        account_id=account_id, region=region,
                        detail=(f"KMS key '{kid}' has a key policy statement with Principal: '*'. "
                                "This allows any AWS principal to use the key for cryptographic operations."),
                        remediation=("Replace Principal: '*' with specific IAM role or account ARNs. "
                                     "Use conditions (aws:PrincipalOrgID) if cross-org access is needed."),
                        cis_control=get_cis("KMS-002"), compliance_controls=get_controls("KMS-002")))
                    break
        except Exception as e:
            logger.warning("KMS-002 key %s: %s", kid, e)
    logger.info("KMS-002 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_keys_pending_deletion(kms, account_id, region):
    findings = []
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for k in page.get("Keys", []):
                try:
                    meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                    if meta.get("KeyState") == "PendingDeletion":
                        findings.append(Finding(
                            check_id="KMS-003", check_name="KMS Key Pending Deletion",
                            severity=Severity.HIGH,
                            resource=meta.get("Arn", k["KeyId"]),
                            account_id=account_id, region=region,
                            detail=(f"KMS key '{k['KeyId']}' is scheduled for deletion on "
                                    f"{meta.get('DeletionDate', 'unknown')}. "
                                    "If data encrypted with this key has not been re-encrypted, "
                                    "it will become permanently inaccessible."),
                            remediation=(f"aws kms cancel-key-deletion --key-id {k['KeyId']} "
                                         "if the deletion is accidental."),
                            cis_control=get_cis("KMS-003"), compliance_controls=get_controls("KMS-003")))
                except Exception:
                    pass
    except Exception as e:
        logger.error("KMS-003 failed [%s]: %s", region, e)
    return findings


def check_key_grants(kms, account_id, region):
    findings = []
    for key in _list_customer_keys(kms):
        kid = key["KeyId"]
        try:
            paginator = kms.get_paginator("list_grants")
            for page in paginator.paginate(KeyId=kid):
                for grant in page.get("Grants", []):
                    grantee = grant.get("GranteePrincipal", "")
                    # Flag grants to principals outside this account
                    if grantee and account_id not in grantee and "amazonaws.com" not in grantee:
                        findings.append(Finding(
                            check_id="KMS-004", check_name="KMS Key Grant to External Principal",
                            severity=Severity.HIGH,
                            resource=key.get("Arn", kid),
                            account_id=account_id, region=region,
                            detail=(f"KMS key '{kid}' has a grant to external principal '{grantee}' "
                                    f"(grant ID: {grant.get('GrantId', 'unknown')}). "
                                    "External grants allow third parties to use your encryption keys."),
                            remediation=(f"Review grant {grant.get('GrantId')} and revoke if unexpected: "
                                         f"aws kms retire-grant --key-id {kid} "
                                         f"--grant-id {grant.get('GrantId')}"),
                            cis_control=get_cis("KMS-004"), compliance_controls=get_controls("KMS-004")))
        except Exception as e:
            logger.warning("KMS-004 key %s: %s", kid, e)
    logger.info("KMS-004 [%s]: %d finding(s)", region, len(findings))
    return findings


def _run(ctx: ScanContext):
    kms = ctx.client("kms")
    aid, reg = ctx.account_id, ctx.region
    findings = []
    findings.extend(check_key_rotation(kms, aid, reg))
    findings.extend(check_key_policy(kms, aid, reg))
    findings.extend(check_keys_pending_deletion(kms, aid, reg))
    findings.extend(check_key_grants(kms, aid, reg))
    return findings


CHECKS: list = [
    ("KMS Checks", "kms", False, _run),
]
