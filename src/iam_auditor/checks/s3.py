"""
checks/s3.py
------------
Checks:
  S3-001  Account-level public access block incomplete   -> CRITICAL (CIS 2.1.5)
  S3-002  Bucket-level public access block missing       -> CRITICAL (CIS 2.1.5)
  S3-003  Bucket policy allows public access             -> CRITICAL (CIS 2.1.5)
  S3-004  Bucket ACL grants public access                -> CRITICAL (CIS 2.1.5)
  S3-005  Bucket encryption not enabled                  -> HIGH     (CIS 2.1.1)
  S3-006  Object ownership not enforced                  -> CRITICAL (CIS 2.1.3)
  S3-007  Versioning not enabled                         -> MEDIUM
  S3-008  Access logging not enabled                     -> HIGH     (CIS 2.1.2)
"""

from __future__ import annotations

import json
import logging

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)


def _all_buckets(s3):
    try:
        return s3.list_buckets().get("Buckets", [])
    except Exception as e:
        logger.error("S3: list_buckets failed: %s", e)
        return []


def check_account_public_access_block(s3control, account_id):
    findings = []
    try:
        resp = s3control.get_public_access_block(AccountId=account_id)
        cfg = resp.get("PublicAccessBlockConfiguration", {})
        missing = [k for k in ["BlockPublicAcls", "IgnorePublicAcls",
                                "BlockPublicPolicy", "RestrictPublicBuckets"]
                   if not cfg.get(k, False)]
        if missing:
            findings.append(Finding(
                check_id="S3-001",
                check_name="S3 Account Public Access Block Incomplete",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:s3:::account/{account_id}",
                account_id=account_id,
                region="global",
                detail=f"Account-level S3 Block Public Access missing: {', '.join(missing)}.",
                remediation=(
                    f"aws s3control put-public-access-block --account-id {account_id} "
                    "--public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
                cis_control=get_cis("S3-001"),
                compliance_controls=get_controls("S3-001"),
            ))
    except Exception as e:
        if "NoSuchPublicAccessBlockConfiguration" in str(e):
            findings.append(Finding(
                check_id="S3-001",
                check_name="S3 Account Public Access Block Not Configured",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:s3:::account/{account_id}",
                account_id=account_id,
                region="global",
                detail="No account-level S3 Block Public Access configuration found.",
                remediation="Enable all four S3 Block Public Access settings at account level.",
                cis_control=get_cis("S3-001"),
                compliance_controls=get_controls("S3-001"),
            ))
        else:
            logger.error("S3-001 failed: %s", e)
    return findings


def check_bucket_public_access_block(s3, account_id):
    findings = []
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        missing = []
        try:
            resp = s3.get_public_access_block(Bucket=name)
            cfg = resp.get("PublicAccessBlockConfiguration", {})
            missing = [k for k in ["BlockPublicAcls", "IgnorePublicAcls",
                                    "BlockPublicPolicy", "RestrictPublicBuckets"]
                       if not cfg.get(k, False)]
        except Exception as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                missing = ["BlockPublicAcls", "IgnorePublicAcls",
                           "BlockPublicPolicy", "RestrictPublicBuckets"]
            else:
                logger.warning("S3-002 bucket %s: %s", name, e)
                continue
        if missing:
            findings.append(Finding(
                check_id="S3-002",
                check_name="S3 Bucket Public Access Block Incomplete",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:s3:::{name}",
                account_id=account_id,
                region="global",
                detail=f"Bucket '{name}' missing public access block: {', '.join(missing)}.",
                remediation=(
                    f"aws s3api put-public-access-block --bucket {name} "
                    "--public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
                cis_control=get_cis("S3-002"),
                compliance_controls=get_controls("S3-002"),
            ))
    logger.info("S3-002: %d finding(s)", len(findings))
    return findings


def check_bucket_policy_public(s3, account_id):
    findings = []
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
        except Exception as e:
            if "NoSuchBucketPolicy" in str(e):
                continue
            logger.warning("S3-003 bucket %s: %s", name, e)
            continue
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                findings.append(Finding(
                    check_id="S3-003",
                    check_name="S3 Bucket Policy Allows Public Access",
                    severity=Severity.CRITICAL,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id,
                    region="global",
                    detail=f"Bucket '{name}' policy has Principal: '*' with Effect: Allow.",
                    remediation=f"Remove the public Principal from the bucket policy on '{name}'.",
                    cis_control=get_cis("S3-003"),
                    compliance_controls=get_controls("S3-003"),
                ))
                break
    logger.info("S3-003: %d finding(s)", len(findings))
    return findings


def check_bucket_acl(s3, account_id):
    findings = []
    PUBLIC_URIS = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                if uri in PUBLIC_URIS:
                    findings.append(Finding(
                        check_id="S3-004",
                        check_name="S3 Bucket ACL Grants Public Access",
                        severity=Severity.CRITICAL,
                        resource=f"arn:aws:s3:::{name}",
                        account_id=account_id,
                        region="global",
                        detail=(
                            f"Bucket '{name}' ACL grants {grant.get('Permission')} to "
                            f"{'AllUsers' if 'AllUsers' in uri else 'AuthenticatedUsers'}."
                        ),
                        remediation=f"aws s3api put-bucket-acl --bucket {name} --acl private",
                        cis_control=get_cis("S3-004"),
                        compliance_controls=get_controls("S3-004"),
                    ))
                    break
        except Exception as e:
            logger.warning("S3-004 bucket %s: %s", name, e)
    logger.info("S3-004: %d finding(s)", len(findings))
    return findings


def check_bucket_encryption(s3, account_id):
    findings = []
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception as e:
            if any(x in str(e) for x in ["ServerSideEncryptionConfigurationNotFoundError",
                                           "NoSuchEncryptionConfiguration"]):
                findings.append(Finding(
                    check_id="S3-005",
                    check_name="S3 Bucket Encryption Not Enabled",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id,
                    region="global",
                    detail=f"Bucket '{name}' has no default server-side encryption configured.",
                    remediation=(
                        f"aws s3api put-bucket-encryption --bucket {name} "
                        "--server-side-encryption-configuration "
                        "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
                        "{\"SSEAlgorithm\":\"aws:kms\"}}]}'"
                    ),
                    cis_control=get_cis("S3-005"),
                    compliance_controls=get_controls("S3-005"),
                ))
    logger.info("S3-005: %d finding(s)", len(findings))
    return findings


def check_object_ownership(s3, account_id):
    findings = []
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            resp = s3.get_bucket_ownership_controls(Bucket=name)
            rules = resp.get("OwnershipControls", {}).get("Rules", [])
            ownership = rules[0].get("ObjectOwnership", "") if rules else ""
            if ownership != "BucketOwnerEnforced":
                findings.append(Finding(
                    check_id="S3-006",
                    check_name="S3 Object Ownership Not Enforced",
                    severity=Severity.CRITICAL,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id,
                    region="global",
                    detail=f"Bucket '{name}' ObjectOwnership is '{ownership}', not BucketOwnerEnforced.",
                    remediation=(
                        f"aws s3api put-bucket-ownership-controls --bucket {name} "
                        "--ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]"
                    ),
                    cis_control=get_cis("S3-006"),
                    compliance_controls=get_controls("S3-006"),
                ))
        except Exception as e:
            if "OwnershipControlsNotFoundError" in str(e):
                findings.append(Finding(
                    check_id="S3-006",
                    check_name="S3 Object Ownership Not Configured",
                    severity=Severity.CRITICAL,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id,
                    region="global",
                    detail=f"Bucket '{name}' has no Object Ownership controls configured.",
                    remediation=(
                        f"aws s3api put-bucket-ownership-controls --bucket {name} "
                        "--ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]"
                    ),
                    cis_control=get_cis("S3-006"),
                    compliance_controls=get_controls("S3-006"),
                ))
    logger.info("S3-006: %d finding(s)", len(findings))
    return findings


def check_bucket_versioning(s3, account_id):
    findings = []
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            resp = s3.get_bucket_versioning(Bucket=name)
            if resp.get("Status") != "Enabled":
                findings.append(Finding(
                    check_id="S3-007",
                    check_name="S3 Bucket Versioning Not Enabled",
                    severity=Severity.MEDIUM,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id,
                    region="global",
                    detail=f"Bucket '{name}' versioning is {resp.get('Status', 'Disabled')}.",
                    remediation=(
                        f"aws s3api put-bucket-versioning --bucket {name} "
                        "--versioning-configuration Status=Enabled"
                    ),
                    cis_control=get_cis("S3-007"),
                    compliance_controls=get_controls("S3-007"),
                ))
        except Exception as e:
            logger.warning("S3-007 bucket %s: %s", name, e)
    logger.info("S3-007: %d finding(s)", len(findings))
    return findings


def check_bucket_logging(s3, account_id):
    findings = []
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            resp = s3.get_bucket_logging(Bucket=name)
            if not resp.get("LoggingEnabled"):
                findings.append(Finding(
                    check_id="S3-008",
                    check_name="S3 Bucket Access Logging Not Enabled",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id,
                    region="global",
                    detail=f"Bucket '{name}' does not have server access logging enabled.",
                    remediation="Enable access logging on this bucket pointing to a dedicated log bucket.",
                    cis_control=get_cis("S3-008"),
                    compliance_controls=get_controls("S3-008"),
                ))
        except Exception as e:
            logger.warning("S3-008 bucket %s: %s", name, e)
    logger.info("S3-008: %d finding(s)", len(findings))
    return findings


def run(session: boto3.Session) -> list[Finding]:
    s3        = session.client("s3", region_name="us-east-1")
    s3control = session.client("s3control", region_name="us-east-1")
    aid       = session.client("sts").get_caller_identity()["Account"]
    findings  = []
    findings.extend(check_account_public_access_block(s3control, aid))
    findings.extend(check_bucket_public_access_block(s3, aid))
    findings.extend(check_bucket_policy_public(s3, aid))
    findings.extend(check_bucket_acl(s3, aid))
    findings.extend(check_bucket_encryption(s3, aid))
    findings.extend(check_object_ownership(s3, aid))
    findings.extend(check_bucket_versioning(s3, aid))
    findings.extend(check_bucket_logging(s3, aid))
    return findings
