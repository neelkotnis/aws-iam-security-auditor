"""
checks/s3.py
------------
Checks:
  S3-001  Account-level S3 public access block not fully enabled    → CRITICAL
  S3-002  Bucket-level public access block not fully enabled        → CRITICAL
  S3-003  Bucket policy allows public read/write                    → CRITICAL
  S3-004  Bucket ACL grants to AllUsers / AuthenticatedUsers        → CRITICAL
  S3-005  Bucket server-side encryption not enabled                 → HIGH
  S3-006  S3 Object Ownership not set to BucketOwnerEnforced        → CRITICAL
  S3-007  Bucket versioning not enabled                             → MEDIUM
  S3-008  Bucket access logging not enabled                         → HIGH

is_global=True — S3 control plane APIs work from any region; we scan all buckets once.
"""
from __future__ import annotations
import json
import logging
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)


def _all_buckets(s3):
    try:
        return s3.list_buckets().get("Buckets", [])
    except Exception as e:
        logger.error("list_buckets failed: %s", e)
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
                check_id="S3-001", check_name="S3 Account Public Access Block Incomplete",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:s3:::account/{account_id}",
                account_id=account_id, region="global",
                detail=(f"Account-level S3 Block Public Access is missing: {', '.join(missing)}. "
                        "Without all four settings, individual buckets can be made public."),
                remediation=("aws s3control put-public-access-block --account-id " + account_id +
                             " --public-access-block-configuration "
                             "BlockPublicAcls=true,IgnorePublicAcls=true,"
                             "BlockPublicPolicy=true,RestrictPublicBuckets=true"),
                cis_control=get_cis("S3-001"), compliance_controls=get_controls("S3-001")))
    except s3control.exceptions.NoSuchPublicAccessBlockConfiguration:
        findings.append(Finding(
            check_id="S3-001", check_name="S3 Account Public Access Block Not Configured",
            severity=Severity.CRITICAL,
            resource=f"arn:aws:s3:::account/{account_id}",
            account_id=account_id, region="global",
            detail="No account-level S3 Block Public Access configuration found.",
            remediation=("Enable all four S3 Block Public Access settings at the account level."),
            cis_control=get_cis("S3-001"), compliance_controls=get_controls("S3-001")))
    except Exception as e:
        logger.error("S3-001 failed: %s", e)
    return findings


def check_bucket_public_access_block(s3, account_id):
    findings = []
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            resp = s3.get_public_access_block(Bucket=name)
            cfg = resp.get("PublicAccessBlockConfiguration", {})
            missing = [k for k in ["BlockPublicAcls", "IgnorePublicAcls",
                                    "BlockPublicPolicy", "RestrictPublicBuckets"]
                       if not cfg.get(k, False)]
            if missing:
                raise ValueError(missing)
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            missing = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
        except ValueError as e:
            missing = e.args[0]
        except Exception as e:
            logger.warning("S3-002 bucket %s: %s", name, e)
            continue
        else:
            continue
        findings.append(Finding(
            check_id="S3-002", check_name="S3 Bucket Public Access Block Incomplete",
            severity=Severity.CRITICAL,
            resource=f"arn:aws:s3:::{name}",
            account_id=account_id, region="global",
            detail=f"Bucket '{name}' is missing public access block settings: {', '.join(missing)}.",
            remediation=(f"aws s3api put-public-access-block --bucket {name} "
                         "--public-access-block-configuration "
                         "BlockPublicAcls=true,IgnorePublicAcls=true,"
                         "BlockPublicPolicy=true,RestrictPublicBuckets=true"),
            cis_control=get_cis("S3-002"), compliance_controls=get_controls("S3-002")))
    logger.info("S3-002: %d finding(s)", len(findings))
    return findings


def check_bucket_policy_public(s3, account_id):
    findings = []
    PUBLIC_PRINCIPALS = {"*", "arn:aws:iam::*:root"}
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
        except s3.exceptions.NoSuchBucketPolicy:
            continue
        except Exception as e:
            logger.warning("S3-003 bucket %s: %s", name, e)
            continue
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            is_public = (principal == "*" or
                         (isinstance(principal, dict) and principal.get("AWS") == "*"))
            if is_public:
                findings.append(Finding(
                    check_id="S3-003", check_name="S3 Bucket Policy Allows Public Access",
                    severity=Severity.CRITICAL,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id, region="global",
                    detail=(f"Bucket '{name}' has a bucket policy with Principal: '*' and "
                            f"Effect: Allow on action(s): {stmt.get('Action', 'unknown')}. "
                            "This grants unauthenticated public access."),
                    remediation=(f"Review and remove the public Principal from the bucket policy on '{name}'. "
                                 "Use specific IAM principal ARNs instead."),
                    cis_control=get_cis("S3-003"), compliance_controls=get_controls("S3-003")))
                break
    logger.info("S3-003: %d finding(s)", len(findings))
    return findings


def check_bucket_acl(s3, account_id):
    findings = []
    PUBLIC_URIS = {"http://acs.amazonaws.com/groups/global/AllUsers",
                   "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            acl = s3.get_bucket_acl(Bucket=name)
        except Exception as e:
            logger.warning("S3-004 bucket %s: %s", name, e)
            continue
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri in PUBLIC_URIS:
                perm = grant.get("Permission", "UNKNOWN")
                findings.append(Finding(
                    check_id="S3-004", check_name="S3 Bucket ACL Grants Public Access",
                    severity=Severity.CRITICAL,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id, region="global",
                    detail=(f"Bucket '{name}' ACL grants {perm} to "
                            f"{'AllUsers (public internet)' if 'AllUsers' in uri else 'AuthenticatedUsers (all AWS accounts)'}."),
                    remediation=(f"aws s3api put-bucket-acl --bucket {name} --acl private. "
                                 "Remove public ACL grants and use bucket policies with specific principals."),
                    cis_control=get_cis("S3-004"), compliance_controls=get_controls("S3-004")))
                break
    logger.info("S3-004: %d finding(s)", len(findings))
    return findings


def check_bucket_encryption(s3, account_id):
    findings = []
    for bucket in _all_buckets(s3):
        name = bucket["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
        except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            findings.append(Finding(
                check_id="S3-005", check_name="S3 Bucket Encryption Not Enabled",
                severity=Severity.HIGH,
                resource=f"arn:aws:s3:::{name}",
                account_id=account_id, region="global",
                detail=f"Bucket '{name}' has no default server-side encryption configured.",
                remediation=(f"aws s3api put-bucket-encryption --bucket {name} "
                             "--server-side-encryption-configuration "
                             "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
                             "{\"SSEAlgorithm\":\"aws:kms\"}}]}'"),
                cis_control=get_cis("S3-005"), compliance_controls=get_controls("S3-005")))
        except Exception as e:
            logger.warning("S3-005 bucket %s: %s", name, e)
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
                    check_id="S3-006", check_name="S3 Object Ownership Not Enforced",
                    severity=Severity.CRITICAL,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id, region="global",
                    detail=(f"Bucket '{name}' ObjectOwnership is '{ownership}' (not BucketOwnerEnforced). "
                            "Objects uploaded by other accounts may retain ownership, "
                            "allowing them to control object ACLs."),
                    remediation=(f"aws s3api put-bucket-ownership-controls --bucket {name} "
                                 "--ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]"),
                    cis_control=get_cis("S3-006"), compliance_controls=get_controls("S3-006")))
        except s3.exceptions.OwnershipControlsNotFoundError:
            findings.append(Finding(
                check_id="S3-006", check_name="S3 Object Ownership Not Configured",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:s3:::{name}",
                account_id=account_id, region="global",
                detail=f"Bucket '{name}' has no Object Ownership controls configured.",
                remediation=(f"aws s3api put-bucket-ownership-controls --bucket {name} "
                             "--ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]"),
                cis_control=get_cis("S3-006"), compliance_controls=get_controls("S3-006")))
        except Exception as e:
            logger.warning("S3-006 bucket %s: %s", name, e)
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
                    check_id="S3-007", check_name="S3 Bucket Versioning Not Enabled",
                    severity=Severity.MEDIUM,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id, region="global",
                    detail=f"Bucket '{name}' versioning is {resp.get('Status', 'Disabled')}. "
                           "Accidental deletions or overwrites are unrecoverable.",
                    remediation=f"aws s3api put-bucket-versioning --bucket {name} "
                                "--versioning-configuration Status=Enabled",
                    cis_control=get_cis("S3-007"), compliance_controls=get_controls("S3-007")))
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
                    check_id="S3-008", check_name="S3 Bucket Access Logging Not Enabled",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:s3:::{name}",
                    account_id=account_id, region="global",
                    detail=f"Bucket '{name}' does not have server access logging enabled. "
                           "S3 object-level requests are not being recorded.",
                    remediation=(f"aws s3api put-bucket-logging --bucket {name} "
                                 "--bucket-logging-status '{\"LoggingEnabled\":"
                                 "{\"TargetBucket\":\"<logging-bucket>\",\"TargetPrefix\":\"" + name + "/\"}}'"),
                    cis_control=get_cis("S3-008"), compliance_controls=get_controls("S3-008")))
        except Exception as e:
            logger.warning("S3-008 bucket %s: %s", name, e)
    logger.info("S3-008: %d finding(s)", len(findings))
    return findings


def _run(ctx: ScanContext):
    s3 = ctx.client("s3")
    s3control = ctx.session.client("s3control", region_name="us-east-1")
    aid = ctx.account_id
    findings = []
    findings.extend(check_account_public_access_block(s3control, aid))
    findings.extend(check_bucket_public_access_block(s3, aid))
    findings.extend(check_bucket_policy_public(s3, aid))
    findings.extend(check_bucket_acl(s3, aid))
    findings.extend(check_bucket_encryption(s3, aid))
    findings.extend(check_object_ownership(s3, aid))
    findings.extend(check_bucket_versioning(s3, aid))
    findings.extend(check_bucket_logging(s3, aid))
    return findings


CHECKS: list = [
    ("S3 Checks", "s3", True, _run),
]
