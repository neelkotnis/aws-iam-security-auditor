"""
checks/cloudtrail.py
--------------------
Checks:
  CT-001  No multi-region trail enabled or trail not logging         → CRITICAL
  CT-002  Log file validation disabled on trail                      → HIGH
  CT-003  CloudTrail S3 bucket is publicly accessible               → CRITICAL
  CT-004  S3 data events not enabled for any trail                   → HIGH
  CT-005  Lambda data events not enabled for any trail               → HIGH
  CT-006  CloudTrail logs not KMS-encrypted                          → HIGH
  CT-007  CloudTrail S3 bucket lacks a lifecycle policy (retention)  → MEDIUM

All checks are GLOBAL (CloudTrail management APIs are us-east-1/global).
Regional trail checks can be added in a separate regional module later.
"""

from __future__ import annotations

import json
import logging

from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_trails(ct_client) -> list[dict]:
    """Return all trails visible in this region (includes shadow trails)."""
    try:
        resp = ct_client.describe_trails(includeShadowTrails=True)
        return resp.get("trailList", [])
    except Exception as exc:
        logger.error("describe_trails failed: %s", exc)
        return []


def _trail_status(ct_client, trail_arn: str) -> dict:
    try:
        return ct_client.get_trail_status(Name=trail_arn)
    except Exception as exc:
        logger.warning("get_trail_status failed for %s: %s", trail_arn, exc)
        return {}


def _bucket_is_public(s3_client, bucket_name: str) -> bool:
    """Return True if the S3 bucket has any public-access permission."""
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = pab.get("PublicAccessBlockConfiguration", {})
        # If all four are True, the bucket is NOT public
        if all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False),
        ]):
            return False
    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        pass  # No block config → potentially public, check ACL/policy below
    except Exception as exc:
        logger.warning("get_public_access_block for %s: %s", bucket_name, exc)

    # Also check bucket ACL for AllUsers / AuthenticatedUsers grants
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
    except Exception as exc:
        logger.warning("get_bucket_acl for %s: %s", bucket_name, exc)

    return False


def _bucket_has_lifecycle(s3_client, bucket_name: str) -> bool:
    try:
        s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        return True
    except s3_client.exceptions.NoSuchLifecycleConfiguration:
        return False
    except Exception:
        return True  # Assume present on API error (don't false-positive)


def _get_event_selectors(ct_client, trail_arn: str) -> list[dict]:
    try:
        resp = ct_client.get_event_selectors(TrailName=trail_arn)
        return resp.get("EventSelectors", [])
    except Exception as exc:
        logger.warning("get_event_selectors for %s: %s", trail_arn, exc)
        return []


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_multi_region_trail(ct_client, account_id: str) -> list[Finding]:
    """CT-001: At least one multi-region trail must exist and be actively logging."""
    findings: list[Finding] = []
    trails = _get_trails(ct_client)

    multi_region_logging = [
        t for t in trails
        if t.get("IsMultiRegionTrail", False)
        and _trail_status(ct_client, t["TrailARN"]).get("IsLogging", False)
    ]

    if not multi_region_logging:
        findings.append(Finding(
            check_id="CT-001",
            check_name="No Multi-Region CloudTrail",
            severity=Severity.CRITICAL,
            resource=f"arn:aws:cloudtrail:::account/{account_id}",
            account_id=account_id,
            region="global",
            detail=(
                "No active multi-region CloudTrail trail found. "
                f"Total trails found: {len(trails)}. "
                "Without a multi-region trail, API activity in non-primary regions "
                "is not logged, creating audit blind spots."
            ),
            remediation=(
                "Create a multi-region trail: aws cloudtrail create-trail "
                "--name org-trail --s3-bucket-name <bucket> --is-multi-region-trail "
                "--enable-log-file-validation. "
                "Enable organisation-level trails via the management account for full coverage."
            ),
            cis_control=get_cis("CT-001"),
            compliance_controls=get_controls("CT-001"),
        ))

    logger.info("CT-001 completed — %d multi-region active trails found", len(multi_region_logging))
    return findings


def check_log_file_validation(ct_client, account_id: str) -> list[Finding]:
    """CT-002: Log file validation must be enabled on every trail."""
    findings: list[Finding] = []
    trails = _get_trails(ct_client)

    for trail in trails:
        if not trail.get("LogFileValidationEnabled", False):
            trail_name = trail.get("Name", "unknown")
            findings.append(Finding(
                check_id="CT-002",
                check_name="CloudTrail Log File Validation Disabled",
                severity=Severity.HIGH,
                resource=trail.get("TrailARN", trail_name),
                account_id=account_id,
                region="global",
                detail=(
                    f"Trail '{trail_name}' does not have log file validation enabled. "
                    "Log file validation uses SHA-256 hashing to detect tampered or deleted logs."
                ),
                remediation=(
                    f"aws cloudtrail update-trail --name {trail_name} "
                    "--enable-log-file-validation"
                ),
                cis_control=get_cis("CT-002"),
                compliance_controls=get_controls("CT-002"),
            ))

    logger.info("CT-002 completed — %d finding(s)", len(findings))
    return findings


def check_cloudtrail_bucket_public(ct_client, s3_client, account_id: str) -> list[Finding]:
    """CT-003: The S3 bucket backing CloudTrail must not be publicly accessible."""
    findings: list[Finding] = []
    trails = _get_trails(ct_client)
    checked_buckets: set[str] = set()

    for trail in trails:
        bucket = trail.get("S3BucketName", "")
        if not bucket or bucket in checked_buckets:
            continue
        checked_buckets.add(bucket)

        if _bucket_is_public(s3_client, bucket):
            findings.append(Finding(
                check_id="CT-003",
                check_name="CloudTrail S3 Bucket Publicly Accessible",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:s3:::{bucket}",
                account_id=account_id,
                region="global",
                detail=(
                    f"The S3 bucket '{bucket}' used by trail '{trail.get('Name')}' "
                    "is publicly accessible. This exposes your audit logs to anyone on the internet."
                ),
                remediation=(
                    f"Enable S3 Block Public Access on bucket '{bucket}': "
                    "aws s3api put-public-access-block --bucket <name> "
                    "--public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
                cis_control=get_cis("CT-003"),
                compliance_controls=get_controls("CT-003"),
            ))

    logger.info("CT-003 completed — %d finding(s)", len(findings))
    return findings


def check_s3_data_events(ct_client, account_id: str) -> list[Finding]:
    """CT-004: At least one trail must have S3 data events enabled."""
    findings: list[Finding] = []
    trails = _get_trails(ct_client)

    has_s3_data_events = False
    for trail in trails:
        selectors = _get_event_selectors(ct_client, trail["TrailARN"])
        for sel in selectors:
            for resource in sel.get("DataResources", []):
                if resource.get("Type") == "AWS::S3::Object":
                    has_s3_data_events = True
                    break

    if not has_s3_data_events:
        findings.append(Finding(
            check_id="CT-004",
            check_name="CloudTrail S3 Data Events Not Enabled",
            severity=Severity.HIGH,
            resource=f"arn:aws:cloudtrail:::account/{account_id}",
            account_id=account_id,
            region="global",
            detail=(
                "No CloudTrail trail has S3 data events (object-level logging) enabled. "
                "GetObject, PutObject, and DeleteObject calls on S3 are not being recorded, "
                "making data exfiltration invisible."
            ),
            remediation=(
                "Enable S3 data events on your primary trail using advanced event selectors "
                "targeting AWS::S3::Object. Consider enabling for sensitive buckets first "
                "to control cost."
            ),
            cis_control=get_cis("CT-004"),
            compliance_controls=get_controls("CT-004"),
        ))

    logger.info("CT-004 completed — S3 data events present: %s", has_s3_data_events)
    return findings


def check_lambda_data_events(ct_client, account_id: str) -> list[Finding]:
    """CT-005: At least one trail must have Lambda data events enabled."""
    findings: list[Finding] = []
    trails = _get_trails(ct_client)

    has_lambda_events = False
    for trail in trails:
        selectors = _get_event_selectors(ct_client, trail["TrailARN"])
        for sel in selectors:
            for resource in sel.get("DataResources", []):
                if resource.get("Type") == "AWS::Lambda::Function":
                    has_lambda_events = True
                    break

    if not has_lambda_events:
        findings.append(Finding(
            check_id="CT-005",
            check_name="CloudTrail Lambda Data Events Not Enabled",
            severity=Severity.HIGH,
            resource=f"arn:aws:cloudtrail:::account/{account_id}",
            account_id=account_id,
            region="global",
            detail=(
                "No CloudTrail trail has Lambda data events (Invoke) enabled. "
                "Function invocations are not being recorded, limiting visibility "
                "into serverless workload abuse."
            ),
            remediation=(
                "Add Lambda data events to your primary trail with event selector "
                "Type=AWS::Lambda::Function, Values=[arn:aws:lambda] to capture all functions."
            ),
            cis_control=get_cis("CT-005"),
            compliance_controls=get_controls("CT-005"),
        ))

    logger.info("CT-005 completed — Lambda data events present: %s", has_lambda_events)
    return findings


def check_cloudtrail_kms_encryption(ct_client, account_id: str) -> list[Finding]:
    """CT-006: CloudTrail logs must be encrypted with a KMS CMK."""
    findings: list[Finding] = []
    trails = _get_trails(ct_client)

    for trail in trails:
        if not trail.get("KMSKeyId"):
            trail_name = trail.get("Name", "unknown")
            findings.append(Finding(
                check_id="CT-006",
                check_name="CloudTrail Logs Not KMS-Encrypted",
                severity=Severity.HIGH,
                resource=trail.get("TrailARN", trail_name),
                account_id=account_id,
                region="global",
                detail=(
                    f"Trail '{trail_name}' does not use a KMS CMK for log encryption. "
                    "Logs are stored as plaintext in S3 (protected only by S3 SSE-S3 if enabled)."
                ),
                remediation=(
                    f"aws cloudtrail update-trail --name {trail_name} "
                    "--kms-key-id arn:aws:kms:<region>:<account>:key/<key-id>. "
                    "Create a dedicated KMS key for CloudTrail with a restrictive key policy."
                ),
                cis_control=get_cis("CT-006"),
                compliance_controls=get_controls("CT-006"),
            ))

    logger.info("CT-006 completed — %d finding(s)", len(findings))
    return findings


def check_cloudtrail_log_retention(ct_client, s3_client, account_id: str) -> list[Finding]:
    """CT-007: CloudTrail S3 buckets must have a lifecycle policy (log retention)."""
    findings: list[Finding] = []
    trails = _get_trails(ct_client)
    checked_buckets: set[str] = set()

    for trail in trails:
        bucket = trail.get("S3BucketName", "")
        if not bucket or bucket in checked_buckets:
            continue
        checked_buckets.add(bucket)

        if not _bucket_has_lifecycle(s3_client, bucket):
            findings.append(Finding(
                check_id="CT-007",
                check_name="CloudTrail Log Retention Not Configured",
                severity=Severity.MEDIUM,
                resource=f"arn:aws:s3:::{bucket}",
                account_id=account_id,
                region="global",
                detail=(
                    f"S3 bucket '{bucket}' (CloudTrail destination) has no lifecycle policy. "
                    "Logs accumulate indefinitely or may be deleted without retention enforcement. "
                    "CIS and most compliance frameworks require ≥365-day log retention."
                ),
                remediation=(
                    f"Add an S3 lifecycle rule to bucket '{bucket}' that transitions logs "
                    "to S3 Glacier after 90 days and expires objects after 365 days (or your "
                    "required retention period)."
                ),
                cis_control=get_cis("CT-007"),
                compliance_controls=get_controls("CT-007"),
            ))

    logger.info("CT-007 completed — %d finding(s)", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Plugin registry
# ---------------------------------------------------------------------------

def _run(ctx: ScanContext) -> list[Finding]:
    """Engine entry point. CloudTrail management APIs are global."""
    ct  = ctx.client("cloudtrail")
    s3  = ctx.client("s3")
    aid = ctx.account_id

    findings: list[Finding] = []
    findings.extend(check_multi_region_trail(ct, aid))
    findings.extend(check_log_file_validation(ct, aid))
    findings.extend(check_cloudtrail_bucket_public(ct, s3, aid))
    findings.extend(check_s3_data_events(ct, aid))
    findings.extend(check_lambda_data_events(ct, aid))
    findings.extend(check_cloudtrail_kms_encryption(ct, aid))
    findings.extend(check_cloudtrail_log_retention(ct, s3, aid))
    return findings


CHECKS: list = [
    ("CloudTrail Checks", "cloudtrail", True, _run),
]
