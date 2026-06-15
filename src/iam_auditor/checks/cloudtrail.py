"""
checks/cloudtrail.py
--------------------
Checks:
  CT-001  No multi-region trail enabled and logging      -> CRITICAL (CIS 3.1)
  CT-002  Log file validation disabled                   -> HIGH     (CIS 3.2)
  CT-003  CloudTrail S3 bucket publicly accessible       -> CRITICAL (CIS 3.7)
  CT-004  S3 data events not enabled                     -> HIGH     (CIS 3.10)
  CT-005  Lambda data events not enabled                 -> HIGH     (CIS 3.11)
  CT-006  Trail logs not KMS-encrypted                   -> HIGH
  CT-007  No log retention lifecycle on S3 bucket        -> MEDIUM   (CIS 3.6)
"""

from __future__ import annotations

import json
import logging

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)


def _get_trails(ct):
    try:
        return ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    except Exception as e:
        logger.error("CT: describe_trails failed: %s", e)
        return []


def _trail_status(ct, arn):
    try:
        return ct.get_trail_status(Name=arn)
    except Exception:
        return {}


def _bucket_is_public(s3, bucket):
    try:
        pab = s3.get_public_access_block(Bucket=bucket)
        cfg = pab.get("PublicAccessBlockConfiguration", {})
        if all([cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")]):
            return False
    except Exception:
        pass
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
    except Exception:
        pass
    return False


def _bucket_has_lifecycle(s3, bucket):
    try:
        s3.get_bucket_lifecycle_configuration(Bucket=bucket)
        return True
    except Exception:
        return False


def _get_event_selectors(ct, arn):
    try:
        return ct.get_event_selectors(TrailName=arn).get("EventSelectors", [])
    except Exception:
        return []


def check_multi_region_trail(ct, account_id):
    findings = []
    trails = _get_trails(ct)
    active = [t for t in trails
              if t.get("IsMultiRegionTrail")
              and _trail_status(ct, t["TrailARN"]).get("IsLogging")]
    if not active:
        findings.append(Finding(
            check_id="CT-001",
            check_name="No Multi-Region CloudTrail",
            severity=Severity.CRITICAL,
            resource=f"arn:aws:cloudtrail:::account/{account_id}",
            account_id=account_id,
            region="global",
            detail=(
                f"No active multi-region trail found. Total trails: {len(trails)}. "
                "API activity in non-primary regions is not logged."
            ),
            remediation=(
                "aws cloudtrail create-trail --name org-trail "
                "--s3-bucket-name <bucket> --is-multi-region-trail "
                "--enable-log-file-validation"
            ),
            cis_control=get_cis("CT-001"),
            compliance_controls=get_controls("CT-001"),
        ))
    logger.info("CT-001: %d finding(s)", len(findings))
    return findings


def check_log_file_validation(ct, account_id):
    findings = []
    for trail in _get_trails(ct):
        if not trail.get("LogFileValidationEnabled"):
            name = trail.get("Name", "unknown")
            findings.append(Finding(
                check_id="CT-002",
                check_name="CloudTrail Log File Validation Disabled",
                severity=Severity.HIGH,
                resource=trail.get("TrailARN", name),
                account_id=account_id,
                region="global",
                detail=f"Trail '{name}' does not have log file validation enabled.",
                remediation=f"aws cloudtrail update-trail --name {name} --enable-log-file-validation",
                cis_control=get_cis("CT-002"),
                compliance_controls=get_controls("CT-002"),
            ))
    logger.info("CT-002: %d finding(s)", len(findings))
    return findings


def check_cloudtrail_bucket_public(ct, s3, account_id):
    findings = []
    checked = set()
    for trail in _get_trails(ct):
        bucket = trail.get("S3BucketName", "")
        if not bucket or bucket in checked:
            continue
        checked.add(bucket)
        if _bucket_is_public(s3, bucket):
            findings.append(Finding(
                check_id="CT-003",
                check_name="CloudTrail S3 Bucket Publicly Accessible",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:s3:::{bucket}",
                account_id=account_id,
                region="global",
                detail=f"S3 bucket '{bucket}' (CloudTrail destination) is publicly accessible.",
                remediation=(
                    f"aws s3api put-public-access-block --bucket {bucket} "
                    "--public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
                cis_control=get_cis("CT-003"),
                compliance_controls=get_controls("CT-003"),
            ))
    logger.info("CT-003: %d finding(s)", len(findings))
    return findings


def check_s3_data_events(ct, account_id):
    findings = []
    has_s3 = False
    for trail in _get_trails(ct):
        for sel in _get_event_selectors(ct, trail["TrailARN"]):
            for r in sel.get("DataResources", []):
                if r.get("Type") == "AWS::S3::Object":
                    has_s3 = True
    if not has_s3:
        findings.append(Finding(
            check_id="CT-004",
            check_name="CloudTrail S3 Data Events Not Enabled",
            severity=Severity.HIGH,
            resource=f"arn:aws:cloudtrail:::account/{account_id}",
            account_id=account_id,
            region="global",
            detail="No trail has S3 data events enabled. Object-level S3 activity is not logged.",
            remediation="Enable S3 data events on your primary trail using advanced event selectors.",
            cis_control=get_cis("CT-004"),
            compliance_controls=get_controls("CT-004"),
        ))
    logger.info("CT-004: %d finding(s)", len(findings))
    return findings


def check_lambda_data_events(ct, account_id):
    findings = []
    has_lambda = False
    for trail in _get_trails(ct):
        for sel in _get_event_selectors(ct, trail["TrailARN"]):
            for r in sel.get("DataResources", []):
                if r.get("Type") == "AWS::Lambda::Function":
                    has_lambda = True
    if not has_lambda:
        findings.append(Finding(
            check_id="CT-005",
            check_name="CloudTrail Lambda Data Events Not Enabled",
            severity=Severity.HIGH,
            resource=f"arn:aws:cloudtrail:::account/{account_id}",
            account_id=account_id,
            region="global",
            detail="No trail has Lambda data events enabled. Function invocations are not logged.",
            remediation="Add Lambda data events to your primary trail.",
            cis_control=get_cis("CT-005"),
            compliance_controls=get_controls("CT-005"),
        ))
    logger.info("CT-005: %d finding(s)", len(findings))
    return findings


def check_cloudtrail_kms(ct, account_id):
    findings = []
    for trail in _get_trails(ct):
        if not trail.get("KMSKeyId"):
            name = trail.get("Name", "unknown")
            findings.append(Finding(
                check_id="CT-006",
                check_name="CloudTrail Logs Not KMS-Encrypted",
                severity=Severity.HIGH,
                resource=trail.get("TrailARN", name),
                account_id=account_id,
                region="global",
                detail=f"Trail '{name}' does not use a KMS CMK for log encryption.",
                remediation=f"aws cloudtrail update-trail --name {name} --kms-key-id <key-arn>",
                cis_control=get_cis("CT-006"),
                compliance_controls=get_controls("CT-006"),
            ))
    logger.info("CT-006: %d finding(s)", len(findings))
    return findings


def check_log_retention(ct, s3, account_id):
    findings = []
    checked = set()
    for trail in _get_trails(ct):
        bucket = trail.get("S3BucketName", "")
        if not bucket or bucket in checked:
            continue
        checked.add(bucket)
        if not _bucket_has_lifecycle(s3, bucket):
            findings.append(Finding(
                check_id="CT-007",
                check_name="CloudTrail Log Retention Not Configured",
                severity=Severity.MEDIUM,
                resource=f"arn:aws:s3:::{bucket}",
                account_id=account_id,
                region="global",
                detail=f"S3 bucket '{bucket}' has no lifecycle policy. Log retention is not enforced.",
                remediation=(
                    f"Add an S3 lifecycle rule to '{bucket}' "
                    "expiring objects after 365 days."
                ),
                cis_control=get_cis("CT-007"),
                compliance_controls=get_controls("CT-007"),
            ))
    logger.info("CT-007: %d finding(s)", len(findings))
    return findings


def run(session: boto3.Session) -> list[Finding]:
    ct  = session.client("cloudtrail", region_name="us-east-1")
    s3  = session.client("s3", region_name="us-east-1")
    aid = session.client("sts").get_caller_identity()["Account"]
    findings = []
    findings.extend(check_multi_region_trail(ct, aid))
    findings.extend(check_log_file_validation(ct, aid))
    findings.extend(check_cloudtrail_bucket_public(ct, s3, aid))
    findings.extend(check_s3_data_events(ct, aid))
    findings.extend(check_lambda_data_events(ct, aid))
    findings.extend(check_cloudtrail_kms(ct, aid))
    findings.extend(check_log_retention(ct, s3, aid))
    return findings
