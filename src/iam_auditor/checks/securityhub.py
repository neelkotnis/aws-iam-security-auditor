"""
checks/securityhub.py
---------------------
Checks:
  SH-001  Security Hub not enabled or no active standards -> HIGH
"""

from __future__ import annotations

import logging

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)


def run(session: boto3.Session) -> list[Finding]:
    region   = session.region_name or "us-east-1"
    sh       = session.client("securityhub", region_name=region)
    aid      = session.client("sts").get_caller_identity()["Account"]
    findings = []

    try:
        hub       = sh.describe_hub()
        standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
        active    = [s for s in standards if s.get("StandardsStatus") == "READY"]
        if not active:
            findings.append(Finding(
                check_id="SH-001",
                check_name="Security Hub Has No Active Standards",
                severity=Severity.HIGH,
                resource=hub.get("HubArn", f"securityhub:{region}:{aid}"),
                account_id=aid,
                region=region,
                detail=f"Security Hub is enabled in {region} but no security standards are active.",
                remediation="Enable CIS AWS Foundations Benchmark standard in Security Hub.",
                cis_control=get_cis("SH-001"),
                compliance_controls=get_controls("SH-001"),
            ))
    except Exception as e:
        err = str(e)
        if "InvalidAccessException" in err or "not subscribed" in err.lower() \
                or "SubscriptionRequiredException" in err:
            findings.append(Finding(
                check_id="SH-001",
                check_name="Security Hub Not Enabled",
                severity=Severity.HIGH,
                resource=f"arn:aws:securityhub:{region}:{aid}:hub/default",
                account_id=aid,
                region=region,
                detail=(
                    f"Security Hub is not enabled in {region}. "
                    "Centralised security findings aggregation is inactive."
                ),
                remediation=(
                    f"aws securityhub enable-security-hub --region {region} "
                    "--enable-default-standards"
                ),
                cis_control=get_cis("SH-001"),
                compliance_controls=get_controls("SH-001"),
            ))
        else:
            logger.warning("SH-001 [%s]: %s", region, e)

    logger.info("SH-001 [%s]: %d finding(s)", region, len(findings))
    return findings