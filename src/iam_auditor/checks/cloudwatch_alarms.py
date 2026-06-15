"""
checks/cloudwatch_alarms.py
---------------------------
CIS baseline alarm checks — verifies that CloudWatch metric filters
and alarms exist for the four most critical activity types.

Checks:
  CWA-001  No alarm for root account usage              -> CRITICAL (CIS 4.3)
  CWA-002  No alarm for unauthorized API calls          -> HIGH     (CIS 4.1)
  CWA-003  No alarm for console sign-in without MFA     -> HIGH     (CIS 4.2)
  CWA-004  No alarm for IAM policy changes              -> HIGH     (CIS 4.4)
"""

from __future__ import annotations

import logging

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)

REQUIRED_ALARMS = [
    (
        "CWA-001", "Root Account Usage Alarm", Severity.CRITICAL,
        ["Root"],
        "Root account usage",
    ),
    (
        "CWA-002", "Unauthorized API Call Alarm", Severity.HIGH,
        ["UnauthorizedAttempt", "AccessDenied"],
        "Unauthorized API calls",
    ),
    (
        "CWA-003", "Console Sign-In Without MFA Alarm", Severity.HIGH,
        ["ConsoleLogin", "MFAUsed"],
        "Console login without MFA",
    ),
    (
        "CWA-004", "IAM Policy Change Alarm", Severity.HIGH,
        ["DeleteGroupPolicy", "PutGroupPolicy", "AttachGroupPolicy",
         "DeleteRolePolicy", "PutRolePolicy", "AttachRolePolicy"],
        "IAM policy changes",
    ),
]


def run(session: boto3.Session) -> list[Finding]:
    region = session.region_name or "us-east-1"
    logs   = session.client("logs", region_name=region)
    cw     = session.client("cloudwatch", region_name=region)
    aid    = session.client("sts").get_caller_identity()["Account"]
    findings = []

    # Get all metric filters and alarms
    try:
        paginator = logs.get_paginator("describe_metric_filters")
        all_filters = []
        for page in paginator.paginate():
            all_filters.extend(page.get("metricFilters", []))
    except Exception as e:
        logger.error("CWA: describe_metric_filters failed [%s]: %s", region, e)
        all_filters = []

    try:
        paginator = cw.get_paginator("describe_alarms")
        alarmed_metrics = set()
        for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
            for alarm in page.get("MetricAlarms", []):
                alarmed_metrics.add(alarm["MetricName"])
    except Exception as e:
        logger.error("CWA: describe_alarms failed [%s]: %s", region, e)
        alarmed_metrics = set()

    for check_id, name, severity, keywords, desc in REQUIRED_ALARMS:
        matched = False
        for f in all_filters:
            fp = f.get("filterPattern", "").lower()
            if any(kw.lower() in fp for kw in keywords):
                for trans in f.get("metricTransformations", []):
                    if trans.get("metricName") in alarmed_metrics:
                        matched = True
                        break
            if matched:
                break

        if not matched:
            findings.append(Finding(
                check_id=check_id,
                check_name=f"Missing CIS Alarm: {name}",
                severity=severity,
                resource=f"arn:aws:cloudwatch:{region}:{aid}",
                account_id=aid,
                region=region,
                detail=(
                    f"No CloudWatch metric filter + alarm found for: {desc}. "
                    "This CIS baseline alarm is missing."
                ),
                remediation=(
                    f"Create a CloudTrail-backed CloudWatch Logs metric filter for '{desc}' "
                    "and attach a CloudWatch Alarm with an SNS notification."
                ),
                cis_control=get_cis(check_id),
                compliance_controls=get_controls(check_id),
            ))

    logger.info("CWA [%s]: %d missing alarm(s)", region, len(findings))
    return findings
