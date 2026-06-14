"""
checks/cloudwatch_alarms.py
---------------------------
Verifies the CIS AWS Foundations Benchmark alarm baselines exist.
Each CIS control requires a CloudWatch Metric Filter + Alarm on CloudTrail logs.

Checks:
  CWA-001  No alarm for root account usage              → CRITICAL (CIS 4.3)
  CWA-002  No alarm for unauthorized API calls          → HIGH     (CIS 4.1)
  CWA-003  No alarm for console sign-in without MFA     → HIGH     (CIS 4.2)
  CWA-004  No alarm for IAM policy changes              → HIGH     (CIS 4.4)
"""
from __future__ import annotations
import logging
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)

# Each entry: (check_id, name, severity, cis_ref, filter_pattern_keywords, description)
REQUIRED_ALARMS = [
    (
        "CWA-001", "Root Account Usage Alarm", Severity.CRITICAL,
        ["Root"],
        "Root account usage",
        "userIdentity.type = Root",
    ),
    (
        "CWA-002", "Unauthorized API Call Alarm", Severity.HIGH,
        ["UnauthorizedAttempt", "AccessDenied"],
        "Unauthorized API calls",
        "errorCode = AccessDenied OR errorCode = UnauthorizedAttempt",
    ),
    (
        "CWA-003", "Console Sign-In Without MFA Alarm", Severity.HIGH,
        ["ConsoleLogin", "MFAUsed", "No"],
        "Console login without MFA",
        "eventName = ConsoleLogin AND additionalEventData.MFAUsed = No",
    ),
    (
        "CWA-004", "IAM Policy Change Alarm", Severity.HIGH,
        ["DeleteGroupPolicy", "PutGroupPolicy", "AttachGroupPolicy",
         "DeleteRolePolicy", "PutRolePolicy", "AttachRolePolicy",
         "DeleteUserPolicy", "PutUserPolicy", "AttachUserPolicy"],
        "IAM policy changes",
        "IAM policy create/modify/delete events",
    ),
]


def _get_all_metric_filters(logs_client, log_group_name=None):
    """Return all metric filters, optionally filtered by log group."""
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        kwargs = {}
        if log_group_name:
            kwargs["logGroupName"] = log_group_name
        filters = []
        for page in paginator.paginate(**kwargs):
            filters.extend(page.get("metricFilters", []))
        return filters
    except Exception as e:
        logger.warning("describe_metric_filters: %s", e)
        return []


def _get_all_alarms(cw_client):
    try:
        paginator = cw_client.get_paginator("describe_alarms")
        alarms = []
        for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
            alarms.extend(page.get("MetricAlarms", []))
        return alarms
    except Exception as e:
        logger.warning("describe_alarms: %s", e)
        return []


def check_cis_alarms(logs_client, cw_client, account_id, region):
    findings = []
    all_filters = _get_all_metric_filters(logs_client)
    all_alarms  = _get_all_alarms(cw_client)

    # Build set of metric names that have alarms
    alarmed_metrics = {a["MetricName"] for a in all_alarms}

    for check_id, name, severity, keywords, desc, pattern_desc in REQUIRED_ALARMS:
        # Look for a metric filter whose pattern contains any of the keywords
        matched_filter = None
        for f in all_filters:
            fp = f.get("filterPattern", "").lower()
            if any(kw.lower() in fp for kw in keywords):
                # Check if this filter's metric has an alarm
                for trans in f.get("metricTransformations", []):
                    if trans.get("metricName") in alarmed_metrics:
                        matched_filter = f
                        break
            if matched_filter:
                break

        if not matched_filter:
            findings.append(Finding(
                check_id=check_id,
                check_name=f"Missing CIS Alarm: {name}",
                severity=severity,
                resource=f"arn:aws:cloudwatch:{region}:{account_id}",
                account_id=account_id, region=region,
                detail=(f"No CloudWatch metric filter + alarm found for: {desc}. "
                        f"Expected filter pattern covering: {pattern_desc}. "
                        "This CIS baseline alarm is missing, leaving the activity unmonitored."),
                remediation=(f"Create a CloudTrail-backed CloudWatch Logs metric filter for '{desc}' "
                             "and attach a CloudWatch Alarm with an SNS notification. "
                             "See CIS AWS Foundations Benchmark section 4 for exact filter patterns."),
                cis_control=get_cis(check_id),
                compliance_controls=get_controls(check_id),
            ))

    logger.info("CWA checks [%s]: %d missing alarm(s)", region, len(findings))
    return findings


def _run(ctx: ScanContext):
    logs = ctx.client("logs")
    cw   = ctx.client("cloudwatch")
    return check_cis_alarms(logs, cw, ctx.account_id, ctx.region)


CHECKS: list = [
    ("CloudWatch Alarm Checks", "cloudwatch_alarms", False, _run),
]
