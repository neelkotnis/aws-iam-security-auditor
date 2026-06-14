"""
checks/iam_advanced.py
----------------------
Checks:
  IAM-012  Stale IAM roles - no activity in >90 days         -> HIGH
  IAM-013  Privileged role without permission boundary        -> HIGH
  IAM-014  Cross-account role trust without ExternalId        -> CRITICAL
  IAM-015  IAM Access Analyzer not enabled                    -> HIGH
  IAM-016  IAM Access Analyzer has unresolved findings        -> HIGH
  IAM-017  IAM role max session duration >12 hours            -> MEDIUM
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)

STALE_ROLE_DAYS = 90
MAX_SESSION_HOURS = 12


def _paginate(client, method: str, result_key: str, **kwargs) -> list:
    paginator = client.get_paginator(method)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(result_key, []))
    return results


def _days_since(dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


def check_stale_roles(iam_client) -> list[Finding]:
    """
    IAM-012: Roles with no activity in >90 days.
    Uses get_role() to retrieve RoleLastUsed which is the most accurate signal.
    Skips AWS service-linked roles — they are managed by AWS.
    """
    findings: list[Finding] = []
    try:
        roles = _paginate(iam_client, "list_roles", "Roles")
    except Exception as exc:
        logger.error("IAM-012: failed to list roles: %s", exc)
        return findings

    for role in roles:
        rname = role["RoleName"]
        rarn  = role["Arn"]

        # Skip AWS service-linked roles
        if "aws-service-role" in rarn or rname.startswith("AWSServiceRole"):
            continue

        try:
            detail    = iam_client.get_role(RoleName=rname)["Role"]
            last_used = detail.get("RoleLastUsed", {})
            last_date = last_used.get("LastUsedDate")
            created   = role.get("CreateDate")
        except Exception as exc:
            logger.warning("IAM-012: could not get role %s: %s", rname, exc)
            continue

        if last_date is None:
            # Role has never been used - check age
            if created and _days_since(created) > STALE_ROLE_DAYS:
                age = _days_since(created)
                findings.append(Finding(
                    check_id="IAM-012",
                    check_name="IAM Role Never Used",
                    severity=Severity.HIGH,
                    resource=rarn,
                    detail=(
                        f"Role '{rname}' has never been used and is {age} days old. "
                        "Unused roles are unnecessary attack surface."
                    ),
                    remediation=(
                        f"Verify if role '{rname}' is still needed. "
                        "Delete it if no longer required."
                    ),
                    cis_control=get_cis("IAM-012"),
                    compliance_controls=get_controls("IAM-012"),
                ))
        else:
            days = _days_since(last_date)
            if days > STALE_ROLE_DAYS:
                findings.append(Finding(
                    check_id="IAM-012",
                    check_name="IAM Role Stale",
                    severity=Severity.HIGH,
                    resource=rarn,
                    detail=(
                        f"Role '{rname}' has not been used for {days} days "
                        f"(last used: {last_date.date()})."
                    ),
                    remediation=(
                        f"Review role '{rname}' and delete if no longer required. "
                        "Use IAM Access Advisor to confirm no active dependencies."
                    ),
                    cis_control=get_cis("IAM-012"),
                    compliance_controls=get_controls("IAM-012"),
                ))

    logger.info("IAM-012: %d finding(s)", len(findings))
    return findings


def check_permission_boundaries(iam_client) -> list[Finding]:
    """
    IAM-013: Privileged roles (AdministratorAccess or PowerUserAccess)
    without a permission boundary attached.
    Permission boundaries prevent privilege escalation when delegating role creation.
    """
    findings: list[Finding] = []
    PRIVILEGED = {"arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/PowerUserAccess"}

    try:
        roles = _paginate(iam_client, "list_roles", "Roles")
    except Exception as exc:
        logger.error("IAM-013: failed to list roles: %s", exc)
        return findings

    for role in roles:
        rname = role["RoleName"]
        rarn  = role["Arn"]

        if "aws-service-role" in rarn or rname.startswith("AWSServiceRole"):
            continue

        # Only flag if no boundary set
        if role.get("PermissionsBoundary"):
            continue

        try:
            attached = iam_client.list_attached_role_policies(
                RoleName=rname
            ).get("AttachedPolicies", [])
        except Exception as exc:
            logger.warning("IAM-013: could not get policies for %s: %s", rname, exc)
            continue

        is_privileged = any(p["PolicyArn"] in PRIVILEGED for p in attached)
        if is_privileged:
            findings.append(Finding(
                check_id="IAM-013",
                check_name="Privileged Role Without Permission Boundary",
                severity=Severity.HIGH,
                resource=rarn,
                detail=(
                    f"Role '{rname}' has AdministratorAccess or PowerUserAccess "
                    "but no permission boundary. It can create new roles/users "
                    "with any permissions, enabling privilege escalation."
                ),
                remediation=(
                    f"Attach a permission boundary to role '{rname}': "
                    "aws iam put-role-permissions-boundary "
                    f"--role-name {rname} "
                    "--permissions-boundary <boundary-policy-arn>"
                ),
                cis_control=get_cis("IAM-013"),
                compliance_controls=get_controls("IAM-013"),
            ))

    logger.info("IAM-013: %d finding(s)", len(findings))
    return findings


def check_external_id(iam_client) -> list[Finding]:
    """
    IAM-014: Cross-account role trust policies without an ExternalId condition.
    Without ExternalId, any customer of the trusted account can assume the role
    (confused deputy attack).
    """
    import json
    findings: list[Finding] = []

    try:
        roles = _paginate(iam_client, "list_roles", "Roles")
    except Exception as exc:
        logger.error("IAM-014: failed to list roles: %s", exc)
        return findings

    for role in roles:
        rarn  = role["Arn"]
        rname = role["RoleName"]
        trust = role.get("AssumeRolePolicyDocument", {})

        if isinstance(trust, str):
            try:
                trust = json.loads(trust)
            except Exception:
                continue

        for stmt in trust.get("Statement", []):
            if stmt.get("Effect", "").lower() != "allow":
                continue

            principal = stmt.get("Principal", {})
            aws_principals = []
            if isinstance(principal, dict):
                aws = principal.get("AWS", [])
                aws_principals = [aws] if isinstance(aws, str) else aws

            # Only flag cross-account trusts (external account ID in principal)
            # Extract account ID from the role ARN (arn:aws:iam::ACCOUNT:root etc)
            try:
                own_account = rarn.split(":")[4]
            except IndexError:
                continue

            cross_account = [
                p for p in aws_principals
                if isinstance(p, str)
                and own_account not in p
                and "amazonaws.com" not in p
            ]

            if not cross_account:
                continue

            # Check for ExternalId condition
            conditions = stmt.get("Condition", {})
            has_external_id = "sts:ExternalId" in str(conditions)

            if not has_external_id:
                findings.append(Finding(
                    check_id="IAM-014",
                    check_name="Cross-Account Trust Without ExternalId",
                    severity=Severity.CRITICAL,
                    resource=rarn,
                    detail=(
                        f"Role '{rname}' trusts external account(s) "
                        f"{cross_account} without an ExternalId condition. "
                        "Any customer of that account can assume this role "
                        "(confused deputy attack)."
                    ),
                    remediation=(
                        "Add an ExternalId condition to the trust policy: "
                        '{"Condition": {"StringEquals": {"sts:ExternalId": "<unique-id>"}}}. '
                        "Coordinate the ExternalId value with the trusted third party."
                    ),
                    cis_control=get_cis("IAM-014"),
                    compliance_controls=get_controls("IAM-014"),
                ))

    logger.info("IAM-014: %d finding(s)", len(findings))
    return findings


def check_access_analyzer(session: boto3.Session) -> list[Finding]:
    """
    IAM-015 / IAM-016: Check that IAM Access Analyzer is enabled in at least
    one region, and surface any active (unresolved) findings it has raised.
    Access Analyzer identifies external access to your resources continuously.
    """
    findings: list[Finding] = []

    # Check in us-east-1 as the primary region
    # (Access Analyzer is regional; checking one region is a baseline)
    try:
        aa = session.client("accessanalyzer", region_name="us-east-1")
        analyzers = aa.list_analyzers().get("analyzers", [])
        active = [a for a in analyzers if a.get("status") == "ACTIVE"]
    except Exception as exc:
        logger.error("IAM-015: failed to check Access Analyzer: %s", exc)
        return findings

    if not active:
        findings.append(Finding(
            check_id="IAM-015",
            check_name="IAM Access Analyzer Not Enabled",
            severity=Severity.HIGH,
            resource="arn:aws:access-analyzer:us-east-1",
            detail=(
                "No active IAM Access Analyzer found in us-east-1. "
                "External access to your S3 buckets, IAM roles, KMS keys, "
                "and other resources is not being continuously analysed."
            ),
            remediation=(
                "aws accessanalyzer create-analyzer "
                "--analyzer-name default --type ACCOUNT "
                "--region us-east-1"
            ),
            cis_control=get_cis("IAM-015"),
            compliance_controls=get_controls("IAM-015"),
        ))
        return findings

    # Check for unresolved findings on each active analyzer
    for analyzer in active:
        aarn = analyzer["arn"]
        try:
            resp = aa.list_findings(
                analyzerArn=aarn,
                filter={"status": {"eq": ["ACTIVE"]}},
                maxResults=20,
            )
            active_findings = resp.get("findings", [])
            if active_findings:
                findings.append(Finding(
                    check_id="IAM-016",
                    check_name="IAM Access Analyzer Has Unresolved Findings",
                    severity=Severity.HIGH,
                    resource=aarn,
                    detail=(
                        f"IAM Access Analyzer has {len(active_findings)} active "
                        "finding(s) representing external or cross-account access "
                        "to your resources that may not be intentional."
                    ),
                    remediation=(
                        "Review and archive or remediate each finding in the IAM "
                        "Access Analyzer console. Archive findings that represent "
                        "known-good intentional access."
                    ),
                    cis_control=get_cis("IAM-016"),
                    compliance_controls=get_controls("IAM-016"),
                ))
        except Exception as exc:
            logger.warning("IAM-016: could not list findings for %s: %s", aarn, exc)

    logger.info("IAM-015/016: %d finding(s)", len(findings))
    return findings


def check_sts_session_duration(iam_client) -> list[Finding]:
    """
    IAM-017: IAM roles with MaxSessionDuration > 12 hours.
    Long sessions increase the window of exposure if a session token is compromised.
    """
    findings: list[Finding] = []
    max_seconds = MAX_SESSION_HOURS * 3600

    try:
        roles = _paginate(iam_client, "list_roles", "Roles")
    except Exception as exc:
        logger.error("IAM-017: failed to list roles: %s", exc)
        return findings

    for role in roles:
        rname    = role["RoleName"]
        rarn     = role["Arn"]
        duration = role.get("MaxSessionDuration", 3600)

        if "aws-service-role" in rarn:
            continue

        if duration > max_seconds:
            hours = duration // 3600
            findings.append(Finding(
                check_id="IAM-017",
                check_name="IAM Role Max Session Duration Too Long",
                severity=Severity.MEDIUM,
                resource=rarn,
                detail=(
                    f"Role '{rname}' has MaxSessionDuration of {hours}h "
                    f"(threshold: {MAX_SESSION_HOURS}h). "
                    "Long sessions increase the exposure window if a token is leaked."
                ),
                remediation=(
                    f"aws iam update-role --role-name {rname} "
                    f"--max-session-duration {max_seconds}"
                ),
                cis_control=get_cis("IAM-017"),
                compliance_controls=get_controls("IAM-017"),
            ))

    logger.info("IAM-017: %d finding(s)", len(findings))
    return findings


def run(session: boto3.Session) -> list[Finding]:
    """Entry point called by the engine."""
    iam = session.client("iam")
    findings: list[Finding] = []
    findings.extend(check_stale_roles(iam))
    findings.extend(check_permission_boundaries(iam))
    findings.extend(check_external_id(iam))
    findings.extend(check_access_analyzer(session))   # needs full session for regional client
    findings.extend(check_sts_session_duration(iam))
    return findings
