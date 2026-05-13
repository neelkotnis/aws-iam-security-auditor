"""
checks/permissions.py
---------------------
Checks:
  IAM-003  Wildcard Action (*) in customer-managed policies  → HIGH
  IAM-004  AdministratorAccess policy attached to users/roles → CRITICAL
"""

from __future__ import annotations

import json
import logging

import boto3

from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _paginate(client, method: str, result_key: str, **kwargs) -> list:
    """Generic paginator helper — avoids repetition across checks."""
    paginator = client.get_paginator(method)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(result_key, []))
    return results


def _policy_has_wildcard_action(policy_document: dict) -> bool:
    """
    Return True if any statement in the policy grants Action: '*'
    on Effect: Allow.  Handles both list and string forms.
    """
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]  # single-statement policies

    for stmt in statements:
        if stmt.get("Effect", "").lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions:
            return True
    return False


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def check_wildcard_permissions(iam_client) -> list[Finding]:
    """
    Scan all customer-managed policies (Scope='Local') for wildcard actions.
    AWS-managed policies are intentionally excluded — they are AWS's
    responsibility and flagging them produces noise, not signal.
    """
    findings: list[Finding] = []

    try:
        policies = _paginate(
            iam_client, "list_policies", "Policies",
            Scope="Local", OnlyAttached=False,
        )
    except Exception as exc:
        logger.error("Failed to list policies: %s", exc)
        return findings

    for policy in policies:
        policy_arn = policy["Arn"]
        policy_name = policy["PolicyName"]
        version_id = policy.get("DefaultVersionId", "v1")

        try:
            version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            doc = version["PolicyVersion"]["Document"]
            # Document may already be a dict (boto3 auto-decodes) or a string
            if isinstance(doc, str):
                doc = json.loads(doc)
        except Exception as exc:
            logger.warning("Could not retrieve policy %s: %s", policy_arn, exc)
            continue

        if _policy_has_wildcard_action(doc):
            findings.append(Finding(
                check_id="IAM-003",
                check_name="Wildcard Action in Policy",
                severity=Severity.HIGH,
                resource=policy_arn,
                detail=(
                    f"Customer-managed policy '{policy_name}' contains "
                    "Action: '*' with Effect: Allow. This grants unrestricted "
                    "access to all AWS APIs."
                ),
                remediation=(
                    "Replace the wildcard action with an explicit list of required "
                    "actions following the principle of least privilege. "
                    "Use IAM Access Analyzer to generate least-privilege policies."
                ),
            ))

    logger.info("Wildcard permission check found %d finding(s)", len(findings))
    return findings


def check_admin_access_attached(iam_client) -> list[Finding]:
    """
    Find all IAM entities (users, roles, groups) with AdministratorAccess
    policy directly attached.
    """
    findings: list[Finding] = []

    entity_mappings = [
        ("User", "PolicyUsers", "UserName", "user"),
        ("Role", "PolicyRoles", "RoleName", "role"),
        ("Group", "PolicyGroups", "GroupName", "group"),
    ]

    for entity_filter, result_key, name_key, resource_type in entity_mappings:
        try:
            response = iam_client.list_entities_for_policy(
                PolicyArn=ADMIN_POLICY_ARN,
                EntityFilter=entity_filter,
            )
        except Exception as exc:
            logger.error(
                "Failed to list %s entities for AdminAccess policy: %s",
                entity_filter,
                exc,
            )
            continue

        for entity in response.get(result_key, []):
            name = entity[name_key]

            findings.append(Finding(
                check_id="IAM-004",
                check_name="AdministratorAccess Policy Attached",
                severity=Severity.CRITICAL,
                resource=f"iam::{resource_type}/{name}",
                detail=(
                    f"{entity_filter} '{name}' has AdministratorAccess attached."
                ),
                remediation=(
                    "Replace AdministratorAccess with least-privilege permissions "
                    "and restrict elevated access through role assumption and MFA."
                ),
            ))

    logger.info("AdminAccess check found %d finding(s)", len(findings))
    return findings

def run(session: boto3.Session) -> list[Finding]:
    """Entry point called by the engine."""
    iam = session.client("iam")
    return check_wildcard_permissions(iam) + check_admin_access_attached(iam)
