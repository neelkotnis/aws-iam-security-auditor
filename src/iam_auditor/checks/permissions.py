"""
checks/permissions.py
---------------------
Checks:
  IAM-003  Wildcard Action (*) in customer-managed policies    → HIGH     (CIS 1.16)
  IAM-004  AdministratorAccess policy attached                 → CRITICAL (CIS 1.16)
  IAM-010  Overly permissive role trust policy (Principal: *)  → CRITICAL
  IAM-011  Inline policies detected on users/roles/groups      → LOW
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
    paginator = client.get_paginator(method)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(result_key, []))
    return results


def _policy_has_wildcard_action(policy_document: dict) -> bool:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect", "").lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions:
            return True
    return False


def _trust_policy_allows_any_principal(policy_document: dict) -> bool:
    """
    Return True if the trust policy contains Principal: '*' or
    Principal: {"AWS": "*"} — granting assume-role to anyone.
    """
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect", "").lower() != "allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS", "")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def check_wildcard_permissions(iam_client) -> list[Finding]:
    """Scan customer-managed policies for wildcard Action: '*'."""
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
                    "Action: '*' with Effect: Allow, granting unrestricted "
                    "access to all AWS APIs."
                ),
                remediation=(
                    "Replace the wildcard action with an explicit list of required "
                    "actions. Use IAM Access Analyzer to generate least-privilege policies."
                ),
                cis_control="CIS 1.16",
            ))

    logger.info("Wildcard permission check found %d finding(s)", len(findings))
    return findings


def check_admin_access_attached(iam_client) -> list[Finding]:
    """Find all IAM entities with AdministratorAccess policy attached."""
    findings: list[Finding] = []

    entity_mappings = [
        ("User",  "PolicyUsers",  "UserName",  "user"),
        ("Role",  "PolicyRoles",  "RoleName",  "role"),
        ("Group", "PolicyGroups", "GroupName", "group"),
    ]

    for entity_filter, result_key, name_key, resource_type in entity_mappings:
        try:
            response = iam_client.list_entities_for_policy(
                PolicyArn=ADMIN_POLICY_ARN,
                EntityFilter=entity_filter,
            )
        except Exception as exc:
            logger.error("Failed to list %s entities for AdminAccess: %s", entity_filter, exc)
            continue

        for entity in response.get(result_key, []):
            name = entity[name_key]
            findings.append(Finding(
                check_id="IAM-004",
                check_name="AdministratorAccess Policy Attached",
                severity=Severity.CRITICAL,
                resource=f"iam::{resource_type}/{name}",
                detail=(
                    f"{entity_filter} '{name}' has AdministratorAccess attached, "
                    "granting full access to all AWS services and resources."
                ),
                remediation=(
                    "Replace AdministratorAccess with least-privilege permissions. "
                    "Restrict elevated access through role assumption with MFA conditions."
                ),
                cis_control="CIS 1.16",
            ))

    logger.info("AdminAccess check found %d finding(s)", len(findings))
    return findings


def check_role_trust_policies(iam_client) -> list[Finding]:
    """
    Scan all IAM roles for overly permissive trust policies that allow
    any principal (Principal: '*') to assume the role.
    """
    findings: list[Finding] = []

    try:
        roles = _paginate(iam_client, "list_roles", "Roles")
    except Exception as exc:
        logger.error("Failed to list roles: %s", exc)
        return findings

    for role in roles:
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # Trust policy is embedded in the role object — no extra API call needed
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        if isinstance(trust_policy, str):
            try:
                trust_policy = json.loads(trust_policy)
            except json.JSONDecodeError:
                continue

        if _trust_policy_allows_any_principal(trust_policy):
            findings.append(Finding(
                check_id="IAM-010",
                check_name="Overly Permissive Role Trust Policy",
                severity=Severity.CRITICAL,
                resource=role_arn,
                detail=(
                    f"Role '{role_name}' has a trust policy with Principal: '*', "
                    "allowing any AWS principal or unauthenticated entity to assume it."
                ),
                remediation=(
                    "Restrict the trust policy Principal to specific AWS account IDs, "
                    "IAM roles, or services. Never use Principal: '*' in trust policies."
                ),
                cis_control="",
            ))

    logger.info("Role trust policy check found %d finding(s)", len(findings))
    return findings


def check_inline_policies(iam_client) -> list[Finding]:
    """
    Detect inline policies on users, roles, and groups.
    Inline policies bypass managed policy controls and are harder to audit.
    """
    findings: list[Finding] = []

    # Users
    try:
        users = _paginate(iam_client, "list_users", "Users")
        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]
            inline = iam_client.list_user_policies(UserName=username)
            policy_names = inline.get("PolicyNames", [])
            if policy_names:
                findings.append(Finding(
                    check_id="IAM-011",
                    check_name="Inline Policy Detected",
                    severity=Severity.LOW,
                    resource=user_arn,
                    detail=(
                        f"User '{username}' has {len(policy_names)} inline "
                        f"policy(s): {', '.join(policy_names)}. Inline policies "
                        "are not reusable and harder to audit centrally."
                    ),
                    remediation=(
                        "Migrate inline policies to customer-managed policies. "
                        "Managed policies are versioned, reusable, and centrally auditable."
                    ),
                    cis_control="",
                ))
    except Exception as exc:
        logger.warning("Could not check user inline policies: %s", exc)

    # Roles
    try:
        roles = _paginate(iam_client, "list_roles", "Roles")
        for role in roles:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            inline = iam_client.list_role_policies(RoleName=role_name)
            policy_names = inline.get("PolicyNames", [])
            if policy_names:
                findings.append(Finding(
                    check_id="IAM-011",
                    check_name="Inline Policy Detected",
                    severity=Severity.LOW,
                    resource=role_arn,
                    detail=(
                        f"Role '{role_name}' has {len(policy_names)} inline "
                        f"policy(s): {', '.join(policy_names)}."
                    ),
                    remediation=(
                        "Migrate inline policies to customer-managed policies "
                        "for better auditability and reuse."
                    ),
                    cis_control="",
                ))
    except Exception as exc:
        logger.warning("Could not check role inline policies: %s", exc)

    # Groups
    try:
        groups = _paginate(iam_client, "list_groups", "Groups")
        for group in groups:
            group_name = group["GroupName"]
            group_arn = group["Arn"]
            inline = iam_client.list_group_policies(GroupName=group_name)
            policy_names = inline.get("PolicyNames", [])
            if policy_names:
                findings.append(Finding(
                    check_id="IAM-011",
                    check_name="Inline Policy Detected",
                    severity=Severity.LOW,
                    resource=group_arn,
                    detail=(
                        f"Group '{group_name}' has {len(policy_names)} inline "
                        f"policy(s): {', '.join(policy_names)}."
                    ),
                    remediation=(
                        "Migrate inline policies to customer-managed policies."
                    ),
                    cis_control="",
                ))
    except Exception as exc:
        logger.warning("Could not check group inline policies: %s", exc)

    logger.info("Inline policy check found %d finding(s)", len(findings))
    return findings


def run(session: boto3.Session) -> list[Finding]:
    """Entry point called by the engine."""
    iam = session.client("iam")
    findings: list[Finding] = []
    findings.extend(check_wildcard_permissions(iam))
    findings.extend(check_admin_access_attached(iam))
    findings.extend(check_role_trust_policies(iam))
    findings.extend(check_inline_policies(iam))
    return findings