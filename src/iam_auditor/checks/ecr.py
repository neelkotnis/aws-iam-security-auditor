"""
checks/ecr.py
-------------
Checks:
  ECR-001  ECR repository allows public access          -> HIGH
  ECR-002  Scan-on-push not enabled                     -> HIGH
  ECR-003  Image has CRITICAL/HIGH CVEs                 -> HIGH
"""

from __future__ import annotations

import json
import logging

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)


def run(session: boto3.Session) -> list[Finding]:
    region = session.region_name or "us-east-1"
    ecr    = session.client("ecr", region_name=region)
    aid    = session.client("sts").get_caller_identity()["Account"]
    findings = []

    try:
        paginator = ecr.get_paginator("describe_repositories")
        repos = []
        for page in paginator.paginate():
            repos.extend(page.get("repositories", []))
    except Exception as e:
        logger.error("ECR: describe_repositories failed [%s]: %s", region, e)
        return findings

    for repo in repos:
        name = repo["repositoryName"]
        rarn = repo.get("repositoryArn", name)

        # ECR-001: public access via policy
        try:
            policy = json.loads(ecr.get_repository_policy(repositoryName=name).get("policyText", "{}"))
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                    findings.append(Finding(
                        check_id="ECR-001",
                        check_name="ECR Repository Allows Public Access",
                        severity=Severity.HIGH,
                        resource=rarn,
                        account_id=aid, region=region,
                        detail=f"ECR repository '{name}' has a policy granting Principal: '*' access.",
                        remediation="Remove the public principal from the ECR repository policy.",
                        cis_control=get_cis("ECR-001"),
                        compliance_controls=get_controls("ECR-001"),
                    ))
                    break
        except Exception as e:
            if "RepositoryPolicyNotFoundException" not in str(e):
                logger.warning("ECR-001 repo %s: %s", name, e)

        # ECR-002: scan on push
        if not repo.get("imageScanningConfiguration", {}).get("scanOnPush", False):
            findings.append(Finding(
                check_id="ECR-002",
                check_name="ECR Image Scanning on Push Disabled",
                severity=Severity.HIGH,
                resource=rarn,
                account_id=aid, region=region,
                detail=f"ECR repository '{name}' does not scan images on push.",
                remediation=(
                    f"aws ecr put-image-scanning-configuration "
                    f"--repository-name {name} --region {region} "
                    "--image-scanning-configuration scanOnPush=true"
                ),
                cis_control=get_cis("ECR-002"),
                compliance_controls=get_controls("ECR-002"),
            ))

        # ECR-003: CVE findings on latest image
        try:
            images = ecr.describe_images(
                repositoryName=name,
                filter={"tagStatus": "TAGGED"}
            ).get("imageDetails", [])
            if images:
                latest = sorted(images, key=lambda i: str(i.get("imagePushedAt", "")), reverse=True)[0]
                digest = latest.get("imageDigest", "")
                try:
                    scan = ecr.describe_image_scan_findings(
                        repositoryName=name, imageId={"imageDigest": digest}
                    )
                    counts = scan.get("imageScanFindings", {}).get("findingSeverityCounts", {})
                    crit = counts.get("CRITICAL", 0)
                    high = counts.get("HIGH", 0)
                    if crit > 0 or high > 0:
                        findings.append(Finding(
                            check_id="ECR-003",
                            check_name="ECR Image Has CRITICAL/HIGH Vulnerabilities",
                            severity=Severity.HIGH,
                            resource=rarn,
                            account_id=aid, region=region,
                            detail=f"Latest image in '{name}' has {crit} CRITICAL and {high} HIGH CVEs.",
                            remediation="Rebuild the image with updated base image and dependencies.",
                            cis_control=get_cis("ECR-003"),
                            compliance_controls=get_controls("ECR-003"),
                        ))
                except Exception:
                    pass
        except Exception as e:
            logger.warning("ECR-003 repo %s: %s", name, e)

    logger.info("ECR [%s]: %d finding(s)", region, len(findings))
    return findings
