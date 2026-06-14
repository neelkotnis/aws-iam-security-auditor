"""
checks/ecr.py
-------------
Checks:
  ECR-001  ECR repository is public                              → HIGH
  ECR-002  ECR image scanning on push not enabled               → HIGH
  ECR-003  ECR repository has unresolved CRITICAL/HIGH findings  → HIGH
"""
from __future__ import annotations
import logging
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)


def _list_repos(ecr):
    try:
        paginator = ecr.get_paginator("describe_repositories")
        repos = []
        for page in paginator.paginate():
            repos.extend(page.get("repositories", []))
        return repos
    except Exception as e:
        logger.error("describe_repositories failed: %s", e)
        return []


def check_ecr_public(ecr, account_id, region):
    findings = []
    # Check ECR Public repos — separate service, only available in us-east-1
    # We detect repos in private ECR that have public access policies
    for repo in _list_repos(ecr):
        name = repo["repositoryName"]
        try:
            policy_resp = ecr.get_repository_policy(repositoryName=name)
            import json
            policy = json.loads(policy_resp.get("policyText", "{}"))
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                    findings.append(Finding(
                        check_id="ECR-001", check_name="ECR Repository Allows Public Access",
                        severity=Severity.HIGH,
                        resource=repo.get("repositoryArn", name),
                        account_id=account_id, region=region,
                        detail=(f"ECR repository '{name}' has a repository policy granting "
                                "Principal: '*' access. Images may be pulled by anyone."),
                        remediation=("Remove the public principal from the ECR repository policy. "
                                     "Use specific IAM principal ARNs for cross-account access."),
                        cis_control=get_cis("ECR-001"), compliance_controls=get_controls("ECR-001")))
                    break
        except ecr.exceptions.RepositoryPolicyNotFoundException:
            pass
        except Exception as e:
            logger.warning("ECR-001 repo %s: %s", name, e)
    logger.info("ECR-001 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_ecr_scan_on_push(ecr, account_id, region):
    findings = []
    for repo in _list_repos(ecr):
        name = repo["repositoryName"]
        scan_cfg = repo.get("imageScanningConfiguration", {})
        if not scan_cfg.get("scanOnPush", False):
            findings.append(Finding(
                check_id="ECR-002", check_name="ECR Image Scanning on Push Disabled",
                severity=Severity.HIGH,
                resource=repo.get("repositoryArn", name),
                account_id=account_id, region=region,
                detail=(f"ECR repository '{name}' does not scan images on push. "
                        "Vulnerable container images can be deployed without detection."),
                remediation=(f"aws ecr put-image-scanning-configuration "
                             f"--repository-name {name} "
                             f"--region {region} "
                             "--image-scanning-configuration scanOnPush=true"),
                cis_control=get_cis("ECR-002"), compliance_controls=get_controls("ECR-002")))
    logger.info("ECR-002 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_ecr_scan_findings(ecr, account_id, region):
    findings = []
    for repo in _list_repos(ecr):
        name = repo["repositoryName"]
        try:
            images = ecr.describe_images(repositoryName=name,
                                          filter={"tagStatus": "TAGGED"}).get("imageDetails", [])
            # Check the most recent image only to avoid rate limits
            if not images:
                continue
            latest = sorted(images, key=lambda i: i.get("imagePushedAt", ""), reverse=True)[0]
            digest = latest.get("imageDigest", "")
            try:
                scan = ecr.describe_image_scan_findings(
                    repositoryName=name,
                    imageId={"imageDigest": digest}
                )
                counts = (scan.get("imageScanFindings", {})
                              .get("findingSeverityCounts", {}))
                crit = counts.get("CRITICAL", 0)
                high = counts.get("HIGH", 0)
                if crit > 0 or high > 0:
                    findings.append(Finding(
                        check_id="ECR-003",
                        check_name="ECR Image Has CRITICAL/HIGH Vulnerabilities",
                        severity=Severity.HIGH,
                        resource=repo.get("repositoryArn", name),
                        account_id=account_id, region=region,
                        detail=(f"Latest image in '{name}' has {crit} CRITICAL and {high} HIGH "
                                f"CVEs. Image digest: {digest[:20]}..."),
                        remediation=("Review findings in ECR console and rebuild the image with "
                                     "updated base image and dependencies. Consider blocking "
                                     "deployment of images with CRITICAL findings via CI/CD."),
                        cis_control=get_cis("ECR-003"), compliance_controls=get_controls("ECR-003")))
            except ecr.exceptions.ScanNotFoundException:
                pass
        except Exception as e:
            logger.warning("ECR-003 repo %s: %s", name, e)
    logger.info("ECR-003 [%s]: %d finding(s)", region, len(findings))
    return findings


def _run(ctx: ScanContext):
    ecr = ctx.client("ecr")
    aid, reg = ctx.account_id, ctx.region
    return (check_ecr_public(ecr, aid, reg) +
            check_ecr_scan_on_push(ecr, aid, reg) +
            check_ecr_scan_findings(ecr, aid, reg))


CHECKS: list = [
    ("ECR Checks", "ecr", False, _run),
]
