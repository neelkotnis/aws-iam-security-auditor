"""
checks/guardduty.py
-------------------
Checks:
  GD-001  GuardDuty not enabled in region              -> CRITICAL (CIS 4.16)
  GD-002  GuardDuty HIGH/CRITICAL findings unresolved  -> CRITICAL
"""

from __future__ import annotations

import logging

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)


def run(session: boto3.Session) -> list[Finding]:
    region = session.region_name or "us-east-1"
    gd     = session.client("guardduty", region_name=region)
    aid    = session.client("sts").get_caller_identity()["Account"]
    findings = []

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
    except Exception as e:
        logger.error("GD: list_detectors failed [%s]: %s", region, e)
        return findings

    if not detectors:
        findings.append(Finding(
            check_id="GD-001",
            check_name="GuardDuty Not Enabled",
            severity=Severity.CRITICAL,
            resource=f"arn:aws:guardduty:{region}:{aid}",
            account_id=aid,
            region=region,
            detail=f"GuardDuty is not enabled in {region}. Threat detection is inactive.",
            remediation=f"aws guardduty create-detector --enable --region {region}",
            cis_control=get_cis("GD-001"),
            compliance_controls=get_controls("GD-001"),
        ))
        return findings

    for did in detectors:
        try:
            det = gd.get_detector(DetectorId=did)
            if det.get("Status") != "ENABLED":
                findings.append(Finding(
                    check_id="GD-001",
                    check_name="GuardDuty Detector Disabled",
                    severity=Severity.CRITICAL,
                    resource=f"arn:aws:guardduty:{region}:{aid}:detector/{did}",
                    account_id=aid,
                    region=region,
                    detail=f"GuardDuty detector '{did}' exists but is not enabled.",
                    remediation=f"aws guardduty update-detector --detector-id {did} --enable",
                    cis_control=get_cis("GD-001"),
                    compliance_controls=get_controls("GD-001"),
                ))
                continue

            # Check for unresolved HIGH/CRITICAL findings (severity >= 7)
            resp = gd.list_findings(
                DetectorId=did,
                FindingCriteria={
                    "Criterion": {
                        "severity": {"Gte": 7},
                        "service.archived": {"Eq": ["false"]},
                    }
                },
                MaxResults=50,
            )
            fids = resp.get("FindingIds", [])
            if fids:
                details = gd.get_findings(DetectorId=did, FindingIds=fids[:10]).get("Findings", [])
                for gdf in details:
                    sev_num = gdf.get("Severity", 0)
                    sev = Severity.CRITICAL if sev_num >= 9 else Severity.HIGH
                    findings.append(Finding(
                        check_id="GD-002",
                        check_name="Unresolved GuardDuty Finding",
                        severity=sev,
                        resource=gdf.get("Arn", f"guardduty:{region}:{did}"),
                        account_id=aid,
                        region=region,
                        detail=(
                            f"GuardDuty finding: {gdf.get('Title', 'unknown')} "
                            f"(type: {gdf.get('Type', 'unknown')}, severity: {sev_num})."
                        ),
                        remediation="Investigate in the GuardDuty console. Archive once resolved.",
                        cis_control=get_cis("GD-002"),
                        compliance_controls=get_controls("GD-002"),
                    ))
        except Exception as e:
            logger.warning("GD: detector %s [%s]: %s", did, region, e)

    logger.info("GD [%s]: %d finding(s)", region, len(findings))
    return findings
