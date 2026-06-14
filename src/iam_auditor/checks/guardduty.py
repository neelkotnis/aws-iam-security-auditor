"""
checks/guardduty.py
-------------------
Checks:
  GD-001  GuardDuty not enabled in region              → CRITICAL
  GD-002  GuardDuty HIGH/CRITICAL findings unresolved  → CRITICAL
"""
from __future__ import annotations
import logging
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)


def check_guardduty_enabled(gd, account_id, region):
    findings = []
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            findings.append(Finding(
                check_id="GD-001", check_name="GuardDuty Not Enabled",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:guardduty:{region}:{account_id}",
                account_id=account_id, region=region,
                detail=f"GuardDuty is not enabled in region {region}. "
                       "Threat detection (cryptomining, credential exfiltration, C2) is inactive.",
                remediation=f"aws guardduty create-detector --enable --region {region}",
                cis_control=get_cis("GD-001"), compliance_controls=get_controls("GD-001")))
            return findings, []
        # Check each detector is actually enabled
        for did in detectors:
            det = gd.get_detector(DetectorId=did)
            if det.get("Status") != "ENABLED":
                findings.append(Finding(
                    check_id="GD-001", check_name="GuardDuty Detector Disabled",
                    severity=Severity.CRITICAL,
                    resource=f"arn:aws:guardduty:{region}:{account_id}:detector/{did}",
                    account_id=account_id, region=region,
                    detail=f"GuardDuty detector '{did}' exists but is not enabled.",
                    remediation=f"aws guardduty update-detector --detector-id {did} --enable",
                    cis_control=get_cis("GD-001"), compliance_controls=get_controls("GD-001")))
        return findings, detectors
    except Exception as e:
        logger.error("GD-001 failed [%s]: %s", region, e)
        return findings, []


def check_guardduty_findings(gd, account_id, region, detector_ids):
    findings = []
    for did in detector_ids:
        try:
            # Get HIGH and CRITICAL severity finding IDs (severity >= 7.0)
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
                        check_id="GD-002", check_name="Unresolved GuardDuty Finding",
                        severity=sev,
                        resource=gdf.get("Arn", f"guardduty:{region}:{did}"),
                        account_id=account_id, region=region,
                        detail=(f"GuardDuty finding: {gdf.get('Title', 'unknown')} "
                                f"(type: {gdf.get('Type', 'unknown')}, severity: {sev_num}). "
                                f"Description: {gdf.get('Description', '')[:200]}"),
                        remediation=("Investigate this GuardDuty finding in the AWS console. "
                                     "Archive it once resolved or if confirmed false positive."),
                        cis_control=get_cis("GD-002"), compliance_controls=get_controls("GD-002")))
                if len(fids) > 10:
                    findings.append(Finding(
                        check_id="GD-002", check_name="Multiple Unresolved GuardDuty Findings",
                        severity=Severity.CRITICAL,
                        resource=f"arn:aws:guardduty:{region}:{account_id}:detector/{did}",
                        account_id=account_id, region=region,
                        detail=f"{len(fids)} unresolved HIGH/CRITICAL GuardDuty findings in {region}. "
                               "Showing first 10 above. Review all in the GuardDuty console.",
                        remediation="Review and triage all findings in AWS GuardDuty console.",
                        cis_control=get_cis("GD-002"), compliance_controls=get_controls("GD-002")))
        except Exception as e:
            logger.warning("GD-002 detector %s [%s]: %s", did, region, e)
    logger.info("GD-002 [%s]: %d finding(s)", region, len(findings))
    return findings


def _run(ctx: ScanContext):
    gd = ctx.client("guardduty")
    aid, reg = ctx.account_id, ctx.region
    enabled_findings, detector_ids = check_guardduty_enabled(gd, aid, reg)
    unresolved = check_guardduty_findings(gd, aid, reg, detector_ids) if detector_ids else []
    return enabled_findings + unresolved


CHECKS: list = [
    ("GuardDuty Checks", "guardduty", False, _run),
]
