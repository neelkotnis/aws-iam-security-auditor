"""
checks/securityhub.py
---------------------
Checks:
  SH-001  Security Hub not enabled in region           → HIGH
"""
from __future__ import annotations
import logging
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)


def check_securityhub_enabled(sh, account_id, region):
    findings = []
    try:
        hub = sh.describe_hub()
        # If we get here, Security Hub is enabled
        # Check if at least one standard is enabled
        standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
        active = [s for s in standards if s.get("StandardsStatus") == "READY"]
        if not active:
            findings.append(Finding(
                check_id="SH-001", check_name="Security Hub Has No Active Standards",
                severity=Severity.HIGH,
                resource=hub.get("HubArn", f"securityhub:{region}:{account_id}"),
                account_id=account_id, region=region,
                detail=f"Security Hub is enabled in {region} but no security standards are active. "
                       "Without standards, automated control checks are not running.",
                remediation=("Enable CIS AWS Foundations Benchmark v1.4 or AWS Foundational Security "
                             "Best Practices standard in Security Hub."),
                cis_control=get_cis("SH-001"), compliance_controls=get_controls("SH-001")))
    except sh.exceptions.InvalidAccessException:
        findings.append(Finding(
            check_id="SH-001", check_name="Security Hub Not Enabled",
            severity=Severity.HIGH,
            resource=f"arn:aws:securityhub:{region}:{account_id}:hub/default",
            account_id=account_id, region=region,
            detail=f"Security Hub is not enabled in region {region}. "
                   "Centralised security findings aggregation is inactive.",
            remediation=f"aws securityhub enable-security-hub --region {region} "
                        "--enable-default-standards",
            cis_control=get_cis("SH-001"), compliance_controls=get_controls("SH-001")))
    except Exception as e:
        logger.warning("SH-001 [%s]: %s", region, e)
    return findings


def _run(ctx: ScanContext):
    sh = ctx.client("securityhub")
    return check_securityhub_enabled(sh, ctx.account_id, ctx.region)


CHECKS: list = [
    ("Security Hub Checks", "securityhub", False, _run),
]
