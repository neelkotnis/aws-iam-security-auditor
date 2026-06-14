"""
reporters/csv_reporter.py
--------------------------
Writes a flat CSV audit report — one row per finding.
Columns include all Finding fields plus compliance framework controls.
Designed for import into Excel, Google Sheets, Jira, or compliance tools.
"""
from __future__ import annotations
import csv
import os
from datetime import datetime
from iam_auditor.models import AuditResult

COLUMNS = [
    "check_id", "check_name", "severity", "account_id", "region",
    "resource", "cis_control", "compliance_controls", "detail", "remediation",
]


def write(result: AuditResult, output_dir: str = ".") -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"iam_audit_{result.account_id}_{ts}.csv"
    path = os.path.join(output_dir, filename)

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for finding in result.sorted_findings():
            writer.writerow({
                "check_id":            finding.check_id,
                "check_name":          finding.check_name,
                "severity":            finding.severity.value,
                "account_id":          finding.account_id,
                "region":              finding.region,
                "resource":            finding.resource,
                "cis_control":         finding.cis_control,
                "compliance_controls": "; ".join(finding.compliance_controls),
                "detail":              finding.detail,
                "remediation":         finding.remediation,
            })

    return path
