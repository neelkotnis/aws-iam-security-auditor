"""
reporters/csv_reporter.py
--------------------------
Writes a flat CSV report.
Output path: <output_dir>/<account_id>/iam_audit_<timestamp>.csv
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
    # Create account-specific subdirectory
    account_dir = os.path.join(output_dir, result.account_id)
    os.makedirs(account_dir, exist_ok=True)

    ts       = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"iam_audit_{ts}.csv"
    path     = os.path.join(account_dir, filename)

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for f in result.sorted_findings():
            writer.writerow({
                "check_id":            f.check_id,
                "check_name":          f.check_name,
                "severity":            f.severity.value,
                "account_id":          f.account_id,
                "region":              f.region,
                "resource":            f.resource,
                "cis_control":         f.cis_control,
                "compliance_controls": "; ".join(f.compliance_controls),
                "detail":              f.detail,
                "remediation":         f.remediation,
            })

    return path
