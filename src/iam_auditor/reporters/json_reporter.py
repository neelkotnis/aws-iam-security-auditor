"""
reporters/json_reporter.py
--------------------------
Writes structured JSON report organised by account ID.
Output path: <output_dir>/<account_id>/iam_audit_<timestamp>.json
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from iam_auditor.models import AuditResult


def write(result: AuditResult, output_dir: str = ".") -> str:
    # Create account-specific subdirectory
    account_dir = os.path.join(output_dir, result.account_id)
    os.makedirs(account_dir, exist_ok=True)

    ts       = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"iam_audit_{ts}.json"
    path     = os.path.join(account_dir, filename)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2)

    return path
