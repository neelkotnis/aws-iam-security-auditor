"""
reporters/json_reporter.py
--------------------------
Writes the AuditResult to a JSON file.

Output file:  <output_dir>/iam_audit_<account_id>_<timestamp>.json

The JSON structure mirrors AuditResult.to_dict():
  {
    "account_id": "...",
    "run_at": "...",
    "summary": { "LOW": N, "MEDIUM": N, "HIGH": N, "CRITICAL": N },
    "total_findings": N,
    "findings": [ { ... }, ... ]
  }
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path

from iam_auditor.models import AuditResult

logger = logging.getLogger(__name__)


def _build_filename(account_id: str, run_at: str) -> str:
    """
    Derive a safe, unique filename from the account ID and run timestamp.
    run_at is ISO-8601; colons are replaced so it's valid on all filesystems.
    """
    # "2024-06-01T12:34:56Z" → "2024-06-01T12-34-56Z"
    safe_ts = run_at.replace(":", "-")
    return f"iam_audit_{account_id}_{safe_ts}.json"


def write(result: AuditResult, output_dir: str = ".") -> str:
    """
    Serialise result to JSON and write to output_dir.

    Args:
        result:     The completed AuditResult.
        output_dir: Directory to write the file into (created if missing).

    Returns:
        The absolute path of the written file.

    Raises:
        OSError: If the file cannot be written.
    """
    out_path = Path(output_dir).expanduser().resolve()

    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("Could not create output directory '%s': %s", out_path, exc)
        raise

    filename = _build_filename(result.account_id, result.run_at)
    filepath = out_path / filename

    try:
        with filepath.open("w", encoding="utf-8") as fh:
            fh.write(result.to_json())
            fh.write("\n")  # POSIX: files end with a newline
    except OSError as exc:
        logger.error("Could not write report to '%s': %s", filepath, exc)
        raise

    logger.info("JSON report written to %s", filepath)
    return str(filepath)
