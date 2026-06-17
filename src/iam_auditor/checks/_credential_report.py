"""
checks/_credential_report.py
-----------------------------
Shared, cached IAM credential report fetcher.

Both mfa.py and unused_users.py need the same credential report CSV.
Previously each called generate_credential_report() + get_credential_report()
independently, doubling a full-account API call and CSV parse.

This module fetches it once per process and caches the parsed rows.
"""

from __future__ import annotations

import csv
import logging
import time
from io import StringIO

logger = logging.getLogger(__name__)

_cache: dict[str, list[dict]] = {}


def get_credential_report_rows(iam_client) -> list[dict]:
    """
    Return parsed credential report rows, generating a fresh report only
    if one hasn't already been fetched in this process.

    AWS credential reports are at most 4 hours stale anyway, so reusing
    one fetched a few seconds earlier within the same scan is safe.
    """
    cache_key = id(iam_client)  # cache per-client (per-session), not globally
    if cache_key in _cache:
        logger.debug("Using cached credential report")
        return _cache[cache_key]

    try:
        iam_client.generate_credential_report()
        # AWS may need a moment to generate the report on first call
        for _ in range(5):
            try:
                response = iam_client.get_credential_report()
                break
            except iam_client.exceptions.CredentialReportNotPresentException:
                time.sleep(1)
        else:
            response = iam_client.get_credential_report()

        report_csv = response["Content"].decode("utf-8")
        rows = list(csv.DictReader(StringIO(report_csv)))
        _cache[cache_key] = rows
        logger.debug("Fetched and cached credential report (%d rows)", len(rows))
        return rows
    except Exception as exc:
        logger.error("Failed to retrieve credential report: %s", exc)
        return []
