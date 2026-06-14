"""
compliance.py
-------------
Loads the compliance_map.yaml file and provides a single helper
that returns formatted control IDs for a given check_id.

Usage inside any check:
    from iam_auditor.compliance import get_controls
    controls = get_controls("IAM-001")
    # → ["CIS 1.10", "NIST IA-2", "NIST IA-5", "SOC2 CC6.1", "ISO A.9.4.2"]
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_MAP_PATH = Path(__file__).parent / "data" / "compliance_map.yaml"


@lru_cache(maxsize=1)
def _load_map() -> dict:
    """Load and cache the compliance YAML. Falls back gracefully if missing."""
    try:
        import yaml  # PyYAML — listed in requirements
        with open(_MAP_PATH) as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logger.warning("compliance_map.yaml not found at %s", _MAP_PATH)
        return {}
    except Exception as exc:
        logger.warning("Failed to load compliance map: %s", exc)
        return {}


def get_controls(check_id: str) -> list[str]:
    """
    Return a flat list of formatted control references for a check ID.

    Example:
        get_controls("IAM-001")
        → ["CIS 1.10", "NIST IA-2", "NIST IA-5", "SOC2 CC6.1", "ISO A.9.4.2"]
    """
    mapping = _load_map()
    entry = mapping.get(check_id, {})
    controls: list[str] = []

    for cis in entry.get("cis", []):
        controls.append(cis)
    for nist in entry.get("nist", []):
        controls.append(f"NIST {nist}")
    for soc2 in entry.get("soc2", []):
        controls.append(f"SOC2 {soc2}")
    for iso in entry.get("iso27001", []):
        controls.append(f"ISO {iso}")

    return controls


def get_cis(check_id: str) -> str:
    """Return just the first CIS control string, or empty string."""
    mapping = _load_map()
    cis_list = mapping.get(check_id, {}).get("cis", [])
    return cis_list[0] if cis_list else ""
