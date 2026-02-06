# src/secgate/parsers/checkov.py
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..models import Finding

logger = logging.getLogger(__name__)


def _pick(obj: dict[str, Any], *keys: str) -> Any:
    """Return first non-empty value among candidate keys."""
    for k in keys:
        v = obj.get(k)
        if v not in (None, ""):
            return v
    return None


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default


def _load_json(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # Some tools might output non-utf8; fall back defensively
        text = path.read_text(encoding="utf-8", errors="replace")

    try:
        data = json.loads(text) #디버깅
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"Unexpected JSON root type in {path}: {type(data).__name__}")
    return data


def parse_checkov_json(path: Path, framework: str) -> list[Finding]:
    """
    Robust parser for Checkov JSON outputs.

    Supports common format variants:
      - {"results": {"failed_checks": [...], "passed_checks": [...], "skipped_checks": [...]}}
      - {"failed_checks": [...], "passed_checks": [...], "skipped_checks": [...]}

    Extracts only stable, minimal fields:
      - check_id, check_name, resource, file_path, file_line_range, severity, guideline
    """
    data = _load_json(path)

    # Some versions nest under "results", some don't.
    results = data.get("results")
    if isinstance(results, dict):
        root = results
    else:
        root = data

    findings: list[Finding] = []

    buckets = [
        ("failed_checks", "FAIL"),
        ("passed_checks", "PASS"),
        ("skipped_checks", "SKIP"),
    ]

    for bucket_name, result in buckets:
        checks = root.get(bucket_name) or []
        if not isinstance(checks, list):
            logger.warning(
                "Checkov JSON %s bucket %s is not a list (got %s). Skipping.",
                path,
                bucket_name,
                type(checks).__name__,
            )
            continue

        for c in checks:
            if not isinstance(c, dict):
                continue

            check_id = _safe_str(_pick(c, "check_id", "checkID"), default="UNKNOWN")
            check_name = _safe_str(_pick(c, "check_name", "name"), default="")

            # Resource key varies by framework / output mode
            resource = _safe_str(_pick(c, "resource", "resource_name", "entity"), default="UNKNOWN_RESOURCE")

            file_path = _pick(c, "file_path", "file", "file_abs_path")
            file_line_range = _pick(c, "file_line_range", "file_line", "line_range")

            severity = _pick(c, "severity")
            guideline = _pick(c, "guideline", "guideline_url")

            findings.append(
                Finding(
                    framework=str(framework),
                    check_id=check_id,
                    check_name=_safe_str(check_name),
                    result=result,  # type: ignore[arg-type]
                    resource=resource,
                    file_path=_safe_str(file_path) if file_path is not None else None,
                    file_line_range=_safe_str(file_line_range) if file_line_range is not None else None,
                    severity=_safe_str(severity) if severity is not None else None,
                    guideline=_safe_str(guideline) if guideline is not None else None,
                )
            )

    return findings
