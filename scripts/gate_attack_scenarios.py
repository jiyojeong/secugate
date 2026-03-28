#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail CI when scenario outputs or finding severities violate security gates."
    )
    parser.add_argument(
        "--input",
        default="artifacts/iac_graph_checkov_paths.json",
        help="Path to scenario output JSON. Supports attack_scenarios.json or iac_graph_checkov_paths.json.",
    )
    parser.add_argument(
        "--checkov-merged",
        default="artifacts/checkov_merged.json",
        help="Path to merged Checkov results used for finding severity gates.",
    )
    parser.add_argument(
        "--checkov-fail-condition",
        default="src/secugate/rules/checkov_fail_condition.json",
        help="Path to checkov_fail_condition.json for canonical severity mapping.",
    )
    parser.add_argument(
        "--fail-on-score",
        default="high",
        help="Comma-separated scenario scores that should fail (e.g. high,critical)",
    )
    parser.add_argument(
        "--fail-on-any-scenario",
        action="store_true",
        help="Fail when any attack scenario is generated regardless of score.",
    )
    parser.add_argument(
        "--fail-on-finding-severity",
        default="",
        help="Comma-separated finding severities that should fail (e.g. critical,high).",
    )
    parser.add_argument(
        "--max-unmapped-check-ids",
        type=int,
        default=0,
        help="Maximum allowed unmapped check IDs before failing.",
    )
    parser.add_argument(
        "--deny-check-ids",
        default="",
        help="Comma-separated check IDs that must never appear in unmapped_check_ids.",
    )
    return parser.parse_args()


def _load_check_severity_index(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    checks = data.get("checks") or []
    if not isinstance(checks, list):
        return {}

    out: dict[str, str] = {}
    for item in checks:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id") or "").strip()
        severity = str(item.get("Severity") or "").strip()
        if check_id and severity:
            out[check_id] = severity
    return out


def _load_failed_check_ids(path: Path) -> list[str]:
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    root = data.get("results", data)
    failed = root.get("failed_checks") or []
    if not isinstance(failed, list):
        return []

    out: list[str] = []
    for item in failed:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id") or "").strip()
        if check_id:
            out.append(check_id)
    return out


def _extract_blocking_scenarios(data: dict[str, object], fail_scores: set[str]) -> list[str]:
    scenarios = data.get("scenarios")
    if isinstance(scenarios, list):
        return [
            f"{s.get('id')}({s.get('score')})"
            for s in scenarios
            if isinstance(s, dict)
            and str(s.get("score", "")).strip().lower() in fail_scores
        ]

    validated_paths = data.get("dfs_all_paths_validated")
    if isinstance(validated_paths, list):
        out: list[str] = []
        for item in validated_paths:
            if not isinstance(item, dict):
                continue
            out.append(
                f"{item.get('path_category', 'path')}:{item.get('from', '-')}"
                f"->{item.get('to', '-')}"
            )
        return out

    return []


def _extract_any_scenarios(data: dict[str, object]) -> list[str]:
    scenarios = data.get("scenarios")
    if isinstance(scenarios, list):
        return [
            f"{s.get('id')}({s.get('score')})"
            for s in scenarios
            if isinstance(s, dict)
        ]

    validated_paths = data.get("dfs_all_paths_validated")
    if isinstance(validated_paths, list):
        out: list[str] = []
        for item in validated_paths:
            if not isinstance(item, dict):
                continue
            out.append(
                f"{item.get('path_category', 'path')}:{item.get('from', '-')}"
                f"->{item.get('to', '-')}"
            )
        return out

    return []


def _format_preview(values: list[str], limit: int = 5) -> str:
    if not values:
        return "-"
    if len(values) <= limit:
        return ", ".join(values)
    return ", ".join(values[:limit]) + f" 외 {len(values) - limit}개"


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"FAIL: missing input file: {input_path}")
        return 1

    data = json.loads(input_path.read_text(encoding="utf-8"))
    summary = data.get("summary") or {}
    unmapped_ids = data.get("unmapped_check_ids") or []

    fail_scores = {x.strip().lower() for x in args.fail_on_score.split(",") if x.strip()}
    fail_finding_severities = {
        x.strip().upper() for x in args.fail_on_finding_severity.split(",") if x.strip()
    }
    deny_ids = {x.strip() for x in args.deny_check_ids.split(",") if x.strip()}

    failing_scenarios = (
        _extract_any_scenarios(data)
        if args.fail_on_any_scenario
        else _extract_blocking_scenarios(data, fail_scores)
    )
    if isinstance(summary, dict):
        unmapped_count = int(summary.get("unmapped_check_ids", len(unmapped_ids)))
    else:
        unmapped_count = len(unmapped_ids)
    denied_unmapped = sorted(deny_ids.intersection(set(unmapped_ids)))
    failed_check_ids = _load_failed_check_ids(Path(args.checkov_merged))
    severity_by_check = _load_check_severity_index(Path(args.checkov_fail_condition))
    finding_severity_counts = Counter(
        severity_by_check[check_id]
        for check_id in failed_check_ids
        if check_id in severity_by_check
    )
    blocked_finding_severities = {
        severity: count
        for severity, count in finding_severity_counts.items()
        if severity.upper() in fail_finding_severities
    }
    blocked_check_ids = sorted(
        {
            check_id
            for check_id in failed_check_ids
            if severity_by_check.get(check_id, "").upper() in fail_finding_severities
        }
    )

    failed = False

    if failing_scenarios:
        failed = True
        print(f"FAIL: blocking scenarios found ({len(failing_scenarios)})")
        print(f"  - {_format_preview(failing_scenarios)}")

    if blocked_finding_severities:
        failed = True
        severity_text = ", ".join(
            f"{key}={value}" for key, value in sorted(blocked_finding_severities.items())
        )
        print(f"FAIL: blocking finding severities found ({severity_text})")
        print(f"  - check_ids: {_format_preview(blocked_check_ids)}")

    if unmapped_count > args.max_unmapped_check_ids:
        failed = True
        print(
            "FAIL: unmapped_check_ids exceeded:",
            f"{unmapped_count} > {args.max_unmapped_check_ids}",
        )

    if denied_unmapped:
        failed = True
        print("FAIL: denied unmapped check IDs found:")
        print(f"  - {_format_preview(denied_unmapped)}")

    if failed:
        return 1

    if finding_severity_counts:
        severity_text = ", ".join(
            f"{key}={value}" for key, value in sorted(finding_severity_counts.items())
        )
        print(f"INFO: finding severity counts: {severity_text}")
    print("PASS: gate conditions satisfied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
