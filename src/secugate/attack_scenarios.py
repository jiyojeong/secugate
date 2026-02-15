from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} JSON 루트는 object여야 합니다.")
    return data


def _load_rules(path: Path) -> dict[str, Any]:
    rules = _load_json(path)
    for key in ("normalize", "atomic_mappings", "scenarios"):
        if key not in rules or not isinstance(rules[key], list):
            raise ValueError(f"{path} 규칙에 '{key}' 리스트가 필요합니다.")
    return rules


def _default_rules_path() -> Path:
    return Path(__file__).resolve().parent / "rules" / "attack_mapping.json"


def _extract_failed_checks(checkov_json: dict[str, Any]) -> list[dict[str, Any]]:
    root = checkov_json.get("results")
    if not isinstance(root, dict):
        root = checkov_json

    failed = root.get("failed_checks") or []
    if not isinstance(failed, list):
        return []
    return [item for item in failed if isinstance(item, dict)]


def _match_capabilities(
    failed_checks: list[dict[str, Any]], normalize_rules: list[dict[str, Any]]
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    capabilities: dict[str, list[dict[str, Any]]] = defaultdict(list)
    matched_check_ids: set[str] = set()

    for finding in failed_checks:
        check_id = str(finding.get("check_id", "")).strip()
        if not check_id:
            continue

        for rule in normalize_rules:
            rule_ids = rule.get("check_ids") or []
            capability = rule.get("capability")
            if not capability or check_id not in rule_ids:
                continue

            matched_check_ids.add(check_id)
            capabilities[str(capability)].append(
                {
                    "check_id": check_id,
                    "resource": finding.get("resource"),
                    "file_path": finding.get("repo_file_path") or finding.get("file_path"),
                    "file_line_range": finding.get("file_line_range"),
                    "check_name": finding.get("check_name"),
                }
            )

    return capabilities, matched_check_ids


def _atomic_coverage(
    capabilities: dict[str, list[dict[str, Any]]], atomic_rules: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    by_atomic: dict[str, dict[str, Any]] = {}

    for rule in atomic_rules:
        capability = str(rule.get("capability", "")).strip()
        if not capability or capability not in capabilities:
            continue

        for atomic_id in rule.get("atomic_ids") or []:
            atomic_key = str(atomic_id)
            if not atomic_key:
                continue
            existing = by_atomic.get(atomic_key, {"atomic_id": atomic_key, "capabilities": []})
            if capability not in existing["capabilities"]:
                existing["capabilities"].append(capability)
            if "name" not in existing and rule.get("name"):
                existing["name"] = rule["name"]
            if "confidence" not in existing and rule.get("confidence"):
                existing["confidence"] = rule["confidence"]
            by_atomic[atomic_key] = existing

    return by_atomic


def _build_scenarios(
    capabilities: dict[str, list[dict[str, Any]]],
    scenarios: list[dict[str, Any]],
    check_id_counter: Counter[str],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    for scenario in scenarios:
        required_caps = [
            str(x) for x in (scenario.get("requires_capabilities") or []) if x
        ]
        required_checks = [str(x) for x in (scenario.get("requires_check_ids") or []) if x]

        if not required_caps and not required_checks:
            continue

        if required_caps and not all(cap in capabilities for cap in required_caps):
            continue

        if required_checks and not all(
            check_id in check_id_counter for check_id in required_checks
        ):
            continue

        cap_evidence_count = (
            sum(len(capabilities[cap]) for cap in required_caps) if required_caps else 0
        )
        check_evidence_count = (
            sum(check_id_counter[check_id] for check_id in required_checks)
            if required_checks
            else 0
        )
        evidence_count = max(cap_evidence_count, check_evidence_count)

        output.append(
            {
                "id": scenario.get("id"),
                "title": scenario.get("title"),
                "description": scenario.get("description"),
                "score": scenario.get("score", "medium"),
                "matched_capabilities": required_caps,
                "matched_check_ids": required_checks,
                "atomic_chain": scenario.get("atomic_chain") or [],
                "evidence_count": evidence_count,
            }
        )

    return output


def _line_range_text(value: Any) -> str:
    if isinstance(value, list) and len(value) == 2:
        return f"{value[0]}-{value[1]}"
    return "-"


def _render_markdown_report(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    lines: list[str] = []

    lines.append("# Attack Scenarios Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Failed findings: {summary.get('failed_findings', 0)}")
    lines.append(f"- Mapped findings: {summary.get('mapped_findings', 0)}")
    lines.append(f"- Capabilities: {summary.get('capabilities', 0)}")
    lines.append(f"- Atomic IDs: {summary.get('atomic_ids', 0)}")
    lines.append(f"- Scenarios: {summary.get('scenarios', 0)}")
    lines.append(f"- Unmapped check IDs: {summary.get('unmapped_check_ids', 0)}")
    lines.append("")

    lines.append("## Scenarios")
    lines.append("")
    scenarios = result.get("scenarios") or []
    if not scenarios:
        lines.append("- No matched scenarios")
    else:
        for scenario in scenarios:
            lines.append(
                f"### {scenario.get('title', scenario.get('id', 'unknown_scenario'))}"
            )
            lines.append("")
            lines.append(f"- ID: `{scenario.get('id', '-')}`")
            lines.append(f"- Score: `{scenario.get('score', '-')}`")
            lines.append(
                f"- Atomic chain: {', '.join(scenario.get('atomic_chain') or ['-'])}"
            )
            lines.append(
                f"- Matched capabilities: {', '.join(scenario.get('matched_capabilities') or ['-'])}"
            )
            lines.append(
                f"- Matched check IDs: {', '.join(scenario.get('matched_check_ids') or ['-'])}"
            )
            lines.append(f"- Evidence count: {scenario.get('evidence_count', 0)}")
            description = scenario.get("description")
            if description:
                lines.append(f"- Description: {description}")
            lines.append("")

    lines.append("## Capabilities")
    lines.append("")
    capabilities = result.get("capabilities") or []
    if not capabilities:
        lines.append("- No mapped capabilities")
    else:
        for cap in capabilities:
            lines.append(f"### `{cap.get('capability', '-')}`")
            lines.append("")
            lines.append(f"- Findings: {cap.get('finding_count', 0)}")

            checks = cap.get("checks") or {}
            if checks:
                check_summary = ", ".join(
                    f"{check_id}({count})"
                    for check_id, count in sorted(checks.items(), key=lambda x: x[0])
                )
                lines.append(f"- Checks: {check_summary}")
            else:
                lines.append("- Checks: -")

            evidence = cap.get("evidence") or []
            lines.append("- Evidence preview:")
            for item in evidence[:5]:
                lines.append(
                    f"  - `{item.get('check_id', '-')}` {item.get('resource', '-')} "
                    f"({item.get('file_path', '-')}:{_line_range_text(item.get('file_line_range'))})"
                )
            if len(evidence) > 5:
                lines.append(f"  - ... and {len(evidence) - 5} more")
            lines.append("")

    lines.append("## Unmapped Check IDs")
    lines.append("")
    unmapped = result.get("unmapped_check_ids") or []
    if not unmapped:
        lines.append("- None")
    else:
        for check_id in unmapped:
            lines.append(f"- `{check_id}`")
    lines.append("")
    return "\n".join(lines)


def generate_attack_scenarios(
    checkov_merged_json_path: Path,
    output_path: Path,
    rules_path: Path | None = None,
    markdown_output_path: Path | None = None,
) -> dict[str, Any]:
    checkov_json = _load_json(checkov_merged_json_path)
    rules = _load_rules(rules_path or _default_rules_path())

    failed_checks = _extract_failed_checks(checkov_json)
    capabilities, matched_check_ids = _match_capabilities(
        failed_checks, rules["normalize"]
    )

    failed_check_ids = [
        str(item.get("check_id", "")).strip()
        for item in failed_checks
        if str(item.get("check_id", "")).strip()
    ]
    check_id_counter = Counter(failed_check_ids)
    scenario_required_check_ids = {
        str(check_id).strip()
        for scenario in rules["scenarios"]
        for check_id in (scenario.get("requires_check_ids") or [])
        if str(check_id).strip()
    }
    scenario_matched_check_ids = {
        check_id for check_id in scenario_required_check_ids if check_id in check_id_counter
    }
    mapped_check_ids = matched_check_ids | scenario_matched_check_ids

    atomic = _atomic_coverage(capabilities, rules["atomic_mappings"])
    scenarios = _build_scenarios(capabilities, rules["scenarios"], check_id_counter)
    unmapped_check_ids = sorted(
        [check_id for check_id in check_id_counter if check_id not in mapped_check_ids]
    )
    mapped_findings = sum(
        count for check_id, count in check_id_counter.items() if check_id in mapped_check_ids
    )

    result: dict[str, Any] = {
        "version": 1,
        "source": str(checkov_merged_json_path),
        "rules": str((rules_path or _default_rules_path()).resolve()),
        "summary": {
            "failed_findings": len(failed_checks),
            "mapped_findings": mapped_findings,
            "capabilities": len(capabilities),
            "atomic_ids": len(atomic),
            "scenarios": len(scenarios),
            "unmapped_check_ids": len(unmapped_check_ids),
        },
        "capabilities": [
            {
                "capability": cap,
                "finding_count": len(items),
                "checks": dict(Counter(item["check_id"] for item in items)),
                "evidence": items,
            }
            for cap, items in sorted(capabilities.items())
        ],
        "atomic_coverage": sorted(atomic.values(), key=lambda x: x["atomic_id"]),
        "scenarios": scenarios,
        "unmapped_check_ids": unmapped_check_ids,
    }

    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if markdown_output_path is not None:
        markdown_output_path.write_text(
            _render_markdown_report(result),
            encoding="utf-8",
        )
    return result
