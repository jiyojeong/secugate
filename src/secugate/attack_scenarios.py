from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FindingEvidence:
    check_id: str
    resource: Any
    file_path: Any
    file_line_range: Any
    check_name: Any


@dataclass(frozen=True)
class NormalizeRule:
    capability: str
    check_ids: set[str]


@dataclass(frozen=True)
class AtomicMappingRule:
    capability: str
    atomic_ids: list[str]
    name: str | None
    confidence: Any


@dataclass(frozen=True)
class ScenarioRule:
    scenario_id: str
    title: str | None
    description: str | None
    score: str
    requires_capabilities: list[str]
    requires_check_ids: list[str]
    atomic_chain: list[str]


@dataclass(frozen=True)
class AttackRules:
    normalize: list[NormalizeRule]
    atomic_mappings: list[AtomicMappingRule]
    scenarios: list[ScenarioRule]


def _parse_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} JSON 루트는 object여야 합니다.")
    return data


def _parse_normalize_rules(raw_rules: list[dict[str, Any]]) -> list[NormalizeRule]:
    normalized: list[NormalizeRule] = []
    for raw in raw_rules:
        capability = str(raw.get("capability", "")).strip()
        if not capability:
            continue
        check_ids = {
            str(check_id).strip()
            for check_id in (raw.get("check_ids") or [])
            if str(check_id).strip()
        }
        if not check_ids:
            continue
        normalized.append(NormalizeRule(capability=capability, check_ids=check_ids))
    return normalized


def _parse_atomic_mapping_rules(raw_rules: list[dict[str, Any]]) -> list[AtomicMappingRule]:
    parsed: list[AtomicMappingRule] = []
    for raw in raw_rules:
        capability = str(raw.get("capability", "")).strip()
        if not capability:
            continue
        atomic_ids = [
            str(atomic_id).strip()
            for atomic_id in (raw.get("atomic_ids") or [])
            if str(atomic_id).strip()
        ]
        if not atomic_ids:
            continue
        parsed.append(
            AtomicMappingRule(
                capability=capability,
                atomic_ids=atomic_ids,
                name=raw.get("name"),
                confidence=raw.get("confidence"),
            )
        )
    return parsed


def _parse_scenario_rules(raw_scenarios: list[dict[str, Any]]) -> list[ScenarioRule]:
    parsed: list[ScenarioRule] = []
    for raw in raw_scenarios:
        scenario_id = str(raw.get("id", "")).strip()
        if not scenario_id:
            continue
        parsed.append(
            ScenarioRule(
                scenario_id=scenario_id,
                title=raw.get("title"),
                description=raw.get("description"),
                score=str(raw.get("score", "medium")),
                requires_capabilities=[
                    str(cap).strip()
                    for cap in (raw.get("requires_capabilities") or [])
                    if str(cap).strip()
                ],
                requires_check_ids=[
                    str(check_id).strip()
                    for check_id in (raw.get("requires_check_ids") or [])
                    if str(check_id).strip()
                ],
                atomic_chain=[
                    str(atomic_id).strip()
                    for atomic_id in (raw.get("atomic_chain") or [])
                    if str(atomic_id).strip()
                ],
            )
        )
    return parsed


def _load_attack_rules(path: Path) -> AttackRules:
    raw = _parse_json_object(path)
    for key in ("normalize", "atomic_mappings", "scenarios"):
        if key not in raw or not isinstance(raw[key], list):
            raise ValueError(f"{path} 규칙에 '{key}' 리스트가 필요합니다.")

    rules = AttackRules(
        normalize=_parse_normalize_rules(raw["normalize"]),
        atomic_mappings=_parse_atomic_mapping_rules(raw["atomic_mappings"]),
        scenarios=_parse_scenario_rules(raw["scenarios"]),
    )
    logger.debug(
        "Loaded rules: normalize=%d atomic_mappings=%d scenarios=%d",
        len(rules.normalize),
        len(rules.atomic_mappings),
        len(rules.scenarios),
    )
    return rules


def _default_rules_path() -> Path:
    return Path(__file__).resolve().parent / "rules" / "attack_mapping.json"


def _extract_failed_findings(checkov_json: dict[str, Any]) -> list[dict[str, Any]]:
    root = checkov_json.get("results")
    if not isinstance(root, dict):
        root = checkov_json

    failed = root.get("failed_checks") or []
    if not isinstance(failed, list):
        return []

    findings = [item for item in failed if isinstance(item, dict)]
    logger.debug("Extracted failed findings: %d", len(findings))
    return findings


def _map_findings_to_capabilities(
    failed_findings: list[dict[str, Any]], normalize_rules: list[NormalizeRule]
) -> tuple[dict[str, list[FindingEvidence]], set[str]]:
    capabilities: dict[str, list[FindingEvidence]] = defaultdict(list)
    matched_check_ids: set[str] = set()

    for finding in failed_findings:
        check_id = str(finding.get("check_id", "")).strip()
        if not check_id:
            continue

        for rule in normalize_rules:
            if check_id not in rule.check_ids:
                continue

            matched_check_ids.add(check_id)
            capabilities[rule.capability].append(
                FindingEvidence(
                    check_id=check_id,
                    resource=finding.get("resource"),
                    file_path=finding.get("repo_file_path") or finding.get("file_path"),
                    file_line_range=finding.get("file_line_range"),
                    check_name=finding.get("check_name"),
                )
            )

    logger.debug(
        "Mapped capabilities: capabilities=%d matched_check_ids=%d",
        len(capabilities),
        len(matched_check_ids),
    )
    return capabilities, matched_check_ids


def _build_atomic_coverage(
    capabilities: dict[str, list[FindingEvidence]], atomic_rules: list[AtomicMappingRule]
) -> dict[str, dict[str, Any]]:
    by_atomic: dict[str, dict[str, Any]] = {}

    for rule in atomic_rules:
        if rule.capability not in capabilities:
            continue

        for atomic_id in rule.atomic_ids:
            existing = by_atomic.get(atomic_id, {"atomic_id": atomic_id, "capabilities": []})
            if rule.capability not in existing["capabilities"]:
                existing["capabilities"].append(rule.capability)
            if "name" not in existing and rule.name:
                existing["name"] = rule.name
            if "confidence" not in existing and rule.confidence:
                existing["confidence"] = rule.confidence
            by_atomic[atomic_id] = existing

    logger.debug("Built atomic coverage: %d", len(by_atomic))
    return by_atomic


def _evaluate_scenario_matches(
    capabilities: dict[str, list[FindingEvidence]],
    scenario_rules: list[ScenarioRule],
    check_id_counter: Counter[str],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    for scenario in scenario_rules:
        if not scenario.requires_capabilities and not scenario.requires_check_ids:
            continue

        if scenario.requires_capabilities and not all(
            cap in capabilities for cap in scenario.requires_capabilities
        ):
            continue

        if scenario.requires_check_ids and not all(
            check_id in check_id_counter for check_id in scenario.requires_check_ids
        ):
            continue

        cap_evidence_count = (
            sum(len(capabilities[cap]) for cap in scenario.requires_capabilities)
            if scenario.requires_capabilities
            else 0
        )
        check_evidence_count = (
            sum(check_id_counter[check_id] for check_id in scenario.requires_check_ids)
            if scenario.requires_check_ids
            else 0
        )
        evidence_count = max(cap_evidence_count, check_evidence_count)

        output.append(
            {
                "id": scenario.scenario_id,
                "title": scenario.title,
                "description": scenario.description,
                "score": scenario.score,
                "matched_capabilities": scenario.requires_capabilities,
                "matched_check_ids": scenario.requires_check_ids,
                "atomic_chain": scenario.atomic_chain,
                "evidence_count": evidence_count,
            }
        )

    logger.debug("Matched scenarios: %d", len(output))
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
    logger.debug("Starting attack scenario generation: source=%s", checkov_merged_json_path)

    checkov_json = _parse_json_object(checkov_merged_json_path)
    loaded_rules_path = rules_path or _default_rules_path()
    rules = _load_attack_rules(loaded_rules_path)

    failed_findings = _extract_failed_findings(checkov_json)
    capabilities, matched_check_ids = _map_findings_to_capabilities(
        failed_findings, rules.normalize
    )

    failed_check_ids = [
        str(item.get("check_id", "")).strip()
        for item in failed_findings
        if str(item.get("check_id", "")).strip()
    ]
    check_id_counter = Counter(failed_check_ids)
    scenario_required_check_ids = {
        check_id
        for scenario in rules.scenarios
        for check_id in scenario.requires_check_ids
    }
    scenario_matched_check_ids = {
        check_id for check_id in scenario_required_check_ids if check_id in check_id_counter
    }
    mapped_check_ids = matched_check_ids | scenario_matched_check_ids

    atomic_coverage = _build_atomic_coverage(capabilities, rules.atomic_mappings)
    scenarios = _evaluate_scenario_matches(capabilities, rules.scenarios, check_id_counter)
    unmapped_check_ids = sorted(
        [check_id for check_id in check_id_counter if check_id not in mapped_check_ids]
    )
    mapped_findings = sum(
        count for check_id, count in check_id_counter.items() if check_id in mapped_check_ids
    )

    result: dict[str, Any] = {
        "version": 1,
        "source": str(checkov_merged_json_path),
        "rules": str(loaded_rules_path.resolve()),
        "summary": {
            "failed_findings": len(failed_findings),
            "mapped_findings": mapped_findings,
            "capabilities": len(capabilities),
            "atomic_ids": len(atomic_coverage),
            "scenarios": len(scenarios),
            "unmapped_check_ids": len(unmapped_check_ids),
        },
        "capabilities": [
            {
                "capability": capability,
                "finding_count": len(evidence_items),
                "checks": dict(Counter(item.check_id for item in evidence_items)),
                "evidence": [
                    {
                        "check_id": item.check_id,
                        "resource": item.resource,
                        "file_path": item.file_path,
                        "file_line_range": item.file_line_range,
                        "check_name": item.check_name,
                    }
                    for item in evidence_items
                ],
            }
            for capability, evidence_items in sorted(capabilities.items())
        ],
        "atomic_coverage": sorted(atomic_coverage.values(), key=lambda x: x["atomic_id"]),
        "scenarios": scenarios,
        "unmapped_check_ids": unmapped_check_ids,
    }

    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if markdown_output_path is not None:
        markdown_output_path.write_text(
            _render_markdown_report(result),
            encoding="utf-8",
        )

    logger.debug(
        "Attack scenario generation completed: failed=%d mapped=%d scenarios=%d",
        result["summary"]["failed_findings"],
        result["summary"]["mapped_findings"],
        result["summary"]["scenarios"],
    )
    return result
