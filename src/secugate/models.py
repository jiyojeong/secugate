import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """Checkov 파서가 반환하는 공통 파인딩 DTO."""

    framework: str
    check_id: str
    check_name: str | None
    result: str
    severity: str | None
    resource: str | None
    resource_address: str | None
    description: str | None
    details: Any
    vulnerability_details: Any
    entity_tags: Any
    evaluations: Any
    breadcrumbs: Any
    file_abs_path: str | None
    repo_file_path: str | None
    file_path: str | None
    file_line_range: Any
    code_block: Any
    guideline: str | None
    check_result: dict[str, Any] | None


@dataclass
class NormalizedFinding:
    """파이프라인 출력용 정규화 파인딩 DTO."""

    framework: str
    check_id: str
    check_name: str | None
    severity: str | None
    resource: str | None
    resource_address: str | None
    description: str | None
    details: Any
    vulnerability_details: Any
    entity_tags: Any
    evaluations: Any
    breadcrumbs: Any
    file_abs_path: str | None
    repo_file_path: str | None
    file_path: str | None
    file_line_range: Any
    code_block: Any
    guideline: str | None
    check_result: dict[str, Any] | None


@dataclass
class Decision:
    """2. CI 정책 판정 결과"""

    framework: str
    allow: bool
    reason: str
    max_score: str
    scenario_count: int


def normalize_findings(checkov_merged: dict[str, Any]) -> list[NormalizedFinding]:
    """Checkov 병합 결과에서 failed finding을 NormalizedFinding 리스트로 변환합니다."""

    root_check_type = str(checkov_merged.get("check_type", "terraform"))

    root = checkov_merged.get("results")
    if not isinstance(root, dict):
        root = checkov_merged

    failed_checks = root.get("failed_checks") or []
    if not isinstance(failed_checks, list):
        return []

    findings: list[NormalizedFinding] = []
    for item in failed_checks:
        if not isinstance(item, dict):
            continue

        check_id = str(item.get("check_id", "")).strip()
        if not check_id:
            continue

        findings.append(
            NormalizedFinding(
                framework=str(item.get("check_type", root_check_type)),
                check_id=check_id,
                check_name=item.get("check_name"),
                severity=item.get("severity"),
                resource=item.get("resource"),
                resource_address=item.get("resource_address"),
                description=item.get("description"),
                details=item.get("details"),
                vulnerability_details=item.get("vulnerability_details"),
                entity_tags=item.get("entity_tags"),
                evaluations=item.get("evaluations"),
                breadcrumbs=item.get("breadcrumbs"),
                file_abs_path=item.get("file_abs_path"),
                repo_file_path=item.get("repo_file_path"),
                file_path=item.get("file_path"),
                file_line_range=item.get("file_line_range"),
                code_block=item.get("code_block"),
                guideline=item.get("guideline"),
                check_result=item.get("check_result")
                if isinstance(item.get("check_result"), dict)
                else None,
            )
        )

    return findings


def save_normalized_findings_json(
    findings: list[NormalizedFinding], output_path: Path
) -> None:
    """NormalizedFinding 리스트를 JSON 파일로 저장합니다."""

    payload = [asdict(item) for item in findings]
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def build_resource_rollup(findings: list[NormalizedFinding]) -> dict[str, Any]:
    raise NotImplementedError


def build_decision(attack_result: dict[str, Any]) -> Decision:
    raise NotImplementedError


def render_report_md(*args: Any, **kwargs: Any) -> str:
    raise NotImplementedError
