# src/secugate/parsers/checkov.py
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..models import Finding

logger = logging.getLogger(__name__)


def _pick(obj: dict[str, Any], *keys: str) -> Any:
    """키 중에서 비어있지 않은 첫 번째 값을 반환"""
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


def _str_or_none(value: Any) -> str | None:
    """값을 안전하게 문자열로 변환하되, None은 그대로 유지.

    - 값이 None이면 None을 반환
    - 값을 문자열로 변환할 수 없는 경우, 경고를 기록하고
      유효한 값이 없음을 나타내는 None을 반환
    - 그 외의 경우에는 문자열 표현을 반환.

    """
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        logger.warning(
            "타입 %s의 값을 문자열로 변환하는데 실패했습니다. 값을 무시합니다.",
            type(value).__name__,
        )
        return None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # 일부 utf-8아닐수 있음
        text = path.read_text(encoding="utf-8", errors="replace")

    try:
        data = json.loads(text)  # 디버깅
    except json.JSONDecodeError as e:
        raise ValueError(f"{path} 파일에 잘못된 JSON 형식이 있습니다: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(
            f"{path} 파일의 JSON 경로가 예상과 다릅니다: {type(data).__name__}"
        )
    return data


def parse_checkov_json(path: Path, framework: str) -> list[Finding]:
    """Checkov JSON 출력물

    일반적인 포맷 변형을 지원
      - {"results": {"failed_checks": [...], ...}}
      - {"failed_checks": [...], ...}

    최소한의 필드만 추출
      - check_id, check_name, resource, file_path, file_line_range, severity, guideline 등

    """
    data = _load_json(path)

    # 일부 버전은 "results" 아래에 중첩
    results = data.get("results")
    if isinstance(results, dict):
        root = results
    else:
        root = data

    findings: list[Finding] = []

    buckets = (
        ("failed_checks", "FAIL"),
        ("passed_checks", "PASS"),
        ("skipped_checks", "SKIP"),
    )

    for bucket_name, result in buckets:
        checks = root.get(bucket_name) or []
        if not isinstance(checks, list):
            logger.warning(
                "Checkov JSON %s의 버킷 %s가 리스트가 아닙니다 (타입: %s). 건너뜁니다.",
                path,
                bucket_name,
                type(checks).__name__,
            )
            continue

        for c in checks:
            if not isinstance(c, dict):
                continue

            check_id = _safe_str(_pick(c, "check_id", "checkID"), default="알수없음")
            check_name = _safe_str(_pick(c, "check_name", "name"), default="")

            # 리소스 키는 프레임워크 / 출력 모드에 따라 다릅니다.
            resource = _safe_str(
                _pick(c, "resource", "resource_name", "entity"),
                default="값없음",
            )

            file_path = _pick(c, "file_path", "file", "file_abs_path")
            file_line_range = _pick(c, "file_line_range", "file_line", "line_range")
            code_block = _pick(c, "code_block")

            severity = _pick(c, "severity")
            guideline = _pick(c, "guideline", "guideline_url")
            repo_file_path = _pick(c, "repo_file_path")

            findings.append(
                Finding(
                    framework=str(framework),
                    check_id=check_id,
                    check_name=_safe_str(check_name),
                    result=result,  # type: ignore[arg-type]
                    resource=resource,
                    file_path=_str_or_none(file_path),
                    repo_file_path=_str_or_none(repo_file_path),
                    file_line_range=_str_or_none(file_line_range),
                    severity=_str_or_none(severity),
                    guideline=_str_or_none(guideline),
                    code_block=_str_or_none(code_block),
                )
            )

    return findings


def merge_checkov_results(
    plan_json_path: Path, hcl_json_path: Path, output_path: Path
) -> None:
    """Checkov plan과 HCL 스캔 병합.

    plan 스캔 결과의 탐지 항목에 HCL 스캔의 소스 코드 위치 정보추가.
    plan 스캔의 탐지 항목에 정확한 위치 정보가 없는 경우(예: 파일 경로가 tfplan.json을
    가리킬 때), HCL 스캔에서 일치하는 탐지 항목(동일한 check_id 및 resource)을 찾아
    위치 관련 필드 붙여줌
    """
    plan_data = _load_json(plan_json_path)  # This should be a dict

    # Load HCL JSON which might be a dict or a list of dicts
    try:
        hcl_data_raw = json.loads(hcl_json_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(
            f"{hcl_json_path}에서 JSON을 로드하거나 파싱하는데 실패했습니다"
        ) from e

    hcl_data: dict[str, Any]
    if isinstance(hcl_data_raw, dict):
        hcl_data = hcl_data_raw
    elif isinstance(hcl_data_raw, list):
        # 'terraform' (HCL) 스캔 타입에 대한 결과.
        hcl_results = [
            result
            for result in hcl_data_raw
            if isinstance(result, dict) and result.get("check_type") == "terraform"
        ]
        if not hcl_results:
            raise ValueError(
                f"{hcl_json_path} 리스트에서 'terraform' 체크 타입을 찾을 수 없습니다"
            )
        hcl_data = hcl_results[0]
    else:
        raise ValueError(
            f"{hcl_json_path} 파일의 JSON 루트 타입이 예상과 다릅니다: {type(hcl_data_raw).__name__}"
        )

    # Checkov 결과는 'results' 키 아래에 중첩
    plan_root = plan_data.get("results")
    if not isinstance(plan_root, dict):
        plan_root = plan_data

    hcl_root = hcl_data.get("results")
    if not isinstance(hcl_root, dict):
        hcl_root = hcl_data

    plan_failed = plan_root.get("failed_checks") or []
    hcl_failed = hcl_root.get("failed_checks") or []

    EVIDENCE_FIELDS = [
        "repo_file_path",
        "file_path",
        "file_abs_path",
        "file_line_range",
        "code_block",
        "definition_context_file_path",
        "breadcrumbs",
    ]

    def needs_evidence(finding: dict[str, Any]) -> bool:
        """plan 스캔 결과에 위치 정보 보강이 필요한지 확인합니다."""
        repo_file_path = (finding.get("repo_file_path") or "").lower()
        file_line_range = finding.get("file_line_range")
        code_block = finding.get("code_block")

        if repo_file_path.endswith("tfplan.json"):
            return True
        if isinstance(file_line_range, list) and file_line_range == [0, 0]:
            return True
        if isinstance(code_block, list) and not code_block:
            return True
        return False

    def build_hcl_index(
        hcl_findings: list[dict[str, Any]],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """빠른 조회를 위해 HCL 스캔 결과를 (check_id, resource) 키로 인덱싱."""
        index: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in hcl_findings:
            check_id = finding.get("check_id")
            resource = finding.get("resource")
            if check_id and resource:
                index[(str(check_id), str(resource))] = finding
        return index

    hcl_index = build_hcl_index(hcl_failed)

    for plan_finding in plan_failed:
        key = (plan_finding.get("check_id"), plan_finding.get("resource"))
        hcl_finding = hcl_index.get(key)
        if not hcl_finding:
            continue

        if needs_evidence(plan_finding):
            for field in EVIDENCE_FIELDS:
                evidence = hcl_finding.get(field)
                if evidence not in (None, [], "", {}):
                    plan_finding[field] = evidence

    # 가독성을 위해 code_block 포맷을 재구성
    for finding in plan_failed:
        code_block = finding.get("code_block")
        if isinstance(code_block, list) and code_block:
            # Checkov에서 출력된 리스트의 리스트 형식인지 확인
            if isinstance(code_block[0], list) and len(code_block[0]) == 2:
                # 예쁘게 출력된 JSON에서 가독성을 높이기 위해 문자열 리스트로 포맷을 변경
                # 각 라인은 리스트에서 별도의 문자열 요소
                reformatted_code = [line.rstrip("\n\r") for _, line in code_block]
                finding["code_block"] = reformatted_code

    output_path.write_text(json.dumps(plan_data, ensure_ascii=False, indent=2))
