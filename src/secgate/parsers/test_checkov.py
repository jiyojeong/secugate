# tests/parsers/test_checkov.py
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import pytest

from secgate.parsers.checkov import parse_checkov_json

# 테스트 실행 시 secgate.models.Finding을 직접 의존하지 않도록
# 테스트용으로 동일한 구조의 Mock 클래스를 정의합니다.
# 이렇게 하면 모델의 변경과 파서 테스트를 분리할 수 있습니다.
@dataclass
class MockFinding:
    framework: str
    check_id: str
    check_name: str
    result: str
    resource: str
    file_path: Optional[str]
    file_line_range: Optional[str]
    severity: Optional[str]
    guideline: Optional[str]


# --- 테스트 데이터 ---

SAMPLE_CHECKOV_NESTED = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_1",
                "check_name": "Ensure something is enabled",
                "file_path": "/main.tf",
                "file_abs_path": "/home/user/project/main.tf",
                "file_line_range": [10, 20],
                "resource": "aws_s3_bucket.my_bucket",
                "severity": "HIGH",
                "guideline": "https://docs.aws.amazon.com/...",
            }
        ],
        "passed_checks": [
            {
                "check_id": "CKV_AWS_2",
                "check_name": "Ensure something else is correct",
                "file_path": "/other.tf",
                "file_line_range": [5, 8],
                "resource": "aws_instance.my_instance",
                "severity": "LOW",
            }
        ],
        "skipped_checks": [],
    },
}

SAMPLE_CHECKOV_ROOT = {
    "failed_checks": [
        {
            "checkID": "CKV_GCP_10",  # Alternative key
            "name": "Ensure logging is enabled",  # Alternative key
            "file": "/gcp.tf",  # Alternative key
            "line_range": [30, 40],  # Alternative key
            "resource": "google_project.my_project",
            "guideline_url": "https://google.com/...",  # Alternative key
        }
    ],
    "passed_checks": [],
    "skipped_checks": None,  # Null bucket should be handled
}


def write_json(path: Path, data: Any):
    """Helper to write test data to a temporary file."""
    path.write_text(json.dumps(data), encoding="utf-8")


def test_parse_checkov_json_nested_format(tmp_path: Path):
    """`results` 객체 내에 결과가 중첩된 표준 형식을 테스트합니다."""
    path = tmp_path / "checkov.json"
    write_json(path, SAMPLE_CHECKOV_NESTED)

    findings = parse_checkov_json(path, "terraform")

    assert len(findings) == 2

    # Finding 객체 대신 MockFinding을 사용하여 비교합니다.
    expected_fail = MockFinding(
        framework="terraform",
        check_id="CKV_AWS_1",
        check_name="Ensure something is enabled",
        result="FAIL",
        resource="aws_s3_bucket.my_bucket",
        file_path="/main.tf",
        file_line_range="[10, 20]",
        severity="HIGH",
        guideline="https://docs.aws.amazon.com/...",
    )
    # 실제 Finding 객체의 __dict__와 비교하여 필드 값을 검증합니다.
    assert findings[0].__dict__ == expected_fail.__dict__

    expected_pass = MockFinding(
        framework="terraform",
        check_id="CKV_AWS_2",
        check_name="Ensure something else is correct",
        result="PASS",
        resource="aws_instance.my_instance",
        file_path="/other.tf",
        file_line_range="[5, 8]",
        severity="LOW",
        guideline=None,  # Guideline이 없는 경우 None이어야 합니다.
    )
    assert findings[1].__dict__ == expected_pass.__dict__


def test_parse_checkov_json_root_format_with_alternative_keys(tmp_path: Path):
    """`results` 없이 최상위에 결과가 있고, 대체 키를 사용하는 형식을 테스트합니다."""
    path = tmp_path / "checkov.json"
    write_json(path, SAMPLE_CHECKOV_ROOT)

    findings = parse_checkov_json(path, "gcp")

    assert len(findings) == 1
    expected = MockFinding(
        framework="gcp",
        check_id="CKV_GCP_10",
        check_name="Ensure logging is enabled",
        result="FAIL",
        resource="google_project.my_project",
        file_path="/gcp.tf",
        file_line_range="[30, 40]",
        severity=None,
        guideline="https://google.com/...",
    )
    assert findings[0].__dict__ == expected.__dict__


def test_parse_invalid_json_file(tmp_path: Path):
    """유효하지 않은 JSON 파일을 파싱할 때 ValueError가 발생하는지 테스트합니다."""
    path = tmp_path / "invalid.json"
    path.write_text("{ not json }")

    with pytest.raises(ValueError, match="Invalid JSON"):
        parse_checkov_json(path, "test")


def test_parse_non_dict_root_json(tmp_path: Path):
    """JSON 최상위 타입이 dict가 아닐 때 ValueError가 발생하는지 테스트합니다."""
    path = tmp_path / "list.json"
    path.write_text("[]")

    with pytest.raises(ValueError, match="Unexpected JSON root type"):
        parse_checkov_json(path, "test")


def test_handle_bucket_not_a_list(tmp_path: Path, caplog):
    """결과 버킷(예: failed_checks)이 리스트가 아닐 때 경고를 기록하고 건너뛰는지 테스트합니다."""
    path = tmp_path / "bad_bucket.json"
    write_json(path, {"failed_checks": {"is_a": "dict"}})

    with caplog.at_level(logging.WARNING):
        findings = parse_checkov_json(path, "test")

    assert len(findings) == 0
    assert "is not a list (got dict). Skipping." in caplog.text


def test_handle_check_item_not_a_dict(tmp_path: Path):
    """결과 버킷의 항목이 dict가 아닐 때 해당 항목을 건너뛰는지 테스트합니다."""
    path = tmp_path / "bad_item.json"
    write_json(path, {"failed_checks": ["i_am_a_string"]})

    findings = parse_checkov_json(path, "test")

    assert len(findings) == 0  # 잘못된 항목은 무시되어야 합니다.