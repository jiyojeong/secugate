from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - optional dependency at runtime
    OpenAI = None

DEFAULT_NON_RUNTIME_PREFIXES = (
    "data.",
    "var.",
    "local.",
    "module.",
    "path.",
    "terraform.",
    "count.",
    "each.",
)

# 벡터(공격 단계) 순서
VECTOR_STAGE_RANK: dict[str, int] = {
    "initial_access_public_exposure": 0,
    "credential_access_and_secrets": 1,
    "privilege_escalation_and_persistence": 1,
    "lateral_movement_remote_access": 1,
    "execution_and_compute_abuse": 2,
    "defense_evasion_and_visibility_gaps": 2,
    "collection_and_exfiltration": 3,
    "impact_and_resilience": 3,
    "data_protection_and_encryption_posture": 2,
}

STAGE_RANK: dict[str, int] = {
    "initial_access": 0,
    "privilege_or_credential_expansion": 1,
    "execution_or_visibility_control": 2,
    "impact_or_exfiltration": 3,
}

STAGE_LABELS: dict[int, str] = {
    0: "initial_access",
    1: "privilege_or_credential_expansion",
    2: "execution_or_visibility_control",
    3: "impact_or_exfiltration",
}

STAGE_LABELS_KO: dict[int, str] = {
    0: "초기 접근/노출",
    1: "권한·자격 확장",
    2: "실행·탐지우회",
    3: "영향·유출",
}

DROP_REASON_LABELS_KO: dict[str, str] = {
    "empty_path": "빈 경로",
    "invalid_node_id": "잘못된 노드 ID",
    "non_runtime_endpoint": "시작점 또는 끝점이 런타임 AWS 리소스가 아님(내부참조값 등)",
    "contains_non_runtime_node": "경로에 var/local/data 같은 비런타임 노드 포함",
    "invalid_path": "유효하지 않은 경로",
    "hops_exceeded": "최대 홉 수 초과",
    "no_findings_on_path": "경로 위에 Checkov 결과 없음",
    "no_attack_stage": "공격 단계로 해석 가능한 체크 없음",
    "stage_order_violation": "공격 단계 순서가 역전됨",
    "insufficient_stage_progress": "공격 단계 진행이 부족함",
    "duplicate_path": "중복 경로",
    "duplicate_scenario": "중복 시나리오",
}

PATH_CATEGORY_LABELS_KO: dict[str, str] = {
    "network_exposure_chain": "네트워크 노출형 경로",
    "iam_privilege_chain": "IAM 권한형 경로",
    "network_to_iam_chain": "네트워크->IAM 혼합 경로",
    "other_chain": "기타 경로",
}

PATH_CATEGORY_ORDER = [
    "network_exposure_chain",
    "iam_privilege_chain",
    "network_to_iam_chain",
    "other_chain",
]

DEFAULT_NETWORK_RESOURCE_PREFIXES = (
    "aws_internet_gateway",
    "aws_route_table",
    "aws_route_table_association",
    "aws_subnet",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_network_acl",
    "aws_networkfirewall",
    "aws_vpc",
    "aws_lb",
    "aws_alb",
    "aws_elb",
)

DEFAULT_IAM_RESOURCE_PREFIXES = ("aws_iam_",)

DEFAULT_COMPUTE_RESOURCE_PREFIXES = (
    "aws_instance",
    "aws_launch_template",
    "aws_launch_configuration",
    "aws_autoscaling_group",
    "aws_lambda_function",
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_eks_",
)

DEFAULT_ATTACK_ENDPOINT_PRIORITY: list[tuple[tuple[str, ...], int]] = [
    (DEFAULT_IAM_RESOURCE_PREFIXES, 500),
    (DEFAULT_COMPUTE_RESOURCE_PREFIXES, 400),
    (("aws_lambda_function", "aws_ecs_service", "aws_ecs_task_definition"), 350),
    (("aws_secretsmanager_", "aws_ssm_parameter", "aws_kms_"), 320),
    (("aws_s3_bucket", "aws_db_", "aws_rds_", "aws_redshift_"), 300),
    (DEFAULT_NETWORK_RESOURCE_PREFIXES, 200),
]

NON_RUNTIME_PREFIXES = DEFAULT_NON_RUNTIME_PREFIXES
NETWORK_RESOURCE_PREFIXES = DEFAULT_NETWORK_RESOURCE_PREFIXES
IAM_RESOURCE_PREFIXES = DEFAULT_IAM_RESOURCE_PREFIXES
COMPUTE_RESOURCE_PREFIXES = DEFAULT_COMPUTE_RESOURCE_PREFIXES
ATTACK_ENDPOINT_PRIORITY = DEFAULT_ATTACK_ENDPOINT_PRIORITY

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

DEFAULT_LLM_MODEL = "gpt-4.1"


def _build_llm_payload(representative: dict[str, Any]) -> dict[str, Any]:
    stage_details = representative.get("stage_details")
    node_findings = representative.get("node_findings")
    return {
        "path": representative.get("path_evaluated")
        or representative.get("path")
        or [],
        "path_category": representative.get("path_category_ko")
        or representative.get("path_category"),
        "stage_sequence": representative.get("stage_sequence") or [],
        "attack_tactic_chain": representative.get("attack_tactic_chain") or [],
        "atomic_chain": representative.get("atomic_chain") or [],
        "existing_scenario": representative.get("attack_scenario"),
        "stage_details": stage_details if isinstance(stage_details, list) else [],
        "node_findings": node_findings if isinstance(node_findings, list) else [],
    }


def summarize_with_llm(representative: dict[str, Any]) -> dict[str, str]:
    fallback = {
        "attack_scenario_one_liner": "",
        "mitigation_one_liner": "",
    }

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return fallback

    payload = _build_llm_payload(representative)
    prompt = (
        "아래 데이터는 내부 규칙 엔진이 MITRE tactic/stage 순서를 검증해 "
        "유효하다고 판단한 최종 공격 경로다.\n"
        "주어진 순서를 바꾸지 말고, evidence에 없는 사실은 추가하지 말라.\n"
        "개별 finding을 나열하기보다 capability/stage 흐름을 연결해서 "
        "사람이 읽기 쉬운 한국어 한 문장 공격 시나리오와 한 문장 대응 방안을 작성하라.\n\n"
        "반드시 아래 JSON 형식으로만 답하라.\n"
        "{\n"
        '  "attack_scenario_one_liner": "...",\n'
        '  "mitigation_one_liner": "..."\n'
        "}\n\n"
        f"[Representative Scenario]\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", DEFAULT_LLM_MODEL),
            input=prompt,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "scenario_summary",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "attack_scenario_one_liner": {"type": "string"},
                            "mitigation_one_liner": {"type": "string"},
                        },
                        "required": [
                            "attack_scenario_one_liner",
                            "mitigation_one_liner",
                        ],
                        "additionalProperties": False,
                    },
                }
            },
        )
        parsed = json.loads(response.output_text)
    except Exception:
        return fallback

    attack = str(parsed.get("attack_scenario_one_liner", "")).strip()
    mitigation = str(parsed.get("mitigation_one_liner", "")).strip()
    return {
        "attack_scenario_one_liner": attack,
        "mitigation_one_liner": mitigation,
    }


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} JSON root must be an object")
    return data


def _load_resource_classification(path: Path) -> None:
    global NON_RUNTIME_PREFIXES
    global NETWORK_RESOURCE_PREFIXES
    global IAM_RESOURCE_PREFIXES
    global COMPUTE_RESOURCE_PREFIXES
    global ATTACK_ENDPOINT_PRIORITY

    if not path.is_file():
        return

    data = _load_json(path)

    non_runtime = data.get("non_runtime_prefixes")
    if isinstance(non_runtime, list):
        values = tuple(str(item).strip() for item in non_runtime if str(item).strip())
        if values:
            NON_RUNTIME_PREFIXES = values

    resource_prefixes = data.get("resource_prefixes")
    if isinstance(resource_prefixes, dict):
        network = resource_prefixes.get("network")
        iam = resource_prefixes.get("iam")
        compute = resource_prefixes.get("compute")
        if isinstance(network, list):
            values = tuple(str(item).strip() for item in network if str(item).strip())
            if values:
                NETWORK_RESOURCE_PREFIXES = values
        if isinstance(iam, list):
            values = tuple(str(item).strip() for item in iam if str(item).strip())
            if values:
                IAM_RESOURCE_PREFIXES = values
        if isinstance(compute, list):
            values = tuple(str(item).strip() for item in compute if str(item).strip())
            if values:
                COMPUTE_RESOURCE_PREFIXES = values

    endpoint_priority = data.get("attack_endpoint_priority")
    if isinstance(endpoint_priority, list):
        configured: list[tuple[tuple[str, ...], int]] = []
        for item in endpoint_priority:
            if not isinstance(item, dict):
                continue
            prefixes = item.get("prefixes")
            score = item.get("score")
            if not isinstance(prefixes, list) or not isinstance(score, int):
                continue
            normalized_prefixes = tuple(
                str(prefix).strip() for prefix in prefixes if str(prefix).strip()
            )
            if normalized_prefixes:
                configured.append((normalized_prefixes, score))
        if configured:
            ATTACK_ENDPOINT_PRIORITY = configured


def _normalize_resource_id(resource_id: str) -> str | None:
    token = resource_id.split("[", 1)[0]
    parts = token.split(".")
    if not parts:
        return None

    if parts[0] == "data" and len(parts) >= 3:
        return ".".join(parts[:3])
    if (
        parts[0] in {"var", "local", "path", "terraform", "count", "each"}
        and len(parts) >= 2
    ):
        return ".".join(parts[:2])
    if parts[0] == "module":
        if len(parts) >= 4 and parts[2] in {"data"}:
            return ".".join(parts[:5]) if len(parts) >= 5 else ".".join(parts[:4])
        if len(parts) >= 4 and "_" in parts[2]:
            return ".".join(parts[:4])
        if len(parts) >= 2:
            return ".".join(parts[:2])
    if len(parts) >= 2:
        return ".".join(parts[:2])
    return token


def _build_checkov_index(
    checkov_merged: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    results = checkov_merged.get("results", {})
    failed_checks = (
        results.get("failed_checks", []) if isinstance(results, dict) else []
    )
    if not isinstance(failed_checks, list):
        failed_checks = []

    index: dict[str, list[dict[str, Any]]] = {}
    unmatched = 0

    for finding in failed_checks:
        if not isinstance(finding, dict):
            continue
        rid = finding.get("resource_address")
        if not isinstance(rid, str) or not rid.strip():
            rid = finding.get("resource")
        if not isinstance(rid, str) or not rid.strip():
            unmatched += 1
            continue

        node_id = _normalize_resource_id(rid.strip())
        if not node_id:
            unmatched += 1
            continue

        index.setdefault(node_id, []).append(
            {
                "check_id": finding.get("check_id"),
                "severity": finding.get("severity"),
                "check_name": finding.get("check_name"),
                "description": finding.get("description"),
                "resource": rid,
                "normalized_resource": node_id,
                "resource_address": finding.get("resource_address")
                or finding.get("resource"),
                "file_abs_path": finding.get("file_abs_path"),
                "file_path": finding.get("file_path"),
                "file_line_range": finding.get("file_line_range"),
                "evaluated_keys": finding.get("evaluated_keys")
                or (
                    finding.get("check_result", {}).get("evaluated_keys")
                    if isinstance(finding.get("check_result"), dict)
                    else None
                ),
            }
        )

    for node_id in index:
        index[node_id] = sorted(
            index[node_id],
            key=lambda x: (str(x.get("severity") or ""), str(x.get("check_id") or "")),
        )

    summary = {
        "failed_checks_total": len([x for x in failed_checks if isinstance(x, dict)]),
        "failed_checks_indexed": sum(len(v) for v in index.values()),
        "failed_checks_unmatched": unmatched,
        "indexed_nodes": len(index),
    }
    return index, summary


def _count_findings_by_severity(
    checkov_index: dict[str, list[dict[str, Any]]],
    check_to_fail_meta: dict[str, dict[str, str]],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for findings in checkov_index.values():
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            check_id = finding.get("check_id")
            severity = None
            if isinstance(check_id, str):
                severity = (check_to_fail_meta.get(check_id) or {}).get("severity")
            if not severity:
                severity = finding.get("severity")
            severity_text = str(severity or "").strip().upper()
            if not severity_text:
                continue
            counts[severity_text] = counts.get(severity_text, 0) + 1
    return counts


def _collect_critical_findings(
    checkov_index: dict[str, list[dict[str, Any]]],
    check_to_fail_meta: dict[str, dict[str, str]],
) -> list[dict[str, str]]:
    critical_items: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for findings in checkov_index.values():
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            check_id = str(finding.get("check_id") or "").strip()
            fail_meta = check_to_fail_meta.get(check_id) if check_id else {}
            severity = (
                str((fail_meta or {}).get("severity") or finding.get("severity") or "")
                .strip()
                .upper()
            )
            if severity != "CRITICAL":
                continue
            file_path = str(
                finding.get("file_abs_path")
                or finding.get("file_path")
                or finding.get("resource_address")
                or "-"
            ).strip()
            issue = str(
                (fail_meta or {}).get("why_fails")
                or finding.get("check_name")
                or check_id
                or "-"
            ).strip()
            key = (check_id, file_path, issue)
            if key in seen:
                continue
            seen.add(key)
            critical_items.append(
                {
                    "check_id": check_id,
                    "file": file_path,
                    "issue": issue,
                }
            )

    return sorted(
        critical_items,
        key=lambda item: (
            item.get("file", ""),
            item.get("check_id", ""),
            item.get("issue", ""),
        ),
    )


def _load_checkov_vector_index(path: Path) -> dict[str, str]:
    # check_id -> primary_vector 인덱스
    if not path.is_file():
        return {}
    data = _load_json(path)
    check_index = data.get("check_index", {})
    if not isinstance(check_index, dict):
        return {}

    out: dict[str, str] = {}
    for check_id, meta in check_index.items():
        if not isinstance(check_id, str) or not isinstance(meta, dict):
            continue
        primary_vector = meta.get("primary_vector")
        if isinstance(primary_vector, str):
            out[check_id] = primary_vector
    return out


def _load_attack_stage_index(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    data = _load_json(path)
    normalize = data.get("normalize", [])
    if not isinstance(normalize, list):
        return {}

    out: dict[str, str] = {}
    for item in normalize:
        if not isinstance(item, dict):
            continue
        stage = item.get("stage")
        if not isinstance(stage, str) or not stage.strip():
            continue
        check_ids = item.get("check_ids", [])
        if not isinstance(check_ids, list):
            continue
        for check_id in check_ids:
            if isinstance(check_id, str) and check_id.strip():
                out[check_id] = stage.strip()
    return out


def _load_check_stage_index(
    attack_mapping_path: Path, fallback_catalog_path: Path
) -> dict[str, int]:
    out: dict[str, int] = {}

    for check_id, stage in _load_attack_stage_index(attack_mapping_path).items():
        rank = STAGE_RANK.get(stage)
        if rank is not None:
            out[check_id] = rank

    # attack_mapping에 없는 check_id만 기존 catalog vector로 보완
    for check_id, vector in _load_checkov_vector_index(fallback_catalog_path).items():
        if check_id in out:
            continue
        rank = VECTOR_STAGE_RANK.get(vector)
        if rank is not None:
            out[check_id] = rank

    return out


def _load_checkov_korean_index(
    labels_path: Path, fallback_path: Path
) -> dict[str, str]:
    # 우선 별도 매핑 파일(check_id -> label_ko)을 읽고, 없으면 기존 why_fails에서 fallback
    if labels_path.is_file():
        data = _load_json(labels_path)
        mapping = data.get("labels", {})
        if isinstance(mapping, dict):
            out = {
                str(check_id): str(label).strip()
                for check_id, label in mapping.items()
                if isinstance(check_id, str)
                and isinstance(label, str)
                and label.strip()
            }
            if out:
                return out

    if not fallback_path.is_file():
        return {}
    data = _load_json(fallback_path)
    checks = data.get("checks", [])
    if not isinstance(checks, list):
        return {}

    out: dict[str, str] = {}
    for item in checks:
        if not isinstance(item, dict):
            continue
        check_id = item.get("check_id")
        if not isinstance(check_id, str):
            continue
        examples = item.get("examples", [])
        if not isinstance(examples, list):
            continue
        for ex in examples:
            if not isinstance(ex, dict):
                continue
            why_fails = ex.get("why_fails")
            if isinstance(why_fails, str) and why_fails.strip():
                out[check_id] = why_fails.strip()
                break
    return out


def _load_checkov_fail_index(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    data = _load_json(path)
    checks = data.get("checks", [])
    if not isinstance(checks, list):
        return {}

    out: dict[str, dict[str, str]] = {}
    for item in checks:
        if not isinstance(item, dict):
            continue
        check_id = item.get("check_id")
        if not isinstance(check_id, str) or not check_id.strip():
            continue

        meta: dict[str, str] = {}
        severity = item.get("Severity")
        if isinstance(severity, str) and severity.strip():
            meta["severity"] = severity.strip()

        examples = item.get("examples", [])
        if isinstance(examples, list):
            for ex in examples:
                if not isinstance(ex, dict):
                    continue
                why_fails = ex.get("why_fails")
                mitigation = ex.get("mitigation")
                if isinstance(why_fails, str) and why_fails.strip():
                    meta["why_fails"] = why_fails.strip()
                if isinstance(mitigation, str) and mitigation.strip():
                    meta["mitigation"] = mitigation.strip()
                if meta.get("why_fails") and meta.get("mitigation"):
                    break

        if meta:
            out[check_id] = meta
    return out


def _load_attack_meta_index(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    data = _load_json(path)

    atomic_by_key: dict[str, list[str]] = {}
    for item in data.get("atomic_mappings", []):
        if not isinstance(item, dict):
            continue
        capability_key = item.get("capability_key")
        if not isinstance(capability_key, str) or not capability_key.strip():
            continue
        atomic_ids = [
            str(atomic_id).strip()
            for atomic_id in (item.get("atomic_ids") or [])
            if str(atomic_id).strip()
        ]
        atomic_by_key[capability_key] = atomic_ids

    out: dict[str, dict[str, Any]] = {}
    for item in data.get("normalize", []):
        if not isinstance(item, dict):
            continue
        capability_key = item.get("capability_key")
        if not isinstance(capability_key, str) or not capability_key.strip():
            continue
        group_type = str(item.get("group_type", "")).strip().lower() or None
        meta = {
            "capability_key": capability_key.strip(),
            "capability_id": str(item.get("capability_id", "")).strip() or None,
            "capability": str(item.get("capability", "")).strip() or None,
            "mitre_tactic": str(item.get("mitre_tactic", "")).strip() or None,
            "stage": str(item.get("stage", "")).strip() or None,
            "group_type": group_type,
            "atomic_ids": atomic_by_key.get(capability_key.strip(), []),
            "representative_atomic_id": (
                atomic_by_key.get(capability_key.strip(), [None])[0]
                if atomic_by_key.get(capability_key.strip())
                else None
            ),
        }
        for check_id in item.get("check_ids", []) or []:
            if isinstance(check_id, str) and check_id.strip():
                key = check_id.strip()
                existing = out.get(key)
                if (
                    existing
                    and existing.get("group_type") == "specific"
                    and group_type != "specific"
                ):
                    continue
                out[key] = meta
    return out


def _resource_type(node_id: str) -> str:
    return node_id.split(".", 1)[0] if "." in node_id else node_id


def _is_path_runtime_valid(path_nodes: list[str]) -> tuple[bool, str | None]:
    # (1) 경로 유효성 필터
    if not path_nodes:
        return False, "empty_path"  # 비어있는경로
    if not all(isinstance(n, str) and n for n in path_nodes):
        return False, "invalid_node_id"  # 노드 전부 문자열?
    if not path_nodes[0].startswith("aws_") or not path_nodes[-1].startswith("aws_"):
        return False, "non_runtime_endpoint"  # 시작과 끝이 aws_
    if any(n.startswith(NON_RUNTIME_PREFIXES) for n in path_nodes):
        return False, "contains_non_runtime_node"  # 중간 var.local.data. 섞였나
    return True, None


def _stage_sequence_from_path(
    path_nodes: list[str],
    node_findings: list[dict[str, Any]],
    check_to_stage_rank: dict[str, int],
) -> list[int]:
    # 경로 노드 순서대로 체크 벡터를 단계(rank) 시퀀스로 변환
    findings_by_node = {
        x["node"]: x["findings"]
        for x in node_findings
        if isinstance(x, dict) and "node" in x
    }
    raw_ranks: list[int] = []
    for node in path_nodes:
        findings = findings_by_node.get(node, [])
        node_ranks: list[int] = []
        for f in findings:
            cid = f.get("check_id")
            if not isinstance(cid, str):
                continue
            rank = check_to_stage_rank.get(cid)
            if rank is None:
                continue
            node_ranks.append(rank)
        if node_ranks:
            raw_ranks.extend(sorted(set(node_ranks)))

    # 연속 중복 rank 압축
    compressed: list[int] = []
    for r in raw_ranks:
        if not compressed or compressed[-1] != r:
            compressed.append(r)
    return compressed


def _select_path_orientation(
    path_nodes: list[str],
    node_findings: list[dict[str, Any]],
    check_to_stage_rank: dict[str, int],
) -> tuple[list[str], list[int], str | None]:
    candidates = [
        ("forward", path_nodes),
        ("reverse", list(reversed(path_nodes))),
    ]

    best_nodes: list[str] = path_nodes
    best_seq: list[int] = []
    best_direction: str | None = None

    for direction, candidate_nodes in candidates:
        stage_seq = _stage_sequence_from_path(
            candidate_nodes, node_findings, check_to_stage_rank
        )
        if not stage_seq:
            continue
        if any(stage_seq[i] > stage_seq[i + 1] for i in range(len(stage_seq) - 1)):
            continue
        if len(set(stage_seq)) < 2:
            continue
        return candidate_nodes, stage_seq, direction

    return best_nodes, best_seq, best_direction


def _build_stage_details(
    path_nodes: list[str],
    node_findings: list[dict[str, Any]],
    check_to_stage_rank: dict[str, int],
    check_to_korean: dict[str, str],
    check_to_fail_meta: dict[str, dict[str, str]],
    check_to_attack_meta: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    findings_by_node = {
        x["node"]: x["findings"]
        for x in node_findings
        if isinstance(x, dict) and "node" in x
    }

    for node in path_nodes:
        findings = findings_by_node.get(node, [])
        if not findings:
            continue

        stage_to_checks: dict[int, set[str]] = {}
        for f in findings:
            cid = f.get("check_id")
            if not isinstance(cid, str):
                continue
            rank = check_to_stage_rank.get(cid)
            if rank is None:
                continue
            stage_to_checks.setdefault(rank, set()).add(cid)

        for rank, cids in sorted(stage_to_checks.items()):
            stage_evidences: list[dict[str, Any]] = []
            for f in findings:
                cid = f.get("check_id")
                if not isinstance(cid, str) or cid not in cids:
                    continue
                stage_evidences.append(
                    _build_evidence_entry(
                        f,
                        check_to_korean,
                        check_to_fail_meta,
                        check_to_attack_meta,
                    )
                )
            representative = _pick_representative_evidence(stage_evidences)
            ordered_evidences = sorted(
                stage_evidences, key=_evidence_sort_key, reverse=True
            )
            evidence_preview = ordered_evidences[:2]
            details.append(
                {
                    "stage_rank": rank,
                    "stage": STAGE_LABELS.get(rank, f"stage_{rank}"),
                    "resource": node,
                    "check_ids": sorted(cids),
                    "representative_evidence": representative,
                    "evidence_preview": evidence_preview,
                }
            )

    return details


def _build_evidence_entry(
    finding: dict[str, Any],
    check_to_korean: dict[str, str],
    check_to_fail_meta: dict[str, dict[str, str]],
    check_to_attack_meta: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    cid = finding.get("check_id")
    attack_meta = check_to_attack_meta.get(cid) if isinstance(cid, str) else {}
    fail_meta = check_to_fail_meta.get(cid) if isinstance(cid, str) else {}
    return {
        "check_id": cid,
        "check_name": finding.get("check_name"),
        "check_name_ko": check_to_korean.get(cid) if isinstance(cid, str) else None,
        "severity": fail_meta.get("severity") or finding.get("severity"),
        "why_fails": fail_meta.get("why_fails"),
        "mitigation": fail_meta.get("mitigation"),
        "mitre_tactic": attack_meta.get("mitre_tactic"),
        "atomic_ids": attack_meta.get("atomic_ids", []),
        "representative_atomic_id": attack_meta.get("representative_atomic_id"),
        "capability_key": attack_meta.get("capability_key"),
        "capability": attack_meta.get("capability"),
        "group_type": attack_meta.get("group_type"),
        "resource_address": finding.get("resource_address") or finding.get("resource"),
        "file_abs_path": finding.get("file_abs_path"),
        "evaluated_keys": finding.get("evaluated_keys"),
    }


def _severity_score(value: Any) -> int:
    text = str(value or "").strip().upper()
    return SEVERITY_RANK.get(text, -1)


def _evidence_sort_key(evidence: dict[str, Any]) -> tuple[int, int, int, int, str]:
    group_type = str(evidence.get("group_type") or "").strip().lower()
    is_specific = 1 if group_type == "specific" else 0
    severity = _severity_score(evidence.get("severity"))
    has_atomic = 1 if evidence.get("representative_atomic_id") else 0
    has_tactic = 1 if str(evidence.get("mitre_tactic") or "").strip() else 0
    check_id = str(evidence.get("check_id") or "")
    return (is_specific, severity, has_atomic, has_tactic, check_id)


def _pick_representative_evidence(
    evidences: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not evidences:
        return None
    return max(evidences, key=_evidence_sort_key)


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in out:
            out.append(text)
    return out


def _build_attack_chains(
    stage_details: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    attack_tactic_chain: list[str] = []
    atomic_chain: list[str] = []
    for detail in stage_details:
        if not isinstance(detail, dict):
            continue
        rep = detail.get("representative_evidence")
        if not isinstance(rep, dict):
            preview = detail.get("evidence_preview") or []
            rep = preview[0] if isinstance(preview, list) and preview else None
        if not isinstance(rep, dict):
            continue
        tactic = str(rep.get("mitre_tactic") or "").strip()
        if tactic:
            attack_tactic_chain.append(tactic)
        rep_atomic = str(rep.get("representative_atomic_id") or "").strip()
        if rep_atomic:
            atomic_chain.append(rep_atomic)
            continue
        atomic_ids = rep.get("atomic_ids") or []
        if isinstance(atomic_ids, list) and atomic_ids:
            atomic_chain.append(str(atomic_ids[0]))
    return _dedupe_preserve_order(attack_tactic_chain), _dedupe_preserve_order(
        atomic_chain
    )


def _build_scenario_text(
    path_nodes: list[str], stage_details: list[dict[str, Any]]
) -> str:
    # 리소스명을 넣은 한국어 시나리오 문장 생성
    if not path_nodes:
        return ""
    entry = path_nodes[0]
    target = path_nodes[-1]
    if not stage_details:
        return f"{entry}에서 시작해 {target}까지 도달 가능한 경로입니다."

    parts: list[str] = []
    for idx, s in enumerate(stage_details):
        rank = s.get("stage_rank")
        resource = s.get("resource")
        stage_ko = STAGE_LABELS_KO.get(rank, str(s.get("stage", "단계")))
        rep = s.get("representative_evidence")
        if not isinstance(rep, dict):
            ev = s.get("evidence_preview", [])
            rep = ev[0] if isinstance(ev, list) and ev else None
        if isinstance(rep, dict):
            e0 = rep
            check_name = (
                e0.get("check_name_ko")
                or e0.get("check_name")
                or e0.get("check_id")
                or "-"
            )
            check_name_en = e0.get("check_name") or e0.get("check_id") or "-"
            resource_address = e0.get("resource_address") or resource or "-"
            file_abs_path = e0.get("file_abs_path") or "-"
            severity = e0.get("severity") or "-"
            why_fails = e0.get("why_fails") or "-"
            mitigation = e0.get("mitigation") or "-"
            mitre_tactic = e0.get("mitre_tactic") or "-"
            atomic_ids = e0.get("atomic_ids") or []
            representative_atomic = e0.get("representative_atomic_id")
            atomic_text = (
                str(representative_atomic).strip()
                if representative_atomic
                else (", ".join(str(x) for x in atomic_ids) if atomic_ids else "-")
            )
            evaluated_keys = e0.get("evaluated_keys")
            if isinstance(evaluated_keys, list):
                eval_text = ", ".join(str(k) for k in evaluated_keys[:2])
                if len(evaluated_keys) > 2:
                    eval_text += f" 외 {len(evaluated_keys)-2}개"
            else:
                eval_text = "-"
            parts.append(
                f"[{idx+1}] {stage_ko}\n"
                f"  - resource: `{resource}`\n"
                f"  - check: `{check_name}`\n"
                f"  - check_id: `{e0.get('check_id') or '-'}`\n"
                f"  - check_name_en: `{check_name_en}`\n"
                f"  - severity: `{severity}`\n"
                f"  - mitre_tactic: `{mitre_tactic}`\n"
                f"  - representative_atomic_id: `{atomic_text}`\n"
                f"  - why_fails: {why_fails}\n"
                f"  - mitigation: {mitigation}\n"
                f"  - resource_address: `{resource_address}`\n"
                f"  - file: `{file_abs_path}`\n"
                f"  - evaluated_keys: `{eval_text}`"
            )
        else:
            parts.append(
                f"[{idx+1}] {stage_ko}\n"
                f"  - resource: `{resource}`\n"
                f"  - note: 이슈가 관찰됩니다"
            )

    flow_text = "\n\n".join(parts)
    return f"`{entry}` -> `{target}` 경로입니다.\n\n" f"{flow_text}"


def _format_drop_reasons(drop_reasons: dict[str, Any]) -> list[str]:
    if not isinstance(drop_reasons, dict) or not drop_reasons:
        return ["- 없음"]
    lines: list[str] = []
    for reason, count in sorted(drop_reasons.items()):
        reason_ko = DROP_REASON_LABELS_KO.get(reason, reason)
        lines.append(f"- `{reason_ko}` (`{reason}`): {count}")
    return lines


def _format_stage_sequence(stage_sequence: Any) -> str:
    if not isinstance(stage_sequence, list) or not stage_sequence:
        return "-"
    parts: list[str] = []
    for rank in stage_sequence:
        label = STAGE_LABELS_KO.get(rank, str(rank))
        parts.append(f"{rank}:{label}")
    return " -> ".join(parts)


def _classify_attack_path(
    path_nodes: list[str],
    check_ids: set[str],
    check_to_stage_rank: dict[str, int],
) -> tuple[str, str]:
    ranks = {
        check_to_stage_rank[cid]
        for cid in check_ids
        if isinstance(cid, str) and cid in check_to_stage_rank
    }

    has_network_resource = any(
        node.startswith(NETWORK_RESOURCE_PREFIXES) for node in path_nodes
    )
    has_iam_resource = any(
        node.startswith(IAM_RESOURCE_PREFIXES) for node in path_nodes
    )
    has_compute_resource = any(
        node.startswith(COMPUTE_RESOURCE_PREFIXES) for node in path_nodes
    )

    has_initial_access = 0 in ranks
    has_iam_vector = 1 in ranks

    if (
        has_initial_access
        and has_network_resource
        and (has_iam_resource or has_iam_vector)
    ):
        code = "network_to_iam_chain"
    elif has_iam_resource or has_iam_vector:
        code = "iam_privilege_chain"
    elif has_initial_access and (has_network_resource or has_compute_resource):
        code = "network_exposure_chain"
    else:
        code = "other_chain"

    return code, PATH_CATEGORY_LABELS_KO.get(code, code)


def _format_path_markdown(
    title: str, paths: list[dict[str, Any]], limit: int = 20
) -> list[str]:
    lines = [f"## {title}", ""]
    if not paths:
        lines.extend(["- 없음", ""])
        return lines

    ordered_paths = sorted(
        paths,
        key=lambda item: (
            -item.get("hops", 0) if isinstance(item.get("hops"), int) else 0,
            str(item.get("from", "")),
            str(item.get("to", "")),
        ),
    )

    lines.append(f"- 개수: {len(paths)}")
    lines.append("")

    for idx, item in enumerate(ordered_paths[:limit], start=1):
        path_nodes = item.get("path_evaluated") or item.get("path") or []
        path_text = " -> ".join(path_nodes) if isinstance(path_nodes, list) else "-"
        check_ids = item.get("check_ids", [])
        scenario_llm = item.get("attack_scenario_llm")
        mitigation_llm = item.get("mitigation_llm")
        if isinstance(check_ids, list) and check_ids:
            checks_text = ", ".join(str(x) for x in check_ids[:8])
            if len(check_ids) > 8:
                checks_text += f" 외 {len(check_ids) - 8}개"
        else:
            checks_text = "-"

        lines.append(f"### {idx}. `{item.get('from', '-')}` -> `{item.get('to', '-')}`")
        lines.append("")
        lines.append(f"- Hops: {item.get('hops', '-')}")
        lines.append(
            f"- Path category: `{item.get('path_category_ko', item.get('path_category', '-'))}`"
        )
        if isinstance(scenario_llm, str) and scenario_llm.strip():
            lines.append("- 요약")
            lines.append(f"  - Scenario (LLM): {scenario_llm}")
            if isinstance(mitigation_llm, str) and mitigation_llm.strip():
                lines.append(f"  - Mitigation (LLM): {mitigation_llm}")
        lines.append(
            f"- Stage sequence: {_format_stage_sequence(item.get('stage_sequence'))}"
        )
        lines.append(
            f"- Findings: {item.get('finding_count', 0)} unique / {item.get('raw_finding_count', 0)} raw"
        )
        attack_tactic_chain = item.get("attack_tactic_chain", [])
        if isinstance(attack_tactic_chain, list) and attack_tactic_chain:
            lines.append(
                f"- ATT&CK chain: {', '.join(str(x) for x in attack_tactic_chain)}"
            )
        atomic_chain = item.get("atomic_chain", [])
        if isinstance(atomic_chain, list) and atomic_chain:
            lines.append(f"- Atomic chain: {', '.join(str(x) for x in atomic_chain)}")
        lines.append(f"- Checks: {checks_text}")
        lines.append(f"- Path: `{path_text}`")
        scenario = item.get("attack_scenario")
        if isinstance(scenario, str) and scenario.strip():
            lines.append(f"- Scenario: {scenario}")
        lines.append("")

    if len(ordered_paths) > limit:
        lines.append(f"- ... {len(ordered_paths) - limit}개 경로는 생략")
        lines.append("")

    return lines


def _format_dropped_markdown(
    title: str, paths: list[dict[str, Any]], limit: int = 20
) -> list[str]:
    lines = [f"## {title}", ""]
    if not paths:
        lines.extend(["- 없음", ""])
        return lines

    ordered_paths = sorted(
        paths,
        key=lambda item: (
            -item.get("hops", 0) if isinstance(item.get("hops"), int) else 0,
            str(item.get("from", "")),
            str(item.get("to", "")),
        ),
    )

    lines.append(f"- Count: {len(paths)}")
    lines.append("")

    for idx, item in enumerate(ordered_paths[:limit], start=1):
        path_nodes = item.get("path") or []
        path_text = " -> ".join(path_nodes) if isinstance(path_nodes, list) else "-"
        lines.append(f"### {idx}. `{item.get('from', '-')}` -> `{item.get('to', '-')}`")
        lines.append("")
        lines.append(f"- Hops: {item.get('hops', '-')}")
        reason = item.get("reason", "-")
        reason_ko = DROP_REASON_LABELS_KO.get(reason, reason)
        lines.append(f"- Reason: `{reason_ko}`")
        lines.append(f"- Path: `{path_text}`")
        lines.append("")

    if len(ordered_paths) > limit:
        lines.append(f"- ... {len(ordered_paths) - limit}개 경로는 생략")
        lines.append("")

    return lines


def _path_dedup_key(item: dict[str, Any]) -> tuple[str, ...]:
    path_nodes = item.get("path_evaluated") or item.get("path") or []
    if not isinstance(path_nodes, list):
        return tuple()
    return tuple(str(x) for x in path_nodes)


def _scenario_dedup_key(item: dict[str, Any]) -> tuple[Any, ...]:
    stage_sequence = item.get("stage_sequence") or []
    if not isinstance(stage_sequence, list):
        stage_sequence = []

    stage_details = item.get("stage_details") or []
    normalized_details: list[tuple[Any, str, tuple[str, ...]]] = []
    if isinstance(stage_details, list):
        for detail in stage_details:
            if not isinstance(detail, dict):
                continue
            rank = detail.get("stage_rank")
            resource = str(detail.get("resource", ""))
            check_ids = detail.get("check_ids") or []
            if not isinstance(check_ids, list):
                check_ids = []
            normalized_details.append(
                (
                    rank,
                    resource,
                    tuple(sorted(str(cid) for cid in check_ids)),
                )
            )

    return (
        str(item.get("path_category", "")),
        tuple(stage_sequence),
        tuple(normalized_details),
    )


def _endpoint_priority(node_id: str) -> int:
    for prefixes, score in ATTACK_ENDPOINT_PRIORITY:
        if node_id.startswith(prefixes):
            return score
    return 0


def _representative_score(item: dict[str, Any]) -> tuple[int, int, int, int, str, str]:
    path_nodes = item.get("path_evaluated") or item.get("path") or []
    if not isinstance(path_nodes, list):
        path_nodes = []

    start_node = str(path_nodes[0]) if path_nodes else ""
    end_node = str(path_nodes[-1]) if path_nodes else ""
    endpoint_score = max(_endpoint_priority(start_node), _endpoint_priority(end_node))
    hops = item.get("hops", 0) if isinstance(item.get("hops"), int) else 0
    finding_count = (
        item.get("finding_count", 0)
        if isinstance(item.get("finding_count"), int)
        else 0
    )
    raw_finding_count = (
        item.get("raw_finding_count", 0)
        if isinstance(item.get("raw_finding_count"), int)
        else 0
    )
    return (
        endpoint_score,
        hops,
        finding_count,
        raw_finding_count,
        start_node,
        end_node,
    )


def _format_category_counts(category_counts: dict[str, Any]) -> list[str]:
    if not isinstance(category_counts, dict) or not category_counts:
        return ["- 없음"]
    lines: list[str] = []
    ordered_codes = [
        code for code in PATH_CATEGORY_ORDER if code in category_counts
    ] + sorted(code for code in category_counts if code not in PATH_CATEGORY_ORDER)
    for code in ordered_codes:
        count = category_counts.get(code, 0)
        label = PATH_CATEGORY_LABELS_KO.get(code, code)
        lines.append(f"- `{label}` (`{code}`): {count}")
    return lines


def _group_paths_by_category(
    paths: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {
        code: [] for code in PATH_CATEGORY_ORDER
    }
    for item in paths:
        if not isinstance(item, dict):
            continue
        code = item.get("path_category")
        if not isinstance(code, str) or not code:
            code = "other_chain"
        grouped.setdefault(code, []).append(item)
    return grouped


def _build_markdown_report(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    checkov_summary = summary.get("checkov", {})
    severity_summary = summary.get("severity_counts", {})
    critical_findings = summary.get("critical_findings", {})
    dfs_summary = summary.get("dfs_paths", {})
    grouped_validated = result.get("dfs_all_paths_validated_by_category", {})

    lines = [
        "# IaC Graph Checkov Paths Report",
        "",
        "## Sources",
        "",
        f"- Graph: `{result.get('source_graph', '-')}`",
        f"- Checkov: `{result.get('source_checkov', '-')}`",
        "",
        "## Summary",
        "",
        f"- Checkov indexed nodes: {checkov_summary.get('indexed_nodes', 0)}",
        f"- Checkov failed checks: {checkov_summary.get('failed_checks_total', 0)}",
        f"- CRITICAL findings: {severity_summary.get('CRITICAL', 0)}",
        f"- DFS validated: {dfs_summary.get('paths_validated', 0)} / {dfs_summary.get('paths_total', 0)}",
        f"- Max hops: {summary.get('max_hops', '-')}",
        "",
    ]

    if isinstance(critical_findings, list) and critical_findings:
        lines.extend(["### CRITICAL Finding Details", ""])
        for item in critical_findings:
            if not isinstance(item, dict):
                continue
            check_id = item.get("check_id", "-")
            file_path = item.get("file", "-")
            issue = item.get("issue", "-")
            lines.append(f"- `{check_id}` | `{file_path}` | {issue}")
        lines.append("")

    lines.extend(
        [
            "## Path Categories",
            "",
            *_format_category_counts(dfs_summary.get("category_counts", {})),
            "",
        ]
    )

    lines.extend(["## DFS Validated Paths By Category", ""])
    for code in PATH_CATEGORY_ORDER:
        label = PATH_CATEGORY_LABELS_KO.get(code, code)
        lines.extend(
            _format_path_markdown(
                f"{label}",
                grouped_validated.get(code, []),
            )
        )

    lines.extend(
        [
            "## Drop Reasons",
            "",
            "### DFS",
            "",
            *_format_drop_reasons(dfs_summary.get("drop_reasons", {})),
            "",
        ]
    )
    lines.extend(
        _format_dropped_markdown(
            "DFS Dropped Paths",
            result.get("dfs_all_paths_dropped", []),
        )
    )
    return "\n".join(lines).rstrip() + "\n"


def _filter_and_annotate_paths(
    paths: list[dict[str, Any]],
    checkov_index: dict[str, list[dict[str, Any]]],
    check_to_stage_rank: dict[str, int],
    check_to_korean: dict[str, str],
    check_to_fail_meta: dict[str, dict[str, str]],
    check_to_attack_meta: dict[str, dict[str, Any]],
    max_hops: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    validated_candidates: list[dict[str, Any]] = []
    validated: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    reasons: dict[str, int] = {}
    seen_validated_keys: set[tuple[str, ...]] = set()

    def drop(item: dict[str, Any], reason: str) -> None:
        reasons[reason] = reasons.get(reason, 0) + 1
        dropped.append(
            {
                "from": item.get("from"),
                "to": item.get("to"),
                "hops": item.get("hops"),
                "reason": reason,
                "path": item.get("path"),
            }
        )

    for item in paths:
        if not isinstance(item, dict):
            continue
        path_nodes = item.get("path", [])
        if not isinstance(path_nodes, list) or not all(
            isinstance(n, str) for n in path_nodes
        ):
            continue

        # (1) 경로 유효성 필터(너무 긴건 빼기)
        ok, reason = _is_path_runtime_valid(path_nodes)
        if not ok:
            drop(item, reason or "invalid_path")
            continue
        hops = item.get("hops")
        if isinstance(hops, int) and hops > max_hops:
            drop(item, "hops_exceeded")
            continue

        # (2) 체크-노드 타입 정합성 + (4) 중복 제거
        node_findings: list[dict[str, Any]] = []
        unique_check_ids: set[str] = set()
        raw_finding_count = 0

        for node_id in path_nodes:
            findings = checkov_index.get(node_id, [])
            if not findings:
                continue

            node_type = _resource_type(node_id)
            dedup_by_check: dict[str, dict[str, Any]] = {}
            for f in findings:
                # finding.resource 타입과 현재 node 타입이 일치하는 것만 통과
                norm_res = f.get("normalized_resource")
                norm_type = (
                    _resource_type(norm_res) if isinstance(norm_res, str) else None
                )
                if norm_type != node_type:
                    continue
                cid = f.get("check_id")
                if isinstance(cid, str):
                    dedup_by_check[cid] = f
                    unique_check_ids.add(cid)
            filtered = [dedup_by_check[c] for c in sorted(dedup_by_check.keys())]
            if filtered:
                raw_finding_count += len(filtered)
                node_findings.append({"node": node_id, "findings": filtered})

        if not unique_check_ids:
            drop(item, "no_findings_on_path")
            continue

        # (3) 공격 단계 정합성 필터
        eval_path_nodes, stage_seq, selected_direction = _select_path_orientation(
            path_nodes, node_findings, check_to_stage_rank
        )
        if not stage_seq:
            raw_stage_seq = _stage_sequence_from_path(
                path_nodes, node_findings, check_to_stage_rank
            )
            if not raw_stage_seq:
                drop(item, "no_attack_stage")
            elif len(set(raw_stage_seq)) < 2:
                drop(item, "insufficient_stage_progress")
            else:
                drop(item, "stage_order_violation")
            continue

        stage_details = _build_stage_details(
            eval_path_nodes,
            node_findings,
            check_to_stage_rank,
            check_to_korean,
            check_to_fail_meta,
            check_to_attack_meta,
        )
        enriched = dict(item)
        # unique check 기준으로 과대계산 방지
        enriched["finding_count"] = len(unique_check_ids)
        enriched["raw_finding_count"] = raw_finding_count
        enriched["check_ids"] = sorted(unique_check_ids)
        enriched["stage_sequence"] = stage_seq
        enriched["stage_details"] = stage_details
        enriched["path_evaluated"] = eval_path_nodes
        enriched["path_direction"] = selected_direction
        category_code, category_ko = _classify_attack_path(
            eval_path_nodes, unique_check_ids, check_to_stage_rank
        )
        enriched["path_category"] = category_code
        enriched["path_category_ko"] = category_ko
        attack_tactic_chain, atomic_chain = _build_attack_chains(stage_details)
        enriched["attack_tactic_chain"] = attack_tactic_chain
        enriched["atomic_chain"] = atomic_chain
        enriched["attack_scenario"] = _build_scenario_text(
            eval_path_nodes, stage_details
        )
        enriched["node_findings"] = node_findings
        dedup_key = _path_dedup_key(enriched)
        if dedup_key in seen_validated_keys:
            drop(item, "duplicate_path")
            continue
        seen_validated_keys.add(dedup_key)
        validated_candidates.append(enriched)

    scenario_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for item in validated_candidates:
        scenario_groups.setdefault(_scenario_dedup_key(item), []).append(item)

    category_counts: dict[str, int] = {}
    for group_items in scenario_groups.values():
        representative = max(group_items, key=_representative_score)
        llm_summary = summarize_with_llm(representative)
        representative["attack_scenario_llm"] = llm_summary["attack_scenario_one_liner"]
        representative["mitigation_llm"] = llm_summary["mitigation_one_liner"]
        validated.append(representative)
        category_code = representative.get("path_category")
        if isinstance(category_code, str):
            category_counts[category_code] = category_counts.get(category_code, 0) + 1

        for item in group_items:
            if item is representative:
                continue
            drop(item, "duplicate_scenario")

    summary = {
        "paths_total": len(validated) + len(dropped),
        "paths_validated": len(validated),
        "paths_dropped": len(dropped),
        "drop_reasons": reasons,
        "category_counts": category_counts,
    }
    return validated, dropped, summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Map Checkov failed checks to IaC graph paths."
    )
    parser.add_argument(
        "--graph", type=Path, required=True, help="Path to iac_graph.json"
    )
    parser.add_argument(
        "--checkov-merged", type=Path, required=True, help="Path to checkov_merged.json"
    )
    parser.add_argument(
        "--checkov-id-catalog",
        type=Path,
        default=Path("src/secugate/rules/checkov_id_catalog.json"),
        help="Fallback path to checkov_id_catalog.json when attack_mapping stage is missing",
    )
    parser.add_argument(
        "--attack-mapping",
        type=Path,
        default=Path("src/secugate/rules/attack_mapping.json"),
        help="Path to attack_mapping.json (primary source for attack stage)",
    )
    parser.add_argument(
        "--checkov-korean-labels",
        type=Path,
        default=Path("src/secugate/rules/checkov_korean_labels.json"),
        help="Path to checkov_korean_labels.json (editable Korean labels by check_id)",
    )
    parser.add_argument(
        "--checkov-fail-condition",
        type=Path,
        default=Path("src/secugate/rules/checkov_fail_condition.json"),
        help="Fallback path to checkov_fail_condition.json",
    )
    parser.add_argument(
        "--resource-classification",
        type=Path,
        default=Path("src/secugate/rules/resource_classification.json"),
        help="Path to resource_classification.json for resource prefix/category rules",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=6,
        help="Max hops allowed for path validation",
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Output path for mapped json"
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        help="Optional output path for a human-readable markdown report",
    )
    args = parser.parse_args()

    _load_resource_classification(args.resource_classification)
    graph = _load_json(args.graph)
    checkov = _load_json(args.checkov_merged)
    check_to_stage_rank = _load_check_stage_index(
        args.attack_mapping, args.checkov_id_catalog
    )
    check_to_korean = _load_checkov_korean_index(
        args.checkov_korean_labels, args.checkov_fail_condition
    )
    check_to_fail_meta = _load_checkov_fail_index(args.checkov_fail_condition)
    check_to_attack_meta = _load_attack_meta_index(args.attack_mapping)

    checkov_index, checkov_summary = _build_checkov_index(checkov)
    severity_counts = _count_findings_by_severity(checkov_index, check_to_fail_meta)
    critical_findings = _collect_critical_findings(checkov_index, check_to_fail_meta)
    dfs_paths = graph.get("dfs_all_paths", [])
    if not isinstance(dfs_paths, list):
        dfs_paths = []

    dfs_valid, dfs_dropped, dfs_summary = _filter_and_annotate_paths(
        dfs_paths,
        checkov_index,
        check_to_stage_rank=check_to_stage_rank,
        check_to_korean=check_to_korean,
        check_to_fail_meta=check_to_fail_meta,
        check_to_attack_meta=check_to_attack_meta,
        max_hops=args.max_hops,
    )
    dfs_grouped_valid = _group_paths_by_category(dfs_valid)

    result = {
        "version": 1,
        "source_graph": str(args.graph),
        "source_checkov": str(args.checkov_merged),
        "summary": {
            "checkov": checkov_summary,
            "severity_counts": severity_counts,
            "critical_findings": critical_findings,
            "dfs_paths": dfs_summary,
            "max_hops": args.max_hops,
        },
        "dfs_all_paths_validated": dfs_valid,
        "dfs_all_paths_validated_by_category": dfs_grouped_valid,
        "dfs_all_paths_dropped": dfs_dropped,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    markdown_output = args.markdown_output or args.output.with_suffix(".md")
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(_build_markdown_report(result), encoding="utf-8")
    print(
        f"ok: dfs_valid={dfs_summary['paths_validated']}/{dfs_summary['paths_total']} "
        f"output={args.output} markdown={markdown_output}"
    )


if __name__ == "__main__":
    main()
