from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

NON_RUNTIME_PREFIXES = ("data.", "var.", "local.", "module.", "path.", "terraform.", "count.", "each.")

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
    "data_protection_and_encryption_posture": 3,
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


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} JSON root must be an object")
    return data


def _normalize_resource_id(resource_id: str) -> str | None:
    token = resource_id.split("[", 1)[0]
    parts = token.split(".")
    if not parts:
        return None

    if parts[0] == "data" and len(parts) >= 3:
        return ".".join(parts[:3])
    if parts[0] in {"var", "local", "path", "terraform", "count", "each"} and len(parts) >= 2:
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


def _build_checkov_index(checkov_merged: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    results = checkov_merged.get("results", {})
    failed_checks = results.get("failed_checks", []) if isinstance(results, dict) else []
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
                "resource_address": finding.get("resource_address") or finding.get("resource"),
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


def _resource_type(node_id: str) -> str:
    return node_id.split(".", 1)[0] if "." in node_id else node_id


def _is_path_runtime_valid(path_nodes: list[str]) -> tuple[bool, str | None]:
    # (1) 경로 유효성 필터
    if not path_nodes:
        return False, "empty_path"
    if not all(isinstance(n, str) and n for n in path_nodes):
        return False, "invalid_node_id"
    if not path_nodes[0].startswith("aws_") or not path_nodes[-1].startswith("aws_"):
        return False, "non_runtime_endpoint"
    if any(n.startswith(NON_RUNTIME_PREFIXES) for n in path_nodes):
        return False, "contains_non_runtime_node"
    return True, None


def _stage_sequence_from_path(
    path_nodes: list[str],
    node_findings: list[dict[str, Any]],
    check_to_vector: dict[str, str],
) -> list[int]:
    # 경로 노드 순서대로 체크 벡터를 단계(rank) 시퀀스로 변환
    findings_by_node = {x["node"]: x["findings"] for x in node_findings if isinstance(x, dict) and "node" in x}
    raw_ranks: list[int] = []
    for node in path_nodes:
        findings = findings_by_node.get(node, [])
        node_ranks: list[int] = []
        for f in findings:
            cid = f.get("check_id")
            if not isinstance(cid, str):
                continue
            vector = check_to_vector.get(cid)
            if not vector:
                continue
            rank = VECTOR_STAGE_RANK.get(vector)
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


def _build_stage_details(
    path_nodes: list[str],
    node_findings: list[dict[str, Any]],
    check_to_vector: dict[str, str],
) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    findings_by_node = {x["node"]: x["findings"] for x in node_findings if isinstance(x, dict) and "node" in x}

    for node in path_nodes:
        findings = findings_by_node.get(node, [])
        if not findings:
            continue

        stage_to_checks: dict[int, set[str]] = {}
        for f in findings:
            cid = f.get("check_id")
            if not isinstance(cid, str):
                continue
            vector = check_to_vector.get(cid)
            if not vector:
                continue
            rank = VECTOR_STAGE_RANK.get(vector)
            if rank is None:
                continue
            stage_to_checks.setdefault(rank, set()).add(cid)

        for rank, cids in sorted(stage_to_checks.items()):
            # 단계별 대표 증거 2개만 추출
            evidence_preview: list[dict[str, Any]] = []
            for f in findings:
                cid = f.get("check_id")
                if not isinstance(cid, str) or cid not in cids:
                    continue
                evidence_preview.append(
                    {
                        "check_id": cid,
                        "check_name": f.get("check_name"),
                        "resource_address": f.get("resource_address") or f.get("resource"),
                        "file_abs_path": f.get("file_abs_path"),
                        "evaluated_keys": f.get("evaluated_keys"),
                    }
                )
            evidence_preview = evidence_preview[:2]
            details.append(
                {
                    "stage_rank": rank,
                    "stage": STAGE_LABELS.get(rank, f"stage_{rank}"),
                    "resource": node,
                    "check_ids": sorted(cids),
                    "evidence_preview": evidence_preview,
                }
            )

    return details


def _build_scenario_text(path_nodes: list[str], stage_details: list[dict[str, Any]]) -> str:
    # 리소스명을 넣은 한국어 시나리오 문장 생성
    if not path_nodes:
        return ""
    entry = path_nodes[0]
    target = path_nodes[-1]
    if not stage_details:
        return f"{entry}에서 시작해 {target}까지 도달 가능한 경로입니다."

    parts: list[str] = []
    for s in stage_details:
        rank = s.get("stage_rank")
        resource = s.get("resource")
        stage_ko = STAGE_LABELS_KO.get(rank, str(s.get("stage", "단계")))
        ev = s.get("evidence_preview", [])
        if isinstance(ev, list) and ev:
            e0 = ev[0]
            check_name = e0.get("check_name") or e0.get("check_id") or "-"
            resource_address = e0.get("resource_address") or resource or "-"
            file_abs_path = e0.get("file_abs_path") or "-"
            evaluated_keys = e0.get("evaluated_keys")
            if isinstance(evaluated_keys, list):
                eval_text = ", ".join(str(k) for k in evaluated_keys[:2])
                if len(evaluated_keys) > 2:
                    eval_text += f" 외 {len(evaluated_keys)-2}개"
            else:
                eval_text = "-"
            parts.append(
                f"{stage_ko} 단계: `{resource}`에서 `{check_name}` 발견 "
                f"(resource_address={resource_address}, file_abs_path={file_abs_path}, evaluated_keys={eval_text})"
            )
        else:
            parts.append(f"{stage_ko} 단계에서 `{resource}` 이슈가 관찰됩니다")

    flow_text = ". ".join(parts)
    return f"`{entry}`에서 시작해 `{target}`로 이어지는 경로입니다. {flow_text}."


def _filter_and_annotate_paths(
    paths: list[dict[str, Any]],
    checkov_index: dict[str, list[dict[str, Any]]],
    check_to_vector: dict[str, str],
    max_hops: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    validated: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    reasons: dict[str, int] = {}

    def drop(item: dict[str, Any], reason: str) -> None:
        reasons[reason] = reasons.get(reason, 0) + 1
        dropped.append({"from": item.get("from"), "to": item.get("to"), "hops": item.get("hops"), "reason": reason, "path": item.get("path")})

    for item in paths:
        if not isinstance(item, dict):
            continue
        path_nodes = item.get("path", [])
        if not isinstance(path_nodes, list) or not all(isinstance(n, str) for n in path_nodes):
            continue

        # (1) 경로 유효성 필터
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
                norm_type = _resource_type(norm_res) if isinstance(norm_res, str) else None
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
        stage_seq = _stage_sequence_from_path(path_nodes, node_findings, check_to_vector)
        if not stage_seq:
            drop(item, "no_attack_stage")
            continue
        if any(stage_seq[i] > stage_seq[i + 1] for i in range(len(stage_seq) - 1)):
            drop(item, "stage_order_violation")
            continue
        if len(set(stage_seq)) < 2:
            drop(item, "insufficient_stage_progress")
            continue

        stage_details = _build_stage_details(path_nodes, node_findings, check_to_vector)
        enriched = dict(item)
        # unique check 기준으로 과대계산 방지
        enriched["finding_count"] = len(unique_check_ids)
        enriched["raw_finding_count"] = raw_finding_count
        enriched["check_ids"] = sorted(unique_check_ids)
        enriched["stage_sequence"] = stage_seq
        enriched["stage_details"] = stage_details
        enriched["attack_scenario"] = _build_scenario_text(path_nodes, stage_details)
        enriched["node_findings"] = node_findings
        validated.append(enriched)

    summary = {
        "paths_total": len(validated) + len(dropped),
        "paths_validated": len(validated),
        "paths_dropped": len(dropped),
        "drop_reasons": reasons,
    }
    return validated, dropped, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Map Checkov failed checks to IaC graph paths.")
    parser.add_argument("--graph", type=Path, required=True, help="Path to iac_graph.json")
    parser.add_argument("--checkov-merged", type=Path, required=True, help="Path to checkov_merged.json")
    parser.add_argument(
        "--checkov-id-catalog",
        type=Path,
        default=Path("src/secugate/rules/checkov_id_catalog.json"),
        help="Path to checkov_id_catalog.json (for attack-stage consistency)",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=6,
        help="Max hops allowed for path validation",
    )
    parser.add_argument("--output", type=Path, required=True, help="Output path for mapped json")
    args = parser.parse_args()

    graph = _load_json(args.graph)
    checkov = _load_json(args.checkov_merged)
    check_to_vector = _load_checkov_vector_index(args.checkov_id_catalog)

    checkov_index, checkov_summary = _build_checkov_index(checkov)
    dfs_paths = graph.get("dfs_all_paths", [])
    bfs_paths = graph.get("bfs_shortest_paths", [])
    if not isinstance(dfs_paths, list):
        dfs_paths = []
    if not isinstance(bfs_paths, list):
        bfs_paths = []

    dfs_valid, dfs_dropped, dfs_summary = _filter_and_annotate_paths(
        dfs_paths,
        checkov_index,
        check_to_vector=check_to_vector,
        max_hops=args.max_hops,
    )
    bfs_valid, bfs_dropped, bfs_summary = _filter_and_annotate_paths(
        bfs_paths,
        checkov_index,
        check_to_vector=check_to_vector,
        max_hops=args.max_hops,
    )

    result = {
        "version": 1,
        "source_graph": str(args.graph),
        "source_checkov": str(args.checkov_merged),
        "summary": {
            "checkov": checkov_summary,
            "dfs_paths": dfs_summary,
            "bfs_paths": bfs_summary,
            "max_hops": args.max_hops,
        },
        "bfs_shortest_paths_validated": bfs_valid,
        "bfs_shortest_paths_dropped": bfs_dropped,
        "dfs_all_paths_validated": dfs_valid,
        "dfs_all_paths_dropped": dfs_dropped,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"ok: bfs_valid={bfs_summary['paths_validated']}/{bfs_summary['paths_total']} "
        f"dfs_valid={dfs_summary['paths_validated']}/{dfs_summary['paths_total']} "
        f"output={args.output}"
    )


if __name__ == "__main__":
    main()
