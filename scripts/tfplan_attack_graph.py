from __future__ import annotations

import argparse
import json
from collections import deque
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} JSON root must be an object")
    return data


def _walk_references(value: Any, refs: list[str]) -> None:
    if isinstance(value, dict):
        local_refs = value.get("references")
        if isinstance(local_refs, list):
            for ref in local_refs:
                if isinstance(ref, str) and ref.strip():
                    refs.append(ref.strip())
        for child in value.values():
            _walk_references(child, refs)
    elif isinstance(value, list):
        for child in value:
            _walk_references(child, refs)


# 차후 수정필요......ㅜㅜ
def _normalize_reference(ref: str) -> str | None:
    # 인덱스 표현([0], ["x"])은 잘라서 기준 토큰만 사용
    token = ref.split("[", 1)[0]
    parts = token.split(".")
    if not parts:
        return None

    # data 참조는 data.<type>.<name>까지만 노드 ID로 사용
    if parts[0] == "data" and len(parts) >= 3:
        return ".".join(parts[:3])
    # var/local/path/terraform/count/each는 앞 2단계만 유지
    if (
        parts[0] in {"var", "local", "path", "terraform", "count", "each"}
        and len(parts) >= 2
    ):
        return ".".join(parts[:2])
    # module 참조
    if parts[0] == "module":
        # module.<name>.data.<type>.<name>
        if len(parts) >= 4 and parts[2] in {"data"}:
            return ".".join(parts[:5]) if len(parts) >= 5 else ".".join(parts[:4])
        # module.<name>.<resource_type>.<name>
        if len(parts) >= 4 and "_" in parts[2]:
            return ".".join(parts[:4])
        # 그 외에는 module.<name>만
        if len(parts) >= 2:
            return ".".join(parts[:2])
    # 일반 리소스는 <type>.<name>까지만 노드 ID로
    if len(parts) >= 2:
        return ".".join(parts[:2])
    # 그 외 원문 토큰을 그대로 사용
    return token


def _is_allowed_reference(
    node_id: str, include_vars: bool, include_locals: bool, include_data: bool
) -> bool:
    # 옵션에 따라 var/local/data 노드를 그래프에 포함할지 결정
    if node_id.startswith("var."):
        return include_vars
    if node_id.startswith("local."):
        return include_locals
    if node_id.startswith("data."):
        return include_data
    return True


def _collect_resources(plan: dict[str, Any]) -> list[dict[str, Any]]:
    # tfplan.configuration.root_module.resources만 추출
    root_module = plan.get("configuration", {}).get("root_module", {})
    resources = root_module.get("resources", [])
    if not isinstance(resources, list):
        return []
    return [r for r in resources if isinstance(r, dict)]


def _build_graph(
    plan: dict[str, Any],
    include_vars: bool,
    include_locals: bool,
    include_data: bool,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    # nodes: address -> node 메타데이터
    # edge_set: 중복 제거를 위한 (from, to) 집합
    nodes: dict[str, dict[str, Any]] = {}
    edge_set: set[tuple[str, str]] = set()

    # 1) 리소스 address를 노드로 생성
    for resource in _collect_resources(plan):
        address = resource.get("address")
        if not isinstance(address, str) or not address:
            continue
        nodes[address] = {
            "id": address,
            "type": resource.get("type"),
            "mode": resource.get("mode"),
            "provider": resource.get("provider_config_key"),
            "capabilities": [],
            "check_ids": [],
        }

    # 2) expressions.references를 기반으로 엣지 생성
    for resource in _collect_resources(plan):
        from_addr = resource.get("address")
        if not isinstance(from_addr, str) or from_addr not in nodes:
            continue
        references: list[str] = []
        _walk_references(resource.get("expressions", {}), references)

        for raw_ref in references:
            # reference 문자열을 노드 주소 수준으로 정규화
            to_addr = _normalize_reference(raw_ref)
            if not to_addr:
                continue
            if not _is_allowed_reference(
                to_addr,
                include_vars=include_vars,
                include_locals=include_locals,
                include_data=include_data,
            ):
                continue
            # tfplan에 없던 참조 노드는 placeholder 노드로 추가
            if to_addr not in nodes:
                nodes[to_addr] = {
                    "id": to_addr,
                    "type": None,
                    "mode": None,
                    "provider": None,
                    "capabilities": [],
                    "check_ids": [],
                }
            edge_set.add((from_addr, to_addr))

    # 최종 엣지 목록을 정렬된 배열로 변환
    edges = [{"from": src, "to": dst} for src, dst in sorted(edge_set)]
    return nodes, edges


def _load_check_id_to_capabilities(rules_path: Path | None) -> dict[str, set[str]]:
    # attack_mapping.json(normalize)에서 check_id -> capability 집합 생성
    if rules_path is None:
        return {}
    rules = _load_json(rules_path)
    normalize = rules.get("normalize", [])
    if not isinstance(normalize, list):
        return {}

    mapping: dict[str, set[str]] = {}
    for rule in normalize:
        if not isinstance(rule, dict):
            continue
        cap = (
            # 스키마 변형 대응: capability_key > capability > capability_id 순서로 사용
            str(rule.get("capability_key", "")).strip()
            or str(rule.get("capability", "")).strip()
            or str(rule.get("capability_id", "")).strip()
        )
        if not cap:
            continue
        for check_id in rule.get("check_ids") or []:
            check_key = str(check_id).strip()
            if not check_key:
                continue
            mapping.setdefault(check_key, set()).add(cap)
    return mapping


def _tag_nodes_with_findings(
    nodes: dict[str, dict[str, Any]],
    checkov_path: Path | None,
    check_id_to_caps: dict[str, set[str]],
) -> None:
    # checkov failed_checks를 읽어 resource 노드에 check_id/capability 태그를 부착
    if checkov_path is None:
        return
    checkov = _load_json(checkov_path)
    root = checkov.get("results")
    if not isinstance(root, dict):
        root = checkov
    failed = root.get("failed_checks") or []
    if not isinstance(failed, list):
        return

    for finding in failed:
        if not isinstance(finding, dict):
            continue
        # finding.resource 문자열을 노드 ID로 사용 (예: aws_security_group.ec2_server)
        resource = finding.get("resource")
        if not isinstance(resource, str) or not resource:
            continue
        check_id = str(finding.get("check_id", "")).strip()
        if not check_id:
            continue

        # 그래프에 없던 리소스도 추적을 위해 placeholder 노드로 추가
        if resource not in nodes:
            nodes[resource] = {
                "id": resource,
                "type": None,
                "mode": None,
                "provider": None,
                "capabilities": [],
                "check_ids": [],
            }

        # 중복 없이 check_id/capability를 누적
        node = nodes[resource]
        if check_id not in node["check_ids"]:
            node["check_ids"].append(check_id)
        for cap in sorted(check_id_to_caps.get(check_id, set())):
            if cap not in node["capabilities"]:
                node["capabilities"].append(cap)


def _build_undirected_adjacency(edges: list[dict[str, str]]) -> dict[str, set[str]]:
    # 경로 탐색용으로 방향 그래프를 무방향 인접 리스트로 변환
    graph: dict[str, set[str]] = {}
    for edge in edges:
        src = edge["from"]
        dst = edge["to"]
        graph.setdefault(src, set()).add(dst)
        graph.setdefault(dst, set()).add(src)
    return graph


def _shortest_path(
    graph: dict[str, set[str]],
    start: str,
    goal: str,
    max_depth: int,
) -> list[str] | None:
    # BFS로 최단 경로 탐색 (max_depth 제한 포함)
    if start == goal:
        return [start]
    queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
    visited = {start}

    while queue:
        current, path = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue
        for nxt in graph.get(current, set()):
            if nxt in visited:
                continue
            new_path = path + [nxt]
            if nxt == goal:
                return new_path
            visited.add(nxt)
            queue.append((nxt, new_path))
    return None


def _find_paths(
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, str]],
    max_depth: int,
) -> list[dict[str, Any]]:
    # 엔트리포인트 capability(외부 노출) 기준 시작 노드 정의
    entry_caps = {
        "sg_ingress_ssh_open",
        "sg_ingress_http_open",
        "ec2_public_ip_exposed",
        "subnet_auto_public_ip",
    }
    # 시작 노드: 퍼블릭 노출 성격 capability가 붙은 노드
    entry_nodes = [
        node_id
        for node_id, node in nodes.items()
        if set(node.get("capabilities", [])) & entry_caps
    ]
    # 도착 노드: IAM 관련 capability가 붙은 노드
    iam_nodes = [
        node_id
        for node_id, node in nodes.items()
        if any(cap.startswith("iam_") for cap in node.get("capabilities", []))
    ]

    # 엔트리 -> IAM 경로를 중복 제거하며 수집
    graph = _build_undirected_adjacency(edges)
    out: list[dict[str, Any]] = []
    seen_paths: set[tuple[str, ...]] = set()

    for src in sorted(entry_nodes):
        for dst in sorted(iam_nodes):
            path = _shortest_path(graph, src, dst, max_depth=max_depth)
            if not path:
                continue
            key = tuple(path)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            out.append(
                {
                    "from": src,
                    "to": dst,
                    "hops": len(path) - 1,
                    "path": path,
                }
            )
    return sorted(out, key=lambda x: (x["hops"], x["from"], x["to"]))


def main() -> None:
    # CLI 인자 정의
    parser = argparse.ArgumentParser(
        description="Build attack graph from tfplan.json references and optional Checkov findings.",
    )
    parser.add_argument(
        "--tfplan", type=Path, required=True, help="Path to terraform plan json"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Output path for graph json"
    )
    parser.add_argument(
        "--checkov", type=Path, default=None, help="Optional checkov merged json path"
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="Optional attack mapping rules json path",
    )
    parser.add_argument(
        "--include-vars",
        action="store_true",
        help="Include var.* references as graph nodes",
    )
    parser.add_argument(
        "--include-locals",
        action="store_true",
        help="Include local.* references as graph nodes",
    )
    parser.add_argument(
        "--exclude-data",
        action="store_true",
        help="Exclude data.* references from graph nodes",
    )
    parser.add_argument(
        "--max-path-depth",
        type=int,
        default=6,
        help="Max depth for entrypoint->IAM path search (undirected).",
    )
    args = parser.parse_args()

    # 1) tfplan에서 그래프(노드/엣지) 생성
    tfplan = _load_json(args.tfplan)
    nodes, edges = _build_graph(
        tfplan,
        include_vars=args.include_vars,
        include_locals=args.include_locals,
        include_data=not args.exclude_data,
    )

    # 2) rules/checkov가 있으면 capability 태깅
    check_id_to_caps = _load_check_id_to_capabilities(args.rules)
    _tag_nodes_with_findings(nodes, args.checkov, check_id_to_caps)
    # 3) 엔트리 -> IAM 경로 탐색
    paths = _find_paths(nodes, edges, max_depth=args.max_path_depth)

    # 4) 결과 JSON 구성
    result = {
        "version": 1,
        "source": str(args.tfplan),
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "entry_to_iam_paths": len(paths),
        },
        "nodes": [nodes[node_id] for node_id in sorted(nodes.keys())],
        "edges": edges,
        "entry_to_iam_paths": paths,
    }

    # 5) 파일 저장 및 요약 출력
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        f"ok: nodes={result['summary']['nodes']} "
        f"edges={result['summary']['edges']} "
        f"paths={result['summary']['entry_to_iam_paths']} "
        f"output={args.output}"
    )


if __name__ == "__main__":
    main()
