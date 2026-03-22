from __future__ import annotations

import argparse
import fnmatch
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    # JSON 파일을 읽고 object(dict) 타입인지 검증
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} JSON root must be an object")
    return data


def _walk_references(value: Any, refs: list[str]) -> None:
    # 중첩 구조(dict/list)를 재귀로 순회하면서 references 배열을 수집
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
    if parts[0] in {"var", "local", "path", "terraform", "count", "each"} and len(parts) >= 2:
        return ".".join(parts[:2])
    # module 참조는 형태가 다양해서 케이스별로 자름
    if parts[0] == "module":
        if len(parts) >= 4 and parts[2] in {"data"}:
            return ".".join(parts[:5]) if len(parts) >= 5 else ".".join(parts[:4])
        if len(parts) >= 4 and "_" in parts[2]:
            return ".".join(parts[:4])
        if len(parts) >= 2:
            return ".".join(parts[:2])
    # 일반 리소스는 <type>.<name>까지만 노드 ID로 사용
    if len(parts) >= 2:
        return ".".join(parts[:2])
    # 예외 케이스는 원문 토큰을 그대로 사용
    return token


def _is_allowed_reference(node_id: str, include_vars: bool, include_locals: bool, include_data: bool) -> bool:
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


def _collect_planned_resources(plan: dict[str, Any]) -> list[dict[str, Any]]:
    # tfplan.planned_values.root_module.resources만 추출
    root_module = plan.get("planned_values", {}).get("root_module", {})
    resources = root_module.get("resources", [])
    if not isinstance(resources, list):
        return []
    return [r for r in resources if isinstance(r, dict)]


def _parse_json_policy(value: Any) -> dict[str, Any] | None:
    # 정책 문자열(JSON) 또는 dict를 dict로 변환
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def _as_list(value: Any) -> list[Any]:
    # string/단일값/배열을 통일해서 리스트로 반환
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _extract_statements(policy_doc: dict[str, Any]) -> list[dict[str, Any]]:
    # IAM 정책의 Statement를 항상 리스트 형태로 반환
    statements = policy_doc.get("Statement")
    if isinstance(statements, list):
        return [s for s in statements if isinstance(s, dict)]
    if isinstance(statements, dict):
        return [statements]
    return []


def _extract_account_id(plan: dict[str, Any]) -> str | None:
    # account_id를 여러 위치에서 최대한 추출
    outputs = plan.get("planned_values", {}).get("outputs", {})
    if isinstance(outputs, dict):
        v = outputs.get("cloudgoat_output_aws_account_id", {})
        if isinstance(v, dict) and isinstance(v.get("value"), str):
            return v.get("value")

    prior_outputs = plan.get("prior_state", {}).get("values", {}).get("outputs", {})
    if isinstance(prior_outputs, dict):
        v = prior_outputs.get("cloudgoat_output_aws_account_id", {})
        if isinstance(v, dict) and isinstance(v.get("value"), str):
            return v.get("value")
    return None


def _extract_allow_assume_role_resources(policy_doc: dict[str, Any]) -> list[str]:
    # Allow + Action(sts:AssumeRole 또는 sts:* 또는 *) 인 Statement의 Resource 추출
    targets: list[str] = []
    for stmt in _extract_statements(policy_doc):
        if str(stmt.get("Effect", "Allow")) != "Allow":
            continue

        actions = [str(a) for a in _as_list(stmt.get("Action"))]
        action_hit = False
        for action in actions:
            action_l = action.lower()
            if action_l in {"sts:assumerole", "sts:*", "*"}:
                action_hit = True
                break
        if not action_hit:
            continue

        for r in _as_list(stmt.get("Resource")):
            if isinstance(r, str) and r:
                targets.append(r)
    return targets


def _extract_trust_entries(policy_doc: dict[str, Any]) -> list[dict[str, Any]]:
    # AssumeRole trust 정책에서 Principal/Condition 정보를 추출
    out: list[dict[str, Any]] = []
    for stmt in _extract_statements(policy_doc):
        if str(stmt.get("Effect", "Allow")) != "Allow":
            continue
        actions = [str(a).lower() for a in _as_list(stmt.get("Action"))]
        if not any(a in {"sts:assumerole", "sts:*", "*"} for a in actions):
            continue

        principal = stmt.get("Principal")
        if principal is None:
            continue
        if principal == "*":
            out.append(
                {
                    "aws": ["*"],
                    "service": [],
                    "federated": [],
                    "condition": stmt.get("Condition"),
                }
            )
            continue
        if not isinstance(principal, dict):
            continue

        out.append(
            {
                "aws": [str(x) for x in _as_list(principal.get("AWS")) if isinstance(x, str)],
                "service": [str(x) for x in _as_list(principal.get("Service")) if isinstance(x, str)],
                "federated": [str(x) for x in _as_list(principal.get("Federated")) if isinstance(x, str)],
                "condition": stmt.get("Condition"),
            }
        )
    return out


def _match_condition(condition: Any, src_arn: str | None, src_account_id: str | None) -> bool:
    # 조건 미지정이면 통과
    if condition is None:
        return True
    if not isinstance(condition, dict):
        return False

    # 일부 주요 condition key만 안전하게 해석
    for _, clause in condition.items():
        if not isinstance(clause, dict):
            return False
        for key, raw_val in clause.items():
            vals = [str(v) for v in _as_list(raw_val)]
            key_l = str(key).lower()
            if key_l == "aws:principalarn":
                if not src_arn:
                    return False
                if not any(fnmatch.fnmatch(src_arn, p) for p in vals):
                    return False
            elif key_l == "aws:principalaccount":
                if not src_account_id:
                    return False
                if src_account_id not in vals:
                    return False
            else:
                # 해석하지 못하는 condition은 보수적으로 미통과 처리
                return False
    return True


def _trust_allows_source(
    trust_entries: list[dict[str, Any]],
    src_arn: str | None,
    src_account_id: str | None,
) -> tuple[bool, list[dict[str, Any]]]:
    # 신뢰정책이 source principal을 허용하는지 판정
    matched: list[dict[str, Any]] = []
    for entry in trust_entries:
        aws_principals = entry.get("aws", []) or []
        cond = entry.get("condition")

        aws_hit = False
        for p in aws_principals:
            if p == "*":
                aws_hit = True
                break
            if src_arn and (p == src_arn or fnmatch.fnmatch(src_arn, p)):
                aws_hit = True
                break
            if src_account_id and p == f"arn:aws:iam::{src_account_id}:root":
                aws_hit = True
                break
        if not aws_hit:
            continue
        if not _match_condition(cond, src_arn=src_arn, src_account_id=src_account_id):
            continue
        matched.append(entry)

    return (len(matched) > 0), matched


def _build_iam_analysis(plan: dict[str, Any], max_depth: int) -> dict[str, Any]:
    # tfplan 기반 IAM 엔티티/정책/트러스트/AssumeRole 체인 분석
    planned_resources = _collect_planned_resources(plan)
    config_resources = _collect_resources(plan)
    account_id = _extract_account_id(plan)

    # address -> config resource (attachment의 policy 참조 보강용)
    config_by_address: dict[str, dict[str, Any]] = {}
    for r in config_resources:
        address = r.get("address")
        if isinstance(address, str):
            config_by_address[address] = r

    entities: dict[str, dict[str, Any]] = {}
    policies_by_address: dict[str, dict[str, Any]] = {}
    policy_arn_to_address: dict[str, str] = {}
    trust_map: dict[str, list[dict[str, Any]]] = {}
    principal_policy_docs: dict[str, list[dict[str, Any]]] = {}
    group_members: dict[str, set[str]] = {}

    def add_entity(resource: dict[str, Any], entity_type: str) -> None:
        address = resource.get("address")
        values = resource.get("values", {})
        if not isinstance(address, str) or not isinstance(values, dict):
            return
        name = values.get("name")
        if not isinstance(name, str):
            return
        arn = values.get("arn")
        if not isinstance(arn, str) and account_id:
            arn = f"arn:aws:iam::{account_id}:{entity_type}/{name}"
        entities[address] = {
            "address": address,
            "entity_type": entity_type,
            "name": name,
            "arn": arn,
        }

    # 1) IAM 엔티티/정책/멤버십 수집
    for resource in planned_resources:
        rtype = resource.get("type")
        address = resource.get("address")
        values = resource.get("values", {})
        if not isinstance(rtype, str) or not isinstance(address, str) or not isinstance(values, dict):
            continue

        if rtype == "aws_iam_user":
            add_entity(resource, "user")
        elif rtype == "aws_iam_role":
            add_entity(resource, "role")
        elif rtype == "aws_iam_group":
            add_entity(resource, "group")
        elif rtype == "aws_iam_policy":
            policy_doc = _parse_json_policy(values.get("policy"))
            arn = values.get("arn")
            if not isinstance(arn, str):
                arn = None
            if policy_doc:
                policies_by_address[address] = {
                    "address": address,
                    "arn": arn,
                    "name": values.get("name"),
                    "policy": policy_doc,
                }
                if arn:
                    policy_arn_to_address[arn] = address
        elif rtype in {"aws_iam_group_membership", "aws_iam_user_group_membership"}:
            user = values.get("user")
            groups = values.get("groups")
            if isinstance(user, str) and isinstance(groups, list):
                for g in groups:
                    if isinstance(g, str):
                        group_members.setdefault(g, set()).add(user)

    # 2) Role trust 정책 파싱
    for resource in planned_resources:
        rtype = resource.get("type")
        address = resource.get("address")
        values = resource.get("values", {})
        if rtype != "aws_iam_role" or not isinstance(address, str) or not isinstance(values, dict):
            continue
        assume_doc = _parse_json_policy(values.get("assume_role_policy"))
        if assume_doc:
            trust_map[address] = _extract_trust_entries(assume_doc)
        else:
            trust_map[address] = []

    # 3) principal별 정책 합치기 (managed + inline)
    # 3-1) inline policy 리소스
    inline_map = {
        "aws_iam_role_policy": "role",
        "aws_iam_user_policy": "user",
        "aws_iam_group_policy": "group",
    }
    for resource in planned_resources:
        rtype = resource.get("type")
        values = resource.get("values", {})
        if rtype not in inline_map or not isinstance(values, dict):
            continue
        policy_doc = _parse_json_policy(values.get("policy"))
        if not policy_doc:
            continue
        key = inline_map[rtype]
        principal_name = values.get(key)
        if not isinstance(principal_name, str):
            continue
        principal_policy_docs.setdefault(principal_name, []).append(policy_doc)

    # 3-2) managed policy attachment 리소스
    attach_types = {
        "aws_iam_user_policy_attachment": "user",
        "aws_iam_role_policy_attachment": "role",
        "aws_iam_group_policy_attachment": "group",
    }
    for resource in planned_resources:
        rtype = resource.get("type")
        address = resource.get("address")
        values = resource.get("values", {})
        if rtype not in attach_types or not isinstance(values, dict):
            continue
        principal_key = attach_types[rtype]
        principal_name = values.get(principal_key)
        if not isinstance(principal_name, str):
            continue

        policy_arn = values.get("policy_arn")
        if not isinstance(policy_arn, str):
            policy_arn = None

        # plan에서 policy_arn이 unknown일 수 있어 config.references로 보강
        if not policy_arn and isinstance(address, str):
            cfg = config_by_address.get(address, {})
            refs: list[str] = []
            _walk_references(cfg.get("expressions", {}), refs)
            for ref in refs:
                normalized = _normalize_reference(ref)
                if isinstance(normalized, str) and normalized.startswith("aws_iam_policy."):
                    p = policies_by_address.get(normalized)
                    if p and isinstance(p.get("arn"), str):
                        policy_arn = p["arn"]
                    elif p and isinstance(p.get("policy"), dict):
                        principal_policy_docs.setdefault(principal_name, []).append(p["policy"])
                    break

        if not policy_arn:
            continue
        policy_addr = policy_arn_to_address.get(policy_arn)
        if not policy_addr:
            continue
        p = policies_by_address.get(policy_addr)
        if p and isinstance(p.get("policy"), dict):
            principal_policy_docs.setdefault(principal_name, []).append(p["policy"])

    # group 정책은 group membership을 통해 user에 전달
    for entity in entities.values():
        if entity["entity_type"] != "user":
            continue
        uname = entity["name"]
        for gname, members in group_members.items():
            if uname in members:
                for pdoc in principal_policy_docs.get(gname, []):
                    principal_policy_docs.setdefault(uname, []).append(pdoc)

    # 4) 권한정책에서 AssumeRole 허용 target 추출
    role_arns: dict[str, str] = {}
    role_names: dict[str, str] = {}
    for address, e in entities.items():
        if e["entity_type"] != "role":
            continue
        name = e.get("name")
        arn = e.get("arn")
        if isinstance(arn, str):
            role_arns[address] = arn
        if isinstance(name, str):
            role_names[name] = address

    principal_assume_targets: dict[str, set[str]] = {}
    principal_docs_debug: dict[str, int] = {}
    for address, e in entities.items():
        if e["entity_type"] not in {"user", "role"}:
            continue
        pname = e["name"]
        docs = principal_policy_docs.get(pname, [])
        principal_docs_debug[address] = len(docs)
        allowed_resources: list[str] = []
        for doc in docs:
            allowed_resources.extend(_extract_allow_assume_role_resources(doc))

        target_roles: set[str] = set()
        for res in allowed_resources:
            if res == "*":
                target_roles.update(role_arns.keys())
                continue
            for role_addr, role_arn in role_arns.items():
                if res == role_arn or fnmatch.fnmatch(role_arn, res):
                    target_roles.add(role_addr)
            # role name만 있는 경우를 위한 최소 보강
            if res.startswith("arn:aws:iam::") and ":role/" in res:
                rname = res.split(":role/", 1)[1]
                if rname in role_names:
                    target_roles.add(role_names[rname])
        principal_assume_targets[address] = target_roles

    # 5) AssumeRole 체인 엣지 생성 (권한 + 신뢰 동시 만족)
    assume_edges: list[dict[str, Any]] = []
    for src_addr, targets in principal_assume_targets.items():
        src_entity = entities.get(src_addr, {})
        src_arn = src_entity.get("arn") if isinstance(src_entity.get("arn"), str) else None
        src_account = None
        if src_arn and src_arn.startswith("arn:aws:iam::"):
            src_account = src_arn.split("::", 1)[1].split(":", 1)[0]
        if not src_account:
            src_account = account_id

        for dst_addr in sorted(targets):
            trust_entries = trust_map.get(dst_addr, [])
            allowed, matched_entries = _trust_allows_source(
                trust_entries,
                src_arn=src_arn,
                src_account_id=src_account,
            )
            if not allowed:
                continue
            assume_edges.append(
                {
                    "from": src_addr,
                    "to": dst_addr,
                    "reason": "permission_and_trust_matched",
                    "matched_trust_entries": matched_entries,
                }
            )

    # 6) 깊이 제한 BFS/DFS 경로 탐색
    principal_nodes = {
        addr: {
            "id": addr,
            "entity_type": ent["entity_type"],
            "name": ent["name"],
            "arn": ent["arn"],
            "policy_docs_count": principal_docs_debug.get(addr, 0),
        }
        for addr, ent in entities.items()
        if ent["entity_type"] in {"user", "role"}
    }
    principal_edge_min = [{"from": e["from"], "to": e["to"]} for e in assume_edges]
    bfs_paths = _find_bfs_shortest_paths(
        principal_nodes,
        principal_edge_min,
        max_depth=max_depth,
        undirected=False,
    )
    dfs_paths = _find_all_paths(
        principal_nodes,
        principal_edge_min,
        max_depth=max_depth,
        undirected=False,
    )

    return {
        "summary": {
            "account_id": account_id,
            "entities_total": len(entities),
            "principal_nodes": len(principal_nodes),
            "assume_role_edges": len(assume_edges),
            "bfs_paths": len(bfs_paths),
            "dfs_paths": len(dfs_paths),
            "max_depth": max_depth,
        },
        "principals": [principal_nodes[k] for k in sorted(principal_nodes.keys())],
        "assume_role_edges": sorted(assume_edges, key=lambda x: (x["from"], x["to"])),
        "bfs_shortest_paths": bfs_paths,
        "dfs_all_paths": dfs_paths,
        "role_trust": {k: trust_map.get(k, []) for k in sorted(role_arns.keys())},
    }


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
                }
            edge_set.add((from_addr, to_addr))

    # 최종 엣지 목록을 정렬된 배열로 변환
    edges = [{"from": src, "to": dst} for src, dst in sorted(edge_set)]
    return nodes, edges


def _build_adjacency(edges: list[dict[str, str]], undirected: bool) -> dict[str, set[str]]:
    # 경로 탐색용 인접 리스트 생성 (기본: 방향 그래프)
    graph: dict[str, set[str]] = {}
    for edge in edges:
        src = edge["from"]
        dst = edge["to"]
        graph.setdefault(src, set()).add(dst)
        if undirected:
            graph.setdefault(dst, set()).add(src)
    return graph


def _all_simple_paths(
    graph: dict[str, set[str]],
    start: str,
    goal: str,
    max_depth: int,
) -> list[list[str]]:
    # DFS로 단순 경로(노드 중복 없음)를 전부 탐색
    paths: list[list[str]] = []

    def dfs(current: str, visited: set[str], path: list[str]) -> None:
        if len(path) - 1 > max_depth:
            return
        if current == goal and len(path) > 1:
            paths.append(path[:])
            return

        for nxt in sorted(graph.get(current, set())):
            if nxt in visited:
                continue
            visited.add(nxt)
            path.append(nxt)
            dfs(nxt, visited, path)
            path.pop()
            visited.remove(nxt)

    dfs(start, {start}, [start])
    return paths


def _shortest_path_bfs(
    graph: dict[str, set[str]],
    start: str,
    goal: str,
    max_depth: int,
) -> list[str] | None:
    # BFS로 최단 경로(홉 수 최소) 1개를 탐색
    if start == goal:
        return [start]

    # queue에는 (현재노드, 경로) 형태로 저장
    queue: list[tuple[str, list[str]]] = [(start, [start])]
    # 같은 노드를 더 긴 경로로 재방문하지 않도록 방문 체크
    visited: set[str] = {start}
    idx = 0

    while idx < len(queue):
        current, path = queue[idx]
        idx += 1

        # max_depth는 홉 수 기준이라 path 길이-1로 비교
        if len(path) - 1 >= max_depth:
            continue

        for nxt in sorted(graph.get(current, set())):
            if nxt in visited:
                continue
            next_path = path + [nxt]
            if nxt == goal:
                return next_path
            visited.add(nxt)
            queue.append((nxt, next_path))

    return None


def _find_bfs_shortest_paths(
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, str]],
    max_depth: int,
    undirected: bool,
) -> list[dict[str, Any]]:
    # 모든 노드 쌍에 대해 BFS 최단 경로 1개만 수집
    graph = _build_adjacency(edges, undirected=undirected)
    node_ids = sorted(nodes.keys())
    out: list[dict[str, Any]] = []

    for src in node_ids:
        for dst in node_ids:
            if src == dst:
                continue
            path = _shortest_path_bfs(graph, src, dst, max_depth=max_depth)
            if not path:
                continue
            out.append(
                {
                    "from": src,
                    "to": dst,
                    "hops": len(path) - 1,
                    "path": path,
                }
            )

    return sorted(out, key=lambda x: (x["hops"], x["from"], x["to"], x["path"]))


def _find_all_paths(
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, str]],
    max_depth: int,
    undirected: bool,
) -> list[dict[str, Any]]:
    # 모든 노드 쌍에 대해 DFS 단순 경로를 전부 수집
    graph = _build_adjacency(edges, undirected=undirected)
    node_ids = sorted(nodes.keys())
    out: list[dict[str, Any]] = []

    for src in node_ids:
        for dst in node_ids:
            if src == dst:
                continue
            paths = _all_simple_paths(graph, src, dst, max_depth=max_depth)
            for path in paths:
                out.append(
                    {
                        "from": src,
                        "to": dst,
                        "hops": len(path) - 1,
                        "path": path,
                    }
                )

    # hop 수가 작은 경로부터 정렬
    return sorted(out, key=lambda x: (x["hops"], x["from"], x["to"], x["path"]))


def main() -> None:
    # CLI 인자 정의
    parser = argparse.ArgumentParser(
        description="Build IaC graph from tfplan.json and enumerate reachable paths.",
    )
    parser.add_argument("--tfplan", type=Path, required=True, help="Path to terraform plan json")
    parser.add_argument("--output", type=Path, required=True, help="Output path for IaC graph json")
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
        help="Max depth for all-path search.",
    )
    parser.add_argument(
        "--directed",
        action="store_true",
        help="Use directed edges for path search (default: undirected).",
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

    # 2) 노드 간 경로 탐색: DFS(모든 경로), BFS(최단 1개)
    dfs_all_paths = _find_all_paths(
        nodes,
        edges,
        max_depth=args.max_path_depth,
        undirected=not args.directed,
    )
    bfs_shortest_paths = _find_bfs_shortest_paths(
        nodes,
        edges,
        max_depth=args.max_path_depth,
        undirected=not args.directed,
    )
    # 3) IAM AssumeRole 체인 분석 (항상 방향 그래프)
    iam_analysis = _build_iam_analysis(tfplan, max_depth=args.max_path_depth)

    # 4) 결과 JSON 구성
    result = {
        "version": 1,
        "graph_type": "iac_graph",
        "source": str(args.tfplan),
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "dfs_all_paths": len(dfs_all_paths),
            "bfs_shortest_paths": len(bfs_shortest_paths),
            "iam_assume_role_edges": iam_analysis["summary"]["assume_role_edges"],
            "iam_bfs_paths": iam_analysis["summary"]["bfs_paths"],
            "iam_dfs_paths": iam_analysis["summary"]["dfs_paths"],
            "max_path_depth": args.max_path_depth,
            "undirected": not args.directed,
        },
        "nodes": [nodes[node_id] for node_id in sorted(nodes.keys())],
        "edges": edges,
        "dfs_all_paths": dfs_all_paths,
        "bfs_shortest_paths": bfs_shortest_paths,
        "iam_analysis": iam_analysis,
    }

    # 5) 파일 저장 및 요약 출력
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"ok: nodes={result['summary']['nodes']} "
        f"edges={result['summary']['edges']} "
        f"dfs_all_paths={result['summary']['dfs_all_paths']} "
        f"bfs_shortest_paths={result['summary']['bfs_shortest_paths']} "
        f"iam_assume_role_edges={result['summary']['iam_assume_role_edges']} "
        f"iam_bfs_paths={result['summary']['iam_bfs_paths']} "
        f"iam_dfs_paths={result['summary']['iam_dfs_paths']} "
        f"output={args.output}"
    )


if __name__ == "__main__":
    main()
