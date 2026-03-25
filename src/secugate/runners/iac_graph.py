from pathlib import Path

from secugate.utils.subprocess import run_cmd


def build_iac_graph_json(
    tfplan_json: Path,
    out_json: Path,
    max_path_depth: int = 6,
    directed: bool = False,
) -> None:
    tfplan_json = tfplan_json.resolve()
    out_json = out_json.resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    project_root = Path(__file__).resolve().parents[3]
    script_path = project_root / "scripts" / "tfplan_iac_graph.py"

    cmd = [
        "python3",
        str(script_path),
        "--tfplan",
        str(tfplan_json),
        "--output",
        str(out_json),
        "--max-path-depth",
        str(max_path_depth),
    ]
    if directed:
        cmd.append("--directed")

    run_cmd(cmd, cwd=project_root)


def build_iac_graph_checkov_paths(
    graph_json: Path,
    checkov_merged_json: Path,
    out_json: Path,
    markdown_out: Path | None = None,
    max_hops: int = 6,
) -> None:
    graph_json = graph_json.resolve()
    checkov_merged_json = checkov_merged_json.resolve()
    out_json = out_json.resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    if markdown_out is not None:
        markdown_out = markdown_out.resolve()
        markdown_out.parent.mkdir(parents=True, exist_ok=True)

    project_root = Path(__file__).resolve().parents[3]
    script_path = project_root / "scripts" / "map_checkov_to_iac_paths.py"

    cmd = [
        "python3",
        str(script_path),
        "--graph",
        str(graph_json),
        "--checkov-merged",
        str(checkov_merged_json),
        "--output",
        str(out_json),
        "--max-hops",
        str(max_hops),
    ]
    if markdown_out is not None:
        cmd.extend(["--markdown-output", str(markdown_out)])

    run_cmd(cmd, cwd=project_root)
