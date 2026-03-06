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
