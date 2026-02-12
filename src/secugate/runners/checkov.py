from pathlib import Path

from secugate.utils.subprocess import run_cmd


def run_checkov_on_tfplan(
    tfplan_json: Path,
    out_json: Path,
    repo_root: Path,
) -> None:
    tfplan_json = tfplan_json.resolve()
    out_json = out_json.resolve()
    repo_root = repo_root.resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    # checkov 리턴 있으면, fail, 아웃풋 캡쳐
    cmd = [
        "checkov",
        "-f",
        str(tfplan_json),
        "-o",
        "json",
        "--quiet",
        "--repo-root-for-plan-enrichment",
        str(repo_root),
        "--deep-analysis",
    ]
    res = run_cmd(cmd, cwd=str(repo_root), capture_output=True, allow_error=True)
    out_json.write_text(res, encoding="utf-8")
