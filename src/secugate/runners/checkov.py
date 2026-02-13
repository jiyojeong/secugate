from pathlib import Path

from secugate.utils.subprocess import run_cmd


def _run_checkov(cmd: list[str], cwd: Path, out_json: Path) -> None:
    """Helper to run a checkov command and save the output."""
    out_json.parent.mkdir(parents=True, exist_ok=True)
    res = run_cmd(cmd, cwd=str(cwd), capture_output=True, allow_error=True)
    out_json.write_text(res, encoding="utf-8")


def run_checkov_on_tfplan(
    tfplan_json: Path,
    out_json: Path,
    repo_root: Path,
) -> None:
    tfplan_json = tfplan_json.resolve()
    out_json = out_json.resolve()
    repo_root = repo_root.resolve()

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
    _run_checkov(cmd, cwd=repo_root, out_json=out_json)


def run_checkov_on_hcl(
    terraform_dir: Path,
    out_json: Path,
) -> None:
    """Runs checkov on a directory of HCL files."""
    terraform_dir = terraform_dir.resolve()
    out_json = out_json.resolve()

    cmd = [
        "checkov",
        "-d",
        str(terraform_dir),
        "--framework",
        "terraform",
        "-o",
        "json",
        "--quiet",
    ]
    _run_checkov(cmd, cwd=terraform_dir, out_json=out_json)
