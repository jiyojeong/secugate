from pathlib import Path

from secugate.utils.subprocess import run_cmd

def run_checkov_on_tfplan(
    tfplan_json: Path,
    out_json: Path,
    repo_root_for_plan_enrichment: Path | None = None,
) -> None:
    tfplan_json = tfplan_json.resolve()
    out_json = out_json.resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    # checkov 리턴 있으면, fail, 아웃풋 캡쳐
    cmd = ["checkov", "-f", str(tfplan_json), "-o", "json"]
    if repo_root_for_plan_enrichment is not None:
        cmd.extend(
            [
                "--repo-root-for-plan-enrichment",
                str(repo_root_for_plan_enrichment.resolve()),
            ]
        )
    res = run_cmd(cmd, cwd=tfplan_json.parent, capture_output=True, allow_error=True)
    out_json.write_text(res, encoding="utf-8")
