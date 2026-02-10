from pathlib import Path

from secugate.utils.subprocess import run_cmd

def build_tfplan_json(terraform_dir: Path, out_json: Path) -> None:
    terraform_dir = terraform_dir.resolve()
    out_json = out_json.resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    plan_bin = out_json.parent / "tfplan.bin"

    # init
    run_cmd(["terraform", "init"], cwd=terraform_dir)

    # plan
    run_cmd(["terraform", "plan", "-out", str(plan_bin), "-input=false", "-refresh=false"], cwd=terraform_dir)

    # show json
    result = run_cmd(["terraform", "show", "-json", str(plan_bin)], cwd=terraform_dir, capture_output=True)
    out_json.write_text(result, encoding="utf-8")
