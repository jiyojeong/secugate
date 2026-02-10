from pathlib import Path

from secugate.utils.subprocess import run_cmd

def run_checkov_on_tfplan(tfplan_json: Path, out_json: Path) -> None:
    tfplan_json = tfplan_json.resolve()
    out_json = out_json.resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    # checkov 리턴 있으면, fail, 아웃풋 캡쳐
    cmd = ["checkov", "-f", str(tfplan_json), "-o", "json"]
    res = run_cmd(cmd, cwd=tfplan_json.parent, capture_output=True, allow_error=True)
    out_json.write_text(res, encoding="utf-8")