from pathlib import Path

from secugate.runners.terraform import build_tfplan_json
from secugate.runners.checkov import run_checkov_on_tfplan


def run_pipeline(terraform_dir: Path, output_dir: Path, k8s_dir: Path | None = None) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    tfplan_json = output_dir / "tfplan.json"
    checkov_tf_json = output_dir / "checkov_tf.json"

    build_tfplan_json(terraform_dir=terraform_dir, out_json=tfplan_json)
    run_checkov_on_tfplan(tfplan_json=tfplan_json, out_json=checkov_tf_json)

    return {
        "tfplan_json": str(tfplan_json),
        "checkov_tf_json": str(checkov_tf_json),
    }
