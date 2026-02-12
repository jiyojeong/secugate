from pathlib import Path

from secugate.runners.terraform import build_tfplan_json
from secugate.runners.checkov import run_checkov_on_tfplan, run_checkov_on_hcl
from secugate.parsers.checkov import merge_checkov_results


def run_pipeline(
    terraform_dir: Path,
    output_dir: Path,
    k8s_dir: Path | None = None,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    terraform_dir = terraform_dir.resolve()
    tfplan_json = output_dir / "tfplan.json"
    checkov_plan_json = output_dir / "checkov_plan.json"
    checkov_hcl_json = output_dir / "checkov_hcl.json"
    checkov_merged_json = output_dir / "checkov_merged.json"

    # 1. Terraform Plan 실행하여 tfplan.json 생성
    build_tfplan_json(terraform_dir=terraform_dir, out_json=tfplan_json)

    # 2. Plan 파일 기반으로 Checkov 스캔 실행
    run_checkov_on_tfplan(
        tfplan_json=tfplan_json,
        out_json=checkov_plan_json,
        repo_root=terraform_dir,
    )

    # 3. HCL 소스코드 기반으로 Checkov 스캔 실행
    run_checkov_on_hcl(
        terraform_dir=terraform_dir,
        out_json=checkov_hcl_json,
    )

    # 4. 두 스캔 결과를 병합하여 최종 보고서 생성
    merge_checkov_results(
        plan_json_path=checkov_plan_json,
        hcl_json_path=checkov_hcl_json,
        output_path=checkov_merged_json,
    )

    return {
        "tfplan_json": str(tfplan_json),
        "checkov_tf_json": str(checkov_merged_json),
    }
