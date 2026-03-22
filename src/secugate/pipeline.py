import shutil
from pathlib import Path
import typer

from secugate.attack_scenarios import generate_attack_scenarios
from secugate.parsers.checkov import merge_checkov_results
from secugate.runners.checkov import run_checkov_on_hcl, run_checkov_on_tfplan
from secugate.runners.iac_graph import build_iac_graph_json
from secugate.runners.terraform import build_tfplan_json
from secugate.utils.caching import calculate_dir_hash


def run_pipeline(
    terraform_dir: Path,
    output_dir: Path,
    k8s_dir: Path | None = None,
    no_cache: bool = False,
    scenario_rules_path: Path | None = None,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    terraform_dir = terraform_dir.resolve()

    # --- Caching Logic Start ---
    dir_hash = calculate_dir_hash(terraform_dir)
    cache_root = output_dir / ".cache"
    cache_dir = cache_root / dir_hash

    # Define final output paths
    tfplan_json = output_dir / "tfplan.json"
    iac_graph_json = output_dir / "iac_graph.json"
    checkov_plan_json = output_dir / "checkov_plan.json"
    checkov_hcl_json = output_dir / "checkov_hcl.json"
    checkov_merged_json = output_dir / "checkov_merged.json"
    attack_scenarios_json = output_dir / "attack_scenarios.json"
    attack_scenarios_md = output_dir / "attack_scenarios.md"

    # Define cached artifact paths
    cached_tfplan_json = cache_dir / "tfplan.json"
    cached_iac_graph_json = cache_dir / "iac_graph.json"
    cached_checkov_plan_json = cache_dir / "checkov_plan.json"
    cached_checkov_hcl_json = cache_dir / "checkov_hcl.json"
    cached_checkov_merged_json = cache_dir / "checkov_merged.json"
    cached_attack_scenarios_json = cache_dir / "attack_scenarios.json"
    cached_attack_scenarios_md = cache_dir / "attack_scenarios.md"

    if not no_cache and cached_checkov_merged_json.is_file():
        typer.echo(f"Cache hit for hash: {dir_hash[:12]}")
        typer.echo("Restoring artifacts from cache...")
        shutil.copy(cached_tfplan_json, tfplan_json)
        if cached_iac_graph_json.is_file():
            shutil.copy(cached_iac_graph_json, iac_graph_json)
        else:
            build_iac_graph_json(tfplan_json=tfplan_json, out_json=iac_graph_json)
        shutil.copy(cached_checkov_plan_json, checkov_plan_json)
        shutil.copy(cached_checkov_hcl_json, checkov_hcl_json)
        shutil.copy(cached_checkov_merged_json, checkov_merged_json)
        if scenario_rules_path is None and cached_attack_scenarios_json.is_file():
            shutil.copy(cached_attack_scenarios_json, attack_scenarios_json)
            if cached_attack_scenarios_md.is_file():
                shutil.copy(cached_attack_scenarios_md, attack_scenarios_md)
            else:
                generate_attack_scenarios(
                    checkov_merged_json_path=checkov_merged_json,
                    output_path=attack_scenarios_json,
                    markdown_output_path=attack_scenarios_md,
                )
        else:
            generate_attack_scenarios(
                checkov_merged_json_path=checkov_merged_json,
                output_path=attack_scenarios_json,
                rules_path=scenario_rules_path,
                markdown_output_path=attack_scenarios_md,
            )

        return {
            "tfplan_json": str(tfplan_json),
            "iac_graph_json": str(iac_graph_json),
            "checkov_tf_json": str(checkov_merged_json),
            "attack_scenarios_json": str(attack_scenarios_json),
            "attack_scenarios_md": str(attack_scenarios_md),
        }

    if not no_cache:
        typer.echo(f"Cache miss for hash: {dir_hash[:12]}")
        cache_dir.mkdir(parents=True, exist_ok=True)
    # --- Caching Logic End ---

    build_tfplan_json(terraform_dir=terraform_dir, out_json=tfplan_json)
    build_iac_graph_json(tfplan_json=tfplan_json, out_json=iac_graph_json)

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
    generate_attack_scenarios(
        checkov_merged_json_path=checkov_merged_json,
        output_path=attack_scenarios_json,
        rules_path=scenario_rules_path,
        markdown_output_path=attack_scenarios_md,
    )

    # --- Caching Logic Start ---
    if not no_cache:
        typer.echo("Saving artifacts to cache.")
        shutil.copy(tfplan_json, cached_tfplan_json)
        shutil.copy(iac_graph_json, cached_iac_graph_json)
        shutil.copy(checkov_plan_json, cached_checkov_plan_json)
        shutil.copy(checkov_hcl_json, cached_checkov_hcl_json)
        shutil.copy(checkov_merged_json, cached_checkov_merged_json)
        if scenario_rules_path is None:
            shutil.copy(attack_scenarios_json, cached_attack_scenarios_json)
            shutil.copy(attack_scenarios_md, cached_attack_scenarios_md)
    # --- Caching Logic End ---

    return {
        "tfplan_json": str(tfplan_json),
        "iac_graph_json": str(iac_graph_json),
        "checkov_tf_json": str(checkov_merged_json),
        "attack_scenarios_json": str(attack_scenarios_json),
        "attack_scenarios_md": str(attack_scenarios_md),
    }
