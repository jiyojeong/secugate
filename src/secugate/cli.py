from pathlib import Path
import typer  # deprecate 확인

from secugate.pipeline import run_pipeline

app = typer.Typer(add_completion=False)


@app.callback()
def main() -> None:
    """SecuGate CLI."""
    return


@app.command()
def run(
    tf: Path = typer.Option(..., "--tf", exists=True, file_okay=False, dir_okay=True),
    out: Path = typer.Option(Path("./artifacts"), "--out"),
    rules: Path | None = typer.Option(
        None,
        "--rules",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Path to attack scenario mapping rules JSON.",
    ),
    k8s: Path | None = typer.Option(
        None, "--k8s", exists=True, file_okay=False, dir_okay=True
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Disable caching of results."
    ),
):
    """
    실행: Terraform Plan ->Checkov ->write artifacts
    """
    out.mkdir(parents=True, exist_ok=True)
    result = run_pipeline(
        terraform_dir=tf,
        output_dir=out,
        scenario_rules_path=rules,
        k8s_dir=k8s,
        no_cache=no_cache,
    )
    typer.echo(
        "ok: "
        f"tfplan={result['tfplan_json']} "
        f"checkov={result['checkov_tf_json']} "
        f"iac_paths={result['iac_graph_checkov_paths_json']} "
        f"iac_paths_report={result['iac_graph_checkov_paths_md']} "
        f"attack_scenarios={result['attack_scenarios_json']} "
        f"attack_report={result['attack_scenarios_md']}"
    )


if __name__ == "__main__":
    app()
