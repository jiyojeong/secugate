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
    k8s: Path | None = typer.Option(
        None, "--k8s", exists=True, file_okay=False, dir_okay=True
    ),
    repo_root_for_plan_enrichment: Path | None = typer.Option(
        None,
        "--repo-root-for-plan-enrichment",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Checkov tfplan enrichment용 Terraform repo root 경로 (기본값: --tf)",
    ),
):
    """
    실행: Terraform Plan ->Checkov ->write artifacts
    """
    out.mkdir(parents=True, exist_ok=True)
    result = run_pipeline(
        terraform_dir=tf,
        output_dir=out,
        k8s_dir=k8s,
        repo_root_for_plan_enrichment=repo_root_for_plan_enrichment,
    )
    typer.echo(
        f"ok: tfplan={result['tfplan_json']} checkov={result['checkov_tf_json']}"
    )


if __name__ == "__main__":
    app()
