# SecuGate
English | [한국어](README.ko.md)

SecuGate turns Terraform security findings into ATT&CK-aligned attack paths and CI gate decisions.

## Representative Output
- [IaC Graph Checkov Paths Report](artifacts/iac_graph_checkov_paths.md)

# Overview
SecuGate analyzes Terraform configurations before deployment and asks a practical question: "Can these findings be connected into a meaningful attack path?"

Instead of stopping at a flat list of scanner results, it:
- collects Checkov findings from Terraform plans and HCL
- normalizes them into attacker capabilities
- maps them to ATT&CK-aligned stages and representative techniques
- builds chained attack paths from the IaC resource graph
- produces CI-friendly outputs for blocking or warning decisions

# Requirements
- Python 3.10+
- Terraform dir

# Install (recommended)
python3 -m venv .venv
source .venv/bin/activate

# command
python3 main.py run --tf ./inputs/terraform --out ./artifacts

## Optional LLM Summaries
SecuGate can optionally add OpenAI-based one-line summaries for validated attack paths in the final path report.

This feature:
- uses existing Checkov evidence and internal capability/stage mappings
- does not re-decide ATT&CK ordering or path validity
- rewrites already validated paths into more readable text

### Setup
Install the OpenAI Python package:

```bash
pip install openai
```

Set your API key:

```bash
export OPENAI_API_KEY="YOUR_API_KEY"
```

Optionally choose a model:

```bash
export OPENAI_MODEL="gpt-4.1"
```

Run SecuGate as usual:

```bash
python3 main.py run --tf ./inputs/terraform --out ./artifacts
```

If LLM summarization succeeds, `artifacts/iac_graph_checkov_paths.md` will include:
- `Summary`
- `Scenario (LLM)`
- `Mitigation (LLM)`

If OpenAI is not configured or a request fails, SecuGate keeps the existing rule-based report and omits the LLM summary block.

# Analysis Flow
```
Terraform / tfplan
-> Checkov finding collection
-> Finding normalization
-> Capability mapping
-> ATT&CK stage + atomic mapping
-> Attack path correlation on IaC graph
-> CI gate decision output
```

# Outputs
```
artifacts/
├─ normalized_findings.json   # normalized Checkov findings
├─ resource_rollup.json       # resource-level security summary
├─ report.md                  # human-readable security report
└─ decision.json              # machine-readable decision for CI integration
```

# CI Integration
SecuGate is designed to fit into CI rather than replace it.
Teams can use its outputs to define their own policies, such as:

- block when CRITICAL findings are present
- block when validated attack paths are generated
- warn on feature branches and enforce on protected branches
