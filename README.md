# SecuGate
English | [한국어](README.ko.md)

SecuGate correlates IaC misconfigurations into attack scenarios and produces risk scores for CI-based security gating.

# Overview
SecuGate is a security analysis tool designed to identify infrastructure risks at the Terraform IaC stage.  
It collects security findings from Checkov and correlates them into attacker capabilities and scenarios to assess risk.  
The resulting scores can be consumed by CI pipelines to implement policy-based security gates.

# Requirements
- Python 3.10+
- Terraform dir

# Install (recommended)
python3 -m venv .venv
source .venv/bin/activate

# command
python3 main.py run --tf ./inputs/terraform --out ./artifacts

# secugate
```
Terraform 
→ Checkov analysis 
→ Finding normalization 
→ Capability mapping 
→ MITRE Tactic Mapping 
→ Scenario detection 
→ Risk scoring for CI decision generation
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
SecuGate does not enforce a single CI policy.
Instead, it outputs a machine-readable decision.json file containing risk scores and scenario information, allowing each team to define its own enforcement rules.

Example policies may include:
- block deployment when overall_score ≥ N
- block merges when max_scenario_score ≥ N
- warn on feature branches and enforce on main branches