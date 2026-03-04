## Overview
SecuGate는 Terraform 기반 IaC(Infrastructure as Code) 프로젝트에서 보안 리스크를 조기에 식별하기 위한 도구입니다.  
Checkov 분석 결과로부터 보안 Finding을 수집하고, 이를 공격자 관점의 capability 및 시나리오로 상관 분석하여 리스크를 점수화합니다.  
생성된 결과는 CI 환경에서 정책 기반 보안 게이트로 활용될 수 있습니다.

# Requirements
- Python 3.10+
- Terraform dir

# Install (권장)
python3 -m venv .venv
source .venv/bin/activate

# Install (비권장)
pip install sec-gate

# 실행코드(PoC 2026-02-09)
python3 main.py run --tf ./inputs/terraform --out ./artifacts

# 출력물
```
artifacts/
├─ normalized_findings.json   # Checkov 결과 정규화
├─ resource_rollup.json       # 리소스별 보안 상태 요약
├─ report.md                  # 사람이 읽을 수 있는 보안 리포트
└─ decision.json              # CI 정책 적용을 위한 머신 리더블 결과
```

# CI Integration
SecuGate는 특정 CI 정책을 강제하지 않습니다.
대신 decision.json 파일을 통해 리스크 점수와 시나리오 정보를 제공하며, 조직은 이를 기반으로 원하는 정책을 구성할 수 있습니다.

예를 들어 다음과 같은 방식으로 사용할 수 있습니다.

- overall_score ≥ N 이면 배포 차단
- max_scenario_score ≥ N 이면 머지 차단
- 특정 브랜치에서만 경고 또는 차단