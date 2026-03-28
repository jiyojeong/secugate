# SecuGate
[English](README.md) | 한국어

## Overview
SecuGate는 Terraform 보안 설정 문제를 개별 finding이 아니라 공격 경로 관점에서 해석하는 IaC 보안 분석 프로젝트입니다.

## 대표 결과물
- [IaC Graph Checkov Paths Report](artifacts/iac_graph_checkov_paths.md)

이 프로젝트는 Checkov 결과를 그대로 나열하는 대신,
- Terraform plan / HCL 기준으로 finding을 수집하고
- 이를 공격자 capability로 정규화한 뒤
- ATT&CK 단계/Atomic ID 으로 매핑하고
- IaC graph 상에서 연결 가능한 공격 경로를 구성하여
- CI에서 차단 또는 경고 판단에 활용할 수 있는 결과를 생성합니다

# Requirements
- Python 3.10+
- Terraform dir

# Install (권장)
python3 -m venv .venv
source .venv/bin/activate

# Install (비권장)
pip install sec-gate

# 실행
python3 main.py run --tf ./inputs/terraform --out ./artifacts

# 분석 흐름
```
Terraform 
-> Checkov finding 수집
-> Finding 정규화
-> Capability 매핑
-> ATT&CK 단계 / Atomic ID 매핑
-> IaC graph 기반 공격 경로 상관 분석
-> CI 게이트 판단용 결과 생성
```
# 출력물
```
artifacts/
├─ normalized_findings.json   # Checkov 결과 정규화
├─ resource_rollup.json       # 리소스별 보안 상태 요약
├─ report.md                  # 사람이 읽을 수 있는 보안 리포트
└─ decision.json              # CI 정책 적용을 위한 머신 리더블 결과
```

# CI Integration
SecuGate는 특정 CI 정책을 강제하기보다, 팀이 정책을 설계할 수 있도록 판단 근거를 제공하는 쪽에 가깝습니다.

예를 들어 다음과 같은 방식으로 적용할 수 있습니다.

- CRITICAL finding이 존재하면 차단
- validated attack path가 생성되면 차단
- feature branch에서는 경고, protected branch에서는 차단
