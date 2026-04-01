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

## LLM 요약 (옵션)
SecuGate는 최종 공격 경로 보고서에 대해 OpenAI 기반 한 줄 요약을 선택적으로 추가할 수 있습니다.

이 기능은 다음 원칙으로 동작합니다.
- Checkov evidence와 내부 capability/stage 매핑 결과를 그대로 사용합니다
- 이미 검증된 경로를 더 읽기 쉬운 자연어로 요약합니다

### 설정 방법
OpenAI Python 패키지를 설치합니다.

```bash
pip install openai
```

API 키를 설정합니다.

```bash
export OPENAI_API_KEY="YOUR_API_KEY"
```

필요하면 모델을 지정할 수 있습니다.

```bash
export OPENAI_MODEL="gpt-4.1"
```

그 다음 기존과 동일하게 실행합니다.

```bash
python3 main.py run --tf ./inputs/terraform --out ./artifacts
```

LLM 요약이 성공하면 `artifacts/iac_graph_checkov_paths.md` 각 경로 섹션에 다음 항목이 추가됩니다.
- `요약`
- `Scenario (LLM)`
- `Mitigation (LLM)`

OpenAI 설정이 없거나 요청이 실패하면 기존 규칙 기반 보고서는 그대로 유지되고, LLM 요약 블록만 표시되지 않습니다.

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
