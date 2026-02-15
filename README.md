## Requirements
- Python 3.10+
- Terraform dir

## Install (권장)

python3 -m venv .venv
source .venv/bin/activate
pip install sec-gate

## Install (비권장)
pip install sec-gate

## 실행코드(PoC 2026-02-09)
python3 main.py run --tf ./inputs/terraform --out ./artifacts
python3 main.py run --tf ./inputs/terraform --out ./artifacts --repo-root-for-plan-enrichment ./inputs/terraform
python3 main.py run --tf ./inputs/terraform --out ./artifacts --rules ./src/secugate/rules/checkov_id_scenarios.json
python3 -m src.secugate.validate_fail_examples --file ./artifacts/checkov_fail_examples.json
python3 -m src.secugate.validate_fail_examples --file ./artifacts/checkov_fail_examples.json --require-filled


# secugate
sec-gate/
├─ pyproject.toml
├─ README.md
├─ .gitignore
├─ artifacts/
└─ src/
   └─ secugate/
      ├─ __init__.py
      ├─ cli.py
      ├─ pipeline.py
      ├─ models.py
      ├─ utils/
      │  └─ subprocess.py
      ├─ runners/
      │  ├─ terraform.py
      │  └─ checkov.py
      └─ parsers/
         └─ checkov.py



# 출력물

├─ inputs/ 
│ ├─ terraform/ # 사용자 입력 
│ └─ k8s/ 
│ 
├─ .cache/ # 🔥 재사용위한 캐시파일(생성파일)
│ ├─ terraform/ 
│ │ ├─ providers/ 
│ │ └─ plans/ 
│ │ └─ <hash>/tfplan.json 
│ └─ checkov/ 
│   └─ <hash>/checkov_tf.json 
│ 
├─ .work/ # ⚠️ 일회성 (실행 중) (생성파일)
│ └─ run-20260206-abc/ 
│   ├─ tfplan.bin 
│   ├─ terraform.log 
│   └─ temp/ 
│ 
├─ artifacts/ # 📦 결과물 (생성파일)
│ ├─ normalized_findings.json 
│ ├─ resource_rollup.json 
│ ├─ report.md 
│ └─ decision.json 
│
└─ src/



## report 구성
- asset: (예) aws_s3_bucket.sls_deployment_bucket_name
- evidence: file_path/line/code_block
- issue: 규칙명 + 요약
- attack_scenario: 공격 플로우(단계별)
- impact: 데이터 유출/권한상승/서비스중단 등
- mitigation: Terraform 수정 가이드(가능하면 코드 스니펫)
- side_effects: 성능/비용/호환성/운영 영향
- validation: 적용 후 확인 방법
- priority: severity + 노출도 기반
