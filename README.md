## Requirements
- Python 3.10+
- Terraform (binary)

## Install (권장)

python3 -m venv .venv
source .venv/bin/activate
pip install sec-gate

## Install (비권장)
pip install sec-gate

## 실행코드(PoC 2026-02-09)
python3 main.py run --tf ./inputs/terraform --out ./artifacts


# secgate
sec-gate/
├─ pyproject.toml
├─ README.md
├─ .gitignore
├─ artifacts/
└─ src/
   └─ secgate/
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