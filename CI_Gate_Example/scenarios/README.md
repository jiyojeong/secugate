# CI Gate Example Scenarios

These fixtures are intentionally insecure and lightweight so `secugate` can be tested in CI without CloudGoat-style variables, assets, or data sources.

## Scenarios

- `chained_ec2_iam_s3`
  - Designed to produce chained results such as public exposure -> credential access -> privilege abuse/exfiltration.
- `public_s3`
  - Minimal public storage exposure fixture.
- `iam_admin`
  - Minimal IAM wildcard/admin privilege fixture.

## Local run example

```bash
python3 main.py run --tf CI_Gate_Example/scenarios/chained_ec2_iam_s3 --out ./artifacts
```
