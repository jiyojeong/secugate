# Attack Scenarios Report

## Summary

- Failed findings: 26
- Mapped findings: 23
- Capabilities: 7
- Atomic IDs: 5
- Scenarios: 3
- Unmapped check IDs: 3

## Scenarios

### 공개 EC2 노출 후 IAM 권한 악용

- ID: `aws_initial_access_to_iam_abuse`
- Score: `high`
- Atomic chain: T1190, T1098.003
- Matched capabilities: compute_public_exposure, iam_overprivileged_policy
- Evidence count: 17
- Description: 공개된 컴퓨트 자산에서 초기 접근 후 과도한 IAM 권한으로 권한 상승/지속성 확보

### 자격증명 수집 후 외부 유출

- ID: `aws_credential_collection_and_exfiltration`
- Score: `high`
- Atomic chain: T1552, T1041
- Matched capabilities: metadata_hardening_missing, open_egress
- Evidence count: 2
- Description: IMDS 하드닝 미흡 및 개방형 egress를 이용해 수집한 자격증명/데이터를 외부로 유출

### IAM 사용자 기반 지속성

- ID: `aws_identity_persistence_via_iam_user`
- Score: `high`
- Atomic chain: T1078.004, T1098.003
- Matched capabilities: iam_user_direct_access, iam_overprivileged_policy
- Evidence count: 15
- Description: IAM 사용자와 직접 정책 부여를 악용해 장기 접근 경로를 유지

## Capabilities

### `compute_public_exposure`

- Findings: 4
- Checks: CKV_AWS_130(1), CKV_AWS_24(1), CKV_AWS_260(1), CKV_AWS_88(1)
- Evidence preview:
  - `CKV_AWS_88` aws_instance.super_critical_security_server (/ec2.tf:39-62)
  - `CKV_AWS_24` aws_security_group.ec2_server (/ec2.tf:1-37)
  - `CKV_AWS_260` aws_security_group.ec2_server (/ec2.tf:1-37)
  - `CKV_AWS_130` aws_subnet.public (/vpc.tf:18-27)

### `iam_overprivileged_policy`

- Findings: 13
- Checks: CKV2_AWS_40(1), CKV_AWS_286(2), CKV_AWS_287(1), CKV_AWS_288(1), CKV_AWS_289(2), CKV_AWS_290(2), CKV_AWS_355(2), CKV_AWS_62(1), CKV_AWS_63(1)
- Evidence preview:
  - `CKV_AWS_355` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_287` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_289` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_286` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_63` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - ... and 8 more

### `iam_user_direct_access`

- Findings: 2
- Checks: CKV_AWS_273(1), CKV_AWS_40(1)
- Evidence preview:
  - `CKV_AWS_273` aws_iam_user.kerrigan (/iam.tf:1-4)
  - `CKV_AWS_40` aws_iam_user_policy_attachment.kerrigan_attachment (/iam.tf:46-49)

### `instance_profile_missing`

- Findings: 1
- Checks: CKV2_AWS_41(1)
- Evidence preview:
  - `CKV2_AWS_41` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `metadata_hardening_missing`

- Findings: 1
- Checks: CKV_AWS_79(1)
- Evidence preview:
  - `CKV_AWS_79` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `network_visibility_missing`

- Findings: 1
- Checks: CKV2_AWS_11(1)
- Evidence preview:
  - `CKV2_AWS_11` aws_vpc.vpc (/vpc.tf:1-8)

### `open_egress`

- Findings: 1
- Checks: CKV_AWS_382(1)
- Evidence preview:
  - `CKV_AWS_382` aws_security_group.ec2_server (/ec2.tf:1-37)

## Unmapped Check IDs

- `CKV2_AWS_12`
- `CKV_AWS_126`
- `CKV_AWS_135`
