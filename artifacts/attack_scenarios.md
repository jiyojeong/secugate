# Attack Scenarios Report

## Summary

- Failed findings: 26
- Mapped findings: 26
- Capabilities: 19
- Atomic IDs: 7
- Scenarios: 4
- Unmapped check IDs: 0

## Scenarios

### 공개 SSH 노출 후 IAM 권한 악용

- ID: `aws_initial_access_to_iam_abuse`
- Score: `high`
- Atomic chain: T1190, T1098.003
- Matched capabilities: sg_ingress_ssh_open, iam_policy_admin_or_wildcard
- Matched check IDs: -
- Evidence count: 6
- Description: 공개 SSH 인바운드 노출 자산 초기 접근 이후 관리자급/와일드카드 IAM 정책으로 권한 상승 또는 지속성 확보

### IMDS 자격증명 수집 후 외부 유출

- ID: `aws_credential_collection_and_exfiltration`
- Score: `high`
- Atomic chain: T1552, T1041
- Matched capabilities: imdsv1_enabled, sg_egress_all_open
- Matched check IDs: -
- Evidence count: 2
- Description: IMDSv1 활성화와 전방위 egress 허용 조합으로 수집 자격증명/데이터 외부 반출 위험 증가

### IAM 사용자 직접 정책 기반 지속성

- ID: `aws_identity_persistence_via_iam_user`
- Score: `high`
- Atomic chain: T1078.004, T1098.003
- Matched capabilities: iam_user_present, iam_policy_attached_to_user, iam_policy_privilege_escalation
- Matched check IDs: -
- Evidence count: 4
- Description: IAM 사용자 사용과 사용자 직접 정책 부여가 결합되면 장기 자격증명 기반 지속성이 강화됨

### 가시성 공백과 기본 SG 원격 접근 위험

- ID: `aws_visibility_gap_and_remote_access_risk`
- Score: `medium`
- Atomic chain: T1046, T1021
- Matched capabilities: vpc_flow_logs_disabled, default_sg_not_restricted
- Matched check IDs: -
- Evidence count: 2
- Description: VPC 플로우 로그 미설정 상태에서 기본 보안그룹이 트래픽을 제한하지 않으면 원격 접근 활동 탐지/분석이 어려워짐

## Capabilities

### `default_sg_not_restricted`

- Findings: 1
- Checks: CKV2_AWS_12(1)
- Evidence preview:
  - `CKV2_AWS_12` aws_vpc.vpc (/vpc.tf:1-8)

### `ec2_instance_profile_missing`

- Findings: 1
- Checks: CKV2_AWS_41(1)
- Evidence preview:
  - `CKV2_AWS_41` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `ec2_public_ip_exposed`

- Findings: 1
- Checks: CKV_AWS_88(1)
- Evidence preview:
  - `CKV_AWS_88` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `iam_policy_admin_or_wildcard`

- Findings: 5
- Checks: CKV2_AWS_40(1), CKV_AWS_355(2), CKV_AWS_62(1), CKV_AWS_63(1)
- Evidence preview:
  - `CKV_AWS_355` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_63` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_62` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_355` aws_iam_policy.kerrigan_policy (/iam.tf:10-44)
  - `CKV2_AWS_40` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)

### `iam_policy_attached_to_user`

- Findings: 1
- Checks: CKV_AWS_40(1)
- Evidence preview:
  - `CKV_AWS_40` aws_iam_user_policy_attachment.kerrigan_attachment (/iam.tf:46-49)

### `iam_policy_credential_exposure`

- Findings: 1
- Checks: CKV_AWS_287(1)
- Evidence preview:
  - `CKV_AWS_287` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)

### `iam_policy_data_exfiltration`

- Findings: 1
- Checks: CKV_AWS_288(1)
- Evidence preview:
  - `CKV_AWS_288` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)

### `iam_policy_permission_mgmt_unscoped`

- Findings: 2
- Checks: CKV_AWS_289(2)
- Evidence preview:
  - `CKV_AWS_289` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_289` aws_iam_policy.kerrigan_policy (/iam.tf:10-44)

### `iam_policy_privilege_escalation`

- Findings: 2
- Checks: CKV_AWS_286(2)
- Evidence preview:
  - `CKV_AWS_286` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_286` aws_iam_policy.kerrigan_policy (/iam.tf:10-44)

### `iam_policy_write_unscoped`

- Findings: 2
- Checks: CKV_AWS_290(2)
- Evidence preview:
  - `CKV_AWS_290` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_290` aws_iam_policy.kerrigan_policy (/iam.tf:10-44)

### `iam_user_present`

- Findings: 1
- Checks: CKV_AWS_273(1)
- Evidence preview:
  - `CKV_AWS_273` aws_iam_user.kerrigan (/iam.tf:1-4)

### `imdsv1_enabled`

- Findings: 1
- Checks: CKV_AWS_79(1)
- Evidence preview:
  - `CKV_AWS_79` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `non_attack_compute_performance_hardening_missing`

- Findings: 1
- Checks: CKV_AWS_135(1)
- Evidence preview:
  - `CKV_AWS_135` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `non_attack_monitoring_depth_missing`

- Findings: 1
- Checks: CKV_AWS_126(1)
- Evidence preview:
  - `CKV_AWS_126` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `sg_egress_all_open`

- Findings: 1
- Checks: CKV_AWS_382(1)
- Evidence preview:
  - `CKV_AWS_382` aws_security_group.ec2_server (/ec2.tf:1-37)

### `sg_ingress_http_open`

- Findings: 1
- Checks: CKV_AWS_260(1)
- Evidence preview:
  - `CKV_AWS_260` aws_security_group.ec2_server (/ec2.tf:1-37)

### `sg_ingress_ssh_open`

- Findings: 1
- Checks: CKV_AWS_24(1)
- Evidence preview:
  - `CKV_AWS_24` aws_security_group.ec2_server (/ec2.tf:1-37)

### `subnet_auto_public_ip`

- Findings: 1
- Checks: CKV_AWS_130(1)
- Evidence preview:
  - `CKV_AWS_130` aws_subnet.public (/vpc.tf:18-27)

### `vpc_flow_logs_disabled`

- Findings: 1
- Checks: CKV2_AWS_11(1)
- Evidence preview:
  - `CKV2_AWS_11` aws_vpc.vpc (/vpc.tf:1-8)

## Unmapped Check IDs

- None
