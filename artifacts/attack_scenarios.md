# Attack Scenarios Report

## Summary

- Failed findings: 26
- Mapped findings: 26
- Technique groups: 18
- Atomic IDs: 7
- Scenarios: 7
- Unmapped check IDs: 0

## Scenarios

### 공개 SSH 노출 후 IAM 권한 악용

- ID: `aws_initial_access_to_iam_abuse`
- Score: `high`
- Atomic chain: T1190, T1098.003
- Matched capability keys: sg_ingress_ssh_open, iam_policy_admin_or_wildcard
- Matched check IDs: -
- Evidence count: 6
- Description: 공개 SSH 인바운드 노출 자산에 대한 초기 접근 이후, 관리자급/와일드카드 IAM 권한을 악용해 권한 상승 또는 지속성을 확보할 수 있음
- Evidence preview:
  - `CKV_AWS_24` Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=ingress/[0]/from_port, ingress/[0]/to_port, ingress/[0]/cidr_blocks 외 1개
  - `CKV_AWS_355` Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_63` Ensure no IAM policies documents allow "*" as a statement's actions | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy, inline_policy
  - `CKV_AWS_62` Ensure IAM policies that allow full "*-*" administrative privileges are not created | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy, inline_policy
  - `CKV_AWS_355` Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[0]/Action
  - ... and 1 more

### IMDS 자격증명 수집 후 외부 유출

- ID: `aws_credential_collection_and_exfiltration`
- Score: `high`
- Atomic chain: T1552, T1041
- Matched capability keys: imdsv1_enabled, sg_egress_all_open
- Matched check IDs: -
- Evidence count: 2
- Description: IMDSv1 활성화로 자격증명 수집이 쉬워지고, 전방위 egress 허용이 결합되면 외부 반출 위험이 증가함
- Evidence preview:
  - `CKV_AWS_79` Ensure Instance Metadata Service Version 1 is not enabled | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=metadata_options/[0]/http_tokens
  - `CKV_AWS_382` Ensure no security groups allow egress from 0.0.0.0:0 to port -1 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=egress/[0]/from_port, egress/[0]/to_port, egress/[0]/cidr_blocks 외 1개

### IAM 사용자 직접 정책 기반 지속성

- ID: `aws_identity_persistence_via_iam_user`
- Score: `high`
- Atomic chain: T1078.004, T1098.003
- Matched capability keys: iam_user_present, iam_policy_attached_to_user, iam_policy_privilege_escalation
- Matched check IDs: -
- Evidence count: 4
- Description: IAM 사용자 존재 + 사용자 직접 정책 부여 + 권한상승 가능 정책이 결합되면 장기 자격증명 기반 지속성이 강화됨
- Evidence preview:
  - `CKV_AWS_273` Ensure access is controlled through SSO and not AWS IAM defined users | resource_address=aws_iam_user.kerrigan | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=
  - `CKV_AWS_40` Ensure IAM policies are attached only to groups or roles (Reducing access management complexity may in-turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.) | resource_address=aws_iam_user_policy_attachment.kerrigan_attachment | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=user
  - `CKV_AWS_286` Ensure IAM policies does not allow privilege escalation | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_286` Ensure IAM policies does not allow privilege escalation | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[0]/Action

### 가시성 공백과 기본 SG 원격 접근 위험

- ID: `aws_visibility_gap_and_remote_access_risk`
- Score: `medium`
- Atomic chain: T1046, T1021
- Matched capability keys: vpc_flow_logs_disabled, default_sg_not_restricted
- Matched check IDs: -
- Evidence count: 2
- Description: VPC Flow Logs가 없고 기본 SG가 제한되지 않으면 원격 접근 시도 및 네트워크 활동에 대한 탐지/분석 공백이 커짐
- Evidence preview:
  - `CKV2_AWS_11` Ensure VPC flow logging is enabled in all VPCs | resource_address=aws_vpc.vpc | file_abs_path=/home/jiyoon/testterraform/vpc.tf | evaluated_keys=networking, resource_type
  - `CKV2_AWS_12` Ensure the default security group of every VPC restricts all traffic | resource_address=aws_vpc.vpc | file_abs_path=/home/jiyoon/testterraform/vpc.tf | evaluated_keys=egress/to_port, egress/from_port, resource_type 외 6개

### 공개 HTTP 노출 후 외부 데이터 반출

- ID: `aws_public_web_to_data_egress`
- Score: `high`
- Atomic chain: T1190, T1041
- Matched capability keys: sg_ingress_http_open, sg_egress_all_open
- Matched check IDs: -
- Evidence count: 2
- Description: 공개 HTTP 인바운드와 전방위 egress 허용이 결합되면 초기 침입 후 외부 반출 경로가 성립함
- Evidence preview:
  - `CKV_AWS_260` Ensure no security groups allow ingress from 0.0.0.0:0 to port 80 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=ingress/[2]/from_port, ingress/[2]/to_port, ingress/[2]/cidr_blocks 외 1개
  - `CKV_AWS_382` Ensure no security groups allow egress from 0.0.0.0:0 to port -1 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=egress/[0]/from_port, egress/[0]/to_port, egress/[0]/cidr_blocks 외 1개

### 퍼블릭 인스턴스 노출 후 IMDS 자격증명 수집

- ID: `aws_public_instance_imds_credential_access`
- Score: `high`
- Atomic chain: T1190, T1552
- Matched capability keys: ec2_public_ip_exposed, imdsv1_enabled
- Matched check IDs: -
- Evidence count: 2
- Description: 퍼블릭 IP가 노출된 EC2 인스턴스에서 IMDSv1이 활성화되어 있으면 초기 접근 이후 자격증명 수집 위험이 커짐
- Evidence preview:
  - `CKV_AWS_88` EC2 instance should not have public IP. | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=associate_public_ip_address
  - `CKV_AWS_79` Ensure Instance Metadata Service Version 1 is not enabled | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=metadata_options/[0]/http_tokens

### IAM 과권한으로 인한 자격증명 접근 및 데이터 반출

- ID: `aws_iam_credential_access_and_exfiltration`
- Score: `high`
- Atomic chain: T1552, T1041
- Matched capability keys: iam_policy_credential_exposure, iam_policy_data_exfiltration
- Matched check IDs: -
- Evidence count: 2
- Description: IAM 정책이 자격증명 접근 액션과 데이터 반출 액션을 동시에 과도하게 허용하면 침해 후 수집과 반출이 연쇄적으로 가능해짐
- Evidence preview:
  - `CKV_AWS_287` Ensure IAM policies does not allow credentials exposure | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_288` Ensure IAM policies does not allow data exfiltration | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action

## Technique Groups

### `auto_stage_execution_or_visibility_control`

- MITRE tactic: `DE`
- Stage: `execution_or_visibility_control`
- Capability ID: `AUTO_STAGE_EXECUTION_VISIBILITY`
- Description: 실행·탐지우회 단계로 분류되는 체크 자동 보강 그룹
- Findings: 2
- Checks: CKV_AWS_126(1), CKV_AWS_135(1)
- Evidence preview:
  - `CKV_AWS_126` Ensure that detailed monitoring is enabled for EC2 instances | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=monitoring
  - `CKV_AWS_135` Ensure that EC2 is EBS optimized | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=ebs_optimized

### `default_sg_not_restricted`

- MITRE tactic: `IA`
- Stage: `initial_access`
- Capability ID: `VIS_DEFAULT_SG_NOT_RESTRICTED`
- Description: 기본 보안그룹이 제한되지 않음(원격 접근/이상행위 탐지 어려움)
- Findings: 1
- Checks: CKV2_AWS_12(1)
- Evidence preview:
  - `CKV2_AWS_12` Ensure the default security group of every VPC restricts all traffic | resource_address=aws_vpc.vpc | file_abs_path=/home/jiyoon/testterraform/vpc.tf | evaluated_keys=egress/to_port, egress/from_port, resource_type 외 6개

### `ec2_instance_profile_missing`

- MITRE tactic: `PR`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `CMP_INSTANCE_PROFILE_MISSING`
- Description: EC2 인스턴스 역할/프로파일 거버넌스 부재(권한 통제/감사 약화)
- Findings: 1
- Checks: CKV2_AWS_41(1)
- Evidence preview:
  - `CKV2_AWS_41` Ensure an IAM role is attached to EC2 instance | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=iam_instance_profile

### `ec2_public_ip_exposed`

- MITRE tactic: `IA`
- Stage: `initial_access`
- Capability ID: `CMP_EC2_PUBLIC_IP`
- Description: EC2 퍼블릭 IP 직접 노출(외부에서 직접 접근 가능)
- Findings: 1
- Checks: CKV_AWS_88(1)
- Evidence preview:
  - `CKV_AWS_88` EC2 instance should not have public IP. | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=associate_public_ip_address

### `iam_policy_admin_or_wildcard`

- MITRE tactic: `PE`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `IAM_WILDCARD_POLICY`
- Description: IAM 와일드카드/관리자급 권한 남용 우려. 리소스/권한 제한이 충분히 특정되지 않음.
- Findings: 5
- Checks: CKV2_AWS_40(1), CKV_AWS_355(2), CKV_AWS_62(1), CKV_AWS_63(1)
- Evidence preview:
  - `CKV_AWS_355` Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_63` Ensure no IAM policies documents allow "*" as a statement's actions | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy, inline_policy
  - `CKV_AWS_62` Ensure IAM policies that allow full "*-*" administrative privileges are not created | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy, inline_policy
  - `CKV_AWS_355` Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV2_AWS_40` Ensure AWS IAM policy does not allow full IAM privileges | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement[?(@/Effect == Allow)]/Action[*], statement[?(@/effect == Allow)]/actions[*], inline_policy/Statement[?(@/Effect == Allow)]/Action[*]

### `iam_policy_attached_to_user`

- MITRE tactic: `PR`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `IAM_POLICY_ATTACHED_TO_USER`
- Description: 사용자 직접 정책 부여로 장기 권한 유지/확장 가능
- Findings: 1
- Checks: CKV_AWS_40(1)
- Evidence preview:
  - `CKV_AWS_40` Ensure IAM policies are attached only to groups or roles (Reducing access management complexity may in-turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.) | resource_address=aws_iam_user_policy_attachment.kerrigan_attachment | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=user

### `iam_policy_credential_exposure`

- MITRE tactic: `CA`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `IAM_CREDENTIAL_EXPOSURE`
- Description: IAM 정책이 자격증명 접근 액션을 과도하게 허용함
- Findings: 1
- Checks: CKV_AWS_287(1)
- Evidence preview:
  - `CKV_AWS_287` Ensure IAM policies does not allow credentials exposure | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action

### `iam_policy_data_exfiltration`

- MITRE tactic: `EX`
- Stage: `impact_or_exfiltration`
- Capability ID: `IAM_DATA_EXFILTRATION`
- Description: IAM 정책이 데이터 반출 액션을 과도하게 허용함
- Findings: 1
- Checks: CKV_AWS_288(1)
- Evidence preview:
  - `CKV_AWS_288` Ensure IAM policies does not allow data exfiltration | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action

### `iam_policy_permission_mgmt_unscoped`

- MITRE tactic: `PE`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `IAM_PERMISSION_MGMT_UNSCOPED`
- Description: 범위 제한 없는 권한/권한관리 관련 액션 허용(권한 남용/상승 경로)
- Findings: 2
- Checks: CKV_AWS_289(2)
- Evidence preview:
  - `CKV_AWS_289` Ensure IAM policies does not allow permissions management / resource exposure without constraints | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_289` Ensure IAM policies does not allow permissions management / resource exposure without constraints | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[0]/Action

### `iam_policy_privilege_escalation`

- MITRE tactic: `PE`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `IAM_PE_POLICY`
- Description: Privilege Escalation 가능성이 있는 IAM Policy 권한 조합 존재
- Findings: 2
- Checks: CKV_AWS_286(2)
- Evidence preview:
  - `CKV_AWS_286` Ensure IAM policies does not allow privilege escalation | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_286` Ensure IAM policies does not allow privilege escalation | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[0]/Action

### `iam_policy_write_unscoped`

- MITRE tactic: `PE`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `IAM_WRITE_UNSCOPED`
- Description: 범위 제한 없는 쓰기 권한 허용(리소스 변경/정책 변경 악용 가능)
- Findings: 2
- Checks: CKV_AWS_290(2)
- Evidence preview:
  - `CKV_AWS_290` Ensure IAM policies does not allow write access without constraints | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_290` Ensure IAM policies does not allow write access without constraints | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[1]/Action

### `iam_user_present`

- MITRE tactic: `PR`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `IAM_USER_PRESENT`
- Description: IAM 사용자 기반 장기 접근 경로 존재(키/비밀번호 기반)
- Findings: 1
- Checks: CKV_AWS_273(1)
- Evidence preview:
  - `CKV_AWS_273` Ensure access is controlled through SSO and not AWS IAM defined users | resource_address=aws_iam_user.kerrigan | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=

### `imdsv1_enabled`

- MITRE tactic: `PE`
- Stage: `privilege_or_credential_expansion`
- Capability ID: `CMP_IMDSV1_ENABLED`
- Description: IMDSv1 활성화(인스턴스 자격증명 탈취 위험 증가)
- Findings: 1
- Checks: CKV_AWS_79(1)
- Evidence preview:
  - `CKV_AWS_79` Ensure Instance Metadata Service Version 1 is not enabled | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=metadata_options/[0]/http_tokens

### `sg_egress_all_open`

- MITRE tactic: `EX`
- Stage: `impact_or_exfiltration`
- Capability ID: `NET_EGRESS_ALL_OPEN`
- Description: 전방위 egress 허용(유출/원격 통신 경로 확대)
- Findings: 1
- Checks: CKV_AWS_382(1)
- Evidence preview:
  - `CKV_AWS_382` Ensure no security groups allow egress from 0.0.0.0:0 to port -1 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=egress/[0]/from_port, egress/[0]/to_port, egress/[0]/cidr_blocks 외 1개

### `sg_ingress_http_open`

- MITRE tactic: `IA`
- Stage: `initial_access`
- Capability ID: `NET_PUBLIC_HTTP`
- Description: 공개 HTTP 인바운드 노출(공격 표면 증가)
- Findings: 1
- Checks: CKV_AWS_260(1)
- Evidence preview:
  - `CKV_AWS_260` Ensure no security groups allow ingress from 0.0.0.0:0 to port 80 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=ingress/[2]/from_port, ingress/[2]/to_port, ingress/[2]/cidr_blocks 외 1개

### `sg_ingress_ssh_open`

- MITRE tactic: `IA`
- Stage: `initial_access`
- Capability ID: `NET_PUBLIC_SSH`
- Description: 공개 SSH 인바운드 노출(원격 접근 표면 증가)
- Findings: 1
- Checks: CKV_AWS_24(1)
- Evidence preview:
  - `CKV_AWS_24` Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=ingress/[0]/from_port, ingress/[0]/to_port, ingress/[0]/cidr_blocks 외 1개

### `subnet_auto_public_ip`

- MITRE tactic: `IA`
- Stage: `initial_access`
- Capability ID: `CMP_SUBNET_AUTO_PUBLIC_IP`
- Description: 서브넷 기본 퍼블릭 IP 자동 할당(의도치 않은 노출 가능)
- Findings: 1
- Checks: CKV_AWS_130(1)
- Evidence preview:
  - `CKV_AWS_130` Ensure VPC subnets do not assign public IP by default | resource_address=aws_subnet.public | file_abs_path=/home/jiyoon/testterraform/vpc.tf | evaluated_keys=map_public_ip_on_launch

### `vpc_flow_logs_disabled`

- MITRE tactic: `DE`
- Stage: `execution_or_visibility_control`
- Capability ID: `VIS_VPC_FLOW_LOGS_DISABLED`
- Description: VPC Flow Logs 미설정(네트워크 가시성/탐지 공백)
- Findings: 1
- Checks: CKV2_AWS_11(1)
- Evidence preview:
  - `CKV2_AWS_11` Ensure VPC flow logging is enabled in all VPCs | resource_address=aws_vpc.vpc | file_abs_path=/home/jiyoon/testterraform/vpc.tf | evaluated_keys=networking, resource_type

## Unmapped Check IDs

- None
