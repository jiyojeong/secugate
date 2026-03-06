# Attack Scenarios Report

## Summary

- Failed findings: 26
- Mapped findings: 22
- Capabilities: 15
- Atomic IDs: 0
- Scenarios: 0
- Unmapped check IDs: 4

## Scenarios

- No matched scenarios
## Capabilities

### `EC2 인스턴스 역할/프로파일 거버넌스 부재(권한 통제/감사 약화)`

- Findings: 1
- Checks: CKV2_AWS_41(1)
- Evidence preview:
  - `CKV2_AWS_41` Ensure an IAM role is attached to EC2 instance | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=iam_instance_profile

### `EC2 퍼블릭 IP 직접 노출(외부에서 직접 접근 가능)`

- Findings: 1
- Checks: CKV_AWS_88(1)
- Evidence preview:
  - `CKV_AWS_88` EC2 instance should not have public IP. | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=associate_public_ip_address

### `IAM 사용자 기반 장기 접근 경로 존재(키/비밀번호 기반)`

- Findings: 1
- Checks: CKV_AWS_273(1)
- Evidence preview:
  - `CKV_AWS_273` Ensure access is controlled through SSO and not AWS IAM defined users | resource_address=aws_iam_user.kerrigan | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=

### `IAM 와일드카드/관리자급 권한 남용 우려. 리소스/권한 제한이 충분히 특정되지 않음.`

- Findings: 5
- Checks: CKV2_AWS_40(1), CKV_AWS_355(2), CKV_AWS_62(1), CKV_AWS_63(1)
- Evidence preview:
  - `CKV_AWS_355` Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_63` Ensure no IAM policies documents allow "*" as a statement's actions | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy, inline_policy
  - `CKV_AWS_62` Ensure IAM policies that allow full "*-*" administrative privileges are not created | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy, inline_policy
  - `CKV_AWS_355` Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV2_AWS_40` Ensure AWS IAM policy does not allow full IAM privileges | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement[?(@/Effect == Allow)]/Action[*], statement[?(@/effect == Allow)]/actions[*], inline_policy/Statement[?(@/Effect == Allow)]/Action[*]

### `IMDSv1 활성화(인스턴스 자격증명 탈취 위험 증가)`

- Findings: 1
- Checks: CKV_AWS_79(1)
- Evidence preview:
  - `CKV_AWS_79` Ensure Instance Metadata Service Version 1 is not enabled | resource_address=aws_instance.super_critical_security_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=metadata_options/[0]/http_tokens

### `Privilege Escalation 가능성이 있는 IAM Policy 권한 조합 존재`

- Findings: 2
- Checks: CKV_AWS_286(2)
- Evidence preview:
  - `CKV_AWS_286` Ensure IAM policies does not allow privilege escalation | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_286` Ensure IAM policies does not allow privilege escalation | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[0]/Action

### `VPC Flow Logs 미설정(네트워크 가시성/탐지 공백)`

- Findings: 1
- Checks: CKV2_AWS_11(1)
- Evidence preview:
  - `CKV2_AWS_11` Ensure VPC flow logging is enabled in all VPCs | resource_address=aws_vpc.vpc | file_abs_path=/home/jiyoon/testterraform/vpc.tf | evaluated_keys=networking, resource_type

### `공개 HTTP 인바운드 노출(공격 표면 증가)`

- Findings: 1
- Checks: CKV_AWS_260(1)
- Evidence preview:
  - `CKV_AWS_260` Ensure no security groups allow ingress from 0.0.0.0:0 to port 80 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=ingress/[2]/from_port, ingress/[2]/to_port, ingress/[2]/cidr_blocks 외 1개

### `공개 SSH 인바운드 노출(원격 접근 표면 증가)`

- Findings: 1
- Checks: CKV_AWS_24(1)
- Evidence preview:
  - `CKV_AWS_24` Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=ingress/[0]/from_port, ingress/[0]/to_port, ingress/[0]/cidr_blocks 외 1개

### `기본 보안그룹이 제한되지 않음(원격 접근/이상행위 탐지 어려움)`

- Findings: 1
- Checks: CKV2_AWS_12(1)
- Evidence preview:
  - `CKV2_AWS_12` Ensure the default security group of every VPC restricts all traffic | resource_address=aws_vpc.vpc | file_abs_path=/home/jiyoon/testterraform/vpc.tf | evaluated_keys=ingress/protocol, ingress/from_port, egress/from_port 외 6개

### `범위 제한 없는 권한/권한관리 관련 액션 허용(권한 남용/상승 경로)`

- Findings: 2
- Checks: CKV_AWS_289(2)
- Evidence preview:
  - `CKV_AWS_289` Ensure IAM policies does not allow permissions management / resource exposure without constraints | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_289` Ensure IAM policies does not allow permissions management / resource exposure without constraints | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[0]/Action

### `범위 제한 없는 쓰기 권한 허용(리소스 변경/정책 변경 악용 가능)`

- Findings: 2
- Checks: CKV_AWS_290(2)
- Evidence preview:
  - `CKV_AWS_290` Ensure IAM policies does not allow write access without constraints | resource_address=aws_iam_policy.ec2_mighty_policy | file_abs_path=/home/jiyoon/testterraform/iam_mighty.tf | evaluated_keys=policy/Statement/[0]/Action
  - `CKV_AWS_290` Ensure IAM policies does not allow write access without constraints | resource_address=aws_iam_policy.kerrigan_policy | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=policy/Statement/[1]/Action

### `사용자 직접 정책 부여로 장기 권한 유지/확장 가능`

- Findings: 1
- Checks: CKV_AWS_40(1)
- Evidence preview:
  - `CKV_AWS_40` Ensure IAM policies are attached only to groups or roles (Reducing access management complexity may in-turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.) | resource_address=aws_iam_user_policy_attachment.kerrigan_attachment | file_abs_path=/home/jiyoon/testterraform/iam.tf | evaluated_keys=user

### `서브넷 기본 퍼블릭 IP 자동 할당(의도치 않은 노출 가능)`

- Findings: 1
- Checks: CKV_AWS_130(1)
- Evidence preview:
  - `CKV_AWS_130` Ensure VPC subnets do not assign public IP by default | resource_address=aws_subnet.public | file_abs_path=/home/jiyoon/testterraform/vpc.tf | evaluated_keys=map_public_ip_on_launch

### `전방위 egress 허용(유출/원격 통신 경로 확대)`

- Findings: 1
- Checks: CKV_AWS_382(1)
- Evidence preview:
  - `CKV_AWS_382` Ensure no security groups allow egress from 0.0.0.0:0 to port -1 | resource_address=aws_security_group.ec2_server | file_abs_path=/home/jiyoon/testterraform/ec2.tf | evaluated_keys=egress/[0]/from_port, egress/[0]/to_port, egress/[0]/cidr_blocks 외 1개

## Unmapped Check IDs

- `CKV_AWS_126`
- `CKV_AWS_135`
- `CKV_AWS_287`
- `CKV_AWS_288`
