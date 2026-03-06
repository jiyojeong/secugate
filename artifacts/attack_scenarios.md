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
  - `CKV2_AWS_41` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `EC2 퍼블릭 IP 직접 노출(외부에서 직접 접근 가능)`

- Findings: 1
- Checks: CKV_AWS_88(1)
- Evidence preview:
  - `CKV_AWS_88` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `IAM 사용자 기반 장기 접근 경로 존재(키/비밀번호 기반)`

- Findings: 1
- Checks: CKV_AWS_273(1)
- Evidence preview:
  - `CKV_AWS_273` aws_iam_user.kerrigan (/iam.tf:1-4)

### `IAM 와일드카드/관리자급 권한 남용 우려. 리소스/권한 제한이 충분히 특정되지 않음.`

- Findings: 5
- Checks: CKV2_AWS_40(1), CKV_AWS_355(2), CKV_AWS_62(1), CKV_AWS_63(1)
- Evidence preview:
  - `CKV_AWS_355` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_63` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_62` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_355` aws_iam_policy.kerrigan_policy (/iam.tf:10-44)
  - `CKV2_AWS_40` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)

### `IMDSv1 활성화(인스턴스 자격증명 탈취 위험 증가)`

- Findings: 1
- Checks: CKV_AWS_79(1)
- Evidence preview:
  - `CKV_AWS_79` aws_instance.super_critical_security_server (/ec2.tf:39-62)

### `Privilege Escalation 가능성이 있는 IAM Policy 권한 조합 존재`

- Findings: 2
- Checks: CKV_AWS_286(2)
- Evidence preview:
  - `CKV_AWS_286` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_286` aws_iam_policy.kerrigan_policy (/iam.tf:10-44)

### `VPC Flow Logs 미설정(네트워크 가시성/탐지 공백)`

- Findings: 1
- Checks: CKV2_AWS_11(1)
- Evidence preview:
  - `CKV2_AWS_11` aws_vpc.vpc (/vpc.tf:1-8)

### `공개 HTTP 인바운드 노출(공격 표면 증가)`

- Findings: 1
- Checks: CKV_AWS_260(1)
- Evidence preview:
  - `CKV_AWS_260` aws_security_group.ec2_server (/ec2.tf:1-37)

### `공개 SSH 인바운드 노출(원격 접근 표면 증가)`

- Findings: 1
- Checks: CKV_AWS_24(1)
- Evidence preview:
  - `CKV_AWS_24` aws_security_group.ec2_server (/ec2.tf:1-37)

### `기본 보안그룹이 제한되지 않음(원격 접근/이상행위 탐지 어려움)`

- Findings: 1
- Checks: CKV2_AWS_12(1)
- Evidence preview:
  - `CKV2_AWS_12` aws_vpc.vpc (/vpc.tf:1-8)

### `범위 제한 없는 권한/권한관리 관련 액션 허용(권한 남용/상승 경로)`

- Findings: 2
- Checks: CKV_AWS_289(2)
- Evidence preview:
  - `CKV_AWS_289` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_289` aws_iam_policy.kerrigan_policy (/iam.tf:10-44)

### `범위 제한 없는 쓰기 권한 허용(리소스 변경/정책 변경 악용 가능)`

- Findings: 2
- Checks: CKV_AWS_290(2)
- Evidence preview:
  - `CKV_AWS_290` aws_iam_policy.ec2_mighty_policy (/iam_mighty.tf:21-35)
  - `CKV_AWS_290` aws_iam_policy.kerrigan_policy (/iam.tf:10-44)

### `사용자 직접 정책 부여로 장기 권한 유지/확장 가능`

- Findings: 1
- Checks: CKV_AWS_40(1)
- Evidence preview:
  - `CKV_AWS_40` aws_iam_user_policy_attachment.kerrigan_attachment (/iam.tf:46-49)

### `서브넷 기본 퍼블릭 IP 자동 할당(의도치 않은 노출 가능)`

- Findings: 1
- Checks: CKV_AWS_130(1)
- Evidence preview:
  - `CKV_AWS_130` aws_subnet.public (/vpc.tf:18-27)

### `전방위 egress 허용(유출/원격 통신 경로 확대)`

- Findings: 1
- Checks: CKV_AWS_382(1)
- Evidence preview:
  - `CKV_AWS_382` aws_security_group.ec2_server (/ec2.tf:1-37)

## Unmapped Check IDs

- `CKV_AWS_126`
- `CKV_AWS_135`
- `CKV_AWS_287`
- `CKV_AWS_288`
