# IaC Graph Checkov Paths Report

## Sources

- Graph: `/home/jiyoon/secugate/artifacts/iac_graph.json`
- Checkov: `/home/jiyoon/secugate/artifacts/checkov_merged.json`

## Summary

- Checkov indexed nodes: 7
- Checkov failed checks: 31
- CRITICAL findings: 3
- DFS validated: 7 / 368
- Max hops: 6

### CRITICAL Finding Details

- `CKV_AWS_287` | `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf` | 자격증명 접근 액션 과다 허용
- `CKV_AWS_62` | `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf` | Action/Resource 와일드카드 정책
- `CKV_AWS_63` | `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf` | Action/Resource 와일드카드 정책

## Path Categories

- `네트워크 노출형 경로` (`network_exposure_chain`): 2
- `IAM 권한형 경로` (`iam_privilege_chain`): 2
- `네트워크->IAM 혼합 경로` (`network_to_iam_chain`): 1
- `기타 경로` (`other_chain`): 2

## DFS Validated Paths By Category

## 네트워크 노출형 경로

- 개수: 2

### 1. `aws_subnet.public` -> `aws_vpc.main`

- Hops: 4
- Path category: `네트워크 노출형 경로`
- Stage sequence: 0:초기 접근/노출 -> 2:실행·탐지우회
- Findings: 3 unique / 3 raw
- ATT&CK chain: IA, DE
- Atomic chain: T1190, T1021, T1046
- Checks: CKV2_AWS_11, CKV2_AWS_12, CKV_AWS_130
- Path: `aws_subnet.public -> aws_route_table_association.public -> aws_route_table.public -> aws_internet_gateway.gw -> aws_vpc.main`
- Scenario: `aws_subnet.public` -> `aws_vpc.main` 경로입니다.

[1] 초기 접근/노출
  - resource: `aws_subnet.public`
  - check: `퍼블릭 IP 할당`
  - check_id: `CKV_AWS_130`
  - check_name_en: `Ensure VPC subnets do not assign public IP by default`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `T1190`
  - why_fails: 퍼블릭 IP 할당
  - mitigation: aws_subnet 리소스에서 퍼블릭 IP 할당을 비활성화
  - resource_address: `aws_subnet.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `map_public_ip_on_launch`

[2] 초기 접근/노출
  - resource: `aws_vpc.main`
  - check: `기본 SG 미제한`
  - check_id: `CKV2_AWS_12`
  - check_name_en: `Ensure the default security group of every VPC restricts all traffic`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `T1021`
  - why_fails: 기본 SG 미제한
  - mitigation: aws_default_security_group 리소스의 기본 보안 그룹에서 불필요한 ingress/egress 규칙을 제거
  - resource_address: `aws_vpc.main`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `ingress/self, egress/from_port 외 7개`

[3] 실행·탐지우회
  - resource: `aws_vpc.main`
  - check: `VPC Flow Logs 미설정`
  - check_id: `CKV2_AWS_11`
  - check_name_en: `Ensure VPC flow logging is enabled in all VPCs`
  - severity: `MEDIUM`
  - mitre_tactic: `DE`
  - representative_atomic_id: `T1046`
  - why_fails: VPC Flow Logs 미설정
  - mitigation: aws_vpc 리소스에 VPC Flow Logs를 활성화
  - resource_address: `aws_vpc.main`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `resource_type, networking`

### 2. `aws_vpc.main` -> `aws_route_table_association.public`

- Hops: 3
- Path category: `네트워크 노출형 경로`
- Stage sequence: 0:초기 접근/노출 -> 2:실행·탐지우회
- Findings: 2 unique / 2 raw
- ATT&CK chain: IA, DE
- Atomic chain: T1021, T1046
- Checks: CKV2_AWS_11, CKV2_AWS_12
- Path: `aws_vpc.main -> aws_internet_gateway.gw -> aws_route_table.public -> aws_route_table_association.public`
- Scenario: `aws_vpc.main` -> `aws_route_table_association.public` 경로입니다.

[1] 초기 접근/노출
  - resource: `aws_vpc.main`
  - check: `기본 SG 미제한`
  - check_id: `CKV2_AWS_12`
  - check_name_en: `Ensure the default security group of every VPC restricts all traffic`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `T1021`
  - why_fails: 기본 SG 미제한
  - mitigation: aws_default_security_group 리소스의 기본 보안 그룹에서 불필요한 ingress/egress 규칙을 제거
  - resource_address: `aws_vpc.main`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `ingress/self, egress/from_port 외 7개`

[2] 실행·탐지우회
  - resource: `aws_vpc.main`
  - check: `VPC Flow Logs 미설정`
  - check_id: `CKV2_AWS_11`
  - check_name_en: `Ensure VPC flow logging is enabled in all VPCs`
  - severity: `MEDIUM`
  - mitre_tactic: `DE`
  - representative_atomic_id: `T1046`
  - why_fails: VPC Flow Logs 미설정
  - mitigation: aws_vpc 리소스에 VPC Flow Logs를 활성화
  - resource_address: `aws_vpc.main`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `resource_type, networking`

## IAM 권한형 경로

- 개수: 2

### 1. `aws_iam_policy.app` -> `aws_iam_instance_profile.app`

- Hops: 3
- Path category: `IAM 권한형 경로`
- Stage sequence: 1:권한·자격 확장 -> 3:영향·유출
- Findings: 9 unique / 9 raw
- ATT&CK chain: PE, EX
- Atomic chain: T1078, T1537
- Checks: CKV2_AWS_40, CKV_AWS_286, CKV_AWS_287, CKV_AWS_288, CKV_AWS_289, CKV_AWS_290, CKV_AWS_355, CKV_AWS_62 외 1개
- Path: `aws_iam_policy.app -> aws_iam_role_policy_attachment.app -> aws_iam_role.app -> aws_iam_instance_profile.app`
- Scenario: `aws_iam_policy.app` -> `aws_iam_instance_profile.app` 경로입니다.

[1] 권한·자격 확장
  - resource: `aws_iam_policy.app`
  - check: `Action/Resource 와일드카드 정책`
  - check_id: `CKV_AWS_63`
  - check_name_en: `Ensure no IAM policies documents allow "*" as a statement's actions`
  - severity: `CRITICAL`
  - mitre_tactic: `PE`
  - representative_atomic_id: `T1078`
  - why_fails: Action/Resource 와일드카드 정책
  - mitigation: aws_iam_group_policy 정책에서 Action/Resource 와일드카드를 제거하고 최소 권한으로 축소
  - resource_address: `aws_iam_policy.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `policy, inline_policy`

[2] 영향·유출
  - resource: `aws_iam_policy.app`
  - check: `데이터 반출 액션 과다 허용, 외부로 유출 가능성 높음`
  - check_id: `CKV_AWS_288`
  - check_name_en: `Ensure IAM policies does not allow data exfiltration`
  - severity: `HIGH`
  - mitre_tactic: `EX`
  - representative_atomic_id: `T1537`
  - why_fails: 데이터 반출 액션 과다 허용
  - mitigation: aws_iam_group_policy 정책에서 데이터 반출 관련 액션 범위를 최소화
  - resource_address: `aws_iam_policy.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `policy/Statement/[0]/Action`

### 2. `aws_instance.app` -> `aws_iam_role_policy_attachment.app`

- Hops: 3
- Path category: `IAM 권한형 경로`
- Stage sequence: 0:초기 접근/노출 -> 1:권한·자격 확장 -> 2:실행·탐지우회 -> 3:영향·유출
- Findings: 5 unique / 5 raw
- ATT&CK chain: IA, PE, DE, EX
- Atomic chain: T1190, T1552, T1068, T1530
- Checks: CKV_AWS_126, CKV_AWS_135, CKV_AWS_79, CKV_AWS_8, CKV_AWS_88
- Path: `aws_instance.app -> aws_iam_instance_profile.app -> aws_iam_role.app -> aws_iam_role_policy_attachment.app`
- Scenario: `aws_instance.app` -> `aws_iam_role_policy_attachment.app` 경로입니다.

[1] 초기 접근/노출
  - resource: `aws_instance.app`
  - check: `Amazon EC2 인스턴스가 Public IP를 가지고 있고, Security Group과 함께 인터넷과 직접 통신 가능한 상태`
  - check_id: `CKV_AWS_88`
  - check_name_en: `EC2 instance should not have public IP.`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `T1190`
  - why_fails: 퍼블릭 IP 할당
  - mitigation: aws_instance 리소스에서 퍼블릭 IP 할당을 비활성화
  - resource_address: `aws_instance.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `associate_public_ip_address`

[2] 권한·자격 확장
  - resource: `aws_instance.app`
  - check: `IMDSv2 미설정(aws_instance)`
  - check_id: `CKV_AWS_79`
  - check_name_en: `Ensure Instance Metadata Service Version 1 is not enabled`
  - severity: `HIGH`
  - mitre_tactic: `PE`
  - representative_atomic_id: `T1552`
  - why_fails: IMDSv2 미설정(aws_instance)
  - mitigation: aws_instance 리소스 metadata_options에 http_tokens = "required" 설정
  - resource_address: `aws_instance.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `metadata_options/[0]/http_tokens`

[3] 실행·탐지우회
  - resource: `aws_instance.app`
  - check: `필수 보안 설정 누락(설명 기반)`
  - check_id: `CKV_AWS_135`
  - check_name_en: `Ensure that EC2 is EBS optimized`
  - severity: `MEDIUM`
  - mitre_tactic: `DE`
  - representative_atomic_id: `T1068`
  - why_fails: 필수 보안 설정 누락(설명 기반)
  - mitigation: aws_instance 리소스에서 "Ensure that EC2 is EBS optimized" 요구사항을 충족하도록 보안 설정을 명시적으로 추가
  - resource_address: `aws_instance.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `ebs_optimized`

[4] 영향·유출
  - resource: `aws_instance.app`
  - check: `암호화 비활성화`
  - check_id: `CKV_AWS_8`
  - check_name_en: `Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted`
  - severity: `HIGH`
  - mitre_tactic: `EX`
  - representative_atomic_id: `T1530`
  - why_fails: 암호화 비활성화
  - mitigation: aws_instance 리소스에 저장 데이터 암호화를 활성화하고 가능하면 KMS CMK를 사용
  - resource_address: `aws_instance.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `root_block_device`

## 네트워크->IAM 혼합 경로

- 개수: 1

### 1. `aws_iam_role_policy_attachment.app` -> `aws_route_table.public`

- Hops: 6
- Path category: `네트워크->IAM 혼합 경로`
- Stage sequence: 0:초기 접근/노출 -> 1:권한·자격 확장 -> 2:실행·탐지우회 -> 3:영향·유출
- Findings: 6 unique / 6 raw
- ATT&CK chain: IA, PE, DE, EX
- Atomic chain: T1190, T1552, T1068, T1530
- Checks: CKV_AWS_126, CKV_AWS_130, CKV_AWS_135, CKV_AWS_79, CKV_AWS_8, CKV_AWS_88
- Path: `aws_route_table.public -> aws_route_table_association.public -> aws_subnet.public -> aws_instance.app -> aws_iam_instance_profile.app -> aws_iam_role.app -> aws_iam_role_policy_attachment.app`
- Scenario: `aws_route_table.public` -> `aws_iam_role_policy_attachment.app` 경로입니다.

[1] 초기 접근/노출
  - resource: `aws_subnet.public`
  - check: `퍼블릭 IP 할당`
  - check_id: `CKV_AWS_130`
  - check_name_en: `Ensure VPC subnets do not assign public IP by default`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `T1190`
  - why_fails: 퍼블릭 IP 할당
  - mitigation: aws_subnet 리소스에서 퍼블릭 IP 할당을 비활성화
  - resource_address: `aws_subnet.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `map_public_ip_on_launch`

[2] 초기 접근/노출
  - resource: `aws_instance.app`
  - check: `Amazon EC2 인스턴스가 Public IP를 가지고 있고, Security Group과 함께 인터넷과 직접 통신 가능한 상태`
  - check_id: `CKV_AWS_88`
  - check_name_en: `EC2 instance should not have public IP.`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `T1190`
  - why_fails: 퍼블릭 IP 할당
  - mitigation: aws_instance 리소스에서 퍼블릭 IP 할당을 비활성화
  - resource_address: `aws_instance.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `associate_public_ip_address`

[3] 권한·자격 확장
  - resource: `aws_instance.app`
  - check: `IMDSv2 미설정(aws_instance)`
  - check_id: `CKV_AWS_79`
  - check_name_en: `Ensure Instance Metadata Service Version 1 is not enabled`
  - severity: `HIGH`
  - mitre_tactic: `PE`
  - representative_atomic_id: `T1552`
  - why_fails: IMDSv2 미설정(aws_instance)
  - mitigation: aws_instance 리소스 metadata_options에 http_tokens = "required" 설정
  - resource_address: `aws_instance.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `metadata_options/[0]/http_tokens`

[4] 실행·탐지우회
  - resource: `aws_instance.app`
  - check: `필수 보안 설정 누락(설명 기반)`
  - check_id: `CKV_AWS_135`
  - check_name_en: `Ensure that EC2 is EBS optimized`
  - severity: `MEDIUM`
  - mitre_tactic: `DE`
  - representative_atomic_id: `T1068`
  - why_fails: 필수 보안 설정 누락(설명 기반)
  - mitigation: aws_instance 리소스에서 "Ensure that EC2 is EBS optimized" 요구사항을 충족하도록 보안 설정을 명시적으로 추가
  - resource_address: `aws_instance.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `ebs_optimized`

[5] 영향·유출
  - resource: `aws_instance.app`
  - check: `암호화 비활성화`
  - check_id: `CKV_AWS_8`
  - check_name_en: `Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted`
  - severity: `HIGH`
  - mitre_tactic: `EX`
  - representative_atomic_id: `T1530`
  - why_fails: 암호화 비활성화
  - mitigation: aws_instance 리소스에 저장 데이터 암호화를 활성화하고 가능하면 KMS CMK를 사용
  - resource_address: `aws_instance.app`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `root_block_device`

## 기타 경로

- 개수: 2

### 1. `aws_s3_bucket_policy.public` -> `aws_s3_bucket_public_access_block.public`

- Hops: 2
- Path category: `기타 경로`
- Stage sequence: 0:초기 접근/노출 -> 2:실행·탐지우회 -> 3:영향·유출
- Findings: 11 unique / 11 raw
- ATT&CK chain: IA, DE, EX
- Atomic chain: T1190, T1562, T1530
- Checks: CKV2_AWS_6, CKV2_AWS_61, CKV2_AWS_62, CKV_AWS_144, CKV_AWS_145, CKV_AWS_18, CKV_AWS_21, CKV_AWS_53 외 3개
- Path: `aws_s3_bucket_public_access_block.public -> aws_s3_bucket.public -> aws_s3_bucket_policy.public`
- Scenario: `aws_s3_bucket_public_access_block.public` -> `aws_s3_bucket_policy.public` 경로입니다.

[1] 초기 접근/노출
  - resource: `aws_s3_bucket_public_access_block.public`
  - check: `필수 보안 설정 누락(설명 기반)`
  - check_id: `CKV_AWS_56`
  - check_name_en: `Ensure S3 bucket has 'restrict_public_buckets' enabled`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `T1190`
  - why_fails: 필수 보안 설정 누락(설명 기반)
  - mitigation: aws_s3_bucket_public_access_block 리소스에서 "Ensure S3 bucket has ‘restrict_public_buckets’ enabled" 요구사항을 충족하도록 보안 설정을 명시적으로 추가
  - resource_address: `aws_s3_bucket_public_access_block.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `restrict_public_buckets`

[2] 초기 접근/노출
  - resource: `aws_s3_bucket.public`
  - check: `필수 보안 설정 누락(설명 기반)`
  - check_id: `CKV2_AWS_6`
  - check_name_en: `Ensure that S3 bucket has a Public Access block`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `-`
  - why_fails: 필수 보안 설정 누락(설명 기반)
  - mitigation: aws_s3_bucket 리소스에서 "Ensure that S3 bucket has a Public Access block" 요구사항을 충족하도록 보안 설정을 명시적으로 추가
  - resource_address: `aws_s3_bucket.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `resource_type, block_public_acls 외 1개`

[3] 실행·탐지우회
  - resource: `aws_s3_bucket.public`
  - check: `로깅/검증 비활성화`
  - check_id: `CKV_AWS_18`
  - check_name_en: `Ensure the S3 bucket has access logging enabled`
  - severity: `MEDIUM`
  - mitre_tactic: `DE`
  - representative_atomic_id: `T1562`
  - why_fails: 로깅/검증 비활성화
  - mitigation: aws_s3_bucket 리소스에 로깅 및 모니터링 설정을 활성화
  - resource_address: `aws_s3_bucket.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `logging, resource_type`

[4] 영향·유출
  - resource: `aws_s3_bucket.public`
  - check: `암호화 비활성화`
  - check_id: `CKV_AWS_145`
  - check_name_en: `Ensure that S3 buckets are encrypted with KMS by default`
  - severity: `HIGH`
  - mitre_tactic: `EX`
  - representative_atomic_id: `T1530`
  - why_fails: 암호화 비활성화
  - mitigation: aws_s3_bucket 리소스에 저장 데이터 암호화를 활성화하고 가능하면 KMS CMK를 사용
  - resource_address: `aws_s3_bucket.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `resource_type, rule/apply_server_side_encryption_by_default/sse_algorithm 외 1개`

### 2. `aws_s3_bucket_policy.public` -> `aws_s3_bucket.public`

- Hops: 1
- Path category: `기타 경로`
- Stage sequence: 0:초기 접근/노출 -> 2:실행·탐지우회 -> 3:영향·유출
- Findings: 7 unique / 7 raw
- ATT&CK chain: IA, DE, EX
- Atomic chain: T1562, T1530
- Checks: CKV2_AWS_6, CKV2_AWS_61, CKV2_AWS_62, CKV_AWS_144, CKV_AWS_145, CKV_AWS_18, CKV_AWS_21
- Path: `aws_s3_bucket_policy.public -> aws_s3_bucket.public`
- Scenario: `aws_s3_bucket_policy.public` -> `aws_s3_bucket.public` 경로입니다.

[1] 초기 접근/노출
  - resource: `aws_s3_bucket.public`
  - check: `필수 보안 설정 누락(설명 기반)`
  - check_id: `CKV2_AWS_6`
  - check_name_en: `Ensure that S3 bucket has a Public Access block`
  - severity: `HIGH`
  - mitre_tactic: `IA`
  - representative_atomic_id: `-`
  - why_fails: 필수 보안 설정 누락(설명 기반)
  - mitigation: aws_s3_bucket 리소스에서 "Ensure that S3 bucket has a Public Access block" 요구사항을 충족하도록 보안 설정을 명시적으로 추가
  - resource_address: `aws_s3_bucket.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `resource_type, block_public_acls 외 1개`

[2] 실행·탐지우회
  - resource: `aws_s3_bucket.public`
  - check: `로깅/검증 비활성화`
  - check_id: `CKV_AWS_18`
  - check_name_en: `Ensure the S3 bucket has access logging enabled`
  - severity: `MEDIUM`
  - mitre_tactic: `DE`
  - representative_atomic_id: `T1562`
  - why_fails: 로깅/검증 비활성화
  - mitigation: aws_s3_bucket 리소스에 로깅 및 모니터링 설정을 활성화
  - resource_address: `aws_s3_bucket.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `logging, resource_type`

[3] 영향·유출
  - resource: `aws_s3_bucket.public`
  - check: `암호화 비활성화`
  - check_id: `CKV_AWS_145`
  - check_name_en: `Ensure that S3 buckets are encrypted with KMS by default`
  - severity: `HIGH`
  - mitre_tactic: `EX`
  - representative_atomic_id: `T1530`
  - why_fails: 암호화 비활성화
  - mitigation: aws_s3_bucket 리소스에 저장 데이터 암호화를 활성화하고 가능하면 KMS CMK를 사용
  - resource_address: `aws_s3_bucket.public`
  - file: `/home/jiyoon/secugate/CI_Gate_Example/scenarios/chained_ec2_iam_s3/main.tf`
  - evaluated_keys: `resource_type, rule/apply_server_side_encryption_by_default/sse_algorithm 외 1개`

## Drop Reasons

### DFS

- `중복 경로` (`duplicate_path`): 35
- `중복 시나리오` (`duplicate_scenario`): 58
- `공격 단계 진행이 부족함` (`insufficient_stage_progress`): 6
- `경로 위에 Checkov 결과 없음` (`no_findings_on_path`): 12
- `공격 단계 순서가 역전됨` (`stage_order_violation`): 250

## DFS Dropped Paths

- Count: 361

### 1. `aws_iam_instance_profile.app` -> `aws_internet_gateway.gw`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_route_table_association.public -> aws_route_table.public -> aws_vpc.main -> aws_internet_gateway.gw`

### 2. `aws_iam_instance_profile.app` -> `aws_route_table.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main -> aws_subnet.public -> aws_route_table_association.public -> aws_route_table.public`

### 3. `aws_iam_instance_profile.app` -> `aws_route_table_association.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main -> aws_internet_gateway.gw -> aws_route_table.public -> aws_route_table_association.public`

### 4. `aws_iam_instance_profile.app` -> `aws_route_table_association.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_vpc.main -> aws_internet_gateway.gw -> aws_route_table.public -> aws_route_table_association.public`

### 5. `aws_iam_instance_profile.app` -> `aws_security_group.web`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_route_table_association.public -> aws_route_table.public -> aws_vpc.main -> aws_security_group.web`

### 6. `aws_iam_instance_profile.app` -> `aws_subnet.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main -> aws_route_table.public -> aws_route_table_association.public -> aws_subnet.public`

### 7. `aws_iam_instance_profile.app` -> `aws_vpc.main`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_route_table_association.public -> aws_route_table.public -> aws_internet_gateway.gw -> aws_vpc.main`

### 8. `aws_iam_policy.app` -> `aws_route_table_association.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_policy.app -> aws_iam_role_policy_attachment.app -> aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_route_table_association.public`

### 9. `aws_iam_policy.app` -> `aws_vpc.main`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_policy.app -> aws_iam_role_policy_attachment.app -> aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main`

### 10. `aws_iam_policy.app` -> `aws_vpc.main`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_policy.app -> aws_iam_role_policy_attachment.app -> aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_vpc.main`

### 11. `aws_iam_role.app` -> `aws_internet_gateway.gw`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main -> aws_route_table.public -> aws_internet_gateway.gw`

### 12. `aws_iam_role.app` -> `aws_internet_gateway.gw`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_vpc.main -> aws_route_table.public -> aws_internet_gateway.gw`

### 13. `aws_iam_role.app` -> `aws_internet_gateway.gw`

- Hops: 6
- Reason: `중복 시나리오`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_route_table_association.public -> aws_route_table.public -> aws_internet_gateway.gw`

### 14. `aws_iam_role.app` -> `aws_route_table.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main -> aws_internet_gateway.gw -> aws_route_table.public`

### 15. `aws_iam_role.app` -> `aws_route_table.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_vpc.main -> aws_internet_gateway.gw -> aws_route_table.public`

### 16. `aws_iam_role.app` -> `aws_route_table_association.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main -> aws_route_table.public -> aws_route_table_association.public`

### 17. `aws_iam_role.app` -> `aws_route_table_association.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main -> aws_subnet.public -> aws_route_table_association.public`

### 18. `aws_iam_role.app` -> `aws_route_table_association.public`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_vpc.main -> aws_route_table.public -> aws_route_table_association.public`

### 19. `aws_iam_role.app` -> `aws_vpc.main`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_subnet.public -> aws_route_table_association.public -> aws_route_table.public -> aws_vpc.main`

### 20. `aws_iam_role_policy_attachment.app` -> `aws_internet_gateway.gw`

- Hops: 6
- Reason: `공격 단계 순서가 역전됨`
- Path: `aws_iam_role_policy_attachment.app -> aws_iam_role.app -> aws_iam_instance_profile.app -> aws_instance.app -> aws_security_group.web -> aws_vpc.main -> aws_internet_gateway.gw`

- ... 341개 경로는 생략
