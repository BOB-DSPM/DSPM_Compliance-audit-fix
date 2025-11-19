# AWS Marketplace 컨테이너 제출 가이드

> 참고: 본 문서는 [AWS Marketplace Seller Guide - Container Based Product Requirements](https://docs.aws.amazon.com/marketplace/latest/userguide/container-requirements.html)의 핵심 요구 사항을 기준으로 DSPM Compliance Audit API를 준비하기 위한 체크리스트입니다.

## 1. 보안 정책 대응

- **이미지 베이스**: `python:3.12-slim`을 사용하고 `apt-get`으로 설치하는 패키지를 `curl`, `ca-certificates`, `tzdata`로 제한합니다.
- **루트 권한 방지**: Dockerfile에서 `appuser`를 생성한 뒤 `USER appuser`를 사용합니다.
- **취약성 관리**: 빌드 파이프라인에서 `trivy` 또는 `grype` 스캔을 통과시킨 이미지만 ECR에 푸시합니다.
- **비밀 정보 차단**: `.dockerignore`에 `.aws/`, `*.pem` 등 민감 파일을 추가했고, 코드 저장소에는 하드코딩된 키가 없습니다.

## 2. 자격 증명(크리덴셜) 전략

AWS Marketplace 지침에 따라 컨테이너는 자격 증명을 직접 요청하거나 하드코딩하지 않습니다. 항상 AWS가 주입하는 임시 자격 증명에 의존합니다.

### 2.1 공통 원칙

1. **IAM 역할 필수**: 자격 증명은 Amazon EKS IRSA, Amazon ECS Task Role 혹은 AWS Fargate Task Role을 통해 주입합니다.
2. **STS 토큰만 사용**: 장기 Access Key는 허용하지 않고, 필요 시 `aws sts assume-role`을 통해 짧은 수명 키를 주입합니다.
3. **환경 변수 최소화**: `AWS_REGION`만 필수이며, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`는 외부에서 제공되지 않는 한 컨테이너 시작 시 비어 있습니다.
4. **추적/로그**: 자격 증명 관련 로그를 남기지 않으며, CloudTrail을 통해 호출 이력을 별도 추적합니다.

### 2.2 Amazon EKS (IRSA)

1. IAM 역할 생성

```bash
aws iam create-role \
  --role-name DspmAuditRole \
  --assume-role-policy-document file://trust-irsa.json

aws iam attach-role-policy \
  --role-name DspmAuditRole \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

`trust-irsa.json`에는 OIDC 공급자와 서비스 계정(`system:serviceaccount:compliance:dspm-audit`) 매칭을 명시합니다.

2. 서비스 계정/배포

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dspm-audit
  namespace: compliance
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<ACCOUNT_ID>:role/DspmAuditRole
```

애플리케이션 Pod는 위 서비스 계정을 사용하여 자동으로 STS 토큰을 주입받습니다.

### 2.3 Amazon ECS / AWS Fargate

- Task Definition에 `taskRoleArn`을 지정하여 워크로드 권한을 부여합니다.
- `executionRoleArn`은 이미지 pull 및 로그 전송을 담당하며, 비즈니스 로직 접근 권한은 부여하지 않습니다.
- 필요한 정책은 최소한의 읽기 권한(S3 list/get, IAM read-only 등)으로 한정합니다.

### 2.4 로컬 개발 / Marketplace 검증

검증 팀이나 개발자가 Docker 컨테이너를 직접 실행할 때는 `aws-vault` 또는 `aws sts assume-role`로 발급한 임시 자격 증명을 환경 변수로 전달합니다.

```bash
AWS_REGION=ap-northeast-2 \
AWS_ACCESS_KEY_ID=... \
AWS_SECRET_ACCESS_KEY=... \
AWS_SESSION_TOKEN=... \
docker run --rm -p 8103:8103 \
  --env AWS_REGION --env AWS_ACCESS_KEY_ID \
  --env AWS_SECRET_ACCESS_KEY --env AWS_SESSION_TOKEN \
  <ECR>/dspm-audit:latest
```

## 3. 고객 정보 및 데이터 사용

- API는 감사 결과(프레임워크, 리소스 ID, 평가 상태 등)만 반환하며 결제 정보나 개인정보를 수집하지 않습니다.
- 외부 Collector/Mapping API 호출 시 HTTPS만 사용하고, 응답 데이터는 요청-응답 라이프사이클 동안 메모리에만 유지됩니다.
- 로그에는 리소스 ID 등 최소한의 정보만 남기고, 필요 시 CloudWatch Logs에서 수명 주기를 설정합니다.

## 4. 아키텍처 및 배포 요구 사항

1. **이미지 전달**: 각 릴리스마다 `aws ecr-public get-login-password`를 사용해 Marketplace 전용 ECR 리포지토리에 푸시합니다.
2. **멀티 아키텍처**: 필요 시 `docker buildx build --platform linux/amd64,linux/arm64`로 매니페스트를 생성합니다.
3. **데모/테스트**: README 및 본 문서에 Docker/Kubernetes/ECS 배포 예시를 제공하여 “셀프 서비스 배포” 요건을 충족합니다.
4. **헬스체크**: `/health` 라우트를 이용해 Marketplace에서 요구하는 상태 확인 엔드포인트를 제공하며 Dockerfile HEALTHCHECK에 반영되어 있습니다.

## 5. 제출 전 체크리스트

| 구분 | 점검 항목 | 상태 |
| ---- | -------- | ---- |
| 보안 | CVE 스캔 통과(trivy) | ☐ |
| 보안 | `.aws/`, `.pem` 등 비밀 파일 이미지 제외 | ☑ |
| 권한 | IRSA/ECS Task Role로만 자격 증명 전달 | ☑ |
| 권한 | IAM 정책 최소 권한(S3, IAM, Organizations 읽기) | ☐ |
| 문서 | README + 본 파일에 배포 지침 문서화 | ☑ |
| 아키텍처 | ECR 리포지토리 미리 생성, 태그 규칙 정의 | ☐ |
| 테스트 | `/health` 엔드포인트 동작 검증 | ☐ |

체크리스트를 모두 통과하면 AWS Marketplace Management Portal에서 컨테이너 제품 제출 단계를 진행합니다.
