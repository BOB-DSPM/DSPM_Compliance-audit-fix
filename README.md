# DSPM Compliance Audit API

AWS 컴플라이언스 요건을 실제 리소스 설정과 비교하여 자동으로 감사하는 FastAPI 서비스입니다.
Collector(리소스 수집기)와 Mapping(매핑 메타 API)을 호출하거나, 필요시 boto3로 직접 확인합니다.

## 주요 기능

- **자동 감사**: ISMS-P, GDPR, ISO-27001/17 요건을 AWS 리소스에 적용
- **상세 근거**: 단순 통과/실패가 아닌 구체적인 비교 근거 제공
- **유연한 구조**: Collector API 또는 boto3로 리소스 확인

## 빠른 시작

### 사전 요구사항
- Python 3.11 이상
- AWS 자격 증명 설정
- 외부 서비스 (선택):
  - Mapping API: http://localhost:8003
  - Collector API: http://localhost:8000

### 설치 및 실행
```bash

# 0. 가상환경 설정 (권장)
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 1. 의존성 설치
pip install -r requirements.txt

# 2. 환경변수 설정
cat > .env <<'ENV'
AWS_REGION=ap-northeast-2
MAPPING_BASE_URL=http://localhost:8003
COLLECTOR_BASE_URL=http://localhost:8000
ENV

# 3. 서버 실행
uvicorn app.main:app --host 0.0.0.0 --port 8103 --reload
```

API 문서: http://localhost:8103/docs

## 프로젝트 구조
```
app/
├── core/
│   ├── config.py           # 환경변수 로딩
│   └── aws.py              # boto3 클라이언트
├── models/
│   └── schemas.py          # 응답 스키마
├── clients/
│   ├── mapping_client.py   # 매핑 API 클라이언트
│   └── collector_client.py # 수집기 API 클라이언트
├── services/
│   ├── registry.py         # 매핑코드 등록
│   ├── audit_service.py    # 감사 오케스트레이션
│   └── executors/          # 매핑별 점검 로직
│       ├── map_1_0_01_sso_permission_sets.py
│       ├── map_2_0_01_s3_sse_kms.py
│       └── map_2_0_15_cloudfront_https.py
└── routers/
    ├── health.py
    └── audit.py
```

## API 엔드포인트

### Health Check
```bash
GET /health

curl -s http://localhost:8103/health
```

### 특정 요건 감사
```bash
POST /audit/{framework}/{req_id}

# 예시: ISMS-P의 3번 요건 감사
curl -s -X POST http://localhost:8103/audit/ISMS-P/3 | jq
```

### 프레임워크 전체 감사
```bash
POST /audit/{framework}/_all

# 예시: ISO-27017 전체 감사
curl -s -X POST http://localhost:8103/audit/iso-27017/_all | jq
```

### 응답 예시
```json
{
  "framework": "iso-27017",
  "requirement_id": 16,
  "item_code": "10.1.1 암호화 통제 사용 정책",
  "results": [
    {
      "mapping_code": "2.0-01",
      "title": "S3",
      "status": "NON_COMPLIANT",
      "evaluations": [
        {
          "service": "S3",
          "resource_id": "my-mlops-dev-logs",
          "evidence_path": "ServerSideEncryptionConfiguration.Rules[0]...",
          "checked_field": "Default SSE Algorithm",
          "comparator": "eq",
          "expected_value": "aws:kms",
          "observed_value": "AES256",
          "decision": "observed \"AES256\" == \"aws:kms\" → failed",
          "status": "NON_COMPLIANT",
          "source": "aws-sdk"
        }
      ],
      "evidence": {
        "totalBuckets": 7,
        "kmsCompliant": 5,
        "nonCompliant": 2
      }
    }
  ]
}
```

**핵심**: `observed_value`, `expected_value`, `decision`으로 판단 근거를 명확히 제공합니다.

## 환경 변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| AWS_REGION | boto3 리전 | 없음 |
| MAPPING_BASE_URL | 매핑 API URL | http://localhost:8003 |
| COLLECTOR_BASE_URL | 수집기 API URL | http://localhost:8000 |

## 새 매핑 추가 방법

### 1. Executor 파일 생성
```bash
# app/services/executors/map_<code>_<name>.py
```

### 2. 클래스 구현
```python
class Exec_<code>:
    def audit(self) -> AuditResult:
        # 점검 로직 구현
        evaluations = []
        # ServiceEvaluation 생성
        return AuditResult(...)
```

### 3. Registry 등록
```python
# app/services/registry.py
table = {
    "2.0-01": Exec_2_0_01,
    "NEW-CODE": Exec_NEW_CODE,  # 추가
}
```

## IAM 권한 예시

감사 전용 Role에 필요한 읽기 권한:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketEncryption",
        "cloudfront:ListDistributions",
        "iam:GetAccountSummary",
        "organizations:ListPolicies",
        "organizations:DescribeOrganization",
        "config:DescribeConformancePackStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

## 트러블슈팅

### PydanticImportError (BaseSettings)
pydantic v2에서는 별도 패키지 사용:
```python
from pydantic_settings import BaseSettings
```

### ImportError: MappingExtract
`app/models/schemas.py`에 `MappingExtract` 클래스 정의 필요

### 권한 부족 (SKIPPED/ERROR)
응답의 `evaluations[*].extra.missingPermissions`를 확인하여 IAM 정책 보강

### Collector/Mapping API 연결 실패
1. `.env` 파일의 URL 확인
2. 해당 서비스가 실행 중인지 확인
3. Collector 없이도 boto3 폴백으로 동작 가능