DSPM Compliance Audit API

AWS 환경에서 **컴플라이언스 매핑(예: ISMS-P / GDPR / ISO-27001/17)**을 기반으로
실제 리소스 설정을 자동 점검(Audit)하는 FastAPI 서비스입니다.
Collector(리소스 수집기)와 Mapping(매핑 메타 API)을 호출하거나, 필요시 boto3로 직접 확인합니다.

주요 기능

GET /health – 헬스 체크

POST /audit/{framework}/{req_id} – 특정 요구사항의 매핑 전체 감사 (예: ISMS-P/3)

POST /audit/{framework}/_all – 특정 프레임워크 전체 감사 (예: iso-27001)

(WIP) POST /fix/{framework}/{req_id} – 미이행 항목만 자동 해결

감사 결과에는 단순 이행/미이행 뿐 아니라,
어떤 서비스의 어떤 필드가 어떤 값이라서 그렇게 판단했는지까지 근거(evidence) 를 포함합니다.

아키텍처 개요
[AWS 계정]  ← boto3 (보조)
    |
    | (우선) Resource Collector API (localhost:8000)
    |       └─ /api/s3-buckets, /api/rds-instances, ...
    |
    | (메타) Compliance Mapping API (localhost:8003)
    |       └─ /compliance/{code}/requirements/{id}/mappings
    |
[본 서비스] Compliance Audit API (localhost:8103)
    ├─ /audit/... 엔드포인트
    ├─ executors/: 매핑코드별 점검 로직
    └─ 결과에 evidence_path / comparator / expected / observed / decision 포함

파일/폴더 구조
app/
  core/
    __init__.py
    config.py            # 환경변수 로딩(pydantic-settings)
    aws.py               # boto3 클라이언트 팩토리(s3, cloudfront 등)
  models/
    __init__.py
    schemas.py           # 응답/결과 스키마 (ServiceEvaluation, AuditResult 등)
  clients/
    __init__.py
    mapping_client.py    # localhost:8003 호출 (매핑 메타)
    collector_client.py  # localhost:8000 호출 (리소스 목록/상세, 선택적)
  services/
    __init__.py
    registry.py          # 매핑코드 → 실행기 매핑 테이블
    audit_service.py     # 감사 오케스트레이션
    executors/
      __init__.py
      map_1_0_01_sso_permission_sets.py
      map_1_0_02_org_scp.py
      map_1_0_06_root_mfa.py
      map_2_0_01_s3_sse_kms.py
      map_2_0_15_cloudfront_https.py
      map_11_0_02_config_conformance_pack.py
  routers/
    __init__.py
    health.py
    audit.py
main.py
requirements.txt
README.md
.gitignore

요구 사항

Python 3.11+ (권장 3.12)

가상환경(venv) 사용 추천

AWS 자격 증명(profile/role) 또는 환경변수 설정

외부 서비스:

Collector API: http://localhost:8000

Mapping API: http://localhost:8003

Collector가 없을 경우, 일부 점검은 boto3 폴백으로 계속 동작합니다.

설치 & 실행
# 1) 의존성 설치
pip install -r requirements.txt

# 2) (필수) 환경변수 설정
# .env 예시
cat > .env <<'ENV'
AWS_REGION=ap-northeast-2
MAPPING_BASE_URL=http://localhost:8003
COLLECTOR_BASE_URL=http://localhost:8000
ENV

# 3) 실행
uvicorn app.main:app --host 0.0.0.0 --port 8103 --reload

환경 변수
변수	설명	기본값
AWS_REGION	boto3 지역	없음
MAPPING_BASE_URL	매핑 API 베이스 URL	http://localhost:8003
COLLECTOR_BASE_URL	수집기 API 베이스 URL	http://localhost:8000

pydantic v2: pydantic-settings 사용. .env 파일 자동 로드.

엔드포인트
Health
curl -s http://localhost:8103/health

(요구사항) 감사 수행
curl -s -X POST http://localhost:8103/audit/ISMS-P/3 | jq .

(프레임워크 전체) 감사 수행
curl -s -X POST http://localhost:8103/audit/iso-27017/_all | jq .

응답 예시 (발췌)
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
          "evidence_path": "ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm",
          "checked_field": "Default SSE Algorithm",
          "comparator": "eq",
          "expected_value": "aws:kms",
          "observed_value": "AES256",
          "decision": "observed \"AES256\" == \"aws:kms\" → failed",
          "status": "NON_COMPLIANT",
          "source": "aws-sdk"
        }
      ],
      "evidence": { "totalBuckets": 7, "kmsCompliant": 5, "nonCompliant": 2 }
    }
  ]
}


핵심: observed_value와 expected_value, 그리고 decision(비교문)이 명확히 들어가 판단 근거가 바로 보입니다.

현재 구현된 매핑(예시)

1.0-01 IAM Identity Center(SSO) 권한셋 최소화

1.0-02 AWS Organizations SCP 활성화

1.0-06 Root 계정 MFA

2.0-01 S3 SSE-KMS 적용 ✅

2.0-15 CloudFront HTTPS 강제 ✅

11.0-02 AWS Config Conformance Pack

앞으로 2.0-02(RDS 암호화), 2.0-03(DynamoDB SSE), 2.0-04(Redshift 암호화) 등 동일 패턴으로 확장 가능합니다.

새 매핑 추가 방법

app/services/executors/map_<code>_<name>.py 파일 생성

class Exec_<code>에 audit(self) -> AuditResult 구현

여러 리소스 평가 시 evaluations: List[ServiceEvaluation]에 각 리소스별 근거 포함

evidence_path / comparator / expected_value / observed_value / decision / status

app/services/registry.py의 테이블에 코드 등록:

table = {
  "2.0-01": Exec_2_0_01,
  "2.0-15": Exec_2_0_15,
  "NEW-CODE": Exec_NEW_CODE,   # ← 추가
}


필요시 Collector → boto3 폴백 로직 포함

권한(IAM) 샘플

감사 전용 Role에 아래 읽기 권한만 부여하면 대부분의 점검은 동작합니다(예시).

{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:ListAllMyBuckets","s3:GetBucketEncryption"], "Resource": "*" },
    { "Effect": "Allow", "Action": ["cloudfront:ListDistributions"], "Resource": "*" },
    { "Effect": "Allow", "Action": ["iam:GetAccountSummary"], "Resource": "*" },
    { "Effect": "Allow", "Action": ["organizations:ListPolicies","organizations:DescribeOrganization","organizations:ListRoots"], "Resource": "*" },
    { "Effect": "Allow", "Action": ["config:DescribeConformancePackStatus","config:DescribeConformancePacks"], "Resource": "*" }
  ]
}


SSO 관련은 sso:ListInstances, sso:ListPermissionSets 필요.

트러블슈팅

PydanticImportError (BaseSettings)
→ v2에서 pydantic-settings로 이동. from pydantic_settings import BaseSettings 사용.

ImportError: MappingExtract
→ app/models/schemas.py에 MappingExtract 클래스가 정의되어 있어야 합니다.
또한 모든 파일에서 app.models.schemas를 임포트하도록 통일하세요.

권한 부족으로 SKIPPED/ERROR
→ 응답의 evaluations[*].extra.missingPermissions를 참고해 IAM 정책 보강.

Collector나 Mapping API 404/Connection refused
→ .env 값 확인 (MAPPING_BASE_URL, COLLECTOR_BASE_URL)
→ 두 API가 로컬에서 실제로 떠 있는지 확인.

로드맵

(Fix) 미이행 항목 자동 해결 엔드포인트 (CLI/SDK 적용)

(Report) 결과 내보내기 (HTML/CSV/Slack)

(Policy) 매핑-권한 템플릿 자동 추천

(Perf) 병렬 감사/리트라이/타임아웃 튜닝