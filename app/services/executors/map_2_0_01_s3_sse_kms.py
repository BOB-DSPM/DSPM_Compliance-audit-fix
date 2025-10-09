# app/services/executors/map_2_0_01_s3_sse_kms.py
import httpx
from botocore.exceptions import ClientError
from app.models.schemas import AuditResult, ServiceEvaluation
from app.core.config import settings

try:
    from app.core.aws import s3 as _s3_factory
    def _s3():
        return _s3_factory()
except Exception:
    import boto3
    def _s3():
        return boto3.client("s3", region_name=getattr(settings, "AWS_REGION", None))

COLLECTOR_BASE = "http://localhost:8000"

def _final_status(evals):
    if any(e.status == "ERROR" for e in evals):
        return "ERROR"
    if any(e.status == "NON_COMPLIANT" for e in evals):
        return "NON_COMPLIANT"
    if evals and all(e.status == "SKIPPED" for e in evals):
        return "SKIPPED"
    return "COMPLIANT" if evals else "SKIPPED"

class Exec_2_0_01:
    """
    매핑코드: 2.0-01
    점검내용: S3 버킷 기본 암호화가 SSE-KMS(aws:kms)로 설정되어 있는지
    기준: observed == "aws:kms"  (comparator=eq)
    """
    code = "2.0-01"

    def _list_buckets(self) -> list[str]:
        try:
            with httpx.Client(timeout=10.0) as c:
                r = c.get(f"{COLLECTOR_BASE}/api/s3-buckets")
                r.raise_for_status()
                data = r.json()
                names = []
                for x in data or []:
                    if isinstance(x, str):
                        names.append(x)
                    elif isinstance(x, dict):
                        names.append(x.get("name") or x.get("bucket_name") or x.get("Bucket") or x.get("Name"))
                return [n for n in names if n]
        except Exception:
            pass

        try:
            s3 = _s3()
            resp = s3.list_buckets()
            return [b["Name"] for b in resp.get("Buckets", [])]
        except Exception:
            return []

    def _get_bucket_sse_algo(self, bucket: str) -> tuple[str | None, dict]:
        """
        반환: (SSEAlgorithm or None, raw_response/에러정보)
        """
        s3 = _s3()
        try:
            resp = s3.get_bucket_encryption(Bucket=bucket)
            rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                by_default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                algo = by_default.get("SSEAlgorithm")
                return algo, resp
            return None, resp
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"):
                return None, {"error": str(e), "code": code}
            raise
        except Exception as e:
            raise

    def audit(self) -> AuditResult:
        evaluations: list[ServiceEvaluation] = []
        buckets = self._list_buckets()

        if not buckets:
            evaluations.append(ServiceEvaluation(
                service="S3",
                resource_id=None,
                evidence_path="list_buckets()",
                checked_field="Buckets count",
                comparator="ge",
                expected_value=1,
                observed_value=0,
                passed=False,
                decision="no buckets to evaluate",
                status="SKIPPED",
                source="aws-sdk",
                extra={}
            ))
            return AuditResult(mapping_code=self.code,
                               status=_final_status(evaluations),
                               evaluations=evaluations,
                               evidence={"bucketCount": 0},
                               reason="No S3 buckets")

        for b in buckets:
            try:
                algo, raw = self._get_bucket_sse_algo(b)
                observed = algo or "NONE"
                expected = "aws:kms"
                comparator = "eq"
                passed = (observed == expected)
                decision = f'observed "{observed}" == "{expected}" → {"passed" if passed else "failed"}'

                evaluations.append(ServiceEvaluation(
                    service="S3",
                    resource_id=b,
                    evidence_path="ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm",
                    checked_field="Default SSE Algorithm",
                    comparator=comparator,
                    expected_value=expected,
                    observed_value=observed,
                    passed=passed,
                    decision=decision,
                    status="COMPLIANT" if passed else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={"raw": raw}
                ))

            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code in ("AccessDenied", "AccessDeniedException"):
                    evaluations.append(ServiceEvaluation(
                        service="S3",
                        resource_id=b,
                        evidence_path="get_bucket_encryption",
                        checked_field="Default SSE Algorithm",
                        comparator="eq",
                        expected_value="aws:kms",
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"missingPermissions": ["s3:GetBucketEncryption"], "error": str(e)}
                    ))
                else:
                    evaluations.append(ServiceEvaluation(
                        service="S3",
                        resource_id=b,
                        evidence_path="get_bucket_encryption",
                        checked_field="Default SSE Algorithm",
                        comparator="eq",
                        expected_value="aws:kms",
                        observed_value=None,
                        passed=None,
                        decision="check failed due to exception",
                        status="ERROR",
                        source="aws-sdk",
                        extra={"error": str(e)}
                    ))
            except Exception as e:
                evaluations.append(ServiceEvaluation(
                    service="S3",
                    resource_id=b,
                    evidence_path="get_bucket_encryption",
                    checked_field="Default SSE Algorithm",
                    comparator="eq",
                    expected_value="aws:kms",
                    observed_value=None,
                    passed=None,
                    decision="check failed due to exception",
                    status="ERROR",
                    source="aws-sdk",
                    extra={"error": str(e)}
                ))

        total = len(buckets)
        kms_ok = sum(1 for ev in evaluations if ev.status == "COMPLIANT")
        not_ok = sum(1 for ev in evaluations if ev.status == "NON_COMPLIANT")
        skipped = sum(1 for ev in evaluations if ev.status == "SKIPPED")
        errors = sum(1 for ev in evaluations if ev.status == "ERROR")

        return AuditResult(
            mapping_code=self.code,
            status=_final_status(evaluations),
            evaluations=evaluations,
            evidence={"totalBuckets": total, "kmsCompliant": kms_ok, "nonCompliant": not_ok, "skipped": skipped, "errors": errors}
        )
