from __future__ import annotations
from typing import List, Dict, Any
import json
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_12_0_04:
    code = "12.0-04"
    title = "S3 Bucket Policy - PrincipalOrgID로 조직 한정"

    def audit(self) -> AuditResult:
        s3 = boto3.client("s3")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "bucketsChecked": 0,
            "orgRestricted": [],
            "notRestricted": [],
            "noPolicy": []
        }

        try:
            buckets = s3.list_buckets().get("Buckets", []) or []
            if not buckets:
                return AuditResult(
                    mapping_code=self.code, title=self.title, status="SKIPPED",
                    evaluations=[ServiceEvaluation(
                        service="S3", resource_id=None,
                        evidence_path="Buckets", checked_field="Policy",
                        comparator="exists", expected_value=True,
                        observed_value=False, passed=None,
                        decision="no buckets → cannot evaluate",
                        status="SKIPPED", source="aws-sdk", extra={}
                    )],
                    evidence=evidence, reason="No buckets", extract=None
                )

            for b in buckets:
                name = b.get("Name")
                evidence["bucketsChecked"] += 1

                try:
                    pol_resp = s3.get_bucket_policy(Bucket=name)
                    pol_str = pol_resp.get("Policy", "")
                    has_org = "aws:PrincipalOrgID" in pol_str  # 문자열 포함 검사로도 충분
                    # (선택) 공개 위험 간단 힌트: Principal:"*"
                    is_public_principal = '"Principal":"*"' in pol_str or '"Principal": "*"' in pol_str

                    if has_org and not is_public_principal:
                        evidence["orgRestricted"].append(name)
                    else:
                        evidence["notRestricted"].append(name)

                    evals.append(ServiceEvaluation(
                        service="S3",
                        resource_id=name,
                        evidence_path="BucketPolicy",
                        checked_field="aws:PrincipalOrgID",
                        comparator="contains",
                        expected_value="aws:PrincipalOrgID",
                        observed_value=pol_str[:2000],  # 너무 길어질 수 있어 앞부분만 샘플
                        passed=has_org,
                        decision=f"policy contains aws:PrincipalOrgID → {'passed' if has_org else 'failed'}",
                        status="COMPLIANT" if has_org else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"public_principal_hint": is_public_principal}
                    ))

                except botocore.exceptions.ClientError as ie:
                    # NoSuchBucketPolicy 등 → 정책 없음으로 보고 NON_COMPLIANT
                    if ie.response.get("Error", {}).get("Code") in ("NoSuchBucketPolicy",):
                        evidence["noPolicy"].append(name)
                        evidence["notRestricted"].append(name)
                        evals.append(ServiceEvaluation(
                            service="S3",
                            resource_id=name,
                            evidence_path="BucketPolicy",
                            checked_field="Policy",
                            comparator="exists",
                            expected_value=True,
                            observed_value=False,
                            passed=False,
                            decision="no bucket policy → failed",
                            status="NON_COMPLIANT",
                            source="aws-sdk",
                            extra={"error": str(ie)}
                        ))
                    else:
                        # 권한 부족 등 → SKIPPED
                        evals.append(ServiceEvaluation(
                            service="S3",
                            resource_id=name,
                            evidence_path="BucketPolicy",
                            checked_field="Policy",
                            comparator="exists",
                            expected_value=True,
                            observed_value=None,
                            passed=None,
                            decision="cannot evaluate this bucket: missing permissions",
                            status="SKIPPED",
                            source="aws-sdk",
                            extra={"error": str(ie)}
                        ))

            # 전체 판정: 하나라도 Org 제한 미적용이 있으면 NON_COMPLIANT
            noncompliant_exists = len(evidence["notRestricted"]) > 0
            status = "NON_COMPLIANT" if noncompliant_exists else "COMPLIANT"

            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category": "12 (데이터 전송/제3자 제공)", "service": "S3",
                    "console_path": "S3 → 권한 → 버킷 정책",
                    "check_how": "정책에 aws:PrincipalOrgID 조건 포함 여부 확인",
                    "cli_cmd": "aws s3api get-bucket-policy --bucket BUCKET",
                    "return_field": "Policy",
                    "compliant_value": "aws:PrincipalOrgID 포함",
                    "non_compliant_value": "미포함 또는 공개 정책",
                    "console_fix": "버킷 정책에 PrincipalOrgID 조건 추가(조직 한정)",
                    "cli_fix_cmd": "aws s3api put-bucket-policy --bucket BUCKET --policy file://org-only.json"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="S3", resource_id=None,
                    evidence_path="list_buckets", checked_field="Buckets",
                    comparator="exists", expected_value=True,
                    observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions or API error",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions or API error", extract=None
            )
