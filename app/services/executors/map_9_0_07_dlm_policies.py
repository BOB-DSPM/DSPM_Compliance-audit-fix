from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_9_0_07:
    code = "9.0-07"
    title = "EC2/EBS 백업 - DLM 스냅샷 스케줄링"

    def audit(self) -> AuditResult:
        dlm = boto3.client("dlm")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"policiesCount": 0, "samplePolicyIds": []}

        try:
            # DLM 정책 조회 (상태/타입 필터 없이 전체 조회)
            resp = dlm.get_lifecycle_policies()
            policies = resp.get("Policies", []) or []
            evidence["policiesCount"] = len(policies)
            evidence["samplePolicyIds"] = [p.get("PolicyId") for p in policies[:5]]

            passed = evidence["policiesCount"] >= 1

            evals.append(ServiceEvaluation(
                service="DLM",
                resource_id="account/region",
                evidence_path="Policies[].PolicyId",
                checked_field="Policies count",
                comparator="ge",
                expected_value=1,
                observed_value=evidence["policiesCount"],
                passed=passed,
                decision=f"observed {evidence['policiesCount']} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"policyTypeHint": "EBS_SNAPSHOT_MANAGEMENT"}
            ))

            status = "COMPLIANT" if passed else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code,
                    "category": "9 (백업/복구/DR)",
                    "service": "DLM",
                    "console_path": "EC2 → Lifecycle Manager (DLM) → Policies",
                    "check_how": "스냅샷 스케줄 정책 존재 여부",
                    "cli_cmd": "aws dlm get-lifecycle-policies",
                    "return_field": "Policies",
                    "compliant_value": "존재(>=1)",
                    "non_compliant_value": "없음(0)",
                    "console_fix": "DLM 정책 생성(대상 EBS/태그, 빈도, 보존기간 설정)",
                    "cli_fix_cmd": (
                        'aws dlm create-lifecycle-policy '
                        '--execution-role-arn ARN '
                        '--description "ebs-backup" '
                        '--state ENABLED '
                        '--policy-details file://dlm.json'
                    )
                }
            )

        except botocore.exceptions.ClientError as e:
            # 권한 부족/에러 시 SKIPPED 처리
            evals.append(ServiceEvaluation(
                service="DLM",
                resource_id=None,
                evidence_path="Policies",
                checked_field="Policies count",
                comparator="ge",
                expected_value=1,
                observed_value=None,
                passed=None,
                decision="cannot evaluate: missing permissions or error",
                status="SKIPPED",
                source="aws-sdk",
                extra={"error": str(e)}
            ))
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=evals,
                evidence={},
                reason="Missing permissions or API error",
                extract=None
            )
