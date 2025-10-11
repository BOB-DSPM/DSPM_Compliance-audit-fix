from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore, os
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_9_0_07:
    code = "9.0-07"
    title = "EC2/EBS 백업 - DLM 스냅샷 스케줄링"

    def audit(self) -> AuditResult:
        region = os.environ.get("AWS_REGION") or boto3.session.Session().region_name or "unknown"
        dlm = boto3.client("dlm", region_name=None)  # 기본 세션 리전 사용
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "region": region,
            "policiesCountAll": 0,
            "policiesCountEnabledEbsSnap": 0,
            "samplePolicyIds": [],
        }

        try:
            resp = dlm.get_lifecycle_policies()
            # 일부 SDK/환경에서 키 이름이 다를 수 있어 보수적으로 병행 처리
            policies = resp.get("Policies") or resp.get("PolicySummaryList") or []
            evidence["policiesCountAll"] = len(policies)

            enabled_ebs = []
            for p in policies:
                pid = p.get("PolicyId") or p.get("PolicyArn") or "unknown"
                ptype = p.get("PolicyType") or p.get("Type") or ""
                state = p.get("State") or ""
                if ptype == "EBS_SNAPSHOT_MANAGEMENT" and state == "ENABLED":
                    enabled_ebs.append(pid)

            evidence["policiesCountEnabledEbsSnap"] = len(enabled_ebs)
            evidence["samplePolicyIds"] = (enabled_ebs or [p.get("PolicyId") for p in policies])[:5]

            # 판정 기준:
            # - 더 엄격: ENABLED + EBS_SNAPSHOT_MANAGEMENT >= 1 → COMPLIANT
            # - 그 외(정책 0개거나 비활성/다른 타입뿐) → NON_COMPLIANT
            passed = evidence["policiesCountEnabledEbsSnap"] >= 1

            evals.append(ServiceEvaluation(
                service="DLM",
                resource_id=f"account/region:{region}",
                evidence_path="Policies[].(PolicyType, State)",
                checked_field="ENABLED EBS_SNAPSHOT_MANAGEMENT policy count",
                comparator="ge",
                expected_value=1,
                observed_value=evidence["policiesCountEnabledEbsSnap"],
                passed=passed,
                decision=(f"observed {evidence['policiesCountEnabledEbsSnap']} >= 1 → "
                          f"{'passed' if passed else 'failed'}"),
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"allPoliciesCount": evidence["policiesCountAll"]}
            ))

            status = "COMPLIANT" if passed else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if passed else "No ENABLED EBS_SNAPSHOT_MANAGEMENT policy",
                extract={
                    "code": self.code,
                    "category": "9 (백업/복구/DR)",
                    "service": "DLM",
                    "console_path": "EC2 → Lifecycle Manager (DLM) → Policies",
                    "check_how": "EBS 스냅샷 관리 정책(ENABLED) 존재 여부",
                    "cli_cmd": "aws dlm get-lifecycle-policies",
                    "return_field": "Policies[].{PolicyType,State}",
                    "compliant_value": "PolicyType=EBS_SNAPSHOT_MANAGEMENT & State=ENABLED",
                    "non_compliant_value": "정책 없음/비활성/다른 타입만 존재",
                    "console_fix": "DLM 정책 생성(대상 EBS/태그, 빈도, 보존기간 설정) 후 ENABLED",
                    "cli_fix_cmd": (
                        'aws dlm create-lifecycle-policy '
                        '--execution-role-arn ARN '
                        '--description "ebs-backup" '
                        '--state ENABLED '
                        '--policy-details file://dlm.json'
                    ),
                },
            )

        except botocore.exceptions.ClientError as e:
            msg = str(e)
            evals.append(ServiceEvaluation(
                service="DLM",
                resource_id=f"account/region:{region}",
                evidence_path="Policies",
                checked_field="Policies count",
                comparator="ge",
                expected_value=1,
                observed_value=None,
                passed=None,
                decision="cannot evaluate: missing permissions or API error",
                status="SKIPPED",
                source="aws-sdk",
                extra={"error": msg}
            ))
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=evals,
                evidence={"region": region},
                reason=("AccessDenied" if "AccessDenied" in msg else "API error"),
                extract=None,
            )
