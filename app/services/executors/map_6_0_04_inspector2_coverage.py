from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_6_0_04:
    """
    6.0-04 — Inspector2 Coverage
    기준: 커버리지 리소스가 1개 이상(>=1) 존재하면 COMPLIANT, 아니면 NON_COMPLIANT
    우선 list_coverage_statistics 사용, 실패하면 list_coverage로 폴백
    """
    code = "6.0-04"
    title = "Inspector2: Coverage enabled"

    def audit(self) -> AuditResult:
        ins = boto3.client("inspector2")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "coveredCount": 0,
            "byGroup": [],          # list_coverage_statistics 요약(있으면)
            "sampleResources": []   # list_coverage 폴백 시 일부 샘플
        }

        try:
            total = 0
            grouped: List[Dict[str, Any]] = []

            # 1) 통계 API 시도
            try:
                # groupBy를 RESOURCE_TYPE로 시도 (통계가 오면 count 합산)
                resp = ins.list_coverage_statistics(groupBy="RESOURCE_TYPE")
                counts = resp.get("countsByGroup", []) or []
                for it in counts:
                    # {'groupKey': 'ECR', 'count': 3} 형태 기대
                    grouped.append({"group": it.get("groupKey"), "count": it.get("count", 0)})
                    total += int(it.get("count", 0))
                evidence["byGroup"] = grouped
            except Exception:
                # 2) 지원 안 하거나 권한 부족 등으로 실패하면 list_coverage로 폴백하여 총량 카운트
                sample: List[str] = []
                next_token = None
                while True:
                    if next_token:
                        resp = ins.list_coverage(nextToken=next_token, maxResults=100)
                    else:
                        resp = ins.list_coverage(maxResults=100)
                    resources = resp.get("coveredResources", []) or []
                    total += len(resources)
                    for r in resources:
                        if len(sample) < 5:
                            rtype = r.get("resourceType") or r.get("resource", {}).get("type")
                            rid = r.get("resourceId") or r.get("resource", {}).get("id")
                            sample.append(f"{rtype}:{rid}")
                    next_token = resp.get("nextToken")
                    if not next_token:
                        break
                evidence["sampleResources"] = sample

            evidence["coveredCount"] = total
            passed = total >= 1

            evals.append(ServiceEvaluation(
                service="Inspector2",
                resource_id="account/region",
                evidence_path="coverage statistics / coveredResources (count)",
                checked_field="covered resources count",
                comparator="ge",
                expected_value=1,
                observed_value=total,
                passed=passed,
                decision=f"observed {total} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"byGroup": grouped[:5]} if grouped else {}
            ))

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                evaluations=evals,
                evidence=evidence,
                reason=None if passed else "Inspector2 has no covered resources",
                extract={
                    "code": self.code,
                    "category": "6 (모델/배포 무결성)",
                    "service": "Inspector2",
                    "console_path": "Inspector → Coverage",
                    "check_how": "list-coverage-statistics OR list-coverage 로 커버된 리소스 ≥ 1 확인",
                    "cli_cmd": "aws inspector2 list-coverage-statistics",
                    "return_field": "countsByGroup[].count / coveredResources",
                    "compliant_value": ">=1",
                    "non_compliant_value": "0",
                    "console_fix": "Inspector2 활성화 및 리소스(EC2/ECR/ECS 등) 커버리지 등록",
                    "cli_fix_cmd": "aws inspector2 enable --account-ids <ACC> --resource-types ECR,ECR_REPOSITORY,EC2,ECS"
                }
            )

        except botocore.exceptions.ClientError as e:
            # 권한/비활성화 등으로 호출 자체가 실패한 경우
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Inspector2",
                    resource_id=None,
                    evidence_path="list-coverage-statistics / list-coverage",
                    checked_field="covered resources count",
                    comparator=None,
                    expected_value=None,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions or service disabled",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions or Inspector2 disabled",
                extract=None
            )
