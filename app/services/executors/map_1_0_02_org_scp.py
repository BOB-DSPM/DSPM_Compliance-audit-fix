from botocore.exceptions import ClientError
from app.models.schemas import AuditResult, ServiceEvaluation
from app.core.aws import org

def final_status_from_evals(evals):
    if any(e.status == "ERROR" for e in evals):
        return "ERROR"
    if any(e.status == "NON_COMPLIANT" for e in evals):
        return "NON_COMPLIANT"
    if evals and all(e.status == "SKIPPED" for e in evals):
        return "SKIPPED"
    return "COMPLIANT" if evals else "SKIPPED"

class Exec_1_0_02:
    """
    매핑코드: 1.0-02
    점검내용: Organizations SCP 정책 활성화 여부
    기준(comparator): ge (observed >= expected)
    expected: 1 (최소 1개 이상의 SERVICE_CONTROL_POLICY 존재)
    evidence_path: "Policies[].Type" (SERVICE_CONTROL_POLICY만 필터링)
    """
    code = "1.0-02"

    def audit(self) -> AuditResult:
        evaluations = []
        try:
            client = org()
            resp = client.list_policies(Filter="SERVICE_CONTROL_POLICY")
            policies = resp.get("Policies", []) or []
            observed = len(policies)
            expected = 1
            comparator = "ge"
            passed = (observed >= expected)
            decision = f"observed {observed} >= {expected} → {'passed' if passed else 'failed'}"

            evaluations.append(ServiceEvaluation(
                service="AWS Organizations",
                resource_id="org-root",
                evidence_path="Policies[].Type",
                checked_field="SCP policies count",
                comparator=comparator,
                expected_value=expected,
                observed_value=observed,
                passed=passed,
                decision=decision,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"samplePolicies": policies[:3]}
            ))

            return AuditResult(
                mapping_code=self.code,
                status=final_status_from_evals(evaluations),
                evaluations=evaluations,
                evidence={"policyCount": observed}
            )

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            # 권한 없음 → 감사 불가: SKIPPED 로 처리 (원하면 "ERROR" 로 변경 가능)
            if code in ("AccessDenied", "AccessDeniedException"):
                evaluations.append(ServiceEvaluation(
                    service="AWS Organizations",
                    resource_id="org-root",
                    evidence_path="Policies[].Type",
                    checked_field="SCP policies count",
                    comparator="ge",
                    expected_value=1,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"missingPermissions": ["organizations:ListPolicies"], "error": str(e)}
                ))
                return AuditResult(
                    mapping_code=self.code,
                    status=final_status_from_evals(evaluations),
                    evaluations=evaluations,
                    reason="Missing permissions for Organizations read"
                )
            # 그 외 에러는 ERROR
            evaluations.append(ServiceEvaluation(
                service="AWS Organizations",
                resource_id="org-root",
                evidence_path="Policies[].Type",
                checked_field="SCP policies count",
                comparator="ge",
                expected_value=1,
                observed_value=None,
                passed=None,
                decision="check failed due to exception",
                status="ERROR",
                source="aws-sdk",
                extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, status="ERROR",
                               evaluations=evaluations, reason=str(e))
        except Exception as e:
            evaluations.append(ServiceEvaluation(
                service="AWS Organizations",
                resource_id="org-root",
                evidence_path="Policies[].Type",
                checked_field="SCP policies count",
                comparator="ge",
                expected_value=1,
                observed_value=None,
                passed=None,
                decision="check failed due to exception",
                status="ERROR",
                source="aws-sdk",
                extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, status="ERROR",
                               evaluations=evaluations, reason=str(e))
