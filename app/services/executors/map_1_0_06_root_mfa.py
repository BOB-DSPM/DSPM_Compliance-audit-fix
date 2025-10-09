# app/services/executors/map_1_0_06_root_mfa.py (핵심 부분만)
from app.models.schemas import ServiceEvaluation, AuditResult
from app.core.aws import iam

def final_status_from_evals(evals):
    if any(e.status == "ERROR" for e in evals):
        return "ERROR"
    if any(e.status == "NON_COMPLIANT" for e in evals):
        return "NON_COMPLIANT"
    return "COMPLIANT" if evals else "SKIPPED"

class Exec_1_0_06:
    code = "1.0-06"

    def audit(self) -> AuditResult:
        evaluations = []
        try:
            client = iam()
            summary = client.get_account_summary().get("SummaryMap", {})
            observed = 1 if summary.get("AccountMFAEnabled") == 1 else 0

            comparator = "eq"
            expected = 1
            passed = (observed == expected)
            decision = f"observed {observed} == {expected} → {'passed' if passed else 'failed'}"

            evaluations.append(ServiceEvaluation(
                service="IAM",
                resource_id="root-account",
                evidence_path="SummaryMap.AccountMFAEnabled",  # ✅ 어떤 값을 봤는지
                checked_field="AccountMFAEnabled",
                comparator=comparator,                         # ✅ 어떤 비교를 했는지
                expected_value=expected,
                observed_value=observed,                       # ✅ 실제 값
                passed=passed,                                 # ✅ 판단 결과 (불린)
                decision=decision,                             # ✅ 사람이 읽기 쉬운 설명
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            return AuditResult(
                mapping_code=self.code,
                status=final_status_from_evals(evaluations),
                evaluations=evaluations,
                evidence={"AccountMFAEnabled": observed}
            )
        except Exception as e:
            evaluations.append(ServiceEvaluation(
                service="IAM",
                resource_id="root-account",
                evidence_path="SummaryMap.AccountMFAEnabled",
                checked_field="AccountMFAEnabled",
                comparator="eq",
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
