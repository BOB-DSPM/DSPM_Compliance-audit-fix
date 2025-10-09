# app/services/executors/map_11_0_02_config_conformance_pack.py (핵심 부분만)
from app.models.schemas import AuditResult, ServiceEvaluation
from app.core.aws import configservice

def final_status_from_evals(evals):
    if any(e.status == "ERROR" for e in evals):
        return "ERROR"
    if any(e.status == "NON_COMPLIANT" for e in evals):
        return "NON_COMPLIANT"
    return "COMPLIANT" if evals else "SKIPPED"

class Exec_11_0_02:
    code = "11.0-02"

    def audit(self) -> AuditResult:
        evaluations = []
        try:
            client = configservice()
            resp = client.describe_conformance_pack_status()
            packs = resp.get("ConformancePackStatusDetails", [])
            observed = len(packs)

            comparator = "ge"
            expected = 1
            passed = (observed >= expected)
            decision = f"observed {observed} >= {expected} → {'passed' if passed else 'failed'}"

            evaluations.append(ServiceEvaluation(
                service="AWS Config",
                resource_id="account/region",
                evidence_path="ConformancePackStatusDetails[].(count)",  # ✅ 무엇을 셌는지
                checked_field="ConformancePack count",
                comparator=comparator,
                expected_value=expected,
                observed_value=observed,
                passed=passed,
                decision=decision,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"samplePacks": packs[:3]}
            ))

            return AuditResult(mapping_code=self.code,
                               status=final_status_from_evals(evaluations),
                               evaluations=evaluations,
                               evidence={"conformancePackCount": observed})
        except Exception as e:
            evaluations.append(ServiceEvaluation(
                service="AWS Config",
                resource_id="account/region",
                evidence_path="ConformancePackStatusDetails[].(count)",
                checked_field="ConformancePack count",
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
