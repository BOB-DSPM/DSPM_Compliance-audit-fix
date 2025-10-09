from botocore.exceptions import ClientError
from app.models.schemas import AuditResult, ServiceEvaluation
from app.core.aws import sso_admin
from app.core.config import settings

def final_status_from_evals(evals):
    if any(e.status == "ERROR" for e in evals):
        return "ERROR"
    if any(e.status == "NON_COMPLIANT" for e in evals):
        return "NON_COMPLIANT"
    if evals and all(e.status == "SKIPPED" for e in evals):
        return "SKIPPED"
    return "COMPLIANT" if evals else "SKIPPED"

class Exec_1_0_01:
    """
    매핑코드: 1.0-01
    점검내용: IAM Identity Center(SSO) 권한셋 최소화 (권한셋 개수 임계치 이하)
    기준(comparator): le (observed <= expected)
    expected: settings.SSO_PERMISSION_SET_MAX
    evidence_path:
      - "Instances[].InstanceArn" (인스턴스 존재 여부)
      - "PermissionSets[].(count)" (권한셋 개수)
    """
    code = "1.0-01"

    def audit(self) -> AuditResult:
        evaluations = []
        try:
            client = sso_admin()

            # 1) SSO 인스턴스 존재 확인
            instances = client.list_instances().get("Instances", [])
            if not instances:
                observed = 0
                expected = 1
                comparator = "ge"
                passed = (observed >= expected)
                decision = f"observed {observed} >= {expected} → {'passed' if passed else 'failed'}"

                evaluations.append(ServiceEvaluation(
                    service="IAM Identity Center(SSO)",
                    resource_id=None,
                    evidence_path="Instances[].InstanceArn",
                    checked_field="Instances count",
                    comparator=comparator,
                    expected_value=expected,
                    observed_value=observed,
                    passed=passed,
                    decision=decision,
                    status="NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))
                return AuditResult(
                    mapping_code=self.code,
                    status=final_status_from_evals(evaluations),
                    evaluations=evaluations,
                    evidence={"instances": 0},
                    reason="SSO 인스턴스가 존재하지 않음"
                )

            instance_arn = instances[0]["InstanceArn"]

            # 2) 권한셋 개수 확인
            psets = client.list_permission_sets(InstanceArn=instance_arn).get("PermissionSets", [])
            observed = len(psets)
            expected = settings.SSO_PERMISSION_SET_MAX
            comparator = "le"
            passed = (observed <= expected)
            decision = f"observed {observed} <= {expected} → {'passed' if passed else 'failed'}"

            evaluations.append(ServiceEvaluation(
                service="IAM Identity Center(SSO)",
                resource_id=instance_arn,
                evidence_path="PermissionSets[].(count)",
                checked_field="PermissionSets count",
                comparator=comparator,
                expected_value=expected,
                observed_value=observed,
                passed=passed,
                decision=decision,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"samplePermissionSets": psets[:5]}
            ))

            return AuditResult(
                mapping_code=self.code,
                status=final_status_from_evals(evaluations),
                evaluations=evaluations,
                evidence={
                    "instanceArn": instance_arn,
                    "permissionSetCount": observed,
                    "threshold": expected
                }
            )

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            # 권한 없음 → 감사 불가: SKIPPED 로 처리 (원하면 "ERROR" 로 변경 가능)
            if code in ("AccessDenied", "AccessDeniedException"):
                evaluations.append(ServiceEvaluation(
                    service="IAM Identity Center(SSO)",
                    resource_id=None,
                    evidence_path="Instances[].InstanceArn / PermissionSets",
                    checked_field="PermissionSets count",
                    comparator="le",
                    expected_value=settings.SSO_PERMISSION_SET_MAX,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"missingPermissions": ["sso:ListInstances", "sso:ListPermissionSets"], "error": str(e)}
                ))
                return AuditResult(
                    mapping_code=self.code,
                    status=final_status_from_evals(evaluations),
                    evaluations=evaluations,
                    reason="Missing permissions for SSO read"
                )
            # 그 외 에러는 ERROR
            evaluations.append(ServiceEvaluation(
                service="IAM Identity Center(SSO)",
                resource_id=None,
                evidence_path="Instances[].InstanceArn / PermissionSets",
                checked_field="PermissionSets count",
                comparator="le",
                expected_value=settings.SSO_PERMISSION_SET_MAX,
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
                service="IAM Identity Center(SSO)",
                resource_id=None,
                evidence_path="Instances[].InstanceArn / PermissionSets",
                checked_field="PermissionSets count",
                comparator="le",
                expected_value=settings.SSO_PERMISSION_SET_MAX,
                observed_value=None,
                passed=None,
                decision="check failed due to exception",
                status="ERROR",
                source="aws-sdk",
                extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, status="ERROR",
                               evaluations=evaluations, reason=str(e))
