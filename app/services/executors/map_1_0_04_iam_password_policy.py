from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_1_0_04:
    code = "1.0-04"
    title = "IAM Password Policy"

    def audit(self) -> AuditResult:
        iam = boto3.client("iam")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {}

        try:
            resp = iam.get_account_password_policy()
            pol = resp.get("PasswordPolicy", {}) or {}

            min_len = pol.get("MinimumPasswordLength")
            req_symbols = bool(pol.get("RequireSymbols", False))
            # 참고: 아래 필드들은 권장 검사(추가 정보)로 evidence에 담아줌
            req_numbers = bool(pol.get("RequireNumbers", False))
            req_upper = bool(pol.get("RequireUppercaseCharacters", False))
            req_lower = bool(pol.get("RequireLowercaseCharacters", False))
            max_age = pol.get("MaxPasswordAge")  # 존재하면 양수 권장

            evidence.update({
                "MinimumPasswordLength": min_len,
                "RequireSymbols": req_symbols,
                "RequireNumbers": req_numbers,
                "RequireUppercaseCharacters": req_upper,
                "RequireLowercaseCharacters": req_lower,
                "MaxPasswordAge": max_age,
            })

            # 매핑 기준: MinimumPasswordLength ≥ 8 AND RequireSymbols == True
            pass_len = (min_len is not None) and (min_len >= 8)
            pass_sym = req_symbols is True
            overall_pass = pass_len and pass_sym

            # 개별 평가 레코드
            evals.append(ServiceEvaluation(
                service="IAM",
                resource_id="account",
                evidence_path="PasswordPolicy.MinimumPasswordLength",
                checked_field="MinimumPasswordLength",
                comparator="ge",
                expected_value=8,
                observed_value=min_len,
                passed=pass_len,
                decision=f"observed {min_len} >= 8 → {'passed' if pass_len else 'failed'}",
                status="COMPLIANT" if pass_len else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))
            evals.append(ServiceEvaluation(
                service="IAM",
                resource_id="account",
                evidence_path="PasswordPolicy.RequireSymbols",
                checked_field="RequireSymbols",
                comparator="eq",
                expected_value=True,
                observed_value=req_symbols,
                passed=pass_sym,
                decision=f"observed {req_symbols} == True → {'passed' if pass_sym else 'failed'}",
                status="COMPLIANT" if pass_sym else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            status = "COMPLIANT" if overall_pass else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code,
                    "category": "1 (접근제어/RBAC/IAM)",
                    "service": "IAM",
                    "console_path": "IAM → 계정 설정",
                    "check_how": "복잡도·만료 정책 확인",
                    "cli_cmd": 'aws iam get-account-password-policy',
                    "return_field": "MinimumPasswordLength, RequireSymbols",
                    "compliant_value": "≥8, true",
                    "non_compliant_value": "짧거나 단순",
                    "console_fix": "IAM → Account settings → Password policy 편집",
                    "cli_fix_cmd": "aws iam update-account-password-policy --minimum-password-length 8 --require-uppercase-characters --require-symbols --require-numbers",
                }
            )

        except botocore.exceptions.ClientError as e:
            # 정책이 아예 없는 경우: NoSuchEntity → NON_COMPLIANT로 처리
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                evals.append(ServiceEvaluation(
                    service="IAM",
                    resource_id="account",
                    evidence_path="PasswordPolicy",
                    checked_field="exists",
                    comparator="exists",
                    expected_value=True,
                    observed_value=False,
                    passed=False,
                    decision="no password policy configured → failed",
                    status="NON_COMPLIANT",
                    source="aws-sdk",
                    extra={"error": str(e)}
                ))
                return AuditResult(
                    mapping_code=self.code,
                    title=self.title,
                    status="NON_COMPLIANT",
                    evaluations=evals,
                    evidence={"PasswordPolicy": "None"},
                    reason="Password policy not configured",
                    extract={
                        "code": self.code,
                        "category": "1 (접근제어/RBAC/IAM)",
                        "service": "IAM",
                        "console_path": "IAM → 계정 설정",
                        "check_how": "복잡도·만료 정책 확인",
                        "cli_cmd": 'aws iam get-account-password-policy',
                        "return_field": "MinimumPasswordLength, RequireSymbols",
                        "compliant_value": "≥8, true",
                        "non_compliant_value": "짧거나 단순",
                        "console_fix": "IAM → Account settings → Password policy 편집",
                        "cli_fix_cmd": "aws iam update-account-password-policy --minimum-password-length 8 --require-uppercase-characters --require-symbols --require-numbers",
                    }
                )
            # 그 외 에러 → SKIPPED
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="IAM",
                    resource_id="account",
                    evidence_path="PasswordPolicy",
                    checked_field="get-account-password-policy",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions or API error",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions or API error",
                extract=None
            )
