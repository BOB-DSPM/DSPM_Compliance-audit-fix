from __future__ import annotations
from typing import List, Dict, Any, Optional
import csv, io, datetime as dt
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

DATE_FMT = "%Y-%m-%dT%H:%M:%S+00:00"  # IAM credential report format

class Exec_1_0_03:
    code = "1.0-03"
    title = "IAM Credential Report (MFA & AccessKey recency)"

    def _ensure_report(self, iam) -> bytes:
        """
        IAM credential report가 없는 경우 생성 후 바이트 반환.
        """
        try:
            # 이미 있으면 바로 내려옴
            return iam.get_credential_report()["Content"]
        except iam.exceptions.CredentialReportNotPresentException:
            pass

        # 생성 트리거 후 몇 차례 재시도
        iam.generate_credential_report()
        for _ in range(10):
            try:
                return iam.get_credential_report()["Content"]
            except iam.exceptions.CredentialReportNotPresentException:
                import time; time.sleep(1)
        # 끝까지 실패시 예외 던져지게
        return iam.get_credential_report()["Content"]

    def _days_since(self, s: str) -> Optional[int]:
        if not s or s == "N/A":
            return None
        try:
            d = dt.datetime.strptime(s, DATE_FMT)
            delta = dt.datetime.utcnow() - d.replace(tzinfo=None)
            return delta.days
        except Exception:
            return None

    def audit(self) -> AuditResult:
        iam = boto3.client("iam")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "usersTotal": 0,
            "usersCompliant": 0,
            "usersNonCompliant": [],
            "sampleNonCompliant": [],
        }

        try:
            content = self._ensure_report(iam)
            rows = list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
            # IAM 사용자만 필터 (root 등 포함돼 있지만 'user' 컬럼이 <root_account> 일 수 있음)
            for r in rows:
                user = r.get("user")
                if not user or user == "<root_account>":
                    continue

                evidence["usersTotal"] += 1

                mfa_active = (r.get("mfa_active") == "true")
                # 사용 중인 AccessKey들의 최근 사용일(둘 중 최신)을 계산
                last_used_1 = self._days_since(r.get("access_key_1_last_used_date", "N/A"))
                last_used_2 = self._days_since(r.get("access_key_2_last_used_date", "N/A"))
                has_key_1   = r.get("access_key_1_active") == "true"
                has_key_2   = r.get("access_key_2_active") == "true"
                has_keys    = has_key_1 or has_key_2

                # 규칙:
                # - MFA는 반드시 활성 (mfa_active == true)
                # - 액세스키는 없거나, 있으면 최근 90일 이내 사용
                days_recent = None
                if has_keys:
                    candidates = [d for d in [last_used_1, last_used_2] if d is not None]
                    days_recent = min(candidates) if candidates else None  # None이면 사용 이력 없음
                key_ok = (not has_keys) or (days_recent is not None and days_recent <= 90)

                # 개별 평가 1: MFA
                evals.append(ServiceEvaluation(
                    service="IAM",
                    resource_id=user,
                    evidence_path="credential-report.mfa_active",
                    checked_field="mfa_active",
                    comparator="eq",
                    expected_value=True,
                    observed_value=mfa_active,
                    passed=mfa_active,
                    decision=f"observed {mfa_active} == True → {'passed' if mfa_active else 'failed'}",
                    status="COMPLIANT" if mfa_active else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))

                # 개별 평가 2: AccessKey 최근성
                if not has_keys:
                    decision = "no active access keys → passed"
                    passed = True
                    observed = None
                else:
                    if days_recent is None:
                        decision = "no last-used record → failed"
                        passed = False
                        observed = None
                    else:
                        passed = days_recent <= 90
                        decision = f"observed {days_recent} <= 90 days → {'passed' if passed else 'failed'}"
                        observed = days_recent

                evals.append(ServiceEvaluation(
                    service="IAM",
                    resource_id=user,
                    evidence_path="credential-report.access_key_{1,2}_last_used_date",
                    checked_field="access_key_recency_days",
                    comparator="le" if observed is not None else None,
                    expected_value=90 if observed is not None else None,
                    observed_value=observed,
                    passed=passed,
                    decision=decision,
                    status="COMPLIANT" if passed else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={"hasActiveKeys": has_keys, "daysSinceLastUse": observed}
                ))

                user_pass = mfa_active and passed
                if user_pass:
                    evidence["usersCompliant"] += 1
                else:
                    evidence["usersNonCompliant"].append(user)

            status = "COMPLIANT" if evidence["usersTotal"] > 0 and len(evidence["usersNonCompliant"]) == 0 else "NON_COMPLIANT"
            if evidence["usersNonCompliant"]:
                evidence["sampleNonCompliant"] = evidence["usersNonCompliant"][:5]
            if evidence["usersTotal"] == 0:
                status = "SKIPPED"

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if status != "SKIPPED" else "No IAM users",
                extract={
                    "code": self.code, "category": "1 (접근제어/RBAC/IAM)", "service": "IAM Credential Report",
                    "console_path": "IAM → 자격증명 보고서",
                    "check_how": "mfa_active == true AND (no active keys OR last_used ≤ 90d)",
                    "cli_cmd": "aws iam get-credential-report",
                    "return_field": "mfa_active, access_key_*_last_used_date",
                    "compliant_value": "MFA 활성 & 키 최근성 충족",
                    "non_compliant_value": "MFA 미적용 또는 장기 미사용 키",
                    "console_fix": "IAM 사용자 MFA 활성화, 90일↑ 미사용 키 비활성/삭제",
                    "cli_fix_cmd": "aws iam update-access-key --user-name USER --access-key-id KEY --status Inactive"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="IAM", resource_id=None,
                    evidence_path="get-credential-report",
                    checked_field="report",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
