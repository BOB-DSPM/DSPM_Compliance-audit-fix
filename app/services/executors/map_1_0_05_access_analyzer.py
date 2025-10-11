from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_1_0_05:
    code = "1.0-05"
    title = "IAM Access Analyzer 활성(Analyzer ACTIVE)"

    def audit(self) -> AuditResult:
        aa = boto3.client("accessanalyzer")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"analyzers": [], "activeCount": 0}

        try:
            resp = aa.list_analyzers()
            analyzers = resp.get("analyzers", [])
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="AccessAnalyzer", resource_id=None,
                    evidence_path="Analyzers", checked_field="status",
                    comparator="exists", expected_value=True, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions to list analyzers",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )

        for a in analyzers:
            name = a.get("name")
            status = a.get("status")
            evidence["analyzers"].append({"name": name, "status": status})

            passed = (status == "ACTIVE")
            if passed:
                evidence["activeCount"] += 1

            evals.append(ServiceEvaluation(
                service="AccessAnalyzer",
                resource_id=name,
                evidence_path="Analyzers[].status",
                checked_field="status",
                comparator="eq",
                expected_value="ACTIVE",
                observed_value=status,
                passed=passed,
                decision=f"observed {status} == ACTIVE → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

        # 전체 기준: ACTIVE 분석기 1개 이상
        if not analyzers:
            overall = "NON_COMPLIANT"
            reason = "No analyzers"
        else:
            overall = "COMPLIANT" if evidence["activeCount"] > 0 else "NON_COMPLIANT"
            reason = None if overall == "COMPLIANT" else "No ACTIVE analyzers"

        return AuditResult(
            mapping_code=self.code, title=self.title, status=overall,
            evaluations=evals, evidence=evidence, reason=reason,
            extract={
                "code": self.code, "category": "1 (접근제어/RBAC/IAM)", "service": "IAM Access Analyzer",
                "console_path": "IAM → 액세스 분석기",
                "check_how": "Analyzer status 가 ACTIVE",
                "cli_cmd": "aws accessanalyzer list-analyzers",
                "return_field": "status",
                "compliant_value": "ACTIVE",
                "non_compliant_value": "INACTIVE 등",
                "console_fix": "Access Analyzer 생성/활성",
                "cli_fix_cmd": "aws accessanalyzer create-analyzer --type ACCOUNT --name analyzer"
            }
        )
