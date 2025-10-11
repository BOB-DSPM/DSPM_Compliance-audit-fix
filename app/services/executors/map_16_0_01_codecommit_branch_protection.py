from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_16_0_01:
    code = "16.0-01"
    title = "CodeCommit branch protection via approval rule templates"

    def audit(self) -> AuditResult:
        ccc = boto3.client("codecommit")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"repositoriesChecked": 0, "withTemplates": [], "withoutTemplates": []}

        try:
            # 모든 리포지토리 나열
            repos: List[Dict[str, Any]] = []
            paginator = ccc.get_paginator("list_repositories")
            for page in paginator.paginate():
                repos.extend(page.get("repositories", []))

            for r in repos:
                name = r.get("repositoryName")
                evidence["repositoriesChecked"] += 1
                try:
                    resp = ccc.list_associated_approval_rule_templates_for_repository(
                        repositoryName=name
                    )
                    tmpl_names = resp.get("approvalRuleTemplateNames", []) or []
                    has_template = len(tmpl_names) > 0

                    if has_template:
                        evidence["withTemplates"].append({"repo": name, "templates": tmpl_names[:3]})
                    else:
                        evidence["withoutTemplates"].append(name)

                    evals.append(ServiceEvaluation(
                        service="CodeCommit",
                        resource_id=name,
                        evidence_path="approvalRuleTemplateNames",
                        checked_field="approvalRuleTemplateNames",
                        comparator="exists",
                        expected_value=True,
                        observed_value=has_template,
                        passed=has_template,
                        decision=f"templates {'exist' if has_template else 'missing'} → "
                                 f"{'passed' if has_template else 'failed'}",
                        status="COMPLIANT" if has_template else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"sampleTemplates": tmpl_names[:3]}
                    ))
                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="CodeCommit",
                        resource_id=name,
                        evidence_path="approvalRuleTemplateNames",
                        checked_field="approvalRuleTemplateNames",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ie)}
                    ))

            # 종합 판단: 하나라도 템플릿 적용된 리포지토리가 있으면 COMPLIANT(ANY 기준)
            total = evidence["repositoriesChecked"]
            status = "SKIPPED" if total == 0 else ("COMPLIANT" if evidence["withTemplates"] else "NON_COMPLIANT")
            reason = None if status != "SKIPPED" else "No repositories found"

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=reason,
                extract={
                    "code": self.code,
                    "category": "16 (변경관리/형상관리/CI·CD)",
                    "service": "CodeCommit",
                    "console_path": "CodeCommit → Repo → 브랜치",
                    "check_how": "Approval rule template 연결 여부",
                    "cli_cmd": "aws codecommit list-associated-approval-rule-templates-for-repository --repository-name NAME",
                    "return_field": "approvalRuleTemplateNames",
                    "compliant_value": "존재",
                    "non_compliant_value": "없음",
                    "console_fix": "Approval rule template 생성 후 리포지토리에 연결",
                    "cli_fix_cmd": (
                        "aws codecommit create-approval-rule-template --approval-rule-template-name require-2-approvals "
                        "--approval-rule-template-content file://rule.json && "
                        "aws codecommit associate-approval-rule-template-with-repository "
                        "--repository-name NAME --approval-rule-template-name require-2-approvals"
                    )
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CodeCommit",
                    resource_id=None,
                    evidence_path="repositories",
                    checked_field="approvalRuleTemplateNames",
                    comparator=None,
                    expected_value=None,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions",
                extract=None
            )
