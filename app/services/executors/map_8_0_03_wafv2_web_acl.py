# app/services/executors/map_8_0_03_wafv2_web_acl.py

from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_8_0_03:
    code = "8.0-03"
    title = "WAFv2 Web ACL 연결"

    def audit(self) -> AuditResult:
        waf = boto3.client("wafv2")
        elb = boto3.client("elbv2")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "regionalAclCount": 0,
            "albCount": 0,
            "associatedAlbArns": [],
        }

        try:
            # ── 1) REGIONAL Web ACL 존재 개수 (수동 페이지네이션) ─────────────────
            acl_count = 0
            try:
                next_marker = None
                while True:
                    params = {"Scope": "REGIONAL"}
                    if next_marker:
                        params["NextMarker"] = next_marker
                    resp = waf.list_web_acls(**params)
                    acl_count += len(resp.get("WebACLs", []) or [])
                    next_marker = resp.get("NextMarker")
                    if not next_marker:
                        break
            except botocore.exceptions.ClientError as e:
                return AuditResult(
                    mapping_code=self.code,
                    title=self.title,
                    status="SKIPPED",
                    evaluations=[ServiceEvaluation(
                        service="WAFv2",
                        resource_id=None,
                        evidence_path="WebACLs",
                        checked_field="list_web_acls(REGIONAL)",
                        comparator="exists",
                        expected_value=True,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: missing permissions on WAFv2",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(e)},
                    )],
                    evidence={},
                    reason="Missing permissions",
                    extract=None,
                )
            evidence["regionalAclCount"] = acl_count

            # ── 2) ALB 나열 후 연결 여부 확인 (Paginator OK) ─────────────────────
            alb_arns: List[str] = []
            try:
                paginator = elb.get_paginator("describe_load_balancers")
                for page in paginator.paginate():
                    for lb in page.get("LoadBalancers", []) or []:
                        if lb.get("Type") == "application":
                            alb_arns.append(lb.get("LoadBalancerArn"))
            except botocore.exceptions.ClientError as e:
                evals.append(ServiceEvaluation(
                    service="ELBv2",
                    resource_id=None,
                    evidence_path="LoadBalancers",
                    checked_field="list ALBs",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot list ALBs",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)},
                ))
            evidence["albCount"] = len(alb_arns)

            associated = 0
            for arn in alb_arns:
                try:
                    res = waf.get_web_acl_for_resource(ResourceArn=arn)
                    web_acl_arn = (res or {}).get("WebACL", {}).get("ARN")
                    if web_acl_arn:
                        associated += 1
                        evidence["associatedAlbArns"].append(arn)
                        evals.append(ServiceEvaluation(
                            service="WAFv2",
                            resource_id=arn,
                            evidence_path="get_web_acl_for_resource(WebACL.ARN)",
                            checked_field="Associated",
                            comparator="exists",
                            expected_value=True,
                            observed_value=True,
                            passed=True,
                            decision="ALB has associated Web ACL",
                            status="COMPLIANT",
                            source="aws-sdk",
                            extra={"webAclArn": web_acl_arn},
                        ))
                    else:
                        evals.append(ServiceEvaluation(
                            service="WAFv2",
                            resource_id=arn,
                            evidence_path="get_web_acl_for_resource(WebACL)",
                            checked_field="Associated",
                            comparator="exists",
                            expected_value=True,
                            observed_value=False,
                            passed=False,
                            decision="ALB has no associated Web ACL",
                            status="NON_COMPLIANT",
                            source="aws-sdk",
                            extra={},
                        ))
                except botocore.exceptions.ClientError as e:
                    evals.append(ServiceEvaluation(
                        service="WAFv2",
                        resource_id=arn,
                        evidence_path="get_web_acl_for_resource",
                        checked_field="Associated",
                        comparator="exists",
                        expected_value=True,
                        observed_value=None,
                        passed=None,
                        decision="cannot check association for ALB",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(e)},
                    ))

            # ── 3) 최종 판단 ────────────────────────────────────────────────────
            passed_overall = (acl_count >= 1) and (associated >= 1)
            status = "COMPLIANT" if passed_overall else "NON_COMPLIANT"

            evals.append(ServiceEvaluation(
                service="WAFv2",
                resource_id="account/region",
                evidence_path="list_web_acls + get_web_acl_for_resource(ALB*)",
                checked_field="hasAclAndAssociation",
                comparator="eq",
                expected_value=True,
                observed_value=passed_overall,
                passed=passed_overall,
                decision=("web ACL exists and associated to at least one ALB"
                          if passed_overall else "missing web ACL or no associations"),
                status="COMPLIANT" if passed_overall else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"regionalAclCount": acl_count, "associatedAlbCount": associated},
            ))

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if passed_overall else "No REGIONAL Web ACL or no ALB association",
                extract={
                    "code": self.code,
                    "category": "8 (네트워크/VPC/Public 노출)",
                    "service": "WAFv2",
                    "console_path": "WAF & Shield → Web ACLs",
                    "check_how": "list_web_acls(REGIONAL) + get_web_acl_for_resource(ALB)",
                    "cli_cmd": "aws wafv2 list-web-acls --scope REGIONAL",
                    "return_field": "WebACLs",
                    "compliant_value": ">=1 & 연결 존재",
                    "non_compliant_value": "없음 또는 미연결",
                    "console_fix": "Web ACL 생성 후 ALB/API 리소스에 Associate",
                    "cli_fix_cmd": "aws wafv2 associate-web-acl --scope REGIONAL --web-acl-arn WAF_ARN --resource-arn ALB_OR_API_ARN",
                },
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="WAFv2",
                    resource_id=None,
                    evidence_path="Global",
                    checked_field="Prerequisites",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)},
                )],
                evidence={},
                reason="Missing permissions",
                extract=None,
            )
