from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_8_0_05:
    code = "8.0-05"
    title = "Route53 DNS Firewall - Rule group 활성/연결"

    def audit(self) -> AuditResult:
        r53r = boto3.client("route53resolver")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "ruleGroupsCount": 0,
            "associationCount": 0,
            "sampleRuleGroupIds": [],
            "sampleAssociations": [],
        }

        try:
            # ---- 1) DNS Firewall Rule Groups 조회 (수동 페이지네이션) ----
            rule_groups: List[Dict[str, Any]] = []
            token = None
            while True:
                kwargs = {}
                if token:
                    kwargs["NextToken"] = token
                resp = r53r.list_firewall_rule_groups(**kwargs)
                rule_groups.extend(resp.get("FirewallRuleGroups", []) or [])
                token = resp.get("NextToken")
                if not token:
                    break

            evidence["ruleGroupsCount"] = len(rule_groups)
            evidence["sampleRuleGroupIds"] = [g.get("Id") for g in rule_groups[:5]]

            # 평가1: Rule group이 1개 이상 존재하는가?
            passed_rg = evidence["ruleGroupsCount"] >= 1
            evals.append(
                ServiceEvaluation(
                    service="Route53 Resolver",
                    resource_id="account/region",
                    evidence_path="FirewallRuleGroups[*].Id",
                    checked_field="FirewallRuleGroups count",
                    comparator="ge",
                    expected_value=1,
                    observed_value=evidence["ruleGroupsCount"],
                    passed=passed_rg,
                    decision=f"observed {evidence['ruleGroupsCount']} >= 1 → {'passed' if passed_rg else 'failed'}",
                    status="COMPLIANT" if passed_rg else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={"note": "At least one DNS Firewall rule group should exist."},
                )
            )

            # ---- 2) VPC 연결(Association) 존재 여부 확인 ----
            associations: List[Dict[str, Any]] = []
            token = None
            while True:
                kwargs = {}
                if token:
                    kwargs["NextToken"] = token
                resp = r53r.list_firewall_rule_group_associations(**kwargs)
                associations.extend(resp.get("FirewallRuleGroupAssociations", []) or [])
                token = resp.get("NextToken")
                if not token:
                    break

            evidence["associationCount"] = len(associations)
            # 샘플: VPC/RuleGroupId만 미리보기로 제공
            for a in associations[:5]:
                evidence["sampleAssociations"].append(
                    {
                        "VPCId": a.get("VpcId"),
                        "FirewallRuleGroupId": a.get("FirewallRuleGroupId"),
                        "Status": a.get("Status"),
                    }
                )

            # 평가2: 적어도 하나의 VPC에 연결되어 있는가?
            passed_assoc = evidence["associationCount"] >= 1
            evals.append(
                ServiceEvaluation(
                    service="Route53 Resolver",
                    resource_id="account/region",
                    evidence_path="FirewallRuleGroupAssociations[*].VpcId",
                    checked_field="Associations count",
                    comparator="ge",
                    expected_value=1,
                    observed_value=evidence["associationCount"],
                    passed=passed_assoc,
                    decision=f"observed {evidence['associationCount']} >= 1 → {'passed' if passed_assoc else 'failed'}",
                    status="COMPLIANT" if passed_assoc else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={"note": "At least one rule group should be associated to a VPC."},
                )
            )

            # ---- 전체 상태: 둘 다 충족 시 COMPLIANT, 아니면 NON_COMPLIANT ----
            status = "COMPLIANT" if (passed_rg and passed_assoc) else "NON_COMPLIANT"

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code,
                    "category": "8 (네트워크/VPC/Public 노출)",
                    "service": "Route53 Resolver",
                    "console_path": "Route53 Resolver → DNS Firewall",
                    "check_how": "Firewall rule group 및 VPC association 존재 여부 확인",
                    "cli_cmd": "aws route53resolver list-firewall-rule-groups",
                    "return_field": "FirewallRuleGroups",
                    "compliant_value": "존재(>=1) + VPC 연결(>=1)",
                    "non_compliant_value": "없음(0) 또는 연결 없음(0)",
                    "console_fix": "DNS Firewall rule group 생성 후 대상 VPC에 Associate",
                    "cli_fix_cmd": (
                        "aws route53resolver associate-firewall-rule-group "
                        "--vpc-id vpc-XXX --firewall-rule-group-id rg-XXX"
                    ),
                },
            )

        except botocore.exceptions.ClientError as e:
            # 권한/에러 시 SKIPPED
            evals.append(
                ServiceEvaluation(
                    service="Route53 Resolver",
                    resource_id=None,
                    evidence_path="FirewallRuleGroups/Associations",
                    checked_field="API access",
                    comparator="exists",
                    expected_value=True,
                    observed_value=False,
                    passed=None,
                    decision="cannot evaluate: missing permissions or API error",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)},
                )
            )
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=evals,
                evidence={},
                reason="Missing permissions or API error",
                extract=None,
            )
