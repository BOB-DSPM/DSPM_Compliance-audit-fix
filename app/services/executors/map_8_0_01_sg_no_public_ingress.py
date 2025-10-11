from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_8_0_01:
    code = "8.0-01"
    title = "Security Groups: no 0.0.0.0/0 ingress"

    def audit(self) -> AuditResult:
        ec2 = boto3.client("ec2")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"securityGroups": 0, "publicIngress": []}

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            sg_count = 0
            offenders = []

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []) or []:
                    sg_count += 1
                    sgid = sg.get("GroupId")
                    name = sg.get("GroupName")
                    public = False

                    for perm in sg.get("IpPermissions", []) or []:
                        for r in perm.get("IpRanges", []) or []:
                            if r.get("CidrIp") == "0.0.0.0/0":
                                public = True
                                break
                        if public: break
                        for r6 in perm.get("Ipv6Ranges", []) or []:
                            if r6.get("CidrIpv6") == "::/0":  # IPv6 전체 공개도 차단 대상
                                public = True
                                break
                        if public: break

                    if public:
                        offenders.append({"groupId": sgid, "groupName": name})

                    evals.append(ServiceEvaluation(
                        service="EC2",
                        resource_id=f"{name or ''}({sgid})",
                        evidence_path="SecurityGroups[].IpPermissions[].IpRanges[].CidrIp",
                        checked_field="has_public_ingress",
                        comparator="eq",
                        expected_value=False,
                        observed_value=public,
                        passed=(public is False),
                        decision=("no 0.0.0.0/0 or ::/0 → passed" if not public else "public ingress found → failed"),
                        status="COMPLIANT" if not public else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={}
                    ))

            evidence["securityGroups"] = sg_count
            evidence["publicIngress"] = offenders[:10]

            overall_ok = len(offenders) == 0 and sg_count > 0
            status = "COMPLIANT" if overall_ok else ("NON_COMPLIANT" if sg_count > 0 else "SKIPPED")

            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence,
                reason=None if status != "NON_COMPLIANT" else "Security groups with public ingress exist",
                extract={
                    "code": self.code, "category": "8 (네트워크/VPC/Public 노출)", "service": "EC2 Security Group",
                    "console_path": "EC2 → 보안그룹",
                    "check_how": "IpPermissions에 0.0.0.0/0 또는 ::/0 인바운드 존재 여부",
                    "cli_cmd": 'aws ec2 describe-security-groups --query "SecurityGroups[].IpPermissions[].IpRanges[].CidrIp"',
                    "return_field": "CidrIp / CidrIpv6",
                    "compliant_value": "없음",
                    "non_compliant_value": "0.0.0.0/0 또는 ::/0 존재",
                    "console_fix": "보안그룹 인바운드에서 전체 공개 규칙 제거",
                    "cli_fix_cmd": "aws ec2 revoke-security-group-ingress --group-id sg-XXX --protocol -1 --port all --cidr 0.0.0.0/0"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="EC2", resource_id=None,
                    evidence_path="describe-security-groups",
                    checked_field="IpPermissions",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
