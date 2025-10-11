from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_05_06:
    code = "2.0-05/06"
    title = "OpenSearch"

    def audit(self) -> AuditResult:
        client = boto3.client("opensearch")
        evals: List[ServiceEvaluation] = []
        ev: Dict[str, Any] = {"domains": 0, "atRestOK": 0, "n2nOK": 0, "atRestFail": [], "n2nFail": []}

        try:
            # 도메인 이름 나열
            doms = client.list_domain_names().get("DomainNames", [])
            ev["domains"] = len(doms)

            for d in doms:
                name = d["DomainName"]
                desc = client.describe_domain(DomainName=name)["DomainStatus"]
                at_rest = desc.get("EncryptionAtRestOptions", {}).get("Enabled")
                n2n = desc.get("NodeToNodeEncryptionOptions", {}).get("Enabled")

                at_ok = (at_rest is True)
                n2_ok = (n2n is True)
                if at_ok: ev["atRestOK"] += 1
                else: ev["atRestFail"].append(name)
                if n2_ok: ev["n2nOK"] += 1
                else: ev["n2nFail"].append(name)

                evals.append(ServiceEvaluation(
                    service="OpenSearch", resource_id=name,
                    evidence_path="DomainStatus.(EncryptionAtRestOptions.Enabled, NodeToNodeEncryptionOptions.Enabled)",
                    checked_field="At-rest & Node-to-Node",
                    comparator="custom", expected_value={"atRest": True, "nodeToNode": True},
                    observed_value={"atRest": at_rest, "nodeToNode": n2n},
                    passed=(at_ok and n2_ok),
                    decision="both enabled" if (at_ok and n2_ok) else "missing one or both",
                    status="COMPLIANT" if (at_ok and n2_ok) else "NON_COMPLIANT",
                    source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if (ev["atRestFail"] or ev["n2nFail"]) else "COMPLIANT"
            return AuditResult(
                mapping_code="2.0-05/06", title=self.title, status=final,
                evaluations=evals, evidence=ev, reason=None,
                extract={"code": "2.0-05/06", "category":"2 (암호화/KMS/TLS/At-rest)", "service":"OpenSearch",
                         "console_path":"OpenSearch → 도메인 → 보안", "check_how":"At-rest/노드간 암호화",
                         "cli_cmd":"aws opensearch describe-domain --domain-name NAME --query \"DomainStatus.(EncryptionAtRestOptions.Enabled,NodeToNodeEncryptionOptions.Enabled)\"",
                         "return_field":"...Enabled", "compliant_value":"TRUE", "non_compliant_value":"FALSE",
                         "console_fix":"(불가시) 새 도메인 생성 후 마이그레이션", "cli_fix_cmd":"-"}
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code="2.0-05/06", title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="OpenSearch", resource_id=None,
                    evidence_path="DomainStatus.*.Enabled", checked_field="At-rest/Node-to-Node",
                    comparator="custom", expected_value=True, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions", status="SKIPPED",
                    source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
