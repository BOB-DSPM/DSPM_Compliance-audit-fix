from __future__ import annotations

from typing import List, Dict, Any, Optional
import boto3
import botocore

from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_2_0_05_06:
    """
    Mapping: 2.0-05 (OpenSearch at-rest encryption), 2.0-06 (OpenSearch node-to-node encryption)
    기존 오류 원인: ServiceEvaluation.comparator 가 literal 타입으로 제한되었는데 "custom" 값을 사용하던 부분을
    표준 비교자(eq/exists)로 교체하고, 도메인당 2개의 평가 항목으로 분리했습니다.
    """
    code = "2.0-05/06"
    title = "OpenSearch"

    def audit(self) -> AuditResult:
        client = boto3.client("opensearch")
        evaluations: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "domains": 0,
            "atRestOK": 0,
            "n2nOK": 0,
            "atRestFail": [],
            "n2nFail": [],
        }

        try:
            # 1) 도메인 나열
            domains = client.list_domain_names().get("DomainNames", [])
            evidence["domains"] = len(domains)

            # 도메인이 없는 경우에도 전체 상태는 COMPLIANT 로 간주(평가 기준에 따라 조정 가능)
            if not domains:
                return AuditResult(
                    mapping_code=self.code,
                    title=self.title,
                    status="COMPLIANT",
                    evaluations=[],
                    evidence=evidence,
                    reason="No OpenSearch domains found",
                    extract={
                        "code": self.code,
                        "category": "2 (암호화/KMS/TLS/At-rest)",
                        "service": "OpenSearch",
                        "console_path": "OpenSearch → 도메인 → 보안",
                        "check_how": "At-rest/노드간 암호화",
                        "cli_cmd": (
                            'aws opensearch describe-domain --domain-name NAME '
                            '--query "DomainStatus.(EncryptionAtRestOptions.Enabled,NodeToNodeEncryptionOptions.Enabled)"'
                        ),
                        "return_field": "...Enabled",
                        "compliant_value": "TRUE",
                        "non_compliant_value": "FALSE",
                        "console_fix": "(불가시) 새 도메인 생성 후 마이그레이션",
                        "cli_fix_cmd": "-",
                    },
                )

            # 2) 각 도메인 상세 점검
            for d in domains:
                name: str = d.get("DomainName")
                desc: Dict[str, Any] = client.describe_domain(DomainName=name)["DomainStatus"]

                at_rest: Optional[bool] = (
                    desc.get("EncryptionAtRestOptions", {}).get("Enabled")
                )
                n2n: Optional[bool] = (
                    desc.get("NodeToNodeEncryptionOptions", {}).get("Enabled")
                )

                at_ok = (at_rest is True)
                n2_ok = (n2n is True)

                if at_ok:
                    evidence["atRestOK"] += 1
                else:
                    evidence["atRestFail"].append(name)

                if n2_ok:
                    evidence["n2nOK"] += 1
                else:
                    evidence["n2nFail"].append(name)

                # 2.0-05: At-rest encryption == True
                evaluations.append(
                    ServiceEvaluation(
                        service="OpenSearch",
                        resource_id=name,
                        evidence_path="DomainStatus.EncryptionAtRestOptions.Enabled",
                        checked_field="At-rest encryption",
                        comparator="eq",
                        expected_value=True,
                        observed_value=at_rest,
                        passed=at_ok,
                        decision="enabled" if at_ok else "disabled",
                        status="COMPLIANT" if at_ok else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"mapping_code": "2.0-05"},
                    )
                )

                # 2.0-06: Node-to-Node encryption == True
                evaluations.append(
                    ServiceEvaluation(
                        service="OpenSearch",
                        resource_id=name,
                        evidence_path="DomainStatus.NodeToNodeEncryptionOptions.Enabled",
                        checked_field="Node-to-Node encryption",
                        comparator="eq",
                        expected_value=True,
                        observed_value=n2n,
                        passed=n2_ok,
                        decision="enabled" if n2_ok else "disabled",
                        status="COMPLIANT" if n2_ok else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"mapping_code": "2.0-06"},
                    )
                )

            final_status = (
                "NON_COMPLIANT"
                if (evidence["atRestFail"] or evidence["n2nFail"])
                else "COMPLIANT"
            )

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=final_status,
                evaluations=evaluations,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code,
                    "category": "2 (암호화/KMS/TLS/At-rest)",
                    "service": "OpenSearch",
                    "console_path": "OpenSearch → 도메인 → 보안",
                    "check_how": "At-rest/노드간 암호화",
                    "cli_cmd": (
                        'aws opensearch describe-domain --domain-name NAME '
                        '--query "DomainStatus.(EncryptionAtRestOptions.Enabled,NodeToNodeEncryptionOptions.Enabled)"'
                    ),
                    "return_field": "...Enabled",
                    "compliant_value": "TRUE",
                    "non_compliant_value": "FALSE",
                    "console_fix": "(불가시) 새 도메인 생성 후 마이그레이션",
                    "cli_fix_cmd": "-",
                },
            )

        except botocore.exceptions.ClientError as e:
            # 권한/리전 등으로 조회 불가 시: exists 비교자로 SKIPPED 리턴
            err = str(e)
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[
                    ServiceEvaluation(
                        service="OpenSearch",
                        resource_id=None,
                        evidence_path="DomainStatus.EncryptionAtRestOptions.Enabled",
                        checked_field="At-rest encryption",
                        comparator="exists",
                        expected_value=True,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": err, "mapping_code": "2.0-05"},
                    ),
                    ServiceEvaluation(
                        service="OpenSearch",
                        resource_id=None,
                        evidence_path="DomainStatus.NodeToNodeEncryptionOptions.Enabled",
                        checked_field="Node-to-Node encryption",
                        comparator="exists",
                        expected_value=True,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": err, "mapping_code": "2.0-06"},
                    ),
                ],
                evidence={},
                reason="Missing permissions",
                extract=None,
            )
        except Exception as e:  # 방어적 처리: 예기치 못한 오류로 스트리밍 중단 방지
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[],
                evidence={},
                reason=f"Unexpected error: {e}",
                extract=None,
            )
