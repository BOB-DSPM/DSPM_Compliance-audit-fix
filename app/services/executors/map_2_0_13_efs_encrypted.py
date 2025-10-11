from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_13:
    code = "2.0-13"
    title = "EFS"

    def audit(self) -> AuditResult:
        client = boto3.client("efs")
        evals: List[ServiceEvaluation] = []
        ev: Dict[str, Any] = {"fileSystems": 0, "encrypted": 0, "nonEncrypted": []}
        try:
            fss = client.describe_file_systems().get("FileSystems", [])
            ev["fileSystems"] = len(fss)
            for fs in fss:
                fsid = fs["FileSystemId"]
                enc = bool(fs.get("Encrypted"))
                if enc: ev["encrypted"] += 1
                else: ev["nonEncrypted"].append(fsid)

                evals.append(ServiceEvaluation(
                    service="EFS", resource_id=fsid, evidence_path="FileSystems[*].Encrypted",
                    checked_field="Encrypted", comparator="eq", expected_value=True,
                    observed_value=enc, passed=enc, decision=f"observed {enc} == True → {'passed' if enc else 'failed'}",
                    status="COMPLIANT" if enc else "NON_COMPLIANT", source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if ev["nonEncrypted"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=final,
                evaluations=evals, evidence=ev, reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)", "service":"EFS",
                    "console_path":"EFS → 파일시스템 → 일반","check_how":"생성 시 암호화 여부",
                    "cli_cmd":"aws efs describe-file-systems --query \"FileSystems[*].Encrypted\"",
                    "return_field":"Encrypted","compliant_value":"TRUE","non_compliant_value":"FALSE",
                    "console_fix":"(불가시) 새 FS 생성 후 데이터 마이그레이션","cli_fix_cmd":"-"
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="EFS", resource_id=None, evidence_path="FileSystems.Encrypted",
                    checked_field="Encrypted", comparator="eq", expected_value=True,
                    observed_value=None, passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
