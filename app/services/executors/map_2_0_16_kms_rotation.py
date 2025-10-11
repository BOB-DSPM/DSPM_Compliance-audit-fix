from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_16:
    code = "2.0-16"
    title = "KMS Key Rotation"

    def audit(self) -> AuditResult:
        client = boto3.client("kms")
        evals: List[ServiceEvaluation] = []
        ev: Dict[str, Any] = {"keys": 0, "rotationEnabled": 0, "disabled": []}
        try:
            keys = []
            paginator = client.get_paginator("list_keys")
            for page in paginator.paginate():
                keys.extend([k["KeyId"] for k in page.get("Keys", [])])
            ev["keys"] = len(keys)

            for kid in keys:
                rot = client.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False)
                ok = (rot is True)
                if ok: ev["rotationEnabled"] += 1
                else: ev["disabled"].append(kid)

                evals.append(ServiceEvaluation(
                    service="KMS", resource_id=kid, evidence_path="KeyRotationEnabled",
                    checked_field="KeyRotationEnabled", comparator="eq", expected_value=True,
                    observed_value=rot, passed=ok, decision=f"observed {rot} == True → {'passed' if ok else 'failed'}",
                    status="COMPLIANT" if ok else "NON_COMPLIANT", source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if ev["disabled"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=final,
                evaluations=evals, evidence=ev, reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)", "service":"KMS",
                    "console_path":"KMS → 키 → 구성","check_how":"키 회전",
                    "cli_cmd":"aws kms get-key-rotation-status --key-id KEY_ID",
                    "return_field":"KeyRotationEnabled","compliant_value":"TRUE","non_compliant_value":"FALSE",
                    "console_fix":"KMS → Key → Rotation 활성화",
                    "cli_fix_cmd":"aws kms enable-key-rotation --key-id KEY_ID"
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="KMS", resource_id=None, evidence_path="KeyRotationEnabled",
                    checked_field="Rotation", comparator="eq", expected_value=True,
                    observed_value=None, passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
