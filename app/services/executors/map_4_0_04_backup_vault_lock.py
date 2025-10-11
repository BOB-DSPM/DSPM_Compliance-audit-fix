from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_4_0_04:
    code = "4.0-04"
    title = "AWS Backup Vault Lock configured"

    def audit(self) -> AuditResult:
        backup = boto3.client("backup")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"checkedVaults": 0, "nonCompliant": []}

        try:
            paginator = backup.get_paginator("list_backup_vaults")
            vaults = []
            for page in paginator.paginate():
                vaults.extend(page.get("BackupVaultList", []))
            evidence["checkedVaults"] = len(vaults)

            if not vaults:
                return AuditResult(
                    mapping_code=self.code,
                    title=self.title,
                    status="SKIPPED",
                    evaluations=[ServiceEvaluation(
                        service="AWS Backup",
                        resource_id=None,
                        evidence_path="BackupVaultList",
                        checked_field="VaultLock",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="no backup vaults → cannot evaluate",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={}
                    )],
                    evidence=evidence,
                    reason="No backup vaults",
                    extract=_extract_meta(),
                )

            for v in vaults:
                name = v.get("BackupVaultName")
                lock_enabled = False
                observed = "UNKNOWN"
                try:
                    # Prefer explicit lock configuration API
                    conf = backup.get_backup_vault_lock_configuration(BackupVaultName=name)
                    # if MinRetentionDays or MaxRetentionDays or ChangeableForDays present → lock configured
                    lock_enabled = any(k in conf for k in ("MinRetentionDays", "MaxRetentionDays", "ChangeableForDays"))
                    observed = "ENABLED" if lock_enabled else "DISABLED"
                except botocore.exceptions.ClientError as ie:
                    # If API not permitted or not configured, treat as disabled unless access error indicates perms issue
                    if ie.response.get("Error", {}).get("Code") in ("ResourceNotFoundException", "InvalidRequestException"):
                        lock_enabled = False
                        observed = "DISABLED"
                    else:
                        evals.append(ServiceEvaluation(
                            service="AWS Backup",
                            resource_id=name,
                            evidence_path="GetBackupVaultLockConfiguration",
                            checked_field="VaultLock",
                            comparator=None,
                            expected_value=None,
                            observed_value=None,
                            passed=None,
                            decision="cannot evaluate: error",
                            status="SKIPPED",
                            source="aws-sdk",
                            extra={"error": str(ie)}
                        ))
                        continue

                if not lock_enabled:
                    evidence["nonCompliant"].append(name)

                evals.append(ServiceEvaluation(
                    service="AWS Backup",
                    resource_id=name,
                    evidence_path="BackupVaultLockConfiguration",
                    checked_field="VaultLock",
                    comparator="eq",
                    expected_value="ENABLED",
                    observed_value=observed,
                    passed=(observed == "ENABLED"),
                    decision=f"observed {observed} == ENABLED → {'passed' if observed == 'ENABLED' else 'failed'}",
                    status="COMPLIANT" if observed == "ENABLED" else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))

            overall = "COMPLIANT" if not evidence["nonCompliant"] else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=overall,
                evaluations=evals,
                evidence=evidence,
                reason=None if overall == "COMPLIANT" else "Vaults without Vault Lock configured exist",
                extract=_extract_meta(),
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="AWS Backup",
                    resource_id=None,
                    evidence_path="ListBackupVaults",
                    checked_field="VaultLock",
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
                extract=_extract_meta(),
            )

def _extract_meta() -> Dict[str, Any]:
    return {
        "code": "4.0-04",
        "category": "4 (데이터 보존/파기/재식별)",
        "service": "AWS Backup",
        "console_path": "AWS Backup → Vaults",
        "check_how": "Vault Lock 구성 여부 (Min/Max retention 등)",
        "cli_cmd": "aws backup list-backup-vaults",
        "return_field": "Locked/Lock configuration",
        "compliant_value": "TRUE/ENABLED",
        "non_compliant_value": "FALSE/DISABLED",
        "console_fix": "해당 Backup Vault에 Vault Lock 구성 적용",
        "cli_fix_cmd": "aws backup put-backup-vault-lock-configuration --backup-vault-name VAULT --min-retention-days 30"
    }
