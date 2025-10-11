# app/services/executors/map_5_0_06_glue_catalog_schema.py
from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_5_0_06:
    code = "5.0-06"
    title = "Glue 카탈로그 스키마 정합성"

    def audit(self) -> AuditResult:
        glue = boto3.client("glue")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "databases": 0,
            "tablesChecked": 0,
            "tablesWithMissingSchema": [],
            "sampleChecked": []
        }

        try:
            # 1) DB 나열
            db_names: List[str] = []
            next_token = None
            while True:
                params = {}
                if next_token:
                    params["NextToken"] = next_token
                r = glue.get_databases(**params)
                for db in r.get("DatabaseList", []) or []:
                    name = db.get("Name")
                    if name:
                        db_names.append(name)
                next_token = r.get("NextToken")
                if not next_token:
                    break
            evidence["databases"] = len(db_names)

            # 2) 각 DB의 테이블들 점검(필요시 제한)
            def list_tables(db: str) -> List[str]:
                names = []
                nt = None
                while True:
                    p = {"DatabaseName": db}
                    if nt:
                        p["NextToken"] = nt
                    resp = glue.get_tables(**p)
                    for t in resp.get("TableList", []) or []:
                        if t.get("Name"):
                            names.append(t["Name"])
                    nt = resp.get("NextToken")
                    if not nt:
                        break
                return names

            non_compliant = []
            sample = []

            for db in db_names:
                tables = list_tables(db)
                for t in tables:
                    try:
                        tr = glue.get_table(DatabaseName=db, Name=t)
                        tbl = tr.get("Table", {})
                        sd = (tbl.get("StorageDescriptor") or {})
                        cols = sd.get("Columns") or []
                        ok = True if cols else False
                        # 간단한 필드 유효성(name/type 존재) 체크
                        if ok:
                            for c in cols:
                                if not c.get("Name") or not c.get("Type"):
                                    ok = False
                                    break

                        evidence["tablesChecked"] += 1
                        if len(sample) < 5:
                            sample.append({"db": db, "table": t, "columns": len(cols)})

                        evals.append(ServiceEvaluation(
                            service="Glue",
                            resource_id=f"{db}/{t}",
                            evidence_path="Table.StorageDescriptor.Columns",
                            checked_field="columns defined",
                            comparator="eq",
                            expected_value=True,
                            observed_value=ok,
                            passed=ok,
                            decision=f"{'columns present & valid' if ok else 'missing/invalid columns'}",
                            status="COMPLIANT" if ok else "NON_COMPLIANT",
                            source="aws-sdk",
                            extra={}
                        ))

                        if not ok:
                            non_compliant.append(f"{db}/{t}")

                    except botocore.exceptions.ClientError as e:
                        evals.append(ServiceEvaluation(
                            service="Glue",
                            resource_id=f"{db}/{t}",
                            evidence_path="get_table",
                            checked_field="read table",
                            comparator="exists",
                            expected_value=True,
                            observed_value=None,
                            passed=None,
                            decision="cannot read table",
                            status="SKIPPED",
                            source="aws-sdk",
                            extra={"error": str(e)}
                        ))

            evidence["tablesWithMissingSchema"] = non_compliant
            evidence["sampleChecked"] = sample

            overall_ok = len(non_compliant) == 0 and evidence["tablesChecked"] > 0
            status = "COMPLIANT" if overall_ok else "NON_COMPLIANT"

            # 집계 평가 한 줄
            evals.append(ServiceEvaluation(
                service="Glue",
                resource_id="account/region",
                evidence_path="All Databases/Tables",
                checked_field="all tables have columns",
                comparator="eq",
                expected_value=True,
                observed_value=overall_ok,
                passed=overall_ok,
                decision="all checked tables have valid schema" if overall_ok
                         else "tables with missing/invalid schema exist",
                status="COMPLIANT" if overall_ok else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"nonCompliantCount": len(non_compliant)}
            ))

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if overall_ok else "Tables with missing/invalid schema exist",
                extract={
                    "code": self.code,
                    "category": "5 (데이터 품질/출처/라인리지)",
                    "service": "Glue",
                    "console_path": "Glue → Databases/Tables",
                    "check_how": "get-table(...).Table.StorageDescriptor.Columns",
                    "cli_cmd": "aws glue get-table --database-name DB --name TBL",
                    "return_field": "Table.StorageDescriptor.Columns",
                    "compliant_value": "정의 일치(컬럼/타입 존재)",
                    "non_compliant_value": "불일치/누락",
                    "console_fix": "테이블 스키마 정정 또는 크롤러 재실행",
                    "cli_fix_cmd": "aws glue update-table --database-name DB --table-input file://table.json"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Glue",
                    resource_id=None,
                    evidence_path="Global",
                    checked_field="prerequisites",
                    comparator="exists",
                    expected_value=True,
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
