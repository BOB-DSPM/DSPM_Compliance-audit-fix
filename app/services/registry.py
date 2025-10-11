from typing import Dict, Type, Optional, Protocol
from app.models.schemas import AuditResult

# ── 기존 executors ──────────────────────────────────────────────────────────
from app.services.executors.map_1_0_01_sso_permission_sets import Exec_1_0_01
from app.services.executors.map_1_0_02_org_scp import Exec_1_0_02
from app.services.executors.map_1_0_06_root_mfa import Exec_1_0_06
from app.services.executors.map_11_0_02_config_conformance_pack import Exec_11_0_02
from app.services.executors.map_2_0_01_s3_sse_kms import Exec_2_0_01
from app.services.executors.map_2_0_15_cloudfront_https import Exec_2_0_15

# ── 새로 추가한 executors ───────────────────────────────────────────────────
from app.services.executors.map_2_0_02_rds_encryption import Exec_2_0_02
from app.services.executors.map_2_0_03_dynamodb_sse import Exec_2_0_03
from app.services.executors.map_2_0_04_redshift_encryption import Exec_2_0_04
from app.services.executors.map_2_0_05_06_opensearch import Exec_2_0_05_06
from app.services.executors.map_2_0_09_alb_tls import Exec_2_0_09
from app.services.executors.map_2_0_10_kinesis_kms import Exec_2_0_10
from app.services.executors.map_2_0_11_sqs_kms import Exec_2_0_11
from app.services.executors.map_2_0_12_sns_kms import Exec_2_0_12
from app.services.executors.map_2_0_13_efs_encrypted import Exec_2_0_13
from app.services.executors.map_2_0_14_msk_encryption import Exec_2_0_14
from app.services.executors.map_2_0_16_kms_rotation import Exec_2_0_16
from app.services.executors.map_3_0_01_cloudtrail_basics import Exec_3_0_01
from app.services.executors.map_3_0_04_cwlogs_retention import Exec_3_0_04
from app.services.executors.map_3_0_11_cloudtrail_lake_insights import Exec_3_0_11
from app.services.executors.map_7_0_02_guardduty import Exec_7_0_02
from app.services.executors.map_7_0_04_detective_graph import Exec_7_0_04
from app.services.executors.map_11_0_03_s3_event_masking import Exec_11_0_03
from app.services.executors.map_3_0_07_elbv2_access_logs import Exec_3_0_07
from app.services.executors.map_3_0_08_cloudfront_logs import Exec_3_0_08
from app.services.executors.map_4_0_01_s3_lifecycle import Exec_4_0_01
from app.services.executors.map_4_0_03_dynamodb_ttl import Exec_4_0_03
from app.services.executors.map_4_0_04_backup_vault_lock import Exec_4_0_04
from app.services.executors.map_4_0_02_s3_object_lock import Exec_4_0_02
from app.services.executors.map_10_0_04_kms_rotation import Exec_10_0_04
from app.services.executors.map_12_0_05_cloudfront_oac import Exec_12_0_05
from app.services.executors.map_8_0_03_wafv2_web_acl import Exec_8_0_03
from app.services.executors.map_5_0_05_lakeformation_lftags import Exec_5_0_05
from app.services.executors.map_5_0_06_glue_catalog_schema import Exec_5_0_06
from app.services.executors.map_3_0_10_s3_log_bucket_versioning import Exec_3_0_10
from app.services.executors.map_16_0_01_codecommit_branch_protection import Exec_16_0_01
from app.services.executors.map_16_0_02_codepipeline_manual_approval import Exec_16_0_02
from app.services.executors.map_16_0_05_codedeploy_blue_green import Exec_16_0_05
from app.services.executors.map_11_0_01_org_ou_separation import Exec_11_0_01
from app.services.executors.map_13_0_02_lf_tag_separation import Exec_13_0_02
from app.services.executors.map_7_0_01_security_hub import Exec_7_0_01
from app.services.executors.map_1_0_03_iam_credential_report import Exec_1_0_03
from app.services.executors.map_3_0_02_ct_data_events import Exec_3_0_02


class Auditable(Protocol):
    code: str
    def audit(self) -> AuditResult: ...


EXECUTOR_REGISTRY: Dict[str, Type[Auditable]] = {

    "1.0-01": Exec_1_0_01,
    "1.0-02": Exec_1_0_02,
    "1.0-03": Exec_1_0_03,
    "1.0-06": Exec_1_0_06,

    "2.0-01": Exec_2_0_01,
    "2.0-02": Exec_2_0_02,      
    "2.0-03": Exec_2_0_03,     
    "2.0-04": Exec_2_0_04,       
    "2.0-05": Exec_2_0_05_06,    
    "2.0-06": Exec_2_0_05_06,  
    "2.0-09": Exec_2_0_09,      
    "2.0-10": Exec_2_0_10,     
    "2.0-11": Exec_2_0_11,       
    "2.0-12": Exec_2_0_12,     
    "2.0-13": Exec_2_0_13,       
    "2.0-14": Exec_2_0_14,      
    "2.0-15": Exec_2_0_15,
    "2.0-16": Exec_2_0_16,       

    "3.0-01": Exec_3_0_01,
    "3.0-02": Exec_3_0_02,
    "3.0-04": Exec_3_0_04,
    "3.0-07": Exec_3_0_07,
    "3.0-08": Exec_3_0_08,
    "3.0-10": Exec_3_0_10,
    "3.0-11": Exec_3_0_11,

    "4.0-01": Exec_4_0_01,
    "4.0-02": Exec_4_0_02,
    "4.0-03": Exec_4_0_03,
    "4.0-04": Exec_4_0_04,

    "5.0-05": Exec_5_0_05,
    "5.0-06": Exec_5_0_06,

    "7.0-01": Exec_7_0_01,
    "7.0-02": Exec_7_0_02,
    "7.0-04": Exec_7_0_04,

    "8.0-03":  Exec_8_0_03,

    "10.0-04": Exec_10_0_04,

    "11.0-01": Exec_11_0_01,
    "11.0-02": Exec_11_0_02,
    "11.0-03": Exec_11_0_03,

    "12.0-05": Exec_12_0_05,

    "13.0-02": Exec_13_0_02,

    "16.0-01": Exec_16_0_01,
    "16.0-02": Exec_16_0_02,
    "16.0-05": Exec_16_0_05,
}

def make_executor(mapping_code: str) -> Optional[Auditable]:
    cls = EXECUTOR_REGISTRY.get(mapping_code)
    return cls() if cls else None
