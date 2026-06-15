"""
checks/rds.py
-------------
Checks:
  RDS-001  RDS instance publicly accessible             -> CRITICAL (CIS 2.3.2)
  RDS-002  RDS not encrypted at rest                    -> HIGH     (CIS 2.3.1)
  RDS-003  RDS automated backups disabled               -> HIGH
  RDS-004  RDS not Multi-AZ                             -> HIGH
  RDS-005  RDS snapshot publicly accessible             -> CRITICAL
  DDB-001  DynamoDB PITR not enabled                    -> HIGH
"""

from __future__ import annotations

import logging

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)


def _get_instances(rds):
    try:
        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
        return instances
    except Exception as e:
        logger.error("RDS: describe_db_instances failed: %s", e)
        return []


def run(session: boto3.Session) -> list[Finding]:
    region   = session.region_name or "us-east-1"
    rds      = session.client("rds", region_name=region)
    ddb      = session.client("dynamodb", region_name=region)
    aid      = session.client("sts").get_caller_identity()["Account"]
    findings = []

    # RDS-001: public access
    for db in _get_instances(rds):
        dbid = db["DBInstanceIdentifier"]
        if db.get("PubliclyAccessible"):
            findings.append(Finding(
                check_id="RDS-001",
                check_name="RDS Instance Publicly Accessible",
                severity=Severity.CRITICAL,
                resource=db.get("DBInstanceArn", dbid),
                account_id=aid, region=region,
                detail=f"RDS instance '{dbid}' ({db.get('Engine')}) has PubliclyAccessible=true.",
                remediation=(
                    f"aws rds modify-db-instance --db-instance-identifier {dbid} "
                    "--no-publicly-accessible --apply-immediately"
                ),
                cis_control=get_cis("RDS-001"),
                compliance_controls=get_controls("RDS-001"),
            ))

        # RDS-002: encryption
        if not db.get("StorageEncrypted"):
            findings.append(Finding(
                check_id="RDS-002",
                check_name="RDS Instance Not Encrypted",
                severity=Severity.HIGH,
                resource=db.get("DBInstanceArn", dbid),
                account_id=aid, region=region,
                detail=f"RDS instance '{dbid}' storage is not encrypted at rest.",
                remediation="Create an encrypted snapshot and restore to a new encrypted instance.",
                cis_control=get_cis("RDS-002"),
                compliance_controls=get_controls("RDS-002"),
            ))

        # RDS-003: backups
        if db.get("BackupRetentionPeriod", 0) == 0:
            findings.append(Finding(
                check_id="RDS-003",
                check_name="RDS Automated Backups Disabled",
                severity=Severity.HIGH,
                resource=db.get("DBInstanceArn", dbid),
                account_id=aid, region=region,
                detail=f"RDS instance '{dbid}' has automated backups disabled.",
                remediation=(
                    f"aws rds modify-db-instance --db-instance-identifier {dbid} "
                    "--backup-retention-period 7 --apply-immediately"
                ),
                cis_control=get_cis("RDS-003"),
                compliance_controls=get_controls("RDS-003"),
            ))

        # RDS-004: multi-AZ
        if (not db.get("ReadReplicaSourceDBInstanceIdentifier")
                and not db.get("Engine", "").startswith("aurora")
                and not db.get("MultiAZ")):
            findings.append(Finding(
                check_id="RDS-004",
                check_name="RDS Instance Not Multi-AZ",
                severity=Severity.HIGH,
                resource=db.get("DBInstanceArn", dbid),
                account_id=aid, region=region,
                detail=f"RDS instance '{dbid}' is not Multi-AZ.",
                remediation=(
                    f"aws rds modify-db-instance --db-instance-identifier {dbid} "
                    "--multi-az --apply-immediately"
                ),
                cis_control=get_cis("RDS-004"),
                compliance_controls=get_controls("RDS-004"),
            ))

    # RDS-005: public snapshots
    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            for snap in page.get("DBSnapshots", []):
                sid = snap["DBSnapshotIdentifier"]
                try:
                    attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
                    for attr in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
                        if attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", []):
                            findings.append(Finding(
                                check_id="RDS-005",
                                check_name="RDS Snapshot Publicly Accessible",
                                severity=Severity.CRITICAL,
                                resource=snap.get("DBSnapshotArn", sid),
                                account_id=aid, region=region,
                                detail=f"RDS snapshot '{sid}' is publicly shared.",
                                remediation=(
                                    f"aws rds modify-db-snapshot-attribute "
                                    f"--db-snapshot-identifier {sid} "
                                    "--attribute-name restore --values-to-remove all"
                                ),
                                cis_control=get_cis("RDS-005"),
                                compliance_controls=get_controls("RDS-005"),
                            ))
                except Exception as e:
                    logger.warning("RDS-005 snap %s: %s", sid, e)
    except Exception as e:
        logger.error("RDS-005 failed [%s]: %s", region, e)

    # DDB-001: DynamoDB PITR
    try:
        paginator = ddb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                try:
                    resp = ddb.describe_continuous_backups(TableName=table_name)
                    pitr = (resp.get("ContinuousBackupsDescription", {})
                               .get("PointInTimeRecoveryDescription", {}))
                    if pitr.get("PointInTimeRecoveryStatus") != "ENABLED":
                        findings.append(Finding(
                            check_id="DDB-001",
                            check_name="DynamoDB PITR Not Enabled",
                            severity=Severity.HIGH,
                            resource=f"arn:aws:dynamodb:{region}:{aid}:table/{table_name}",
                            account_id=aid, region=region,
                            detail=f"DynamoDB table '{table_name}' does not have PITR enabled.",
                            remediation=(
                                f"aws dynamodb update-continuous-backups "
                                f"--table-name {table_name} "
                                "--point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"
                            ),
                            cis_control=get_cis("DDB-001"),
                            compliance_controls=get_controls("DDB-001"),
                        ))
                except Exception as e:
                    logger.warning("DDB-001 table %s: %s", table_name, e)
    except Exception as e:
        logger.error("DDB-001 failed [%s]: %s", region, e)

    logger.info("RDS/DDB [%s]: %d finding(s)", region, len(findings))
    return findings
