"""
checks/rds.py
-------------
Checks:
  RDS-001  RDS instance publicly accessible             → CRITICAL
  RDS-002  RDS instance not encrypted at rest           → HIGH
  RDS-003  RDS automated backups disabled               → HIGH
  RDS-004  RDS instance not Multi-AZ                    → HIGH
  RDS-005  RDS snapshot publicly accessible             → CRITICAL
  DDB-001  DynamoDB table PITR not enabled              → HIGH
"""
from __future__ import annotations
import logging
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)


def _get_instances(rds):
    try:
        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
        return instances
    except Exception as e:
        logger.error("describe_db_instances failed: %s", e)
        return []


def check_rds_public_access(rds, account_id, region):
    findings = []
    for db in _get_instances(rds):
        if db.get("PubliclyAccessible"):
            dbid = db["DBInstanceIdentifier"]
            findings.append(Finding(
                check_id="RDS-001", check_name="RDS Instance Publicly Accessible",
                severity=Severity.CRITICAL,
                resource=db.get("DBInstanceArn", dbid),
                account_id=account_id, region=region,
                detail=(f"RDS instance '{dbid}' ({db.get('Engine')}) has PubliclyAccessible=true. "
                        "The instance endpoint is resolvable from the public internet."),
                remediation=(f"Modify the instance to disable public accessibility: "
                             f"aws rds modify-db-instance --db-instance-identifier {dbid} "
                             "--no-publicly-accessible --apply-immediately"),
                cis_control=get_cis("RDS-001"), compliance_controls=get_controls("RDS-001")))
    logger.info("RDS-001 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_rds_encryption(rds, account_id, region):
    findings = []
    for db in _get_instances(rds):
        if not db.get("StorageEncrypted"):
            dbid = db["DBInstanceIdentifier"]
            findings.append(Finding(
                check_id="RDS-002", check_name="RDS Instance Not Encrypted",
                severity=Severity.HIGH,
                resource=db.get("DBInstanceArn", dbid),
                account_id=account_id, region=region,
                detail=f"RDS instance '{dbid}' ({db.get('Engine')}) storage is not encrypted at rest.",
                remediation=("Encryption cannot be enabled on an existing unencrypted instance. "
                             f"Create an encrypted snapshot of '{dbid}', restore to a new encrypted instance, "
                             "then cut over traffic."),
                cis_control=get_cis("RDS-002"), compliance_controls=get_controls("RDS-002")))
    logger.info("RDS-002 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_rds_backups(rds, account_id, region):
    findings = []
    for db in _get_instances(rds):
        if db.get("BackupRetentionPeriod", 0) == 0:
            dbid = db["DBInstanceIdentifier"]
            findings.append(Finding(
                check_id="RDS-003", check_name="RDS Automated Backups Disabled",
                severity=Severity.HIGH,
                resource=db.get("DBInstanceArn", dbid),
                account_id=account_id, region=region,
                detail=f"RDS instance '{dbid}' has automated backups disabled (retention = 0 days).",
                remediation=(f"aws rds modify-db-instance --db-instance-identifier {dbid} "
                             "--backup-retention-period 7 --apply-immediately"),
                cis_control=get_cis("RDS-003"), compliance_controls=get_controls("RDS-003")))
    logger.info("RDS-003 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_rds_multi_az(rds, account_id, region):
    findings = []
    for db in _get_instances(rds):
        # Skip Aurora (handled at cluster level) and read replicas
        if db.get("ReadReplicaSourceDBInstanceIdentifier"):
            continue
        if db.get("Engine", "").startswith("aurora"):
            continue
        if not db.get("MultiAZ"):
            dbid = db["DBInstanceIdentifier"]
            findings.append(Finding(
                check_id="RDS-004", check_name="RDS Instance Not Multi-AZ",
                severity=Severity.HIGH,
                resource=db.get("DBInstanceArn", dbid),
                account_id=account_id, region=region,
                detail=f"RDS instance '{dbid}' ({db.get('Engine')}) is not Multi-AZ. "
                       "A single AZ failure will cause downtime.",
                remediation=(f"aws rds modify-db-instance --db-instance-identifier {dbid} "
                             "--multi-az --apply-immediately"),
                cis_control=get_cis("RDS-004"), compliance_controls=get_controls("RDS-004")))
    logger.info("RDS-004 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_rds_snapshot_public(rds, account_id, region):
    findings = []
    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(OwnerString="self"):
            for snap in page.get("DBSnapshots", []):
                sid = snap["DBSnapshotIdentifier"]
                try:
                    attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
                    for attr in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
                        if attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", []):
                            findings.append(Finding(
                                check_id="RDS-005", check_name="RDS Snapshot Publicly Accessible",
                                severity=Severity.CRITICAL,
                                resource=snap.get("DBSnapshotArn", sid),
                                account_id=account_id, region=region,
                                detail=(f"RDS snapshot '{sid}' is publicly shared. "
                                        "Anyone can restore your database from this snapshot."),
                                remediation=(f"aws rds modify-db-snapshot-attribute "
                                             f"--db-snapshot-identifier {sid} "
                                             "--attribute-name restore --values-to-remove all"),
                                cis_control=get_cis("RDS-005"), compliance_controls=get_controls("RDS-005")))
                except Exception as e:
                    logger.warning("RDS-005 snap %s: %s", sid, e)
    except Exception as e:
        logger.error("RDS-005 failed [%s]: %s", region, e)
    logger.info("RDS-005 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_dynamodb_pitr(dynamodb, account_id, region):
    findings = []
    try:
        paginator = dynamodb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                try:
                    resp = dynamodb.describe_continuous_backups(TableName=table_name)
                    pitr = resp.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {})
                    if pitr.get("PointInTimeRecoveryStatus") != "ENABLED":
                        findings.append(Finding(
                            check_id="DDB-001", check_name="DynamoDB PITR Not Enabled",
                            severity=Severity.HIGH,
                            resource=f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}",
                            account_id=account_id, region=region,
                            detail=f"DynamoDB table '{table_name}' does not have Point-in-Time Recovery enabled. "
                                   "Accidental data loss is unrecoverable beyond manual backup schedules.",
                            remediation=(f"aws dynamodb update-continuous-backups "
                                         f"--table-name {table_name} "
                                         "--point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"),
                            cis_control=get_cis("DDB-001"), compliance_controls=get_controls("DDB-001")))
                except Exception as e:
                    logger.warning("DDB-001 table %s: %s", table_name, e)
    except Exception as e:
        logger.error("DDB-001 failed [%s]: %s", region, e)
    logger.info("DDB-001 [%s]: %d finding(s)", region, len(findings))
    return findings


def _run(ctx: ScanContext):
    rds = ctx.client("rds")
    ddb = ctx.client("dynamodb")
    aid, reg = ctx.account_id, ctx.region
    findings = []
    findings.extend(check_rds_public_access(rds, aid, reg))
    findings.extend(check_rds_encryption(rds, aid, reg))
    findings.extend(check_rds_backups(rds, aid, reg))
    findings.extend(check_rds_multi_az(rds, aid, reg))
    findings.extend(check_rds_snapshot_public(rds, aid, reg))
    findings.extend(check_dynamodb_pitr(ddb, aid, reg))
    return findings


CHECKS: list = [
    ("RDS / DynamoDB Checks", "rds", False, _run),
]
