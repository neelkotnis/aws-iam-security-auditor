"""
checks/ec2.py
-------------
Checks:
  EC2-001  IMDSv2 not enforced on instances             -> CRITICAL (CIS 5.6)
  EC2-002  EBS default encryption disabled              -> CRITICAL (CIS 2.2.1)
  EC2-003  Public EBS snapshots                         -> CRITICAL (CIS 2.2.2)
  EC2-005  Security group open to internet on risky ports -> CRITICAL (CIS 5.2)
  EC2-006  VPC Flow Logs not enabled                    -> HIGH     (CIS 3.9)
  EC2-007  EC2 instance without IAM instance profile    -> HIGH
  EC2-008  Default VPC exists                           -> MEDIUM   (CIS 5.4)
"""

from __future__ import annotations

import logging

import boto3

from iam_auditor.compliance import get_cis, get_controls
from iam_auditor.models import Finding, Severity

logger = logging.getLogger(__name__)

RISKY_PORTS = {22: "SSH", 3389: "RDP", 1433: "MSSQL",
               3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}


def _paginate(client, method, result_key, **kwargs):
    paginator = client.get_paginator(method)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(result_key, []))
    return results


def check_imdsv2(ec2, account_id, region):
    findings = []
    try:
        reservations = _paginate(ec2, "describe_instances", "Reservations")
        for res in reservations:
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") != "running":
                    continue
                meta = inst.get("MetadataOptions", {})
                if meta.get("HttpTokens") != "required":
                    iid = inst["InstanceId"]
                    findings.append(Finding(
                        check_id="EC2-001",
                        check_name="IMDSv2 Not Enforced",
                        severity=Severity.CRITICAL,
                        resource=f"arn:aws:ec2:{region}:{account_id}:instance/{iid}",
                        account_id=account_id,
                        region=region,
                        detail=(
                            f"Instance '{iid}' allows IMDSv1 "
                            f"(HttpTokens={meta.get('HttpTokens', 'optional')}). "
                            "IMDSv1 is exploitable via SSRF to steal instance credentials."
                        ),
                        remediation=(
                            f"aws ec2 modify-instance-metadata-options --instance-id {iid} "
                            "--http-tokens required --http-endpoint enabled"
                        ),
                        cis_control=get_cis("EC2-001"),
                        compliance_controls=get_controls("EC2-001"),
                    ))
    except Exception as e:
        logger.error("EC2-001 failed [%s]: %s", region, e)
    logger.info("EC2-001 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_ebs_encryption_default(ec2, account_id, region):
    findings = []
    try:
        resp = ec2.get_ebs_encryption_by_default()
        if not resp.get("EbsEncryptionByDefault", False):
            findings.append(Finding(
                check_id="EC2-002",
                check_name="EBS Default Encryption Disabled",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:ec2:{region}:{account_id}",
                account_id=account_id,
                region=region,
                detail=f"EBS default encryption is disabled in {region}. New volumes will be unencrypted.",
                remediation=f"aws ec2 enable-ebs-encryption-by-default --region {region}",
                cis_control=get_cis("EC2-002"),
                compliance_controls=get_controls("EC2-002"),
            ))
    except Exception as e:
        logger.error("EC2-002 failed [%s]: %s", region, e)
    return findings


def check_public_snapshots(ec2, account_id, region):
    findings = []
    try:
        snaps = _paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"])
        for snap in snaps:
            sid = snap["SnapshotId"]
            try:
                attrs = ec2.describe_snapshot_attribute(
                    SnapshotId=sid, Attribute="createVolumePermission"
                )
                for perm in attrs.get("CreateVolumePermissions", []):
                    if perm.get("Group") == "all":
                        findings.append(Finding(
                            check_id="EC2-003",
                            check_name="Public EBS Snapshot",
                            severity=Severity.CRITICAL,
                            resource=f"arn:aws:ec2:{region}:{account_id}:snapshot/{sid}",
                            account_id=account_id,
                            region=region,
                            detail=f"EBS snapshot '{sid}' is publicly accessible — anyone can restore it.",
                            remediation=(
                                f"aws ec2 modify-snapshot-attribute --snapshot-id {sid} "
                                "--attribute createVolumePermission "
                                "--operation-type remove --group-names all"
                            ),
                            cis_control=get_cis("EC2-003"),
                            compliance_controls=get_controls("EC2-003"),
                        ))
            except Exception as e:
                logger.warning("EC2-003 snap %s: %s", sid, e)
    except Exception as e:
        logger.error("EC2-003 failed [%s]: %s", region, e)
    logger.info("EC2-003 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_security_groups(ec2, account_id, region):
    findings = []
    try:
        sgs = _paginate(ec2, "describe_security_groups", "SecurityGroups")
        for sg in sgs:
            sgid   = sg["GroupId"]
            sgname = sg.get("GroupName", sgid)
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port   = perm.get("ToPort", 65535)
                proto     = perm.get("IpProtocol", "-1")
                open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if not (open_v4 or open_v6):
                    continue
                if proto == "-1":
                    exposed = list(RISKY_PORTS.values())
                else:
                    exposed = [name for port, name in RISKY_PORTS.items()
                               if from_port <= port <= to_port]
                if exposed or proto == "-1":
                    findings.append(Finding(
                        check_id="EC2-005",
                        check_name="Security Group Open to Internet",
                        severity=Severity.CRITICAL,
                        resource=f"arn:aws:ec2:{region}:{account_id}:security-group/{sgid}",
                        account_id=account_id,
                        region=region,
                        detail=(
                            f"Security group '{sgname}' ({sgid}) allows inbound 0.0.0.0/0 "
                            f"on {'all ports' if proto == '-1' else f'ports {from_port}-{to_port}'} "
                            f"exposing: {', '.join(exposed) if exposed else 'all services'}."
                        ),
                        remediation=(
                            f"Restrict inbound rules on '{sgname}' to specific IP ranges. "
                            "Remove 0.0.0.0/0 for all sensitive ports."
                        ),
                        cis_control=get_cis("EC2-005"),
                        compliance_controls=get_controls("EC2-005"),
                    ))
    except Exception as e:
        logger.error("EC2-005 failed [%s]: %s", region, e)
    logger.info("EC2-005 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_vpc_flow_logs(ec2, account_id, region):
    findings = []
    try:
        vpcs      = _paginate(ec2, "describe_vpcs", "Vpcs")
        flow_logs = _paginate(ec2, "describe_flow_logs", "FlowLogs")
        logged    = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}
        for vpc in vpcs:
            vid = vpc["VpcId"]
            if vid not in logged:
                findings.append(Finding(
                    check_id="EC2-006",
                    check_name="VPC Flow Logs Not Enabled",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:ec2:{region}:{account_id}:vpc/{vid}",
                    account_id=account_id,
                    region=region,
                    detail=f"VPC '{vid}' in {region} has no active Flow Logs.",
                    remediation=(
                        f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vid} "
                        "--traffic-type ALL --log-destination-type cloud-watch-logs "
                        "--log-group-name /aws/vpc/flowlogs"
                    ),
                    cis_control=get_cis("EC2-006"),
                    compliance_controls=get_controls("EC2-006"),
                ))
    except Exception as e:
        logger.error("EC2-006 failed [%s]: %s", region, e)
    logger.info("EC2-006 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_instance_profile(ec2, account_id, region):
    findings = []
    try:
        reservations = _paginate(ec2, "describe_instances", "Reservations")
        for res in reservations:
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") != "running":
                    continue
                if not inst.get("IamInstanceProfile"):
                    iid = inst["InstanceId"]
                    findings.append(Finding(
                        check_id="EC2-007",
                        check_name="EC2 Instance Without IAM Profile",
                        severity=Severity.HIGH,
                        resource=f"arn:aws:ec2:{region}:{account_id}:instance/{iid}",
                        account_id=account_id,
                        region=region,
                        detail=f"Running instance '{iid}' has no IAM instance profile attached.",
                        remediation=(
                            f"aws ec2 associate-iam-instance-profile --instance-id {iid} "
                            "--iam-instance-profile Name=<least-privilege-profile>"
                        ),
                        cis_control=get_cis("EC2-007"),
                        compliance_controls=get_controls("EC2-007"),
                    ))
    except Exception as e:
        logger.error("EC2-007 failed [%s]: %s", region, e)
    logger.info("EC2-007 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_default_vpc(ec2, account_id, region):
    findings = []
    try:
        vpcs = _paginate(ec2, "describe_vpcs", "Vpcs",
                         Filters=[{"Name": "isDefault", "Values": ["true"]}])
        for vpc in vpcs:
            vid = vpc["VpcId"]
            findings.append(Finding(
                check_id="EC2-008",
                check_name="Default VPC Exists",
                severity=Severity.MEDIUM,
                resource=f"arn:aws:ec2:{region}:{account_id}:vpc/{vid}",
                account_id=account_id,
                region=region,
                detail=f"Default VPC '{vid}' exists in {region}. Default VPCs have permissive security groups.",
                remediation=(
                    f"If unused, delete: aws ec2 delete-vpc --vpc-id {vid}. "
                    "Ensure all workloads use custom VPCs."
                ),
                cis_control=get_cis("EC2-008"),
                compliance_controls=get_controls("EC2-008"),
            ))
    except Exception as e:
        logger.error("EC2-008 failed [%s]: %s", region, e)
    return findings


def run(session: boto3.Session) -> list[Finding]:
    region = session.region_name or "us-east-1"
    ec2    = session.client("ec2", region_name=region)
    aid    = session.client("sts").get_caller_identity()["Account"]
    findings = []
    findings.extend(check_imdsv2(ec2, aid, region))
    findings.extend(check_ebs_encryption_default(ec2, aid, region))
    findings.extend(check_public_snapshots(ec2, aid, region))
    findings.extend(check_security_groups(ec2, aid, region))
    findings.extend(check_vpc_flow_logs(ec2, aid, region))
    findings.extend(check_instance_profile(ec2, aid, region))
    findings.extend(check_default_vpc(ec2, aid, region))
    return findings
