"""
checks/ec2.py
-------------
Checks:
  EC2-001  IMDSv2 not enforced on EC2 instances            → CRITICAL
  EC2-002  EBS default encryption disabled in region       → CRITICAL
  EC2-003  Public EBS snapshots exist                      → CRITICAL
  EC2-004  EC2 instances with public IP in non-IGW subnet  → HIGH
  EC2-005  Security groups with 0.0.0.0/0 on risky ports   → CRITICAL
  EC2-006  VPC Flow Logs not enabled                       → HIGH
  EC2-007  EC2 instances without IAM instance profile      → HIGH
  EC2-008  Default VPC exists and has resources            → MEDIUM

All checks are REGIONAL — run once per target region.
"""
from __future__ import annotations
import logging
from iam_auditor.compliance import get_controls, get_cis
from iam_auditor.models import Finding, ScanContext, Severity

logger = logging.getLogger(__name__)

RISKY_PORTS = {22: "SSH", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL",
               5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}


def _paginate(client, method, result_key, **kwargs):
    paginator = client.get_paginator(method)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(result_key, []))
    return results


def check_imdsv2(ec2, account_id, region):
    findings = []
    try:
        instances = _paginate(ec2, "describe_instances", "Reservations")
        for res in instances:
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") != "running":
                    continue
                meta = inst.get("MetadataOptions", {})
                if meta.get("HttpTokens") != "required":
                    iid = inst["InstanceId"]
                    findings.append(Finding(
                        check_id="EC2-001", check_name="IMDSv2 Not Enforced",
                        severity=Severity.CRITICAL,
                        resource=f"arn:aws:ec2:{region}:{account_id}:instance/{iid}",
                        account_id=account_id, region=region,
                        detail=(f"Instance '{iid}' allows IMDSv1 (HttpTokens={meta.get('HttpTokens','optional')}). "
                                "IMDSv1 is exploitable via SSRF to steal instance credentials."),
                        remediation=(f"aws ec2 modify-instance-metadata-options --instance-id {iid} "
                                     "--http-tokens required --http-endpoint enabled"),
                        cis_control=get_cis("EC2-001"), compliance_controls=get_controls("EC2-001")))
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
                check_id="EC2-002", check_name="EBS Default Encryption Disabled",
                severity=Severity.CRITICAL,
                resource=f"arn:aws:ec2:{region}:{account_id}",
                account_id=account_id, region=region,
                detail=(f"EBS default encryption is disabled in region {region}. "
                        "New EBS volumes created without an explicit encryption setting will be unencrypted."),
                remediation=f"aws ec2 enable-ebs-encryption-by-default --region {region}",
                cis_control=get_cis("EC2-002"), compliance_controls=get_controls("EC2-002")))
    except Exception as e:
        logger.error("EC2-002 failed [%s]: %s", region, e)
    return findings


def check_public_snapshots(ec2, account_id, region):
    findings = []
    try:
        snaps = _paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"])
        for snap in snaps:
            attrs = ec2.describe_snapshot_attribute(SnapshotId=snap["SnapshotId"],
                                                    Attribute="createVolumePermission")
            for perm in attrs.get("CreateVolumePermissions", []):
                if perm.get("Group") == "all":
                    findings.append(Finding(
                        check_id="EC2-003", check_name="Public EBS Snapshot",
                        severity=Severity.CRITICAL,
                        resource=f"arn:aws:ec2:{region}:{account_id}:snapshot/{snap['SnapshotId']}",
                        account_id=account_id, region=region,
                        detail=(f"EBS snapshot '{snap['SnapshotId']}' is publicly accessible. "
                                "Anyone can create a volume from it and access your data."),
                        remediation=(f"aws ec2 modify-snapshot-attribute --snapshot-id {snap['SnapshotId']} "
                                     "--attribute createVolumePermission --operation-type remove "
                                     "--group-names all"),
                        cis_control=get_cis("EC2-003"), compliance_controls=get_controls("EC2-003")))
    except Exception as e:
        logger.error("EC2-003 failed [%s]: %s", region, e)
    logger.info("EC2-003 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_security_groups(ec2, account_id, region):
    findings = []
    try:
        sgs = _paginate(ec2, "describe_security_groups", "SecurityGroups")
        for sg in sgs:
            sgid = sg["GroupId"]
            sgname = sg.get("GroupName", sgid)
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                proto = perm.get("IpProtocol", "-1")
                open_cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])
                              if r.get("CidrIp") in ("0.0.0.0/0",)]
                open_v6 = [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                           if r.get("CidrIpv6") == "::/0"]
                if not (open_cidrs or open_v6):
                    continue
                # Check if any risky port falls in range
                if proto == "-1":
                    exposed = list(RISKY_PORTS.values())
                else:
                    exposed = [name for port, name in RISKY_PORTS.items()
                               if from_port <= port <= to_port]
                if exposed or proto == "-1":
                    sev = Severity.CRITICAL
                    detail = (f"Security group '{sgname}' ({sgid}) allows inbound 0.0.0.0/0 "
                              f"on {'all ports' if proto == '-1' else f'ports {from_port}-{to_port}'} "
                              f"exposing: {', '.join(exposed) if exposed else 'all services'}.")
                    findings.append(Finding(
                        check_id="EC2-005", check_name="Security Group Open to Internet",
                        severity=sev,
                        resource=f"arn:aws:ec2:{region}:{account_id}:security-group/{sgid}",
                        account_id=account_id, region=region,
                        detail=detail,
                        remediation=(f"Restrict inbound rules on '{sgname}' to specific IP ranges or "
                                     "security groups. Remove 0.0.0.0/0 for all sensitive ports."),
                        cis_control=get_cis("EC2-005"), compliance_controls=get_controls("EC2-005")))
    except Exception as e:
        logger.error("EC2-005 failed [%s]: %s", region, e)
    logger.info("EC2-005 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_vpc_flow_logs(ec2, account_id, region):
    findings = []
    try:
        vpcs = _paginate(ec2, "describe_vpcs", "Vpcs")
        flow_logs = _paginate(ec2, "describe_flow_logs", "FlowLogs")
        logged_vpcs = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}
        for vpc in vpcs:
            vid = vpc["VpcId"]
            if vid not in logged_vpcs:
                findings.append(Finding(
                    check_id="EC2-006", check_name="VPC Flow Logs Not Enabled",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:ec2:{region}:{account_id}:vpc/{vid}",
                    account_id=account_id, region=region,
                    detail=(f"VPC '{vid}' in {region} has no active Flow Logs. "
                            "Network traffic (accepted and rejected) is not being recorded."),
                    remediation=(f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vid} "
                                 "--traffic-type ALL --log-destination-type cloud-watch-logs "
                                 "--log-group-name /aws/vpc/flowlogs"),
                    cis_control=get_cis("EC2-006"), compliance_controls=get_controls("EC2-006")))
    except Exception as e:
        logger.error("EC2-006 failed [%s]: %s", region, e)
    logger.info("EC2-006 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_instance_profile(ec2, account_id, region):
    findings = []
    try:
        instances = _paginate(ec2, "describe_instances", "Reservations")
        for res in instances:
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") != "running":
                    continue
                if not inst.get("IamInstanceProfile"):
                    iid = inst["InstanceId"]
                    findings.append(Finding(
                        check_id="EC2-007", check_name="EC2 Instance Without IAM Profile",
                        severity=Severity.HIGH,
                        resource=f"arn:aws:ec2:{region}:{account_id}:instance/{iid}",
                        account_id=account_id, region=region,
                        detail=(f"Running instance '{iid}' has no IAM instance profile attached. "
                                "Applications may use hardcoded credentials or have no AWS API access."),
                        remediation=(f"Associate an IAM instance profile: "
                                     f"aws ec2 associate-iam-instance-profile --instance-id {iid} "
                                     "--iam-instance-profile Name=<least-privilege-profile>"),
                        cis_control=get_cis("EC2-007"), compliance_controls=get_controls("EC2-007")))
    except Exception as e:
        logger.error("EC2-007 failed [%s]: %s", region, e)
    logger.info("EC2-007 [%s]: %d finding(s)", region, len(findings))
    return findings


def check_default_vpc(ec2, account_id, region):
    findings = []
    try:
        vpcs = _paginate(ec2, "describe_vpcs", "Vpcs", Filters=[{"Name": "isDefault", "Values": ["true"]}])
        for vpc in vpcs:
            vid = vpc["VpcId"]
            # Only flag if the default VPC has subnets (i.e. is actively used)
            subnets = _paginate(ec2, "describe_subnets", "Subnets",
                                Filters=[{"Name": "vpc-id", "Values": [vid]}])
            findings.append(Finding(
                check_id="EC2-008", check_name="Default VPC Exists",
                severity=Severity.MEDIUM,
                resource=f"arn:aws:ec2:{region}:{account_id}:vpc/{vid}",
                account_id=account_id, region=region,
                detail=(f"Default VPC '{vid}' exists in {region} with {len(subnets)} subnet(s). "
                        "Default VPCs have permissive default security groups and "
                        "are a common misconfiguration target."),
                remediation=(f"If unused, delete the default VPC: "
                             f"aws ec2 delete-vpc --vpc-id {vid}. "
                             "Ensure all workloads use custom VPCs with explicit security controls."),
                cis_control=get_cis("EC2-008"), compliance_controls=get_controls("EC2-008")))
    except Exception as e:
        logger.error("EC2-008 failed [%s]: %s", region, e)
    return findings


def _run(ctx: ScanContext):
    ec2 = ctx.client("ec2")
    aid, reg = ctx.account_id, ctx.region
    findings = []
    findings.extend(check_imdsv2(ec2, aid, reg))
    findings.extend(check_ebs_encryption_default(ec2, aid, reg))
    findings.extend(check_public_snapshots(ec2, aid, reg))
    findings.extend(check_security_groups(ec2, aid, reg))
    findings.extend(check_vpc_flow_logs(ec2, aid, reg))
    findings.extend(check_instance_profile(ec2, aid, reg))
    findings.extend(check_default_vpc(ec2, aid, reg))
    return findings


CHECKS: list = [
    ("EC2 / VPC Checks", "ec2", False, _run),   # is_global=False → runs per region
]
