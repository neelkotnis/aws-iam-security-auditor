# AWS IAM Security Auditor

A production-grade CLI tool that scans AWS accounts for security misconfigurations across IAM, S3, EC2, CloudTrail, KMS, GuardDuty, RDS, Secrets Manager, ECR, and more — across one region or every enabled region in the account. Every finding is mapped to CIS, NIST SP 800-53, SOC 2, and ISO 27001 controls.

```
┌─────────────────────────────────────────────┐
│          AWS IAM Security Audit             │
│  Account:   123456789012                    │
│  Run at:    2024-06-01T10:00:00Z            │
│  Findings:  24 total                        │
│  Duration:  18.4s                           │
└─────────────────────────────────────────────┘
```

## What It Checks

**IAM** — MFA on all users, root account security, password policy, access key rotation and usage, inactive users, stale roles, permission boundaries, cross-account trust without ExternalId, IAM Access Analyzer, session duration limits

**CloudTrail** — Multi-region trail coverage, log file validation, S3 bucket public exposure, S3 and Lambda data events, KMS encryption on logs, log retention policy

**S3** — Account and bucket-level public access block, bucket policies, ACLs, server-side encryption, object ownership enforcement, versioning, access logging

**EC2 / VPC** — IMDSv2 enforcement, EBS default encryption, public snapshots, security groups open to the internet, VPC flow logs, instance profiles, default VPC

**KMS** — CMK rotation, overly permissive key policies, keys pending deletion, grants to external principals

**GuardDuty** — Enabled per region, unresolved HIGH and CRITICAL findings

**Security Hub** — Enabled with active security standards

**RDS / DynamoDB** — Public access, encryption at rest, automated backups, Multi-AZ, public snapshots, DynamoDB PITR

**Secrets Manager** — Rotation enabled, unused secrets

**ECR** — Repository public access, scan-on-push enabled, unresolved CVEs on latest image

**CloudWatch Alarms** — CIS baseline alarms for root account usage, unauthorized API calls, console sign-in without MFA, and IAM policy changes

63 checks total across 15 modules, mapped to CIS AWS Foundations Benchmark v3.0, NIST SP 800-53 Rev 5, SOC 2 TSC, and ISO/IEC 27001:2022.

IAM, CloudTrail, and S3 checks are account-wide and run once per scan. EC2, KMS, GuardDuty, Security Hub, RDS, Secrets Manager, ECR, and CloudWatch Alarms are regional and run once per region in scope — see Multi-Region Scanning below.

## Multi-Region Scanning

Regional checks only see resources in the region(s) you tell them to scan. By default, that's a single region resolved from your AWS config.

```bash
# Default - scans only your configured/default region
iam-auditor

# Scan specific regions
iam-auditor --regions us-east-1,eu-west-1,ap-south-1

# Auto-discover and scan every enabled region on the account
iam-auditor --all-regions

# Override the default region used for session auth and global checks
iam-auditor --region eu-west-1
```

Findings from regional checks are labelled with their region, e.g. `EC2 / VPC Checks [ap-south-1]`, so you can see exactly where each result came from. `--all-regions` takes longer since it multiplies regional check execution by the number of enabled regions on the account — expect scans to take several minutes on accounts with many regions enabled.

## Architecture

```
CLI (argparse)
    │
    ▼
Session Factory (boto3)
    │
    ▼
Audit Engine ──── ThreadPoolExecutor (4 workers, configurable via --workers)
    │
    │   Global checks (run once)        Regional checks (run once per region)
    │   ─────────────────────────       ──────────────────────────────────────
    │   mfa, permissions                ec2, kms, guardduty, securityhub,
    │   access_keys, unused_users       rds, secrets_manager, ecr,
    │   iam_advanced, cloudtrail, s3     cloudwatch_alarms
    │        │                                    │
    │        └──────────────┬─────────────────────┘
    │                       │
    │            CheckResult (findings + timing, region-labelled)
    │                       │
    │         ┌─────────────┼─────────────┐
    │         ▼             ▼             ▼
    │  terminal.py   json_reporter  html_reporter
    │                               csv_reporter
```

IAM credential reports are fetched once per scan and shared between the `mfa` and `unused_users` modules rather than each fetching and parsing their own copy, reducing redundant API calls and memory use on accounts with large user counts.

## Requirements

- Python 3.10+
- AWS credentials configured (env vars, `~/.aws/credentials`, or IAM role)

**Required IAM permissions (read-only):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:GenerateCredentialReport", "iam:GetCredentialReport",
      "iam:GetAccountSummary", "iam:GetAccountPasswordPolicy",
      "iam:ListUsers", "iam:ListRoles", "iam:GetRole", "iam:ListGroups",
      "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
      "iam:ListPolicies", "iam:GetPolicyVersion", "iam:ListEntitiesForPolicy",
      "iam:ListAttachedRolePolicies", "iam:ListUserPolicies",
      "iam:ListRolePolicies", "iam:ListGroupPolicies",
      "accessanalyzer:ListAnalyzers", "accessanalyzer:ListFindings",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
      "cloudtrail:GetEventSelectors",
      "s3:ListAllMyBuckets", "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketAcl", "s3:GetBucketPolicy", "s3:GetBucketEncryption",
      "s3:GetBucketOwnershipControls", "s3:GetBucketVersioning",
      "s3:GetBucketLogging", "s3:GetLifecycleConfiguration",
      "s3control:GetPublicAccessBlock",
      "ec2:DescribeInstances", "ec2:DescribeSnapshots",
      "ec2:DescribeSnapshotAttribute", "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs", "ec2:DescribeFlowLogs", "ec2:DescribeRegions",
      "ec2:GetEbsEncryptionByDefault",
      "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus", "kms:ListGrants",
      "guardduty:ListDetectors", "guardduty:GetDetector",
      "guardduty:ListFindings", "guardduty:GetFindings",
      "securityhub:DescribeHub", "securityhub:GetEnabledStandards",
      "rds:DescribeDBInstances", "rds:DescribeDBSnapshots",
      "rds:DescribeDBSnapshotAttributes",
      "dynamodb:ListTables", "dynamodb:DescribeContinuousBackups",
      "secretsmanager:ListSecrets",
      "ecr:DescribeRepositories", "ecr:GetRepositoryPolicy",
      "ecr:DescribeImages", "ecr:DescribeImageScanFindings",
      "logs:DescribeMetricFilters", "cloudwatch:DescribeAlarms",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

`ec2:DescribeRegions` is only needed if you use `--all-regions`.

## Installation

```bash
git clone https://github.com/neelkotnis/aws-iam-security-auditor
cd aws-iam-security-auditor
pip install -e .
```

## Usage

```bash
# Full audit — saves JSON, HTML, and CSV to ./reports/<account-id>/ automatically
iam-auditor

# Named AWS profile
iam-auditor --profile prod-readonly

# Scan specific regions
iam-auditor --regions us-east-1,ap-south-1

# Scan every enabled region
iam-auditor --all-regions

# Only HIGH and CRITICAL findings
iam-auditor --severity HIGH

# Run specific check modules only
iam-auditor --checks mfa,s3,cloudtrail,ec2

# List all available check modules
iam-auditor --list-checks

# Adjust thread pool size (default: 4)
iam-auditor --all-regions --workers 6

# Custom output directory
iam-auditor --output-dir /tmp/audit-reports

# Skip specific report formats
iam-auditor --no-html
iam-auditor --no-csv
iam-auditor --no-json

# CI/CD mode — suppress terminal output, print only report path
iam-auditor --quiet

# Debug logging
iam-auditor --verbose
```

Or run without installing:
```bash
PYTHONPATH=src python -m iam_auditor --profile my-profile
```

## Output

Reports are saved automatically to `reports/<account-id>/` on every run — no flags needed.

**Terminal** — color-coded findings table sorted by severity, regional checks labelled by region:

```
╭──────────────┬──────────┬─────────┬──────────────────────────────┬─────────────────────╮
│ Severity     │ Check ID │ CIS     │ Check                        │ Resource            │
├──────────────┼──────────┼─────────┼──────────────────────────────┼─────────────────────┤
│ ✖ CRITICAL   │ CT-001   │ CIS 3.1 │ No Multi-Region CloudTrail   │ arn:aws:cloudtrail..│
│ ✖ CRITICAL   │ EC2-002  │ CIS 2.2 │ EBS Default Encryption Off   │ arn:aws:ec2:us-east│
│ ✖ CRITICAL   │ GD-001   │ CIS 4.16│ GuardDuty Not Enabled        │ arn:aws:guardduty..│
│ ■ HIGH       │ CT-004   │ CIS 3.10│ S3 Data Events Not Enabled   │ arn:aws:cloudtrail..│
│ ■ HIGH       │ ECR-002  │ —       │ ECR Scan on Push Disabled    │ arn:aws:ecr:us-east│
╰──────────────┴──────────┴─────────┴──────────────────────────────┴─────────────────────╯

╭──────────────────────────────────────────────╮
│           Check Timings                       │
│  CloudTrail Checks                  3.8s      │
│  S3 Checks                          4.6s      │
│  EC2 / VPC Checks [us-east-1]       4.7s      │
│  EC2 / VPC Checks [ap-south-1]      5.1s      │
│  GuardDuty Checks [us-east-1]       2.1s      │
│  IAM Advanced Checks                2.9s      │
╰────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────────╮
│  Summary                                                 │
│  ✖ CRITICAL: 8   ■ HIGH: 10   ▲ MEDIUM: 4   ● LOW: 2     │
│  Total scan time: 18.4s                                  │
╰──────────────────────────────────────────────────────────╯
```

**JSON / HTML / CSV** — written to `reports/<account-id>/iam_audit_<timestamp>.<ext>`:

```json
{
  "account_id": "123456789012",
  "run_at": "2024-06-01T10:00:00Z",
  "summary": { "CRITICAL": 8, "HIGH": 10, "MEDIUM": 4, "LOW": 2 },
  "total_findings": 24,
  "findings": [
    {
      "check_id": "EC2-002",
      "check_name": "EBS Default Encryption Disabled",
      "severity": "CRITICAL",
      "resource": "arn:aws:ec2:ap-south-1:123456789012",
      "account_id": "123456789012",
      "region": "ap-south-1",
      "cis_control": "CIS 2.2.1",
      "compliance_controls": ["CIS 2.2.1", "NIST SC-28", "SOC2 CC6.7", "ISO A.10.1.1"],
      "detail": "EBS default encryption is disabled in ap-south-1.",
      "remediation": "aws ec2 enable-ebs-encryption-by-default --region ap-south-1"
    }
  ]
}
```

## Exit Codes

| Code | Meaning                                  |
|------|------------------------------------------|
| `0`  | Audit completed, no findings             |
| `1`  | Findings found, none CRITICAL            |
| `2`  | One or more CRITICAL findings found      |

Use in CI/CD:
```bash
iam-auditor --quiet --severity HIGH || notify-oncall.sh
```

## Project Structure

```text
src/
└── iam_auditor/
    ├── cli.py                      # CLI entrypoint, argparse, exit codes
    ├── engine.py                   # Check orchestration, region fan-out, threading
    ├── models.py                   # Finding, Severity, AuditResult models
    ├── compliance.py               # Loads compliance_map.yaml, get_controls()
    │
    ├── data/
    │   └── compliance_map.yaml     # CIS / NIST / SOC2 / ISO27001 mappings
    │
    ├── checks/
    │   ├── _credential_report.py   # Shared, cached IAM credential report fetch
    │   ├── mfa.py                  # IAM-001, IAM-002, IAM-007, IAM-008
    │   ├── permissions.py          # IAM-003, IAM-004, IAM-010, IAM-011
    │   ├── access_keys.py          # IAM-005, IAM-006
    │   ├── unused_users.py         # IAM-009, IAM-010
    │   ├── iam_advanced.py         # IAM-012 to IAM-017
    │   ├── cloudtrail.py           # CT-001 to CT-007 (global)
    │   ├── s3.py                   # S3-001 to S3-008 (global)
    │   ├── ec2.py                  # EC2-001 to EC2-008 (regional)
    │   ├── kms.py                  # KMS-001 to KMS-004 (regional)
    │   ├── guardduty.py            # GD-001, GD-002 (regional)
    │   ├── securityhub.py          # SH-001 (regional)
    │   ├── rds.py                  # RDS-001 to RDS-005, DDB-001 (regional)
    │   ├── secrets_manager.py      # SM-001, SM-002 (regional)
    │   ├── ecr.py                  # ECR-001 to ECR-003 (regional)
    │   └── cloudwatch_alarms.py    # CWA-001 to CWA-004 (regional)
    │
    └── reporters/
        ├── terminal.py             # Rich terminal output
        ├── json_reporter.py        # JSON → reports/<account-id>/
        ├── html_reporter.py        # HTML dashboard → reports/<account-id>/
        └── csv_reporter.py         # CSV export → reports/<account-id>/
```
