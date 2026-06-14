# AWS IAM Security Auditor

A production-grade CLI tool that audits AWS IAM configurations against the **CIS AWS Foundations Benchmark** and surfaces security misconfigurations with actionable remediation guidance. Every finding is mapped to CIS, NIST SP 800-53, SOC 2, and ISO 27001 controls.

```
┌─────────────────────────────────────────────┐
│          AWS IAM Security Audit             │
│  Account:   123456789012                    │
│  Run at:    2024-06-01T10:00:00Z            │
│  Findings:  9 total                         │
│  Duration:  4.2s                            │
└─────────────────────────────────────────────┘
```

## Checks

| ID      | Check                                        | Severity | CIS Control | Module       |
|---------|----------------------------------------------|----------|-------------|--------------|
| IAM-001 | IAM user without MFA                         | HIGH     | CIS 1.10    | mfa          |
| IAM-002 | Root account MFA disabled                    | CRITICAL | CIS 1.5     | mfa          |
| IAM-007 | Root account access keys present             | CRITICAL | CIS 1.4     | mfa          |
| IAM-008 | Weak or missing password policy              | MEDIUM   | CIS 1.8     | mfa          |
| IAM-003 | Wildcard action (`*`) in policy              | HIGH     | CIS 1.16    | permissions  |
| IAM-004 | AdministratorAccess attached                 | CRITICAL | CIS 1.16    | permissions  |
| IAM-010 | Overly permissive role trust policy          | CRITICAL | —           | permissions  |
| IAM-011 | Inline policies detected                     | LOW      | —           | permissions  |
| IAM-005 | Access key inactive / never used             | MEDIUM   | CIS 1.12    | access_keys  |
| IAM-006 | Access key rotation overdue                  | HIGH     | CIS 1.14    | access_keys  |
| IAM-009 | IAM user inactive >90 days                   | MEDIUM   | CIS 1.12    | unused_users |
| IAM-010 | IAM user never logged in                     | LOW      | CIS 1.12    | unused_users |
| IAM-012 | IAM role unused >90 days                     | HIGH     | CIS 1.17    | iam_advanced |
| IAM-013 | Privileged role without permission boundary  | HIGH     | —           | iam_advanced |
| IAM-014 | Cross-account trust without ExternalId       | CRITICAL | —           | iam_advanced |
| IAM-015 | IAM Access Analyzer not enabled              | HIGH     | —           | iam_advanced |
| IAM-016 | IAM Access Analyzer has unresolved findings  | HIGH     | —           | iam_advanced |
| IAM-017 | IAM role max session duration >12 hours      | MEDIUM   | —           | iam_advanced |

## Architecture

```
CLI (argparse)
    │
    ▼
Session Factory (boto3)
    │
    ▼
Audit Engine ──── ThreadPoolExecutor (4 workers)
    │                   │
    │      ┌────────────┼────────────┬────────────┬────────────┐
    │      ▼            ▼            ▼            ▼            ▼
    │  mfa.py    permissions.py  access_keys  unused_users  iam_advanced
    │      │            │            │            │            │
    └──────┴────────────┴────────────┴────────────┴────────────┘
                        │
                   CheckResult (findings + timing)
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
       terminal.py          json_reporter.py
```

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
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "iam:GetAccountSummary",
      "iam:GetAccountPasswordPolicy",
      "iam:ListUsers",
      "iam:ListRoles",
      "iam:GetRole",
      "iam:ListGroups",
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
      "iam:ListPolicies",
      "iam:GetPolicyVersion",
      "iam:ListEntitiesForPolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListUserPolicies",
      "iam:ListRolePolicies",
      "iam:ListGroupPolicies",
      "accessanalyzer:ListAnalyzers",
      "accessanalyzer:ListFindings",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

## Installation

```bash
git clone https://github.com/neelkotnis/aws-iam-security-auditor
cd aws-iam-security-auditor
pip install -e .
```

## Usage

```bash
# Full audit, all severities
iam-auditor

# Named AWS profile
iam-auditor --profile prod-readonly

# Only HIGH and CRITICAL findings
iam-auditor --severity HIGH

# Run specific checks only
iam-auditor --checks mfa,iam_advanced

# Save JSON report to ./reports/
iam-auditor --output-dir ./reports

# CI/CD mode — suppress terminal output, print only JSON path
iam-auditor --quiet

# Terminal only, no JSON file
iam-auditor --no-json

# Debug logging
iam-auditor --verbose
```

Or run without installing:
```bash
PYTHONPATH=src python -m iam_auditor --profile my-profile
```

## Output

**Terminal** — color-coded findings table with CIS controls, per-check timings, and summary:

```
╭──────────────┬──────────┬─────────┬──────────────────────────────┬─────────────────────╮
│ Severity     │ Check ID │ CIS     │ Check                        │ Resource            │
├──────────────┼──────────┼─────────┼──────────────────────────────┼─────────────────────┤
│ ✖ CRITICAL   │ IAM-002  │ CIS 1.5 │ Root Account MFA Disabled    │ root-account        │
│ ✖ CRITICAL   │ IAM-004  │ CIS 1.16│ AdministratorAccess Attached │ iam::user/admin     │
│ ✖ CRITICAL   │ IAM-014  │ —       │ Cross-Account Trust No ExtId │ arn:aws:iam::role/..│
│ ■ HIGH       │ IAM-001  │ CIS 1.10│ IAM User Without MFA         │ arn:aws:iam::user/..│
│ ■ HIGH       │ IAM-015  │ —       │ Access Analyzer Not Enabled  │ arn:aws:access-anal.│
│ ▲ MEDIUM     │ IAM-008  │ CIS 1.8 │ Weak IAM Password Policy     │ account-password-.. │
╰──────────────┴──────────┴─────────┴──────────────────────────────┴─────────────────────╯

╭──────────────────────────────────╮
│         Check Timings            │
│  MFA Checks            1.2s      │
│  Permission Checks     2.1s      │
│  Access Key Checks     0.8s      │
│  Unused User Checks    0.5s      │
│  IAM Advanced Checks   2.9s      │
╰──────────────────────────────────╯

╭──────────────────────────────────────────────────────────╮
│  Summary                                                 │
│  ✖ CRITICAL: 3   ■ HIGH: 2   ▲ MEDIUM: 2   ● LOW: 1    │
│  Total scan time: 7.5s                                   │
╰──────────────────────────────────────────────────────────╯
```

**JSON** — written to `iam_audit_<account>_<timestamp>.json`:

```json
{
  "account_id": "123456789012",
  "run_at": "2024-06-01T10:00:00Z",
  "summary": { "LOW": 1, "MEDIUM": 2, "HIGH": 2, "CRITICAL": 3 },
  "total_findings": 9,
  "check_timings": {
    "MFA Checks": 1200.4,
    "Permission Checks": 2100.1,
    "Access Key Checks": 800.2,
    "Unused User Checks": 500.8,
    "IAM Advanced Checks": 2900.3
  },
  "total_duration_ms": 7501.8,
  "findings": [
    {
      "check_id": "IAM-002",
      "check_name": "Root Account MFA Disabled",
      "severity": "CRITICAL",
      "resource": "root-account",
      "account_id": "123456789012",
      "region": "global",
      "cis_control": "CIS 1.5",
      "compliance_controls": ["CIS 1.5", "NIST IA-2", "NIST AC-2", "SOC2 CC6.1", "ISO A.9.2.4"],
      "detail": "...",
      "remediation": "..."
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
    ├── cli.py                 # CLI entrypoint, argparse, exit codes
    ├── engine.py              # Check orchestration, threading, timings
    ├── models.py              # Finding, Severity, AuditResult models
    ├── compliance.py          # Loads compliance_map.yaml, get_controls()
    │
    ├── data/
    │   └── compliance_map.yaml  # CIS / NIST / SOC2 / ISO27001 mappings
    │
    ├── checks/
    │   ├── mfa.py             # IAM-001, IAM-002, IAM-007, IAM-008
    │   ├── permissions.py     # IAM-003, IAM-004, IAM-010, IAM-011
    │   ├── access_keys.py     # IAM-005, IAM-006
    │   ├── unused_users.py    # IAM-009, IAM-010
    │   └── iam_advanced.py    # IAM-012 to IAM-017
    │
    └── reporters/
        ├── terminal.py        # Rich terminal reporting & summaries
        └── json_reporter.py   # Structured JSON report generation
```
