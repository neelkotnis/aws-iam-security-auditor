# AWS IAM Security Auditor

A lightweight, production-style CLI tool that audits AWS IAM configurations and surfaces common security misconfigurations.

## Checks

| ID       | Check                          | Severity |
|----------|--------------------------------|----------|
| IAM-001  | IAM user without MFA           | HIGH     |
| IAM-002  | Root account MFA disabled      | CRITICAL |
| IAM-003  | Wildcard action in policy      | HIGH     |
| IAM-004  | AdministratorAccess attached   | CRITICAL |
| IAM-005  | Access key inactive / unused   | MEDIUM   |
| IAM-006  | Access key rotation overdue    | HIGH     |

## Requirements

- Python 3.10+
- AWS credentials configured (env vars, `~/.aws/credentials`, or IAM role)
- Required IAM permissions: `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`, `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:ListEntitiesForPolicy`, `iam:GetAccountSummary`, `sts:GetCallerIdentity`

## Installation

```bash
# From source
pip install -e .

# Or directly
pip install -r requirements.txt
```

## Usage

```bash
# Full audit, all severities
iam-auditor

# Use a named AWS profile
iam-auditor --profile prod-readonly

# Show only HIGH and CRITICAL
iam-auditor --severity HIGH

# Save JSON report to ./reports/
iam-auditor --output-dir ./reports

# Terminal output only (skip JSON)
iam-auditor --no-json

# Enable verbose logging
iam-auditor --verbose
```

Or run as a module without installing:

```bash
cd aws-iam-auditor
PYTHONPATH=src python -m iam_auditor --profile my-profile
```

## Output

**Terminal** — Rich-formatted table sorted by severity (CRITICAL first):

```
┌─────────────────────────────────────────────┐
|        AWS IAM Security Audit               |
| Account:  123456789012                      |
| Run at:   2024-06-01T10:00:00Z              |
| Findings: 7 total                           |
└─────────────────────────────────────────────┘

┌──────────────┬──────────┬─────────────────────────────────────┬─────────────────────────┐
│ Severity     │ Check ID │ Check                               │ Resource                │
├──────────────┼──────────┼─────────────────────────────────────┼─────────────────────────┤
│ ✖ CRITICAL   │ IAM-002  │ Root Account MFA Disabled           │ arn:aws:iam::root       │
│ ✖ CRITICAL   │ IAM-004  │ AdministratorAccess Attached        │ iam::user/admin         │
│ ■ HIGH       │ IAM-001  │ IAM User Without MFA                │ arn:aws:iam::user/bob   │
│ ■ HIGH       │ IAM-003  │ Wildcard Action in Policy           │ arn:aws:iam::policy/... │
│ ■ HIGH       │ IAM-006  │ Access Key Rotation Overdue         │ arn:aws:iam::user/bob   │
│ ▲ MEDIUM     │ IAM-005  │ Access Key Never Used               │ arn:aws:iam::user/svc1  │
│ ▲ MEDIUM     │ IAM-005  │ Access Key Inactive                 │ arn:aws:iam::user/svc2  │
└──────────────┴──────────┴─────────────────────────────────────┴─────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Summary                                                     │
│  ✖ CRITICAL: 2   ■ HIGH: 3   ▲ MEDIUM: 2   ● LOW: 0          │
└──────────────────────────────────────────────────────────────┘
```

**JSON** — Written to `iam_audit_<account>_<timestamp>.json`:

```json
{
  "account_id": "123456789012",
  "run_at": "2024-06-01T10:00:00Z",
  "summary": { "LOW": 0, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 2 },
  "total_findings": 7,
  "findings": [ { ... } ]
}
```

## Project Structure

```
src/
└── iam_auditor/
    ├── cli.py                 # argparse entrypoint
    ├── engine.py              # ThreadPoolExecutor orchestrator
    ├── models.py              # Finding, AuditResult, Severity
    │
    ├── checks/
    │   ├── mfa.py             # IAM-001, IAM-002, IAM-007
    │   ├── permissions.py     # IAM-003, IAM-004
    │   └── access_keys.py     # IAM-005, IAM-006
    │
    └── reporters/
        ├── terminal.py        # Rich table output
        └── json_reporter.py   # JSON report output
```
