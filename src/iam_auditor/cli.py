"""
cli.py
------
Command-line entrypoint for the AWS IAM Security Auditor.

Usage examples:
  # Audit using the default AWS profile
  python -m iam_auditor

  # Use a specific named profile
  python -m iam_auditor --profile prod-readonly

  # Only surface HIGH and CRITICAL findings
  python -m iam_auditor --severity HIGH

  # Save JSON report to a custom directory
  python -m iam_auditor --output-dir ./reports

  # Skip JSON report (terminal only)
  python -m iam_auditor --no-json

  # Verbose logging
  python -m iam_auditor --verbose
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, NoCredentialsError, ProfileNotFound
from rich.console import Console

from iam_auditor.engine import run_audit
from iam_auditor.models import Severity
from iam_auditor.reporters import terminal, json_reporter

console = Console()

# Valid --severity choices in display order
_SEVERITY_CHOICES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-auditor",
        description="AWS IAM Security Auditor — detect common IAM misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  iam-auditor
  iam-auditor --profile staging --severity HIGH
  iam-auditor --output-dir ./reports --region us-west-2
  iam-auditor --no-json --verbose
        """,
    )

    parser.add_argument(
        "--profile",
        metavar="NAME",
        default=None,
        help="AWS named profile to use (default: environment / instance role)",
    )
    parser.add_argument(
        "--region",
        metavar="REGION",
        default=None,
        help="AWS region for the session (IAM is global; affects STS endpoint)",
    )
    parser.add_argument(
        "--severity",
        choices=_SEVERITY_CHOICES,
        default="LOW",
        metavar="LEVEL",
        help=(
            f"Minimum severity to include in output "
            f"[choices: {', '.join(_SEVERITY_CHOICES)}] (default: LOW)"
        ),
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default=".",
        help="Directory to write JSON report into (default: current directory)",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip writing the JSON report; terminal output only",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="Thread pool size for concurrent checks (default: 4)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging",
    )

    return parser


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    # Quieten noisy boto/urllib libraries unless we're in verbose mode
    if not verbose:
        logging.getLogger("botocore").setLevel(logging.ERROR)
        logging.getLogger("urllib3").setLevel(logging.ERROR)


def _build_session(profile: str | None, region: str | None) -> boto3.Session:
    kwargs: dict = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def main() -> int:
    """
    Main entry point.  Returns an exit code:
      0  — clean run (findings may exist; tool completed successfully)
      1  — unrecoverable error (bad credentials, missing permissions, etc.)
    """
    parser = build_parser()
    args = parser.parse_args()

    _configure_logging(args.verbose)

    # --- Build AWS session ---
    try:
        session = _build_session(args.profile, args.region)
        # Eagerly validate credentials with a lightweight STS call
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        console.print(
            f"[dim]Authenticated as:[/dim] [bold]{identity.get('Arn', 'unknown')}[/bold]"
        )
    except ProfileNotFound:
        console.print(
            f"[bold red]Error:[/bold red] AWS profile '{args.profile}' not found. "
            "Check ~/.aws/credentials or ~/.aws/config."
        )
        return 1
    except NoCredentialsError:
        console.print(
            "[bold red]Error:[/bold red] No AWS credentials found. "
            "Configure via environment variables, ~/.aws/credentials, or an IAM role."
        )
        return 1
    except (BotoCoreError, Exception) as exc:
        console.print(f"[bold red]Error:[/bold red] Could not authenticate: {exc}")
        return 1

    # --- Run audit ---
    min_severity = Severity(args.severity)

    try:
        result = run_audit(
            session=session,
            min_severity=min_severity,
            max_workers=args.workers,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted by user.[/yellow]")
        return 1
    except Exception as exc:
        console.print(f"[bold red]Fatal error during audit:[/bold red] {exc}")
        logging.getLogger(__name__).exception("Unhandled exception in run_audit")
        return 1

    # --- Terminal report ---
    terminal.render(result)

    # --- JSON report ---
    if not args.no_json:
        try:
            output_path = json_reporter.write(result, output_dir=args.output_dir)
            console.print(f"\n[dim]JSON report saved to:[/dim] [bold]{output_path}[/bold]")
        except OSError as exc:
            console.print(f"[bold red]Warning:[/bold red] Could not write JSON report: {exc}")
            # Non-fatal — terminal output was still produced

    return 0


if __name__ == "__main__":
    sys.exit(main())
