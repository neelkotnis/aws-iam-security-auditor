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

  # Run only specific checks
  python -m iam_auditor --checks mfa,permissions

  # Save JSON report to a custom directory
  python -m iam_auditor --output-dir ./reports

  # Skip JSON report (terminal only)
  python -m iam_auditor --no-json

  # Suppress all output except JSON path (CI/CD mode)
  python -m iam_auditor --quiet

  # Verbose logging
  python -m iam_auditor --verbose
"""

from __future__ import annotations

import argparse
import logging
import sys

import boto3
from botocore.exceptions import BotoCoreError, NoCredentialsError, ProfileNotFound
from rich.console import Console

from iam_auditor.engine import run_audit, ALL_CHECK_KEYS
from iam_auditor.models import Severity
from iam_auditor.reporters import terminal, json_reporter

console = Console()

_SEVERITY_CHOICES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-auditor",
        description="AWS IAM Security Auditor — detect common IAM misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Checks available (use with --checks):
  {", ".join(ALL_CHECK_KEYS)}

Exit codes:
  0  No findings
  1  Findings found, none CRITICAL
  2  One or more CRITICAL findings found

Examples:
  iam-auditor
  iam-auditor --profile staging --severity HIGH
  iam-auditor --checks mfa,permissions
  iam-auditor --output-dir ./reports --quiet
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
            f"Minimum severity to report "
            f"[choices: {', '.join(_SEVERITY_CHOICES)}] (default: LOW)"
        ),
    )
    parser.add_argument(
        "--checks",
        metavar="LIST",
        default=None,
        help=(
            f"Comma-separated checks to run. "
            f"Available: {', '.join(ALL_CHECK_KEYS)} "
            f"(default: all)"
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
        "--quiet", "-q",
        action="store_true",
        help="Suppress terminal output; print only the JSON report path (CI/CD mode)",
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


def _configure_logging(verbose: bool, quiet: bool) -> None:
    if quiet:
        level = logging.CRITICAL  # suppress everything in quiet mode
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
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


def _parse_checks(raw: str | None) -> list[str] | None:
    """Split and normalise the --checks comma-separated string."""
    if not raw:
        return None
    return [c.strip().lower() for c in raw.split(",") if c.strip()]


def _validate_checks(selected: list[str] | None) -> list[str]:
    """Return any unrecognised check keys."""
    if not selected:
        return []
    return [k for k in selected if k not in ALL_CHECK_KEYS]


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    _configure_logging(args.verbose, args.quiet)

    # --- Validate --checks before touching AWS ---
    selected_checks = _parse_checks(args.checks)
    unknown = _validate_checks(selected_checks)
    if unknown:
        console.print(
            f"[bold red]Error:[/bold red] Unknown check(s): {', '.join(unknown)}\n"
            f"Available: {', '.join(ALL_CHECK_KEYS)}"
        )
        return 1

    # --- Build and validate AWS session ---
    try:
        session = _build_session(args.profile, args.region)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        if not args.quiet:
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
        result, exit_code = run_audit(
            session=session,
            min_severity=min_severity,
            max_workers=args.workers,
            selected_checks=selected_checks,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted by user.[/yellow]")
        return 1
    except Exception as exc:
        console.print(f"[bold red]Fatal error during audit:[/bold red] {exc}")
        logging.getLogger(__name__).exception("Unhandled exception in run_audit")
        return 1

    # --- Terminal report ---
    if not args.quiet:
        terminal.render(result)

    # --- JSON report ---
    if not args.no_json:
        try:
            output_path = json_reporter.write(result, output_dir=args.output_dir)
            if args.quiet:
                # In quiet mode, only print the path — scriptable
                print(output_path)
            else:
                console.print(
                    f"\n[dim]JSON report saved to:[/dim] [bold]{output_path}[/bold]"
                )
        except OSError as exc:
            console.print(
                f"[bold red]Warning:[/bold red] Could not write JSON report: {exc}"
            )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())