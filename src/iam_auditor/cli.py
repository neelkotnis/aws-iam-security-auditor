"""
cli.py
------
Command-line entrypoint for the AWS Security Auditor.
"""

from __future__ import annotations

import argparse
import logging
import sys

import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound
from rich.console import Console

from iam_auditor.engine import ALL_CHECK_KEYS, run_audit
from iam_auditor.models import Severity
from iam_auditor.reporters import json_reporter, terminal

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-auditor",
        description="AWS Security Auditor — multi-service, multi-region misconfiguration scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  No findings
  1  Findings found, none CRITICAL
  2  One or more CRITICAL findings

Examples:
  iam-auditor
  iam-auditor --profile prod --severity HIGH
  iam-auditor --checks mfa,s3,cloudtrail
  iam-auditor --regions us-east-1,eu-west-1,ap-south-1
  iam-auditor --all-regions --html --csv
  iam-auditor --list-checks
        """,
    )

    parser.add_argument(
        "--profile", metavar="NAME", default=None,
        help="AWS named profile (default: env / instance role)",
    )
    parser.add_argument(
        "--region", metavar="REGION", default=None,
        help="Default session region (also used for global checks)",
    )
    parser.add_argument(
        "--regions", metavar="LIST", default=None,
        help="Comma-separated regions for regional checks, e.g. us-east-1,eu-west-1",
    )
    parser.add_argument(
        "--all-regions", action="store_true",
        help="Auto-discover and scan all enabled AWS regions (overrides --regions)",
    )
    parser.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        default="LOW",
        metavar="LEVEL",
        help="Minimum severity to report: LOW / MEDIUM / HIGH / CRITICAL (default: LOW)",
    )
    parser.add_argument(
        "--checks", metavar="LIST", default=None,
        help=(
            "Comma-separated check modules to run. "
            f"Available: {', '.join(ALL_CHECK_KEYS)}"
        ),
    )
    parser.add_argument(
        "--list-checks", action="store_true",
        help="Print all available check keys and exit",
    )
    parser.add_argument(
        "--output-dir", metavar="DIR", default="reports",
        help="Directory for report files (default: ./reports)",
    )
    parser.add_argument(
        "--no-json", action="store_true",
        help="Skip writing the JSON report",
    )
    parser.add_argument(
        "--html", action="store_true", default=True,
        help="Write HTML report (on by default, use --no-html to skip)",
    )
    parser.add_argument(
        "--csv", action="store_true", default=True,
        help="Write CSV report (on by default, use --no-csv to skip)",
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip writing the HTML report",
    )
    parser.add_argument(
        "--no-csv", action="store_true",
        help="Skip writing the CSV report",
    )
    parser.add_argument(
        "--workers", type=int, default=4,
        help="Thread pool size for concurrent scanning (default: 4)",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress terminal output; print only the report path (CI/CD mode)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable DEBUG logging",
    )

    return parser


def _configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.CRITICAL if quiet else (logging.DEBUG if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    if not verbose:
        logging.getLogger("botocore").setLevel(logging.ERROR)
        logging.getLogger("urllib3").setLevel(logging.ERROR)


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # --list-checks
    if args.list_checks:
        console.print("[bold]Available check modules:[/bold]")
        for key in ALL_CHECK_KEYS:
            console.print(f"  {key}")
        return 0

    _configure_logging(args.verbose, args.quiet)

    # Build session
    try:
        kwargs = {}
        if args.profile:
            kwargs["profile_name"] = args.profile
        if args.region:
            kwargs["region_name"] = args.region
        session  = boto3.Session(**kwargs)
        identity = session.client("sts").get_caller_identity()
        if not args.quiet:
            console.print(
                f"Authenticated as: [bold]{identity.get('Arn', 'unknown')}[/bold]"
            )
    except ProfileNotFound:
        console.print(
            f"[bold red]Error:[/bold red] Profile '{args.profile}' not found."
        )
        return 1
    except NoCredentialsError:
        console.print(
            "[bold red]Error:[/bold red] No AWS credentials found. "
            "Run 'aws configure' or set environment variables."
        )
        return 1
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1

    # Parse checks
    selected_checks = (
        [c.strip().lower() for c in args.checks.split(",")]
        if args.checks else None
    )

    # Parse regions
    explicit_regions = (
        [r.strip() for r in args.regions.split(",")]
        if args.regions else None
    )

    if not args.quiet:
        if args.all_regions:
            console.print("Scanning: [bold]all enabled regions[/bold] (this may take a while)")
        elif explicit_regions:
            console.print(f"Scanning regions: [bold]{', '.join(explicit_regions)}[/bold]")

    # Run audit
    try:
        result, exit_code = run_audit(
            session=session,
            min_severity=Severity(args.severity),
            max_workers=args.workers,
            selected_checks=selected_checks,
            regions=explicit_regions,
            all_regions=args.all_regions,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted.[/yellow]")
        return 1
    except Exception as exc:
        console.print(f"[bold red]Fatal error:[/bold red] {exc}")
        return 1

    # Terminal output
    if not args.quiet:
        terminal.render(result)

    # JSON report
    if not args.no_json:
        try:
            path = json_reporter.write(result, output_dir=args.output_dir)
            if args.quiet:
                print(path)
            else:
                console.print(f"\nJSON report saved to: [bold]{path}[/bold]")
        except Exception as exc:
            console.print(f"[yellow]Warning:[/yellow] Could not write JSON report: {exc}")

    # HTML report
    if args.html and not args.no_html:
        try:
            from iam_auditor.reporters import html_reporter
            path = html_reporter.write(result, output_dir=args.output_dir)
            if not args.quiet:
                console.print(f"HTML report saved to: [bold]{path}[/bold]")
        except Exception as exc:
            console.print(f"[yellow]Warning:[/yellow] Could not write HTML report: {exc}")

    # CSV report
    if args.csv and not args.no_csv:
        try:
            from iam_auditor.reporters import csv_reporter
            path = csv_reporter.write(result, output_dir=args.output_dir)
            if not args.quiet:
                console.print(f"CSV report saved to: [bold]{path}[/bold]")
        except Exception as exc:
            console.print(f"[yellow]Warning:[/yellow] Could not write CSV report: {exc}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
