"""
reporters/terminal.py
---------------------
Renders audit findings to the terminal using Rich.

Output structure:
  1. Header panel with account/timestamp
  2. Findings table (sorted critical → low)
  3. Summary counts panel
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from iam_auditor.models import AuditResult, Severity, SEVERITY_COLORS

console = Console()

# Severity → Rich style string (bold for visibility)
_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.LOW:      "bold green",
    Severity.MEDIUM:   "bold yellow",
    Severity.HIGH:     "bold orange1",
    Severity.CRITICAL: "bold red",
}

# Summary badge characters
_SEVERITY_ICONS: dict[Severity, str] = {
    Severity.LOW:      "●",
    Severity.MEDIUM:   "▲",
    Severity.HIGH:     "■",
    Severity.CRITICAL: "✖",
}


def _severity_badge(severity: Severity) -> Text:
    icon = _SEVERITY_ICONS[severity]
    style = _SEVERITY_STYLE[severity]
    return Text(f"{icon} {severity.value}", style=style)


def print_header(result: AuditResult) -> None:
    content = (
        f"[bold]Account:[/bold]  {result.account_id}\n"
        f"[bold]Run at:[/bold]   {result.run_at}\n"
        f"[bold]Findings:[/bold] {len(result.findings)} total"
    )
    console.print(
        Panel(content, title="[bold cyan]AWS IAM Security Audit[/bold cyan]", expand=False),
        "\n",
    )


def print_findings_table(result: AuditResult) -> None:
    if not result.findings:
        console.print("[bold green]✔  No findings to display.[/bold green]\n")
        return

    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
        expand=True,
    )

    table.add_column("Severity",    style="bold", width=10, no_wrap=True)
    table.add_column("Check ID",    style="dim",  width=10, no_wrap=True)
    table.add_column("Check",                     width=28, no_wrap=False)
    table.add_column("Resource",                  width=38, no_wrap=False, overflow="fold")
    table.add_column("Detail",                    ratio=2,  no_wrap=False)
    table.add_column("Remediation",               ratio=3,  no_wrap=False)

    for finding in result.sorted_findings():
        table.add_row(
            _severity_badge(finding.severity),
            finding.check_id,
            finding.check_name,
            finding.resource,
            finding.detail,
            finding.remediation,
        )

    console.print(table, "\n")


def print_summary(result: AuditResult) -> None:
    summary = result.summary()

    parts = []
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = summary[severity.value]
        icon = _SEVERITY_ICONS[severity]
        style = _SEVERITY_STYLE[severity]
        parts.append(f"[{style}]{icon} {severity.value}: {count}[/{style}]")

    content = "   ".join(parts)
    console.print(
        Panel(content, title="[bold]Summary[/bold]", expand=False),
    )


def render(result: AuditResult) -> None:
    """
    Full terminal render: header → table → summary.
    Call this as the single entry point from cli.py.
    """
    print_header(result)
    print_findings_table(result)
    print_summary(result)
