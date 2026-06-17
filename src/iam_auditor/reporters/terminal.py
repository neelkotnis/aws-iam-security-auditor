"""
reporters/terminal.py
---------------------
Renders audit findings to the terminal using Rich.

Output structure:
  1. Header panel — account, timestamp, authenticated identity
  2. Findings table — sorted CRITICAL -> LOW, includes CIS control column
  3. Check timings — per-check duration table, exact finding count per check
  4. Summary panel — severity counts + total scan duration
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.markup import escape

from iam_auditor.models import AuditResult, Severity, SEVERITY_COLORS

console = Console()

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.LOW:      "bold green",
    Severity.MEDIUM:   "bold yellow",
    Severity.HIGH:     "bold orange1",
    Severity.CRITICAL: "bold red",
}

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
    total_ms = result.total_duration_ms()
    duration_str = (
        f"{total_ms / 1000:.1f}s" if total_ms >= 1000 else f"{total_ms:.0f}ms"
    )
    content = (
        f"[bold]Account:[/bold]   {result.account_id}\n"
        f"[bold]Run at:[/bold]    {result.run_at}\n"
        f"[bold]Findings:[/bold]  {len(result.findings)} total\n"
        f"[bold]Duration:[/bold]  {duration_str}"
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
    table.add_column("CIS",         style="dim",  width=9,  no_wrap=True)
    table.add_column("Check",                     width=26, no_wrap=False)
    table.add_column("Resource",                  width=36, no_wrap=False, overflow="fold")
    table.add_column("Detail",                    ratio=2,  no_wrap=False)
    table.add_column("Remediation",               ratio=3,  no_wrap=False)

    for finding in result.sorted_findings():
        table.add_row(
            _severity_badge(finding.severity),
            finding.check_id,
            finding.cis_control or "—",
            finding.check_name,
            finding.resource,
            finding.detail,
            finding.remediation,
        )

    console.print(table, "\n")


def print_timings(result: AuditResult) -> None:
    """
    Render a compact per-check timing table using the exact finding count
    recorded by the engine for each check execution.

    IMPORTANT: check labels contain literal square brackets for region
    suffixes, e.g. "EC2 / VPC Checks [us-east-1]". Rich's Table.add_row()
    treats string cell content as markup by default, so "[us-east-1]" was
    being silently parsed (and discarded) as an attempted, invalid style
    tag rather than rendered as literal text. Escaping the label with
    rich.markup.escape() (or passing a Text object) prevents this.
    """
    if not result.check_details:
        return

    longest_label = max((len(d.label) for d in result.check_details), default=20)
    check_col_width = max(28, min(longest_label + 2, 60))

    table = Table(
        box=box.SIMPLE,
        header_style="bold dim",
        show_edge=False,
        padding=(0, 2),
    )
    table.add_column("Check",    style="dim", width=check_col_width, no_wrap=True, overflow="ellipsis")
    table.add_column("Duration", style="dim", justify="right", width=10, no_wrap=True)
    table.add_column("Findings", style="dim", justify="right", width=10, no_wrap=True)

    for detail in sorted(result.check_details, key=lambda d: d.label):
        duration_str = f"{detail.duration_ms / 1000:.2f}s" if detail.duration_ms >= 1000 else f"{detail.duration_ms:.0f}ms"
        if detail.error:
            count_str = "[red]ERROR[/red]"
        elif detail.finding_count > 0:
            count_str = str(detail.finding_count)
        else:
            count_str = "[dim]0[/dim]"
        # escape() prevents Rich from interpreting [region] as markup
        table.add_row(escape(detail.label), duration_str, count_str)

    console.print(Panel(table, title="[bold]Check Timings[/bold]", expand=False))


def print_summary(result: AuditResult) -> None:
    summary = result.summary()
    total_ms = result.total_duration_ms()
    duration_str = (
        f"{total_ms / 1000:.1f}s" if total_ms >= 1000 else f"{total_ms:.0f}ms"
    )

    parts = []
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = summary[severity.value]
        icon = _SEVERITY_ICONS[severity]
        style = _SEVERITY_STYLE[severity]
        parts.append(f"[{style}]{icon} {severity.value}: {count}[/{style}]")

    severity_line = "   ".join(parts)
    content = f"{severity_line}\n[dim]Total scan time: {duration_str}[/dim]"

    console.print(
        Panel(content, title="[bold]Summary[/bold]", expand=False),
    )


def render(result: AuditResult) -> None:
    """
    Full terminal render: header -> findings table -> timings -> summary.
    Single entry point called from cli.py.
    """
    print_header(result)
    print_findings_table(result)
    print_timings(result)
    print_summary(result)
