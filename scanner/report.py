"""Turn a list of Findings into JSON or a color-coded terminal table."""
from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .models import Finding, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def print_table(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()

    if not findings:
        console.print("[bold green]No misconfigurations found.[/]")
        return

    findings = sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity])

    table = Table(title="AWS CIS Scan Results")
    table.add_column("Severity", no_wrap=True)
    table.add_column("CIS", no_wrap=True)
    table.add_column("Resource")
    table.add_column("Finding")

    for f in findings:
        style = _SEVERITY_STYLE.get(f.severity, "")
        table.add_row(
            f"[{style}]{f.severity.value}[/]",
            f.cis_control,
            f.resource,
            f.title,
        )

    console.print(table)
    console.print(f"\n[bold]{len(findings)}[/] finding(s).")