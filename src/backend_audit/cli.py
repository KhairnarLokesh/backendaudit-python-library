import os
import json
from pathlib import Path
from typing import Optional
import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from .scanner import run_scan

# Load .env variables
load_dotenv()

app = typer.Typer(
    name="backend-audit",
    help="Local backend security, error handling, and code quality auditing tool for Python applications.",
    add_completion=False
)

console = Console()
err_console = Console(stderr=True)

SEVERITY_COLORS = {
    "low": "cyan",
    "medium": "yellow",
    "high": "orange3",
    "critical": "red bold"
}

@app.command("scan")
def scan(
    path: str = typer.Argument(".", help="The target directory or file to scan."),
    framework: Optional[str] = typer.Option(
        None, 
        "--framework", 
        "-f", 
        help="Explicitly set the backend framework (flask, fastapi, django, sanic, plain)."
    ),
    format_type: str = typer.Option(
        "text", 
        "--format", 
        help="Output format: 'text' or 'json'."
    ),
    output: Optional[str] = typer.Option(
        None, 
        "--output", 
        "-o", 
        help="Save the audit report to a JSON file."
    )
):
    """
    Scan a backend codebase for security, error handling, and REST validation issues.
    """
    is_json = format_type.lower() == "json"

    # Strict Privacy Safeguard Notification for CLI
    if not is_json:
        console.print(
            Panel(
                Text.assemble(
                    ("[SECURE] backend-audit ", "green bold"),
                    ("Security Scan initialized.\n", "white"),
                    ("[LOCAL] 100% Local AST analysis is active. ", "green"),
                    ("No code is transmitted to the cloud.", "white")
                ),
                border_style="green"
            )
        )

    # Resolve scan path
    target = Path(path).resolve()
    if not target.exists():
        if not is_json:
            err_console.print(f"[red bold]Error:[/] Path '{path}' does not exist.")
        raise typer.Exit(code=1)

    # 1. Run static analysis scan
    try:
        if is_json:
            # Run silently
            report = run_scan(str(target), framework_override=framework)
        else:
            console.print(f"Scanning target path: [cyan]{target}[/]...")
            report = run_scan(str(target), framework_override=framework)
            console.print("[green][OK] Static analysis scan complete![/]")
    except Exception as e:
        if not is_json:
            err_console.print(f"[red bold]Scan crashed:[/] {str(e)}")
        raise typer.Exit(code=1)

    # AI enrichment completely removed. This tool runs 100% locally and offline.

    # 3. Handle JSON Output / Export
    report_dict = report.to_dict()

    if output:
        out_path = Path(output).resolve()
        try:
            out_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
            if not is_json:
                console.print(f"[green bold][OK][/] Saved audit report to [cyan]{out_path}[/]")
        except Exception as e:
            if not is_json:
                err_console.print(f"[red bold]Error saving file:[/] {str(e)}")

    if is_json:
        # Print only the raw JSON to stdout so it can be piped/parsed
        print(json.dumps(report_dict, indent=2))
        return

    # Separate vulnerability findings from catalog findings
    vulnerability_findings = [f for f in report.findings if f.rule_id != "rest-status-code-catalog"]
    catalog_findings = [f for f in report.findings if f.rule_id == "rest-status-code-catalog"]

    # 4. Render Console Text Report
    console.print()
    console.print(Panel(
        f"[bold]Scan Summary[/]\n"
        f"Framework Detected: [cyan]{report.framework_detected.upper()}[/]\n"
        f"Files Scanned: [cyan]{len(report.scanned_files)}[/]\n"
        f"Scan Time: [cyan]{report.scan_time_seconds}s[/]\n"
        f"Vulnerabilities Found: [red bold]{len(vulnerability_findings)}[/]\n"
        f"HTTP Status Codes Cataloged: [cyan]{len(catalog_findings)}[/]",
        border_style="blue",
        title="Audit Results"
    ))

    if not vulnerability_findings:
        console.print("[green bold][OK] No issues or security vulnerabilities found! Excellent job.[/]")
    else:
        # Group findings by severity
        findings_by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for f in vulnerability_findings:
            sev = f.severity.lower()
            if sev in findings_by_severity:
                findings_by_severity[sev].append(f)
            else:
                findings_by_severity.setdefault(sev, []).append(f)

        # Render finding cards
        console.print("\n[bold underline]Detailed Findings:[/]")
        
        order = ["critical", "high", "medium", "low"]
        for sev_level in order:
            list_f = findings_by_severity.get(sev_level, [])
            if not list_f:
                continue
            
            sev_color = SEVERITY_COLORS.get(sev_level, "white")
            
            for f in list_f:
                sev_tag = f"[{sev_color}]{f.severity.upper()}[/{sev_color}]"
                card_text = (
                    f"[bold]Rule ID:[/] [cyan]{f.rule_id}[/]\n"
                    f"[bold]Location:[/] [cyan]{f.file_path}:{f.line}:{f.column}[/]\n"
                    f"[bold]Description:[/] {f.message}\n"
                )
                
                if f.code_snippet:
                    card_text += f"\n[bold]Code Snippet:[/]\n{f.code_snippet}\n"

                if f.suggested_fix:
                    card_text += f"\n[green bold][SUGGESTION] Suggested Fix:[/]\n[green]{f.suggested_fix}[/]\n"
                
                console.print(Panel(
                    card_text,
                    title=f"{sev_tag} Vulnerability",
                    border_style=sev_color
                ))

        console.print(f"\n[red bold][FAIL] {len(vulnerability_findings)} potential issues found in the codebase.[/]")

    # Render HTTP Status Code Catalog Table
    if catalog_findings:
        console.print("\n[bold underline]REST API HTTP Status Code Catalog:[/]")
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Status Code & Description", style="cyan", width=35)
        table.add_column("File Location", style="green", width=45)
        table.add_column("Source Context", style="white")

        # Sort catalog by file and line
        catalog_findings.sort(key=lambda x: (x.file_path, x.line))
        for f in catalog_findings:
            clean_msg = f.message.replace("API returns HTTP status: ", "").replace("API raises HTTP status: ", "")
            # Extract marked line from snippet
            source_line = ""
            if f.code_snippet:
                for line in f.code_snippet.splitlines():
                    if ">" in line:
                        source_line = line.replace(">", "").strip()
                        break
                if not source_line:
                    source_line = f.code_snippet.splitlines()[-1].strip()
            table.add_row(
                clean_msg,
                f"{f.file_path}:{f.line}:{f.column}",
                source_line
            )
        console.print(table)
        console.print()

@app.callback()
def main():
    pass

if __name__ == "__main__":
    app()
