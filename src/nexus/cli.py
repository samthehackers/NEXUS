"""NEXUS CLI - AI-powered behavioral detection and attack path engine.

Examples:
    nexus detect --logs auth_logs.json --log-type auth
    nexus graph --topology topology.json --entry-point workstation-12
    nexus run --logs auth_logs.json --log-type auth --topology topology.json \\
        --entry-point workstation-12 --out ./nexus-report
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from nexus import __version__
from nexus.detection.anomaly import run_all_detectors
from nexus.graph.engine import build_graph, load_topology
from nexus.graph.ranking import find_attack_paths
from nexus.ingest.parsers import load_events
from nexus.intel.ioc import StaticReputationEnricher, enrich_events, enrich_findings
from nexus.models import AttackPath, Finding
from nexus.report.generator import write_reports

app = typer.Typer(add_completion=False, help="NEXUS - TrustGeeks Security behavioral detection & attack path engine.")
console = Console()


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return
    table = Table(title="NEXUS Findings")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Title")
    table.add_column("User")
    table.add_column("Risk", justify="right")
    for f in findings:
        color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}[f.severity.value]
        table.add_row(f"[{color}]{f.severity.value.upper()}[/{color}]", f.rule, f.title, f.user or "-", str(f.risk_score))
    console.print(table)


def _apply_ioc_enrichment(events, findings: list[Finding], ioc_feed: Path | None) -> list[Finding]:
    if not ioc_feed:
        return findings
    enricher = StaticReputationEnricher.from_file(ioc_feed)
    event_matches = enrich_events(events, enricher)
    return enrich_findings(findings, event_matches)


def _apply_llm_summaries(findings: list[Finding], paths: list[AttackPath], top_n: int) -> list[Finding]:
    from nexus.llm.investigate import LLMInvestigator

    try:
        investigator = LLMInvestigator()
    except RuntimeError as exc:
        console.print(f"[yellow]Skipping LLM summaries: {exc}[/yellow]")
        return findings

    updated = list(findings)
    for i, finding in enumerate(updated[:top_n]):
        related = [p for p in paths if finding.host in p.nodes or finding.user in p.nodes]
        try:
            summary = investigator.summarize(finding, related)
            updated[i] = finding.model_copy(update={"llm_summary": summary})
        except Exception as exc:  # noqa: BLE001 - network/API errors shouldn't kill the whole run
            console.print(f"[yellow]LLM summary failed for '{finding.title}': {exc}[/yellow]")
    return updated


@app.command()
def version() -> None:
    """Print the NEXUS version."""
    console.print(f"NEXUS v{__version__}")


@app.command()
def detect(
    logs: Path = typer.Option(..., help="Path to JSON log file"),
    log_type: str = typer.Option("auth", help="Log type: auth | cloud | generic"),
    ioc_feed: Path = typer.Option(None, help="Optional static IOC reputation JSON to enrich findings"),
    llm_summary: bool = typer.Option(False, help="Generate LLM investigation summaries (needs ANTHROPIC_API_KEY)"),
    llm_summary_top_n: int = typer.Option(5, help="Max number of findings to summarize (cost control)"),
    out: Path = typer.Option(None, help="Optional directory to write JSON/HTML reports"),
) -> None:
    """Run behavioral anomaly detection over a log file."""
    events = load_events(logs, log_type)
    console.print(f"Loaded [bold]{len(events)}[/bold] events from {logs}")
    findings = run_all_detectors(events)
    findings = _apply_ioc_enrichment(events, findings, ioc_feed)
    if llm_summary:
        findings = _apply_llm_summaries(findings, [], llm_summary_top_n)
    _print_findings(findings)
    if out:
        json_path, html_path = write_reports(findings, [], out)
        console.print(f"Reports written: {json_path}, {html_path}")


@app.command()
def graph(
    topology: Path = typer.Option(..., help="Path to topology JSON (assets + edges)"),
    entry_point: list[str] = typer.Option(..., help="Asset ID(s) to treat as attacker entry points"),
    criticality_threshold: float = typer.Option(7.0, help="Minimum criticality to treat an asset as a target"),
    out: Path = typer.Option(None, help="Optional directory to write JSON/HTML reports"),
) -> None:
    """Build the attack graph and rank paths to critical assets."""
    assets, edges = load_topology(topology)
    g = build_graph(assets, edges)
    console.print(f"Graph built: [bold]{g.number_of_nodes()}[/bold] assets, [bold]{g.number_of_edges()}[/bold] edges")

    paths = find_attack_paths(g, entry_point, criticality_threshold=criticality_threshold)
    if not paths:
        console.print("[green]No attack paths found to critical assets.[/green]")
    else:
        table = Table(title="Ranked Attack Paths")
        table.add_column("Risk", justify="right")
        table.add_column("Entry")
        table.add_column("Target")
        table.add_column("Path")
        for p in paths[:15]:
            table.add_row(str(p.total_risk), p.entry_point, p.target, " -> ".join(p.nodes))
        console.print(table)

    if out:
        json_path, html_path = write_reports([], paths, out)
        console.print(f"Reports written: {json_path}, {html_path}")


@app.command()
def run(
    logs: Path = typer.Option(..., help="Path to JSON log file"),
    log_type: str = typer.Option("auth", help="Log type: auth | cloud | generic"),
    topology: Path = typer.Option(..., help="Path to topology JSON (assets + edges)"),
    entry_point: list[str] = typer.Option(..., help="Asset ID(s) to treat as attacker entry points"),
    criticality_threshold: float = typer.Option(7.0, help="Minimum criticality to treat an asset as a target"),
    ioc_feed: Path = typer.Option(None, help="Optional static IOC reputation JSON to enrich findings"),
    llm_summary: bool = typer.Option(False, help="Generate LLM investigation summaries (needs ANTHROPIC_API_KEY)"),
    llm_summary_top_n: int = typer.Option(5, help="Max number of findings to summarize (cost control)"),
    out: Path = typer.Option(Path("./nexus-report"), help="Directory to write the combined report"),
) -> None:
    """Full pipeline: detect anomalies in logs, then map them onto the attack graph."""
    events = load_events(logs, log_type)
    findings = run_all_detectors(events)
    findings = _apply_ioc_enrichment(events, findings, ioc_feed)
    console.print(f"[bold]{len(findings)}[/bold] findings from {len(events)} events")

    assets, edges = load_topology(topology)
    g = build_graph(assets, edges)
    paths = find_attack_paths(g, entry_point, criticality_threshold=criticality_threshold)
    console.print(f"[bold]{len(paths)}[/bold] ranked attack paths")

    if llm_summary:
        findings = _apply_llm_summaries(findings, paths, llm_summary_top_n)

    _print_findings(findings)
    json_path, html_path = write_reports(findings, paths, out)
    console.print(f"\n[bold green]Reports written:[/bold green] {json_path}, {html_path}")


if __name__ == "__main__":
    app()
