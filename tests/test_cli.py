from pathlib import Path
import json

from typer.testing import CliRunner

from nexus.cli import app

runner = CliRunner()
SAMPLE_LOGS = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_auth_logs.json"
SAMPLE_TOPOLOGY = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_topology.json"
SAMPLE_IOC_FEED = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_ioc_feed.json"


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "NEXUS" in result.stdout


def test_detect_command(tmp_path):
    result = runner.invoke(app, ["detect", "--logs", str(SAMPLE_LOGS), "--log-type", "auth", "--out", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "nexus_report.json").exists()


def test_graph_command(tmp_path):
    result = runner.invoke(app, [
        "graph", "--topology", str(SAMPLE_TOPOLOGY),
        "--entry-point", "workstation-12",
        "--out", str(tmp_path),
    ])
    assert result.exit_code == 0
    assert (tmp_path / "nexus_report.json").exists()


def test_run_full_pipeline(tmp_path):
    out_dir = tmp_path / "report"
    result = runner.invoke(app, [
        "run",
        "--logs", str(SAMPLE_LOGS), "--log-type", "auth",
        "--topology", str(SAMPLE_TOPOLOGY),
        "--entry-point", "workstation-12",
        "--out", str(out_dir),
    ])
    assert result.exit_code == 0
    assert (out_dir / "nexus_report.json").exists()
    assert (out_dir / "nexus_report.html").exists()


def test_detect_command_with_ioc_feed(tmp_path):
    result = runner.invoke(app, [
        "detect", "--logs", str(SAMPLE_LOGS), "--log-type", "auth",
        "--ioc-feed", str(SAMPLE_IOC_FEED),
        "--out", str(tmp_path),
    ])
    assert result.exit_code == 0
    report = json.loads((tmp_path / "nexus_report.json").read_text())
    all_iocs = [m for f in report["findings"] for m in f["ioc_matches"]]
    assert any(m["indicator"] == "45.10.0.9" for m in all_iocs)


def test_detect_command_llm_summary_skips_gracefully_without_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = runner.invoke(app, [
        "detect", "--logs", str(SAMPLE_LOGS), "--log-type", "auth",
        "--llm-summary",
        "--out", str(tmp_path),
    ])
    assert result.exit_code == 0
    assert "Skipping LLM summaries" in result.stdout
