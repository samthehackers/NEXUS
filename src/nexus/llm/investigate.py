"""Turns a raw Finding (+ any attack paths it feeds into) into an analyst-
readable investigation summary using the Anthropic API.

This is a real integration, not a canned template -- but it needs your own
API key at runtime (`ANTHROPIC_API_KEY` env var, or pass one explicitly).
NEXUS will not fabricate a summary if no client/key is available; it raises
a clear error instead, so a missing key fails loudly rather than silently
returning fake analysis.

The Anthropic client is injectable so this module is fully unit-testable
without hitting the network or needing a real key (see tests/test_llm.py).
"""

from __future__ import annotations

import os
from typing import Any, Protocol

from nexus.models import AttackPath, Finding

DEFAULT_MODEL = "claude-sonnet-4-5"

_SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing a concise investigation summary "
    "for a single security finding. Ground every claim ONLY in the facts "
    "given to you -- do not invent usernames, IPs, systems, or techniques "
    "that were not provided. Explain in 2-4 sentences why this matters and "
    "what an analyst should do next. Do not use markdown formatting."
)


class _AnthropicClientProtocol(Protocol):
    """Minimal shape of the anthropic.Anthropic client this module needs,
    so tests can inject a fake without installing/mocking the real SDK."""

    messages: Any


def build_investigation_prompt(finding: Finding, related_paths: list[AttackPath] | None = None) -> str:
    """Builds the user-turn prompt sent to the model. Pure function, no
    network call -- kept separate so prompt construction is independently
    testable and reviewable.
    """
    lines = [
        f"Finding: {finding.title}",
        f"Rule: {finding.rule}",
        f"Severity: {finding.severity.value}",
        f"Description: {finding.description}",
    ]
    if finding.user:
        lines.append(f"User: {finding.user}")
    if finding.host:
        lines.append(f"Host: {finding.host}")
    if finding.attack_techniques:
        techniques = ", ".join(f"{t.technique_id} ({t.name})" for t in finding.attack_techniques)
        lines.append(f"MITRE ATT&CK techniques: {techniques}")
    if finding.ioc_matches:
        iocs = ", ".join(f"{m.indicator} [{m.reputation}] via {m.source}" for m in finding.ioc_matches)
        lines.append(f"Threat intel matches: {iocs}")
    if related_paths:
        for p in related_paths[:3]:
            lines.append(
                f"Related attack path: {' -> '.join(p.nodes)} "
                f"(risk {p.total_risk}, reaches critical asset '{p.target}')"
            )
    lines.append("\nWrite the investigation summary now.")
    return "\n".join(lines)


class LLMInvestigator:
    """Generates investigation summaries via the Anthropic API.

    Usage:
        investigator = LLMInvestigator()  # reads ANTHROPIC_API_KEY from env
        summary = investigator.summarize(finding, related_paths)

    For tests or offline use, inject a fake client:
        investigator = LLMInvestigator(client=fake_client)
    """

    def __init__(self, client: _AnthropicClientProtocol | None = None, model: str = DEFAULT_MODEL,
                 api_key: str | None = None):
        if client is not None:
            self._client = client
        else:
            key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise RuntimeError(
                    "No Anthropic API key available. Set ANTHROPIC_API_KEY or pass "
                    "api_key=... explicitly. NEXUS will not generate a summary without one."
                )
            try:
                import anthropic
            except ImportError as exc:
                raise RuntimeError(
                    "The 'anthropic' package is required for LLM investigation summaries. "
                    "Install it with: pip install anthropic"
                ) from exc
            self._client = anthropic.Anthropic(api_key=key)
        self._model = model

    def summarize(self, finding: Finding, related_paths: list[AttackPath] | None = None) -> str:
        prompt = build_investigation_prompt(finding, related_paths)
        response = self._client.messages.create(
            model=self._model,
            max_tokens=300,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        text_blocks = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        return "\n".join(text_blocks).strip()
