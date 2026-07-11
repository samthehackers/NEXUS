from datetime import datetime, timezone

import pytest

from nexus.llm.investigate import LLMInvestigator, build_investigation_prompt
from nexus.models import AttackPath, AttackTechnique, Finding, IOCMatch, Severity


def _sample_finding() -> Finding:
    return Finding(
        finding_id="f1",
        rule="impossible_travel",
        severity=Severity.HIGH,
        title="Impossible travel for user jane.doe",
        description="jane.doe logged in from NG then DE 20 minutes later.",
        user="jane.doe",
        host="vpn-gw-2",
        related_event_ids=["e1", "e2"],
        risk_score=7.5,
        timestamp=datetime.now(timezone.utc),
        attack_techniques=[AttackTechnique(technique_id="T1078", name="Valid Accounts", tactic="Initial Access")],
        ioc_matches=[IOCMatch(indicator="45.10.0.9", indicator_type="ip", source="static_list", reputation="malicious")],
    )


def _sample_path() -> AttackPath:
    return AttackPath(
        path_id="p1",
        nodes=["jane.doe", "jump-host-1", "db-prod-01"],
        total_risk=18.5,
        entry_point="jane.doe",
        target="db-prod-01",
        rationale="2-hop path",
    )


def test_build_investigation_prompt_includes_key_facts():
    prompt = build_investigation_prompt(_sample_finding(), [_sample_path()])
    assert "jane.doe" in prompt
    assert "impossible_travel" in prompt
    assert "T1078" in prompt
    assert "45.10.0.9" in prompt
    assert "db-prod-01" in prompt


def test_build_investigation_prompt_handles_no_paths():
    prompt = build_investigation_prompt(_sample_finding(), None)
    assert "jane.doe" in prompt


class _FakeTextBlock:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class _FakeResponse:
    def __init__(self, text: str):
        self.content = [_FakeTextBlock(text)]


class _FakeMessages:
    def __init__(self, response_text: str):
        self._response_text = response_text
        self.last_call_kwargs = None

    def create(self, **kwargs):
        self.last_call_kwargs = kwargs
        return _FakeResponse(self._response_text)


class _FakeAnthropicClient:
    def __init__(self, response_text: str = "Account compromise likely; investigate jane.doe's session."):
        self.messages = _FakeMessages(response_text)


def test_llm_investigator_summarize_with_fake_client():
    fake_client = _FakeAnthropicClient()
    investigator = LLMInvestigator(client=fake_client)
    summary = investigator.summarize(_sample_finding(), [_sample_path()])

    assert "jane.doe" in summary or "Account compromise" in summary
    assert fake_client.messages.last_call_kwargs["max_tokens"] == 300
    assert "jane.doe" in fake_client.messages.last_call_kwargs["messages"][0]["content"]


def test_llm_investigator_requires_api_key_without_injected_client(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="API key"):
        LLMInvestigator()


def test_llm_investigator_accepts_explicit_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # We only verify it gets past the "no key" check and attempts real client
    # construction (which requires the anthropic package, installed as a dev dep).
    investigator = LLMInvestigator(api_key="sk-test-fake-key-not-real")
    assert investigator._model == "claude-sonnet-4-5"
