"""Core data models used across ingestion, detection, and graph modules."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EventSource(str, Enum):
    AUTH = "auth"
    CLOUD = "cloud"
    ENDPOINT = "endpoint"
    GENERIC = "generic"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogEvent(BaseModel):
    """A normalized security event, regardless of original source format."""

    event_id: str
    source: EventSource
    timestamp: datetime
    user: Optional[str] = None
    host: Optional[str] = None
    source_ip: Optional[str] = None
    country: Optional[str] = None
    action: str
    resource: Optional[str] = None
    success: bool = True
    raw: dict = Field(default_factory=dict)


class AttackTechnique(BaseModel):
    """A MITRE ATT&CK technique reference."""

    technique_id: str  # e.g. "T1078.004"
    name: str  # e.g. "Valid Accounts: Cloud Accounts"
    tactic: str  # e.g. "Initial Access", "Privilege Escalation"


class IOCMatch(BaseModel):
    """A match against a threat-intelligence indicator of compromise."""

    indicator: str  # the IP/domain/hash that matched
    indicator_type: str  # "ip" | "domain" | "hash"
    source: str  # name of the feed/list that produced the match
    reputation: str  # e.g. "malicious", "suspicious"
    description: Optional[str] = None


class Finding(BaseModel):
    """An anomaly or detection produced by the detection engine."""

    finding_id: str
    rule: str
    severity: Severity
    title: str
    description: str
    user: Optional[str] = None
    host: Optional[str] = None
    related_event_ids: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    timestamp: datetime
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    ioc_matches: list[IOCMatch] = Field(default_factory=list)
    cvss_score: Optional[float] = None  # populated externally (e.g. from a vuln scanner), 0-10
    llm_summary: Optional[str] = None


class Asset(BaseModel):
    """A node in the attack graph: host, user, or resource."""

    asset_id: str
    kind: str  # "host" | "user" | "resource"
    criticality: float = 1.0  # 0-10, business criticality of this asset
    cvss_score: Optional[float] = None  # 0-10, worst known unpatched vuln on this asset (external input)
    tags: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    """A directed relationship/permission edge between two assets."""

    source: str
    target: str
    relation: str  # e.g. "can_login", "can_reach", "has_permission_on"
    weight: float = 1.0  # lower = easier to traverse


class AttackPath(BaseModel):
    """A ranked path from an entry point to a critical asset."""

    path_id: str
    nodes: list[str]
    total_risk: float
    entry_point: str
    target: str
    rationale: str
