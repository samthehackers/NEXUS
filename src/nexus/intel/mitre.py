"""MITRE ATT&CK technique mapping for NEXUS detection rules.

Kept as an explicit, hand-maintained table rather than an inferred/ML
mapping -- an analyst should be able to look at this file and verify every
mapping against the ATT&CK framework directly.

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

from nexus.models import AttackTechnique

_TECHNIQUE_TABLE: dict[str, list[AttackTechnique]] = {
    "impossible_travel": [
        AttackTechnique(technique_id="T1078", name="Valid Accounts", tactic="Initial Access"),
        AttackTechnique(
            technique_id="T1078.004",
            name="Valid Accounts: Cloud Accounts",
            tactic="Defense Evasion",
        ),
    ],
    "off_hours_privileged_access": [
        AttackTechnique(technique_id="T1078", name="Valid Accounts", tactic="Privilege Escalation"),
    ],
    "mass_resource_access": [
        AttackTechnique(technique_id="T1530", name="Data from Cloud Storage", tactic="Collection"),
        AttackTechnique(technique_id="T1005", name="Data from Local System", tactic="Collection"),
    ],
    "privilege_escalation_chain": [
        AttackTechnique(
            technique_id="T1548",
            name="Abuse Elevation Control Mechanism",
            tactic="Privilege Escalation",
        ),
        AttackTechnique(technique_id="T1098", name="Account Manipulation", tactic="Persistence"),
    ],
}


def techniques_for_rule(rule: str) -> list[AttackTechnique]:
    """Return the ATT&CK techniques mapped to a detection rule.

    Returns an empty list (not an error) for an unmapped rule -- a finding
    without a mapping is still a valid finding, just without ATT&CK context
    until the table is extended.
    """
    return list(_TECHNIQUE_TABLE.get(rule, []))


def known_rules() -> list[str]:
    return list(_TECHNIQUE_TABLE.keys())
