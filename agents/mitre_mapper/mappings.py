"""
CortexSOC -- Static MITRE ATT&CK mappings for the MVP.
"""
from __future__ import annotations

from typing import TypedDict


class MitreTechnique(TypedDict):
    tactic: str
    technique_id: str
    technique_name: str


MITRE_MAPPINGS: dict[str, list[MitreTechnique]] = {
    "credential_access": [
        {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
        }
    ],
    "reconnaissance": [
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1595",
            "technique_name": "Active Scanning",
        }
    ],
    "initial_access": [
        {
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
        }
    ],
    "malware": [
        {
            "tactic": "Execution",
            "technique_id": "T1204",
            "technique_name": "User Execution",
        },
        {
            "tactic": "Defense Evasion",
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
        },
    ],
    "command_and_control": [
        {
            "tactic": "Command and Control",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
        }
    ],
    "lateral_movement": [
        {
            "tactic": "Lateral Movement",
            "technique_id": "T1021",
            "technique_name": "Remote Services",
        }
    ],
    "anomalous_activity": [
        {
            "tactic": "Discovery",
            "technique_id": "T1087",
            "technique_name": "Account Discovery",
        }
    ],
}


def lookup_mitre_techniques(category: str | None) -> list[MitreTechnique]:
    """Return static ATT&CK techniques for a threat category."""
    if not category:
        return []
    return list(MITRE_MAPPINGS.get(category, []))
