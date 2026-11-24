#!/usr/bin/env python3
"""
Monitors Windows Event ID 1102 (Audit Log Cleared) and Event ID 4719
(System Audit Policy Changed) for Defense Evasion activity.
"""
import json

sample_events = [
    {
        "timestamp": "2026-11-24T10:15:02Z",
        "host": "DC.lab.local (192.168.2.10)",
        "event_id": 4719,
        "account_name": "LAB\\Administrator",
        "subcategory": "Logon",
        "change": "Success removed"
    },
    {
        "timestamp": "2026-11-24T10:15:11Z",
        "host": "DC.lab.local (192.168.2.10)",
        "event_id": 1102,
        "account_name": "LAB\\Administrator",
        "details": "The audit log was cleared."
    }
]

def check_defense_evasion(events):
    triggered = [e for e in events if e["event_id"] in (1102, 4719)]
    if triggered:
        alert = {
            "incident_id": "INC-2026-1124-EVASION",
            "rule_name": "UC-AD-008: Windows Security Log Cleared / Audit Policy Tampering",
            "severity": "CRITICAL (P1)",
            "host": triggered[0]["host"],
            "account_name": triggered[0]["account_name"],
            "event_ids": [e["event_id"] for e in triggered],
            "mitre_attack": ["T1070.001 (Clear Windows Event Logs)", "T1562.002 (Disable Windows Event Logging)"],
            "recommended_action": "Verify change window, preserve forwarded SIEM logs prior to wipe, and isolate compromised admin session."
        }
        print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    check_defense_evasion(sample_events)
