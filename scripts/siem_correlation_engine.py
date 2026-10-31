#!/usr/bin/env python3
"""
SOC Multi-Event Correlation & Automated Escalation Summary Generator
Environment: lab.local (siem01 - 192.168.6.2)
Use Case: Correlating Brute-Force (4625) -> Valid Logon (4624) -> Domain Admin Escalation (4728)
"""

import json
from datetime import datetime

# Simulated telemetry stream ingested from DC (192.168.2.10) & IT-WS01 (192.168.2.20)
TELEMETRY_STREAM = [
    {"timestamp": "2026-10-28T18:01:10Z", "host": "DC", "event_id": 4625, "user": "LAB\\j.doe", "src_ip": "192.168.2.20", "desc": "Failed Logon (Bad Password)"},
    {"timestamp": "2026-10-28T18:01:14Z", "host": "DC", "event_id": 4625, "user": "LAB\\j.doe", "src_ip": "192.168.2.20", "desc": "Failed Logon (Bad Password)"},
    {"timestamp": "2026-10-28T18:01:19Z", "host": "DC", "event_id": 4625, "user": "LAB\\j.doe", "src_ip": "192.168.2.20", "desc": "Failed Logon (Bad Password)"},
    {"timestamp": "2026-10-28T18:01:45Z", "host": "DC", "event_id": 4624, "user": "LAB\\j.doe", "src_ip": "192.168.2.20", "desc": "Successful Network Logon (LogonType 3)"},
    {"timestamp": "2026-10-28T18:02:30Z", "host": "DC", "event_id": 4728, "user": "LAB\\j.doe", "src_ip": "192.168.2.20", "desc": "Member added to Security-Enabled Global Group: Domain Admins"}
]

def run_correlation():
    print("=== [SIEM01] Running Multi-Stage Event Correlation Rule: UC-AD-004 ===\n")
    
    failed_attempts = [e for e in TELEMETRY_STREAM if e["event_id"] == 4625]
    success_logons = [e for e in TELEMETRY_STREAM if e["event_id"] == 4624]
    priv_escalations = [e for e in TELEMETRY_STREAM if e["event_id"] == 4728]

    for event in TELEMETRY_STREAM:
        print(f"[INGESTED] {event['timestamp']} | Host: {event['host']} | EventID: {event['event_id']} | User: {event['user']} | SrcIP: {event['src_ip']} | {event['desc']}")

    if len(failed_attempts) >= 3 and success_logons and priv_escalations:
        target_user = priv_escalations[0]["user"]
        src_ip = priv_escalations[0]["src_ip"]
        
        alert = {
            "incident_id": "INC-2026-1028",
            "rule_name": "UC-AD-004: Brute-Force Followed by Success & Domain Admin Escalation",
            "severity": "CRITICAL (P1)",
            "correlated_events": [4625, 4624, 4728],
            "compromised_account": target_user,
            "source_workstation_ip": src_ip,
            "target_asset": "DC (192.168.2.10)",
            "mitre_tactics": ["TA0006 Credential Access (T1110)", "TA0004 Privilege Escalation (T1098)"],
            "recommended_action": "Isolate 192.168.2.20, disable LAB\\j.doe in AD, and remove from Domain Admins."
        }
        
        print("\n=== [CORRELATION TRIGGERED - CRITICAL ESCALATION GENERATED] ===")
        print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    run_correlation()
