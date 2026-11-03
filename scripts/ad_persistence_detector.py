#!/usr/bin/env python3
"""
AD Scheduled Task Persistence Detector
Environment: lab.local (siem01)
Use Case: Detecting hidden/encoded PowerShell persistence via Event ID 4698
"""

import json
import re
from datetime import datetime

# Simulated telemetry matching the real event captured on DC.lab.local
TELEMETRY_STREAM = [
    {
        "timestamp": "2026-11-02T19:17:48Z",
        "host": "DC.lab.local",
        "event_id": 4698,
        "subject_user": "Administrator",
        "task_name": "\\WindowsUpdaterSvc",
        "command": "powershell.exe",
        "arguments": "-NoP -W Hidden -Enc JABzAD0A"
    }
]

SUSPICIOUS_FLAGS = ["-enc", "-w hidden", "-nop", "powershell"]

def run_detection():
    print("=== [SIEM01] Running Scheduled Task Persistence Detection: UC-AD-005 ===\n")

    for event in TELEMETRY_STREAM:
        full_command = f"{event['command']} {event['arguments']}".strip()
        is_suspicious = any(flag in full_command.lower() for flag in SUSPICIOUS_FLAGS)
        severity = "CRITICAL" if is_suspicious else "HIGH"

        print(f"[INGESTED] {event['timestamp']} | Host: {event['host']} | "
              f"EventID: {event['event_id']} | User: {event['subject_user']} | "
              f"Task: {event['task_name']} | Command: {full_command}")

        if is_suspicious:
            alert = {
                "incident_id": "INC-2026-1102",
                "rule_name": "UC-AD-005: Scheduled Task Persistence with Obfuscated PowerShell",
                "severity": severity,
                "event_id": event["event_id"],
                "host": event["host"],
                "created_by": event["subject_user"],
                "task_name": event["task_name"],
                "payload": full_command,
                "mitre_technique": "T1053.005 (Scheduled Task Persistence)",
                "recommended_action": f"Delete task {event['task_name']}, decode the Base64 payload, "
                                       f"and verify {event['subject_user']} is the legitimate account owner."
            }
            print("\n=== [DETECTION TRIGGERED - ALERT GENERATED] ===")
            print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    run_detection()
