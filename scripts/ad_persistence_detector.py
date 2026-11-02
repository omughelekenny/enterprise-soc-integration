#!/usr/bin/env python3
import json

sample_event_4698 = {
    "timestamp": "2026-11-02T19:15:22Z",
    "host": "DC (192.168.2.10)",
    "event_id": 4698,
    "subject_user": "LAB\\j.doe",
    "task_name": "\\WindowsUpdaterSvc",
    "command": "powershell.exe",
    "arguments": "-NoP -W Hidden -Enc JABzAD0A",
    "run_as": "SYSTEM"
}

def analyze_task(event):
    suspicious_flags = ["-enc", "-w hidden", "-nop", "powershell"]
    full_cmd = f"{event['command']} {event['arguments']}".lower()
    matched = [flag for flag in suspicious_flags if flag in full_cmd]
    
    if event["event_id"] == 4698 and matched:
        alert = {
            "incident_id": "INC-2026-1102",
            "rule_name": "UC-AD-005: Suspicious Scheduled Task Created",
            "severity": "CRITICAL (P1)",
            "event_id": 4698,
            "host": event["host"],
            "account_name": event["subject_user"],
            "task_name": event["task_name"],
            "payload_executed": f"{event['command']} {event['arguments']}",
            "mitre_attack": ["Persistence (TA0003)", "Scheduled Task (T1053.005)"],
            "recommended_action": "Remove task WindowsUpdaterSvc on DC, disable account, and decode the PowerShell command."
        }
        print("=== [SIEM01] Running Scheduled Task Persistence Rule: UC-AD-005 ===")
        print(f"[INGESTED] {event['timestamp']} | Host: {event['host']} | EventID: {event['event_id']} | User: {event['subject_user']} | Task: {event['task_name']}")
        print("\n=== [ALERT TRIGGERED - CRITICAL ESCALATION GENERATED] ===")
        print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    analyze_task(sample_event_4698)
