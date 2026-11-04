#!/usr/bin/env python3
import json

sample_event_4769 = {
    "timestamp": "2026-11-03T09:10:00Z",
    "host": "DC (192.168.2.10)",
    "event_id": 4769,
    "account_name": "j.doe@LAB.LOCAL",
    "service_name": "MSSQLSvc/DC.lab.local:1433",
    "ticket_encryption": "0x17",
    "client_ip": "192.168.2.10"
}

def detect_kerberoasting(event):
    if event["event_id"] == 4769 and event["service_name"] != "krbtgt" and not event["service_name"].endswith("$"):
        if event["ticket_encryption"] in ["0x17", "0x18"] or "MSSQLSvc" in event["service_name"]:
            alert = {
                "incident_id": "INC-2026-1103",
                "rule_name": "UC-AD-006: Kerberoasting TGS Request Detected (Event ID 4769)",
                "severity": "CRITICAL (P1)",
                "event_id": 4769,
                "host": event["host"],
                "requesting_user": event["account_name"],
                "target_spn": event["service_name"],
                "encryption_type": event["ticket_encryption"],
                "mitre_attack": ["Credential Access (TA0006)", "Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)"],
                "recommended_action": "Rotate service account password, enforce AES256 encryption on SPN, and isolate requesting host."
            }
            print("=== [SIEM01] Running Kerberoasting Detection Rule: UC-AD-006 ===")
            print(f"[INGESTED] {event['timestamp']} | Host: {event['host']} | EventID: {event['event_id']} | User: {event['account_name']} | SPN: {event['service_name']} | Enc: {event['ticket_encryption']}")
            print("\n=== [ALERT TRIGGERED - CRITICAL ESCALATION GENERATED] ===")
            print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    detect_kerberoasting(sample_event_4769)
