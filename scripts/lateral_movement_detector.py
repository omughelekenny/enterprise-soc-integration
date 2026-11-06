#!/usr/bin/env python3
"""
Correlates Windows Event ID 4648 (Explicit Credential Logon) and Event ID 5140
(Administrative Share Access) by normalizing TargetUserName and SubjectUserName.
"""
import json

sample_telemetry = [
    {
        "timestamp": "2026-11-06T19:10:04Z",
        "host": "DC.lab.local (192.168.2.10)",
        "event_id": 4648,
        "subject_user": "IT-WS01$",
        "target_user": "j.doe",
        "target_server": "DC.lab.local",
        "source_ip": "192.168.2.20"
    },
    {
        "timestamp": "2026-11-06T19:10:06Z",
        "host": "DC.lab.local (192.168.2.10)",
        "event_id": 5140,
        "subject_user": "j.doe",
        "share_name": "\\\\*\\ADMIN$",
        "source_ip": "192.168.2.20"
    },
    {
        "timestamp": "2026-11-06T19:10:09Z",
        "host": "DC.lab.local (192.168.2.10)",
        "event_id": 5140,
        "subject_user": "j.doe",
        "share_name": "\\\\*\\C$",
        "source_ip": "192.168.2.20"
    }
]

def correlate_smb_pivot(events):
    grouped = {}
    for ev in events:
        user = ev.get("target_user") if ev["event_id"] == 4648 else ev.get("subject_user")
        if not user or user.endswith("$"):
            continue
        key = (ev["host"], user, ev.get("source_ip", "unknown"))
        grouped.setdefault(key, {"events": set(), "shares": set(), "first_seen": ev["timestamp"], "last_seen": ev["timestamp"]})
        grouped[key]["events"].add(ev["event_id"])
        grouped[key]["last_seen"] = ev["timestamp"]
        if ev.get("share_name"):
            grouped[key]["shares"].add(ev["share_name"])

    for (host, user, src_ip), data in grouped.items():
        admin_shares = [s for s in data["shares"] if s.endswith("ADMIN$") or s.endswith("C$")]
        if 4648 in data["events"] and 5140 in data["events"] and admin_shares:
            report = {
                "incident_id": "INC-2026-1106",
                "summary": "Explicit credential logon followed by administrative SMB share mount",
                "host": host,
                "account_used": user,
                "source_ip": src_ip,
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "correlated_event_ids": sorted(list(data["events"])),
                "shares_accessed": sorted(admin_shares),
                "mitre_mapping": ["T1021.002 (SMB/Windows Admin Shares)", "T1550 (Use Alternate Authentication Material)"]
            }
            print(json.dumps(report, indent=2))

if __name__ == "__main__":
    correlate_smb_pivot(sample_telemetry)
