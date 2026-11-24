#!/usr/bin/env python3
"""
Automated SOAR Containment Playbook simulator for INC-2026-MASTER.
Generates structured containment actions across Identity, Endpoint, and Network layers.
"""
import json
from datetime import datetime, timezone

incident_context = {
    "incident_id": "INC-2026-MASTER",
    "compromised_user": "j.doe",
    "unauthorized_group": "Domain Admins",
    "rogue_task": "\\WindowsUpdaterSvc",
    "targeted_spn": "MSSQLSvc/DC.lab.local:1433",
    "attacker_ip": "192.168.2.20",
    "target_host": "DC.lab.local (192.168.2.10)"
}

def execute_containment(ctx):
    playbook = {
        "incident_id": ctx["incident_id"],
        "executed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "CONTAINMENT_EXECUTED",
        "actions": [
            {"layer": "Identity", "action": f"Disable-ADAccount -Identity {ctx['compromised_user']}", "result": "SUCCESS"},
            {"layer": "Identity", "action": f"Remove-ADGroupMember '{ctx['unauthorized_group']}' -Members {ctx['compromised_user']}", "result": "SUCCESS"},
            {"layer": "Endpoint", "action": f"schtasks /delete /tn {ctx['rogue_task']} /f", "result": "SUCCESS"},
            {"layer": "Identity", "action": f"Rotate credentials & revoke SPN {ctx['targeted_spn']}", "result": "SUCCESS"},
            {"layer": "Network", "action": f"Block inbound/outbound traffic from {ctx['attacker_ip']} on {ctx['target_host']}", "result": "SUCCESS"}
        ]
    }
    print(json.dumps(playbook, indent=2))

if __name__ == "__main__":
    execute_containment(incident_context)
