#!/usr/bin/env python3
"""
AI Token Budget & Rate-Limiting Gateway (DoS / Denial-of-Wallet Defense)
Environment: lab.local (siem01)
Framework Mapping: OWASP LLM04 / LLM10 (Unbounded Consumption), STRIDE (Denial of Service)
"""

import time
import json
from datetime import datetime
from collections import defaultdict

LOG_FILE = "/var/log/ai_guardrail.json"

# Security Thresholds
MAX_REQUESTS_PER_WINDOW = 3
WINDOW_SECONDS = 60
MAX_TOKENS_PER_PROMPT = 150  # Simulated token cap per query

# Track user request timestamps
user_request_history = defaultdict(list)

def estimate_tokens(prompt_text):
    # Rough industry approximation: ~4 characters per token
    return max(1, len(prompt_text) // 4)

def log_siem_event(user, event_type, severity, tokens, detail):
    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domain": "lab.local",
        "source_user": user,
        "event_type": event_type,
        "severity": severity,
        "estimated_tokens": tokens,
        "detail": detail
    }
    json_output = json.dumps(entry)
    print(json_output)
    try:
        with open(LOG_FILE, "a") as lf:
            lf.write(json_output + "\n")
    except PermissionError:
        pass

def process_ai_request(user, prompt):
    now = time.time()
    est_tokens = estimate_tokens(prompt)

    # 1. Clean up requests older than the 60-second window
    user_request_history[user] = [
        ts for ts in user_request_history[user] if now - ts < WINDOW_SECONDS
    ]

    # 2. Check Per-User Rate Limit (Burst Flood Protection)
    if len(user_request_history[user]) >= MAX_REQUESTS_PER_WINDOW:
        log_siem_event(
            user=user,
            event_type="OWASP_LLM10_RATE_LIMIT_EXCEEDED",
            severity="HIGH",
            tokens=est_tokens,
            detail=f"User exceeded {MAX_REQUESTS_PER_WINDOW} AI requests within {WINDOW_SECONDS}s (HTTP 429 Throttled)."
        )
        print(f"[HTTP 429 BLOCKED] {user} throttled — Rate limit exceeded ({MAX_REQUESTS_PER_WINDOW} req/{WINDOW_SECONDS}s)\n")
        return False

    # 3. Check Token Context Exhaustion Limit
    if est_tokens > MAX_TOKENS_PER_PROMPT:
        log_siem_event(
            user=user,
            event_type="OWASP_LLM10_TOKEN_QUOTA_EXCEEDED",
            severity="MEDIUM",
            tokens=est_tokens,
            detail=f"Prompt size ({est_tokens} tokens) exceeds max quota of {MAX_TOKENS_PER_PROMPT} tokens."
        )
        print(f"[QUOTA BLOCKED]    {user} blocked — Prompt too large ({est_tokens} tokens > {MAX_TOKENS_PER_PROMPT} max)\n")
        return False

    # 4. Record and allow valid request
    user_request_history[user].append(now)
    log_siem_event(
        user=user,
        event_type="AI_REQUEST_ACCEPTED",
        severity="INFO",
        tokens=est_tokens,
        detail=f"Request processed ({len(user_request_history[user])}/{MAX_REQUESTS_PER_WINDOW} window quota used)."
    )
    print(f"[HTTP 200 ALLOWED] {user} — {est_tokens} tokens ({len(user_request_history[user])}/{MAX_REQUESTS_PER_WINDOW} requests used)\n")
    return True

if __name__ == "__main__":
    print("=== Testing lab.local AI Rate-Limiter & Token Quota Gateway ===\n")

    # Simulate an oversized payload trying to exhaust the model context window
    oversized_prompt = "Summarize this log: " + ("ERROR_DUMP_0x99482_STACK_OVERFLOW " * 30)
    process_ai_request("LAB\\hr_user", oversized_prompt)

    # Simulate a rapid burst attack from a compromised account (4 requests in a row)
    for i in range(1, 5):
        print(f"--- Burst Request #{i} from LAB\\sales_user ---")
        process_ai_request("LAB\\sales_user", f"Generate sales forecast report batch #{i}")
