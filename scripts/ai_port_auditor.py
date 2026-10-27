#!/usr/bin/env python3
"""
AI Inference Port & Unauthenticated Endpoint Auditor
Environment: lab.local (siem01)
Framework Mapping: OWASP LLM10 (Model Theft / Unauthenticated API Exposure), STRIDE (Denial of Service / Elevation of Privilege)
"""

import socket
import json
from datetime import datetime

LOG_FILE = "/var/log/ai_guardrail.json"

# Common Local LLM & AI Inference Ports
AI_PORTS = {
    11434: "Ollama LLM API",
    1234: "LM Studio Inference Server",
    7860: "Gradio / WebUI AI Interface",
    8000: "vLLM / FastAPI Model Server",
    5000: "Flask / Text-Gen AI API"
}

TARGET_HOST = "192.168.6.2"  # siem01 / AI host IP in lab.local

def log_siem_event(host, port, service, status, severity, detail):
    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domain": "lab.local",
        "target_host": host,
        "port": port,
        "ai_service": service,
        "event_type": status,
        "severity": severity,
        "detail": detail
    }
    json_output = json.dumps(entry)
    print(json_output)
    try:
        with open(LOG_FILE, "a") as lf:
            lf.write(json_output + "\n")
    except PermissionError:
        pass

def audit_ai_ports(host):
    print(f"=== Auditing {host} for Exposed AI Inference Endpoints ===")
    for port, service in AI_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((host, port))
        if result == 0:
            log_siem_event(
                host=host,
                port=port,
                service=service,
                status="EXPOSED_AI_INFERENCE_PORT",
                severity="HIGH",
                detail=f"Unauthenticated {service} port {port}/tcp exposed on network interface. Bypass risk for AI guardrails."
            )
            print(f"[ALERT - OPEN]   Port {port}/tcp ({service}) is EXPOSED on {host}!\n")
        else:
            print(f"[CLOSED/SAFE]    Port {port}/tcp ({service}) is not exposed.")
        sock.close()

if __name__ == "__main__":
    audit_ai_ports(TARGET_HOST)
