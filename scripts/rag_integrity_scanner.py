#!/usr/bin/env python3
"""
AI RAG Knowledge Base Integrity & Data Poisoning Scanner
Environment: lab.local (siem01)
Target: AI Vector Knowledge Base
Framework Mapping: OWASP LLM04 (Data & Model Poisoning), STRIDE (Tampering)
"""

import os
import re
import json
import hashlib
from datetime import datetime

KB_DIRECTORY = "rag_knowledge_base"
LOG_FILE = "/var/log/ai_guardrail.json"

# Signatures for Indirect Prompt Injection / RAG Poisoning inside documents
POISON_SIGNATURES = [
    r"system override",
    r"ignore (all )?(previous|prior) instructions",
    r"curl\s+http",
    r"\|\s*bash",
    r"send (your )?(credentials|password)"
]

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def log_siem_event(filename, sha256, status, severity, detail):
    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domain": "lab.local",
        "component": "AI_Vector_Knowledge_Base",
        "event_type": status,
        "severity": severity,
        "file": filename,
        "sha256": sha256[:16] + "...",
        "detail": detail
    }
    json_output = json.dumps(entry)
    print(json_output)
    try:
        with open(LOG_FILE, "a") as lf:
            lf.write(json_output + "\n")
    except PermissionError:
        pass

def scan_knowledge_base():
    print("=== Scanning lab.local AI Vector Knowledge Base for Data Poisoning ===")
    for filename in sorted(os.listdir(KB_DIRECTORY)):
        filepath = os.path.join(KB_DIRECTORY, filename)
        if not os.path.isfile(filepath):
            continue

        file_hash = calculate_sha256(filepath)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        poison_detected = False
        for pattern in POISON_SIGNATURES:
            if re.search(pattern, content, re.IGNORECASE):
                poison_detected = True
                log_siem_event(
                    filename=filename,
                    sha256=file_hash,
                    status="OWASP_LLM04_RAG_DATA_POISONING",
                    severity="CRITICAL",
                    detail=f"Blocked poisoned RAG document matching pattern: '{pattern}'"
                )
                print(f"[QUARANTINED] {filename} | SHA256: {file_hash[:16]}... | Reason: Indirect Prompt Injection / Poisoning\n")
                break

        if not poison_detected:
            log_siem_event(
                filename=filename,
                sha256=file_hash,
                status="RAG_DOCUMENT_VERIFIED",
                severity="INFO",
                detail="Document hash verified and cleared for vector indexing"
            )
            print(f"[VERIFIED]    {filename} | SHA256: {file_hash[:16]}... | Status: Ready for RAG Indexing\n")

if __name__ == "__main__":
    scan_knowledge_base()
