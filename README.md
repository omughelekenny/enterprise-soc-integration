# Enterprise SOC Home Lab
A comprehensive enterprise-grade SOC home lab built on VMware Workstation, simulating a full corporate environment for blue team training and detection engineering.

# Tools
- Splunk, Wazuh, TheHive, Cortex, MISP, pfSense, Security Onion, FLARE VM
---

 Lab Infrastructure

| Component | IP Address | Role | Status |
|-----------|-----------|------|--------|
| Splunk SIEM | 192.168.6.2 | Log aggregation & correlation | ✅ Active |
| Wazuh Manager | 192.168.3.5 | XDR / HIDS | ✅ Active |
| TheHive | 192.168.6.3:9000 | Case management | ✅ Active |
| Cortex | 192.168.6.3:9001 | Automated enrichment | ✅ Active |
| MISP | 192.168.6.3:443 | Threat intelligence | ✅ Active |
| pfSense | 192.168.1.1 | Firewall / Network segmentation | ✅ Active |
| DC (lab.local) | 192.168.2.10 | Active Directory | ✅ Active |
| IT-WS01 | 192.168.2.20 | Domain workstation | ✅ Active |
| HR-WS01 | 192.168.2.21 | Domain workstation | ✅ Active |
| SALES-WS01 | 192.168.2.40 | Domain workstation | ⚠️ Known Issue |

---

# Project 01 — Enterprise SOC Lab: Full Stack Deployment

 Overview
Deployed and verified a fully operational enterprise SOC home lab simulating a real corporate environment. Every component was configured, tested, and validated end-to-end.

# Verification Date
May 2026

# Phase 1 — Network Topology Verification
- Confirmed all VMs reachable across three subnets: 192.168.2.x, 192.168.3.x, 192.168.6.x
- Fixed ICMP connectivity between domain workstations via GPO
- Deployed SOC-Lab-Firewall-Policy GPO to lab.local domain

**Known Issue:** SALES-WS01 hostname mismatch (DESKTOP-KT74UB2 vs SALES-WS01). Machine account corrupted in AD. No impact on lab exercises.

# Phase 2 — Wazuh Agent Health Check

| ID | Agent | OS | Version | Status |
|----|-------|----|---------|--------|
| 003 | DC | Windows Server 2025 | v4.14.3 | ✅ Active |
| 004 | Fileserver | Windows Server 2025 | v4.14.3 | ✅ Active |
| 005 | Webserver | - | v4.14.3 | ✅ Active |
| 007 | IT-WS01 | Windows 11 Pro | v4.7.0 | ✅ Active |
| 009 | HR-WS01 | Windows 11 Pro | v4.7.0 | ✅ Active |

# Phase 3 — Splunk Log Pipeline Verification
- Resolved inputs.conf misconfiguration (invalid start_position key)
- Applied Event ID whitelist to reduce log volume
- Confirmed 45,625 events ingested across 5 hosts in 24 hours

| Index | Host | Events (24h) |
|-------|------|-------------|
| main | FILESERVER | ~19,000 |
| main | DC | ~18,000 |
| main | IT-WS01 | ~500 |
| main | HR-WS01 | ~500 |
| firewall | pfSense (192.168.6.1) | Active |

# Phase 4 — TheHive + Cortex + MISP Verification
- TheHive 5.2 running on port 9000
- Cortex 3.1.7 running on port 9001
- MISP 2.5.31 running on port 443
- All services running as Docker containers on 192.168.6.3

# Phase 5 — pfSense Firewall Rule Audit

| Rule | Interface | Action |
|------|-----------|--------|
| Block KALI → WAZUH | KALI | ✅ Applied |
| Block KALI → SPLUNK | KALI | ✅ Applied |
| Block VICTIM → KALI | VICTIM | ✅ Applied |
| Block VICTIM → SPLUNK | VICTIM | ✅ Applied |

# Phase 6 — Splunk SOC Health Dashboard
Built SOC Lab Health Monitor dashboard with 5 panels:
- Log Volume by Host
- Firewall Events 24h
- Top Security Event IDs
- Failed Logon Attempts by Host
- Event Timeline 24h

# Tools & Versions

| Tool | Version |
|------|---------|
| Wazuh Manager | v4.14.3 |
| Splunk Enterprise | v10.x |
| TheHive | v5.2 |
| Cortex | v3.1.7 |
| MISP | v2.5.31 |
| pfSense | Community Edition |
| Windows Server | 2025 |
| Windows 11 | Pro |

---

Next: Project 02 — Active Directory Attack Detection (DCSync, Golden Ticket, Pass-the-Hash)
