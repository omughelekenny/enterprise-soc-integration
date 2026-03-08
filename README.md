# Enterprise SOC Home Lab

A comprehensive Security Operations Center (SOC) home lab built on VMware.

## Environment
- **pfSense** (192.168.1.1) - Firewall/Router
- **Domain Controller** (192.168.2.10) - Windows AD
- **Fileserver** (192.168.2.11) - Windows File Server
- **Webserver** (192.168.2.15) - Ubuntu/Apache
- **Wazuh** (192.168.3.5) - SIEM/IDS
- **Security Onion** (192.168.4.3) - Network Security Monitoring
- **Splunk** (192.168.6.2) - Log Analysis
- **TheHive/Cortex/MISP** (192.168.6.3) - Incident Response

## Integrations
- pfSense → Splunk (Firewall logs)
- Wazuh → Splunk (Security alerts)
- Apache → Splunk (Web logs)
- TheHive ↔ Cortex (Automated analysis)
- TheHive ↔ MISP (Threat intelligence)
- Windows AD → Wazuh (Event logs)

## Tools Used
- Splunk Enterprise
- Wazuh SIEM
- TheHive 5
- Cortex
- MISP
- Security Onion
- pfSense
- Windows Server 2019
- Ubuntu 20.04
