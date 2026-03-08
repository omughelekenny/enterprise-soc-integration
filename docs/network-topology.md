# SOC Home Lab Network Topology

## Network Segments
| Subnet | Purpose |
|--------|---------|
| 192.168.1.x | WAN/Firewall |
| 192.168.2.x | Corporate LAN (DC, Fileserver, Webserver, Workstations) |
| 192.168.3.x | Wazuh/Security Monitoring |
| 192.168.4.x | Security Onion |
| 192.168.6.x | SIEM/SOC Tools |

## Machines
| Machine | IP | OS | Role |
|---------|----|----|------|
| pfSense | 192.168.1.1 | FreeBSD | Firewall/Router |
| DC | 192.168.2.10 | Windows Server | Domain Controller |
| Fileserver | 192.168.2.11 | Windows Server | File Server |
| Webserver | 192.168.2.15 | Ubuntu | Apache Web Server |
| Wazuh | 192.168.3.5 | Ubuntu | SIEM/IDS |
| Security Onion | 192.168.4.3 | Security Onion | NSM |
| Splunk | 192.168.6.2 | Ubuntu | Log Analysis |
| TheHive/Cortex/MISP | 192.168.6.3 | Ubuntu | IR Platform |

## Log Flow
pfSense → Splunk (syslog:514)
Windows AD → Wazuh Agent → Wazuh Manager
Apache → rsyslog → Splunk
Wazuh → Splunk (Logstash:5044)
TheHive ↔ Cortex ↔ MISP
