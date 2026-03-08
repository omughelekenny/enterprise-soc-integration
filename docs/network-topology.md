# SOC Home Lab Network Topology

## Network Segments
| Subnet | Purpose | Key Hosts |
|--------|---------|-----------|
| 192.168.1.x | Firewall | pfSense (192.168.1.1) |
| 192.168.2.x | Corporate | DC (192.168.2.10), Fileserver (192.168.2.11), Webserver (192.168.2.15) |
| 192.168.3.x | Security | Wazuh (192.168.3.5) |
| 192.168.4.x | Monitoring | Security Onion (192.168.4.3) |
| 192.168.6.x | SIEM | Splunk (192.168.6.2), TheHive/Cortex/MISP (192.168.6.3) |

## Data Flow
pfSense → Splunk (Firewall logs via syslog)
Windows AD/Fileserver → Wazuh (Event logs via agent)
Wazuh → TheHive (Automated alerts)
Apache → Splunk (Web logs via rsyslog)
All hosts → Splunk (Syslog port 514)
