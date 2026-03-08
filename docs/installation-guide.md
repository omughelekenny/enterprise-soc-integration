# SOC Home Lab Installation Guide

## Prerequisites
- VMware Workstation/ESXi
- Minimum 32GB RAM
- Minimum 500GB Storage

## Installation Order
1. pfSense (Firewall)
2. Windows Server (DC)
3. Windows Server (Fileserver)
4. Ubuntu (Webserver)
5. Ubuntu (Wazuh)
6. Security Onion
7. Ubuntu (Splunk)
8. Ubuntu (TheHive/Cortex/MISP)

## Step 1 - pfSense Setup
- Download pfSense ISO
- Create VM with 2 NICs minimum
- Configure WAN and LAN interfaces
- Enable syslog forwarding to Splunk and Wazuh

## Step 2 - Windows Domain Controller
- Install Windows Server 2019
- Promote to Domain Controller
- Domain: lab.local
- Run create-ad-users.ps1 to create users

## Step 3 - Wazuh Setup
- Install Wazuh Manager on Ubuntu
- Install Wazuh agents on all Windows machines
- Configure syslog listener on port 514

## Step 4 - Splunk Setup
- Install Splunk Enterprise on Ubuntu
- Enable HEC on port 8088
- Enable syslog on port 514
- Create indexes: main, wineventlog, file_access, web

## Step 5 - TheHive/Cortex/MISP
- Use Docker Compose
- Configure TheHive to connect to Cortex
- Configure MISP threat intel feeds

## Step 6 - Security Onion
- Install Security Onion
- Configure to mirror traffic from pfSense
- Forward alerts to Splunk and TheHive
