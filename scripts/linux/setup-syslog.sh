#!/bin/bash
# SOC Lab - Configure rsyslog to forward to Splunk
# Run on Ubuntu machines

SPLUNK_IP="192.168.6.2"

# Install rsyslog
apt-get install rsyslog -y

# Configure rsyslog
cat >> /etc/rsyslog.conf << RSYSLOG
*.* @${SPLUNK_IP}:514
*.* @@${SPLUNK_IP}:514
RSYSLOG

# Configure Apache log forwarding
cat > /etc/rsyslog.d/apache.conf << APACHE
module(load="imfile" PollingInterval="10")
input(type="imfile"
      File="/var/log/apache2/access.log"
      Tag="apache-access"
      Severity="info"
      Facility="local6")
input(type="imfile"
      File="/var/log/apache2/error.log"
      Tag="apache-error"
      Severity="error"
      Facility="local6")
local6.* @${SPLUNK_IP}:514
APACHE

# Enable firewall logging
ufw logging on
ufw logging medium

# Restart rsyslog
systemctl restart rsyslog
echo "Syslog configured successfully!"
