# Detection Use-Case & SOC Escalation Report (UC-AD-004)

## 1. Detection Use-Case Overview
* **Use-Case ID:** UC-AD-004
* **Title:** Brute-Force Authentication Followed by Successful Logon and Privileged Group Addition
* **Target Environment:** `lab.local` (`DC 192.168.2.10`, `IT-WS01 192.168.2.20`)
* **MITRE ATT&CK Mapping:** T1110 (Brute Force), T1078 (Valid Accounts), T1098 (Account Manipulation)
* **Correlated Windows Event IDs:** `4625` (Failed Logon), `4624` (Successful Logon), `4728` (Member Added to Global Security Group)

---

## 2. Multi-SIEM Detection Queries (SPL / KQL / ES|QL)

### A. Splunk Search Processing Language (SPL)
    index="main" host="DC" EventCode IN (4625, 4624, 4728)
    | stats count(eval(EventCode=4625)) as Failed_Logons,
            count(eval(EventCode=4624)) as Success_Logons,
            count(eval(EventCode=4728)) as Group_Additions,
            values(src_ip) as Source_IP
            by TargetUserName, _time span=10m
    | where Failed_Logons >= 3 AND Success_Logons >= 1 AND Group_Additions >= 1
    | table _time, TargetUserName, Source_IP, Failed_Logons, Success_Logons, Group_Additions

### B. Microsoft Sentinel — Kusto Query Language (KQL)
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | where Computer has "DC" and EventID in (4625, 4624, 4728)
    | summarize 
        FailedLogons = countif(EventID == 4625),
        SuccessLogons = countif(EventID == 4624),
        PrivGroupAdditions = countif(EventID == 4728),
        SourceIPs = make_set(IpAddress)
        by TargetUserName, bin(TimeGenerated, 10m)
    | where FailedLogons >= 3 and SuccessLogons >= 1 and PrivGroupAdditions >= 1
    | project TimeGenerated, TargetUserName, SourceIPs, FailedLogons, SuccessLogons, PrivGroupAdditions

### C. Elastic Security — ES|QL (Elasticsearch Query Language)
    FROM logs-windows.security*
    | WHERE host.name == "DC" AND event.code IN ("4625", "4624", "4728")
    | STATS 
        failed_count = COUNT(CASE(event.code == "4625", 1, NULL)),
        success_count = COUNT(CASE(event.code == "4624", 1, NULL)),
        priv_add_count = COUNT(CASE(event.code == "4728", 1, NULL))
      BY user.target.name, source.ip
    | WHERE failed_count >= 3 AND success_count >= 1 AND priv_add_count >= 1

---

## 3. Tier-2 SOC Incident Escalation Summary

* **Incident ID:** INC-2026-1028
* **Severity:** Critical (P1)
* **Date / Time (UTC):** 2026-10-28 18:02:30Z
* **Affected Assets:** `DC` (`192.168.2.10`), `IT-WS01` (`192.168.2.20`)
* **Impacted Account:** `LAB\j.doe`

### Executive Summary
At 18:01 UTC, the SIEM detected three sequential failed authentication attempts (`Event ID 4625`) against account `LAB\j.doe` originating from workstation `IT-WS01` (`192.168.2.20`). At 18:01:45 UTC, a successful network logon (`Event ID 4624`) occurred from the same workstation. Less than 60 seconds later (18:02:30 UTC), `Event ID 4728` confirmed that `LAB\j.doe` was added to the `Domain Admins` security group on `DC` (`192.168.2.10`).

### Containment & Remediation Actions Recommended
1. **Immediate Account Containment:** Disable `LAB\j.doe` in Active Directory and remove the account from `Domain Admins`.
2. **Host Isolation:** Isolate workstation `IT-WS01` (`192.168.2.20`) at the pfSense firewall (`192.168.6.1`) pending forensic triage.
3. **Credential Reset:** Force password reset and Kerberos ticket revocation (`krbtgt` review if lateral movement is confirmed).
