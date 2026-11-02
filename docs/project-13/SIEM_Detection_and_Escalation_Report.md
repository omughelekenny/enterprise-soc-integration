# Detection Use-Case & SOC Escalation Report (UC-AD-004)

## 1. Detection Use-Case Overview

* **Use-Case ID:** UC-AD-004
* **Title:** Brute-Force Authentication Followed by Successful Logon and Privileged Group Addition
* **Target Environment:** `lab.local` (`DC 192.168.2.10`, `IT-WS01 192.168.2.20`)
* **MITRE ATT&CK Mapping:** T1110 (Brute Force), T1078 (Valid Accounts), T1098 (Account Manipulation)
* **Correlated Windows Event IDs:** `4625` (Failed Logon), `4624` (Successful Logon), `4728` / `4732` (Member Added to Security Group)

---

## 2. Findings from Live Testing

I first wrote this detection as draft queries and a Python script using sample data. Then I ran the attack against my own domain controller and tested the detection in Splunk.

The draft queries did not work on real logs. Windows records the account as `j.doe` in logon events (`4624` / `4625`), but as `CN=John Doe,CN=Users,DC=lab,DC=local` in group change events (`4728` / `4732`). In the group events, `TargetUserName` is the group, not the user. Grouping by `TargetUserName` therefore split one attack across several rows and the three stages never joined.

I fixed it by extracting the account name from the raw event with regex and normalizing both formats to `j.doe` before grouping. After that, Splunk returned one alert row for `j.doe` with the attacker IP `192.168.2.20`.

---

## 3. Detection Queries (SPL / KQL / ES|QL)

The validated Splunk query, the Sentinel KQL and Elastic ES|QL versions, and the Splunk screenshot are in the Lab 13 write-up:

[View the Lab 13 write-up and queries](../../Lab-13-AD-BruteForce-PrivEsc/README.md)

---

## 4. Tier-2 SOC Incident Escalation Summary

This summary is based on the sample telemetry from the Part 1 correlation script (`scripts/siem_correlation_engine.py`).

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
