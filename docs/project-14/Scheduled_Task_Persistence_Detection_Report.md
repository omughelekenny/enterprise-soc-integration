# Scheduled Task Persistence Detection Report (UC-AD-005)

## 1. Overview

Following privilege escalation in Project 13, the next step an attacker usually takes is to make sure they can get back in. A common way to do that on a domain controller is a scheduled task that runs a hidden command at logon.

In this lab I created a scheduled task on `DC.lab.local` using `schtasks`, set to run a hidden, obfuscated PowerShell command every time someone logs on. I then built and tested a Splunk detection against the real event it generated.

* **Use-Case ID:** UC-AD-005
* **Target Environment:** `lab.local` (`DC.lab.local`, `192.168.2.10`)
* **MITRE ATT&CK Mapping:** T1053.005, Scheduled Task Persistence

## 2. How the Telemetry Is Stored

Event ID 4698 does not store the malicious command in a plain field. The task's command and arguments sit inside embedded XML tags, `<Command>` and `<Arguments>`, buried in the raw event text. A query that only checks standard fields like `CommandLine` will miss this completely. My Splunk query uses `rex` to pull both tags out of `_raw` and join them into one readable field before filtering on it.

## 3. Multi-SIEM Detection Queries (SPL / KQL / ES|QL)

The Splunk query below is the one I ran and validated against the real event on `DC.lab.local`. The Sentinel and Elastic versions show the same logic translated to those platforms. I have not run them, since my lab does not currently have Sentinel or Elastic set up.

### A. Splunk (SPL)

```spl
index=* (EventCode=4698 OR "4698")
| rex field=_raw "(?ms)Subject:.*?Account Name:\s+(?<Subject_User>[^\r\n\s]+)"
| rex field=_raw "(?ms)Task Name:\s+(?<Task_Name>[^\r\n\s]+)"
| rex field=_raw "<Command>(?<Command_Exec>[^<]+)</Command>"
| rex field=_raw "<Arguments>(?<Command_Args>[^<]+)</Arguments>"
| eval Full_Command = trim(coalesce(Command_Exec, "") . " " . coalesce(Command_Args, ""))
| eval MITRE_Technique = "T1053.005 (Scheduled Task Persistence)"
| eval Severity = if(match(Full_Command, "(?i)-enc|-w\s+hidden|-nop|powershell"), "CRITICAL", "HIGH")
| stats earliest(_time) as First_Seen, values(Task_Name) as Scheduled_Task, values(Full_Command) as Payload_Executed, values(MITRE_Technique) as MITRE_Technique, values(Severity) as Severity by ComputerName, Subject_User
| eval First_Seen=strftime(First_Seen, "%Y-%m-%d %H:%M:%S")
| table First_Seen, ComputerName, Subject_User, Scheduled_Task, Payload_Executed, MITRE_Technique, Severity
```

### B. Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID == 4698
| parse EventData with * '<Data Name="TaskName">' Task_Name '</Data>' * '<Command>' Command_Exec '</Command>' * '<Arguments>' Command_Args '</Arguments>' *
| extend Payload_Executed = strcat(Command_Exec, " ", Command_Args)
| where Payload_Executed has_any ("-enc", "-w hidden", "-nop", "powershell")
| project TimeGenerated, Computer, SubjectUserName, Task_Name, Payload_Executed, MITRE="T1053.005", Severity="CRITICAL"
```

### C. Elastic Security (ES|QL)

```esql
FROM logs-windows.security*
| WHERE event.code == "4698"
| WHERE message LIKE "*powershell*" OR message LIKE "*-Enc*" OR message LIKE "*-W Hidden*"
| STATS first_seen = MIN(@timestamp) BY host.name, winlog.event_data.SubjectUserName, winlog.event_data.TaskName
```

## 4. Incident Response Steps

1. **Containment:** Disable or delete the scheduled task (`schtasks /delete /tn "WindowsUpdaterSvc" /f`) so it can no longer run at the next logon.
2. **Decode the payload:** The command uses `-Enc`, meaning the script after it is Base64-encoded. Decode it to see what it actually runs before deciding it is safe. In my test the encoded string was deliberately shortened so it would not execute anything, but a real one should always be decoded and reviewed.
3. **Account review:** Check who created the task. In my test it was the `Administrator` account, which is why confirming that the person using that account is who they should be matters as much as the task itself.
4. **Wider check:** Look for other persistence created around the same time, such as new services, new scheduled tasks, or registry run keys, and review logons from the same session to see how the attacker got admin rights in the first place.

## 5. Evidence

[View the Lab 14 write-up, Splunk screenshot and full detection notes](../../Lab-14-AD-Scheduled-Task-Persistence/README.md)
