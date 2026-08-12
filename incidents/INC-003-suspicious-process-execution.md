# INC-003 — Suspicious Process Execution

**Status:** RESOLVED / CLOSED  
**Trigger:** DET-003 — PowerShell Spawned Command Shell  
**Host:** WIN11-SOC-01  
**Final disposition:** BENIGN / CONTROLLED SIMULATION — HIGH CONFIDENCE  
**Severity:** Low

## Initial Signal

DET-003 detected `cmd.exe` spawned directly by PowerShell. Because this relationship can occur in both benign administration and malicious tradecraft, the investigation focused on process lineage and command context.

## Process Tree

```text
powershell.exe
└── cmd.exe /c whoami & hostname & ipconfig /all
    ├── conhost.exe
    ├── whoami.exe
    ├── hostname.exe
    └── ipconfig.exe /all
```

Sysmon `ProcessGuid` and `ParentProcessGuid` values were used to prove direct lineage instead of inferring relationships from timestamp proximity alone.

## Cross-Source Correlation

The same execution chain was independently observed across three telemetry families:

- **PowerShell Event ID 4104** — recorded the script-level intent to start `cmd.exe` with the discovery commands.
- **Windows Security Event ID 4688** — recorded native process creation and the command line.
- **Sysmon Event ID 1** — enriched the process with parent-child identifiers, user context, integrity level, hashes, and full process lineage.

The correlated events occurred in a consistent sequence within roughly one second during the controlled run.

## Child-Process Analysis

Direct children of the correlated `cmd.exe` instance included `whoami.exe`, `hostname.exe`, and `ipconfig.exe`. These utilities are commonly useful for discovery and therefore provide valuable triage context, but they are not inherently malicious.

`conhost.exe` was consistent with normal Windows console-host support for the command shell.

## MITRE ATT&CK

- **T1059.001 — PowerShell**
- **T1059.003 — Windows Command Shell**
- **T1033 — System Owner/User Discovery**
- **T1082 — System Information Discovery**
- **T1016 — System Network Configuration Discovery**

ATT&CK mappings describe the behaviors observed in the process chain. They do not automatically determine malicious intent.

## Final Disposition

**BENIGN / CONTROLLED SIMULATION — HIGH CONFIDENCE.**

The process lineage, command intent, and child utilities all matched the known controlled lab scenario. No suspicious behavior beyond console support and the intended discovery commands was identified in the correlated execution chain.

## Detection Tuning Lessons

- PowerShell spawning `cmd.exe` is a triage signal, not an automatic malicious verdict.
- ProcessGuid / ParentProcessGuid provide stronger process-lineage evidence than timestamps alone.
- Discovery-oriented command content should raise analyst interest, but context and surrounding telemetry still determine disposition.
- Production tuning should consider command line, user context, integrity level, parent process, child-process sequence, surrounding file/network activity, and administrative-tool baselines.

## Final Report

- [Google Doc](https://docs.google.com/document/d/1DNoArfhpLGXbsgYvhDwPeILY0oDP0smGVvFKrOBIeaA/edit)
- [PDF](https://drive.google.com/file/d/1lCsrshQINoS5y0iuMYgRtGRS_eTuiVhI/view)
