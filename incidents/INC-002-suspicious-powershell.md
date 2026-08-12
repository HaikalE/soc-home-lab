# INC-002 — Suspicious PowerShell / Encoded Command Analysis

**Status:** RESOLVED / CLOSED  
**Trigger:** DET-002 — Encoded PowerShell Execution  
**Host:** WIN11-SOC-01  
**Final disposition:** BENIGN / CONTROLLED SIMULATION — HIGH CONFIDENCE  
**Severity:** Low

## Initial Signal

DET-002 identified a PowerShell process launched with `-EncodedCommand`. The signal was intentionally treated as suspicious enough to investigate, but not as proof of malicious execution.

## Controlled Ground Truth

The lab generated a benign payload that wrote the marker:

```text
SOC_INC002_ENCODED_TEST
```

The payload was encoded and executed through a child PowerShell process using `-NoProfile -EncodedCommand`.

## Cross-Source Timeline

| Time (UTC) | Source | Event | Evidence |
|---|---|---|---|
| 00:47:16.006 | PowerShell Operational | 4104 | Payload preparation recorded |
| 00:47:18.250 | Windows Security | 4688 | Child `powershell.exe` created with encoded command line |
| 00:47:18.707 | Sysmon Operational | 1 | Same process enriched with parent/process context |
| 00:47:21.055 | PowerShell Operational | 4104 | Decoded script block recorded |

## Key Investigation Finding

Process-creation telemetry showed the **encoded execution form**, while PowerShell Script Block Logging showed the **semantic decoded content**. The decoded script only wrote the benign marker to standard output.

Sysmon also provided useful enrichment such as:

- Process and parent image.
- ProcessGuid / ParentProcessGuid.
- ProcessId / ParentProcessId.
- Integrity level.
- SHA256 hash.
- Full encoded command line.

## Analyst Assessment

Encoded PowerShell is a valid triage signal because encoding can be used for obfuscation, but it is not inherently malicious. In this incident, cross-source evidence showed no network connection, persistence, credential access, file modification, or suspicious follow-on execution associated with the decoded payload.

## MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The mapping represents the observed PowerShell execution behavior and does not, by itself, establish malicious intent.

## Final Disposition

**BENIGN / CONTROLLED SIMULATION — HIGH CONFIDENCE.**

The execution was intentionally generated in the isolated lab and the decoded script content was benign.

## Detection Tuning Lessons

- Keep encoded PowerShell as a triage signal.
- Use 4104 decoded script content as an investigation pivot.
- Prioritize unusual parent processes, unexpected users, unexplained high-integrity execution, and suspicious follow-on behavior.
- Avoid blanket allowlisting of administrative tooling or all encoded PowerShell activity.

## Final Report

- [Google Doc](https://docs.google.com/document/d/19uxbMiZ5Gr_uK6Q3Hw5PwjdD1VyyMtj5ovl4RbqZHIo/edit)
- [PDF](https://drive.google.com/file/d/1m7nk2CjX5LmBShaKAj9_iaKSd9DwJhUP/view)
