# DET-002 — Encoded PowerShell Execution

**Status:** VALIDATED  
**Primary telemetry:** Sysmon Operational  
**Event ID:** 1 — Process Create  
**ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

## Objective

Detect PowerShell process creation where the command line uses `-EncodedCommand` or `-enc`, then enrich the signal with execution context for analyst triage.

## Generic SPL

```spl
index=soc_lab source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(lower(Image),"\\\\(powershell|pwsh)\.exe$")
| where match(CommandLine,"(?i)(?:^|\s)-(?:encodedcommand|enc)(?:\s|$)")
| rex field=CommandLine "(?i)(?:^|\s)-(?:encodedcommand|enc)\s+(?<encoded_payload>[A-Za-z0-9+/=]+)"
| eval payload_length=len(encoded_payload)
| eval user_context=mvjoin(User," | ")
| eval parent_context=case(
    match(lower(ParentImage),"\\\\(powershell|pwsh)\.exe$"),"POWERSHELL_PARENT",
    match(lower(ParentImage),"\\\\cmd\.exe$"),"CMD_PARENT",
    match(lower(ParentImage),"\\\\(wscript|cscript|mshta|rundll32|regsvr32)\.exe$"),"SCRIPT_HOST_OR_LOLBIN_PARENT",
    true(),"OTHER_PARENT"
)
| eval detection_id="DET-002", detection_name="Encoded PowerShell Execution"
| eval event_time=strftime(_time,"%Y-%m-%d %H:%M:%S.%3N")
| table event_time detection_id detection_name host user_context Image ParentImage parent_context IntegrityLevel CommandLine encoded_payload payload_length ProcessGuid ParentProcessGuid ProcessId ParentProcessId Hashes
| sort 0 - _time
```

## Validation

The generic rule returned exactly one expected controlled event without hardcoding a host or user. Observed context included:

- `powershell.exe` as the process image.
- `-NoProfile -EncodedCommand` in the command line.
- PowerShell as the parent process.
- `IntegrityLevel = High`.
- Base64 payload extraction with `payload_length = 104`.
- Process and parent GUID/PID values preserved for investigation.
- SHA256 hash retained as an investigation pivot.

## Cross-Source Investigation Value

Encoded-command telemetry tells the analyst **how** PowerShell was launched, but not necessarily what the decoded script did. The corresponding incident investigation therefore pivots to:

- Windows Security Event ID 4688 for native process creation.
- Sysmon Event ID 1 for enriched process context.
- PowerShell Event ID 4104 for decoded script-block content.

This prevents the rule from treating encoding itself as proof of malicious intent.

## False-Positive Considerations

Legitimate administration, deployment tooling, automation, troubleshooting, and software-management platforms may use encoded PowerShell. Triage priority should increase when the event also contains unusual parent processes, unexpected users, unexplained high-integrity execution, suspicious decoded 4104 content, or follow-on network/file/credential/persistence behavior.

## Tuning Principle

Do not blanket-allowlist encoded PowerShell or administrative parents. Preserve the signal, enrich it, and make the final verdict from surrounding evidence.
