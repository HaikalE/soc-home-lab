# DET-003 — PowerShell Spawned Command Shell

**Status:** VALIDATED  
**Primary telemetry:** Sysmon Operational  
**Event ID:** 1 — Process Create  
**ATT&CK:** T1059.003 — Command and Scripting Interpreter: Windows Command Shell

## Objective

Identify `cmd.exe` spawned directly by PowerShell and enrich the event with command/discovery context so the parent-child relationship can be triaged rather than automatically classified as malicious.

## Generic SPL

```spl
index=soc_lab source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(lower(Image),"\\\\cmd\.exe$") AND match(lower(ParentImage),"\\\\(powershell|pwsh)\.exe$")
| eval user_context=mvjoin(User," | ")
| eval command_lower=lower(coalesce(CommandLine,""))
| eval discovery_count=
    if(match(command_lower,"(?:^|[\\s&])whoami(?:\.exe)?(?:\\s|&|$)"),1,0)
    + if(match(command_lower,"(?:^|[\\s&])hostname(?:\.exe)?(?:\\s|&|$)"),1,0)
    + if(match(command_lower,"(?:^|[\\s&])ipconfig(?:\.exe)?(?:\\s|&|$)"),1,0)
| eval command_context=case(
    discovery_count>=2,"MULTI_DISCOVERY",
    discovery_count=1,"SINGLE_DISCOVERY",
    isnull(CommandLine) OR trim(CommandLine)="","SHELL_ONLY",
    true(),"OTHER_COMMAND"
)
| eval detection_id="DET-003", detection_name="PowerShell Spawned Command Shell"
| eval event_time=strftime(_time,"%Y-%m-%d %H:%M:%S.%3N")
| table event_time detection_id detection_name host user_context Image ParentImage command_context discovery_count IntegrityLevel CommandLine ParentCommandLine ProcessGuid ParentProcessGuid ProcessId ParentProcessId Hashes
| sort 0 - _time
```

## Validation

The generic rule returned seven historical controlled events without hardcoding host, user, PID, or ProcessGuid. Each matched the intended relationship:

- Child image: `cmd.exe`
- Parent image: `powershell.exe`
- Command line included `whoami`, `hostname`, and `ipconfig /all`
- `command_context = MULTI_DISCOVERY`
- `discovery_count = 3`
- High-integrity execution context retained
- Process GUID/PID and SHA256 fields preserved

The seven rows represent repeated lab executions of the same controlled behavior, not seven independent incidents.

## Investigation Value

DET-003 is most useful as the start of process-tree analysis. The incident investigation pivots on `ProcessGuid` / `ParentProcessGuid` to reconstruct direct child lineage instead of assuming related processes merely because timestamps are close.

## False-Positive Considerations

PowerShell can legitimately launch `cmd.exe` during administration, troubleshooting, software deployment, or automation. Context that should influence triage includes:

- Full command line.
- Discovery utilities or follow-on child processes.
- User and integrity level.
- Parent command line.
- File/network behavior around the same process tree.
- Known administrative tooling and host baseline.

## Tuning Principle

Do not blanket-allowlist PowerShell parents or administrative users. The parent-child relationship is a behavioral signal; command content and surrounding telemetry determine the final assessment.
