# Lab Environment

## Scope

This repository documents a personal, isolated SOC training environment used for blue-team detection and investigation practice. All test activity was intentionally generated inside the lab.

## Components

| Component | Configuration |
|---|---|
| Hypervisor | VMware Workstation |
| Windows endpoint | WIN11-SOC-01 |
| Endpoint OS | Windows 11 Enterprise Evaluation |
| Endpoint resources | 8 GB RAM, 2 vCPU, 80 GB virtual disk |
| SIEM host | SPLUNK-SIEM-01 |
| SIEM OS | Ubuntu Server 24.04 LTS |
| SIEM platform | Splunk Enterprise 10.4.1 |
| Forwarder | Splunk Universal Forwarder 10.4.1 |
| Endpoint enrichment | Sysmon 15.21 / schema 4.91 |
| Network | Controlled VMware NAT lab network |
| Splunk receiver | TCP/9997 |
| Splunk Web | TCP/8000 |
| Security index | `soc_lab` |

## Windows Logging Configuration

### Authentication

Windows Security authentication telemetry was validated using controlled local account tests. Event ID 4625 was examined at field level, including:

- Target account/domain.
- Logon type.
- Failure reason.
- Status and sub-status.
- Source network address.
- Caller process.

The lab specifically demonstrated the difference between an unknown target account (`0xC0000064`) and a valid account with the wrong password (`0xC000006A`).

### Process Creation

Native Windows Process Creation auditing was enabled and validated with Event ID 4688. Command-line process auditing was also enabled so process arguments could be correlated with Sysmon and PowerShell telemetry.

### PowerShell

PowerShell Operational logging was configured and validated for:

- Event ID 4103 — Module / pipeline execution detail.
- Event ID 4104 — Script Block Logging.

This provided decoded/script-level context during encoded PowerShell investigations.

## Sysmon Configuration

Sysmon was installed with SHA256 hashing enabled. Baseline validation covered:

- Event ID 1 — Process Create.
- Event ID 3 — Network Connect.
- Event ID 11 — File Create.

Controlled tests were used so each event type could be tied to known ground truth rather than background activity alone.

## Splunk Pipeline

The Universal Forwarder was installed on WIN11-SOC-01 and configured to forward Windows Security, PowerShell Operational, and Sysmon Operational telemetry to SPLUNK-SIEM-01 over TCP/9997.

Validation included:

- Forwarder service running automatically.
- Active forward-server state.
- Established TCP session to the indexer.
- Internal forwarder telemetry searchable in Splunk.
- Windows Security, Sysmon, and PowerShell data searchable in `index=soc_lab`.
- Controlled multi-source freshness validation.

## Evidence Handling

The full engineering journal retains detailed screenshots, failed experiments, troubleshooting steps, and before/after validation. This public repository intentionally presents a cleaner recruiter-facing summary and avoids publishing unnecessary credentials or sensitive account identifiers.

## Safety Boundary

No production network, employer data, or third-party target was used. Passwords are not included in the repository. Authentication failures, encoded PowerShell, process execution, network connections, and file creation were all generated as benign controlled exercises inside the lab.
