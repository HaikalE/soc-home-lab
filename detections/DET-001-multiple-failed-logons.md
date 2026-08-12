# DET-001 — Multiple Failed Logons

**Status:** VALIDATED  
**Primary telemetry:** Windows Security Log  
**Event ID:** 4625  
**ATT&CK:** T1110.001 — Password Guessing

## Objective

Identify repeated failed authentication attempts against the same target account within a short rolling window while preserving enough context for analyst triage.

## Detection Logic

The lab validation threshold is **3 or more failed logons within 5 minutes** for the same host, target domain/account, source IP, logon type, failure class, and source scope.

The rule deliberately distinguishes:

- `0xC000006A` — valid account / wrong password.
- `0xC0000064` — unknown account.
- Local loopback sources (`127.0.0.1`, `::1`) from remote-or-other sources.

## Generic SPL

```spl
index=soc_lab source="WinEventLog:Security" EventCode=4625
| eval target_account=mvindex(Account_Name,1), target_domain=mvindex(Account_Domain,1)
| eval source_ip=coalesce(Source_Network_Address,"UNKNOWN"), logon_type=coalesce(Logon_Type,"UNKNOWN")
| eval failure_class=case(
    Sub_Status="0xC000006A","VALID_ACCOUNT_WRONG_PASSWORD",
    Sub_Status="0xC0000064","UNKNOWN_ACCOUNT",
    true(),"OTHER"
)
| eval source_scope=case(
    source_ip="127.0.0.1" OR source_ip="::1","LOCAL_LOOPBACK",
    source_ip="-" OR source_ip="UNKNOWN","NO_NETWORK_ADDRESS",
    true(),"REMOTE_OR_OTHER"
)
| where isnotnull(target_account) AND target_account!="-"
| sort 0 host target_domain target_account source_ip _time
| streamstats time_window=5m
    count as failed_count
    min(_time) as first_seen
    max(_time) as last_seen
    by host target_domain target_account source_ip logon_type failure_class source_scope
| where failed_count>=3
| stats
    max(failed_count) as failed_count
    min(first_seen) as first_seen
    max(last_seen) as last_seen
    values(Failure_Reason) as Failure_Reason
    values(Status) as Status
    values(Sub_Status) as Sub_Status
    by host target_domain target_account source_ip source_scope logon_type failure_class
| eval window_duration_seconds=last_seen-first_seen
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S.%3N"),
       last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S.%3N")
| sort - failed_count - last_seen
```

## Validation

The generic rule was tested without hardcoding a host or account and returned the expected controlled candidate. The validation cluster contained three failed interactive logons in approximately **3.6 seconds**, with:

- Logon type: `2`
- Status: `0xC000006D`
- Sub-status: `0xC000006A`
- Failure class: `VALID_ACCOUNT_WRONG_PASSWORD`
- Source scope: `LOCAL_LOOPBACK`

An earlier failed logon occurred outside the five-minute window and did not inflate the detection count, validating the time-window logic.

## Analyst Triage

Useful follow-up questions:

1. Is the target account valid, disabled, privileged, or expected on the host?
2. Is the source local loopback, an internal workstation, VPN address, or external source?
3. Is the activity interactive, network, service, or batch logon?
4. Do surrounding PowerShell/process events explain the authentication attempts?
5. Is there a subsequent successful logon or suspicious execution?

## False-Positive Considerations

Repeated user typos, stale saved credentials, scheduled-task/service retries, administrative automation, and troubleshooting can legitimately produce bursts of 4625 events. Local loopback is useful context but is **not** an automatic benign verdict.

## Production Caveat

The `>=3 failures / 5 minutes` threshold is intentionally low for lab validation. A production threshold must be based on environment baselining, false-positive rate, account criticality, source reputation, and operational tolerance.
