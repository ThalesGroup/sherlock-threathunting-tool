# ruff: noqa: E501 - demonstration data file: sample rows and queries stay on one line each
"""Seeds the local database with demonstration content (development only).

Fills every screen of the platform with realistic material so it can be shown or
screenshotted without a gateway, a SIEM or any threat-intel key: local accounts, hunts in
each state of the lifecycle (indicators to validate, playbook to validate, awaiting review,
closed with a human verdict, interrupted, linked follow-up investigation), full reports
with executed queries and anonymized samples, the audit trail of each hunt, and CTI report
analyses with their probe results.

Every identifier (hosts, accounts, addresses, hashes) is fictitious. The script refuses to
run outside `SHL_ENVIRONMENT=dev` and only ever touches the rows it created itself
(fixed references `PREFIX-YYMM-NNN` and `cti_` identifiers, as the platform issues them): re-running it
replaces the demo content and leaves everything else untouched.

Usage:
    .venv/bin/python scripts/seed_demo.py            # create or refresh the demo content
    .venv/bin/python scripts/seed_demo.py --remove   # delete it

Demo accounts (all with the password printed at the end of the run):
    robin (analyst, admin), m.dubois (analyst), a.leclerc (analyst), j.martin (reader)
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sqlalchemy import delete  # noqa: E402

from api.accounts import AccountRepository  # noqa: E402
from middleware.config import Settings  # noqa: E402
from reporting.models import (  # noqa: E402
    AttackOverview,
    AttackTechnique,
    Entity,
    ExecutedQuery,
    Finding,
    HuntReport,
    HuntStatus,
    Playbook,
    PlaybookStep,
    TimelineEvent,
    Verdict,
)
from storage.models import (  # noqa: E402
    AuditRow,
    CtiAnalysisRow,
    FindingRow,
    HuntRow,
    HuntStateRow,
    IocRow,
    QueryRow,
    ReportRow,
)
from storage.repository import Database  # noqa: E402

DEMO_PASSWORD = "sherlock-demo-2026"  # noqa: S105 - demo credential, printed on purpose

ACCOUNTS = [
    ("robin", ["analyst", "admin"]),
    ("m.dubois", ["analyst"]),
    ("a.leclerc", ["analyst"]),
    ("j.martin", ["reader"]),
]

# References of the demo hunts, in the platform's format PREFIX-YYMM-NNN (origin, year and
# month, rank within the month).
VOLT = "HYP-2609-007"
VOLT_FOLLOWUP = "HYP-2609-009"
SPRAY = "CAMP-2609-018"
SCHTASKS = "HYP-2608-031"
HELPDESK = "CAMP-2609-014"
TEAMCITY = "CTI-2609-020"
KERBEROAST = "HYP-2609-021"

CTI_TEAMCITY = "cti_3f9a12b7c5d0"
CTI_VOLT = "cti_8c2d44e19a3f"

DEMO_HUNT_IDS = (VOLT, VOLT_FOLLOWUP, SPRAY, SCHTASKS, HELPDESK, TEAMCITY, KERBEROAST)
DEMO_CTI_IDS = (CTI_TEAMCITY, CTI_VOLT)

DEFAULT_BUDGET = {"iterations": 30, "siem_queries": 25, "tokens": 600_000, "duration": 1800}


# --------------------------------------------------------------------------- helpers


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def anon(
    *,
    host: int = 0,
    user: int = 0,
    ip: int = 0,
    data: int = 0,
    semantic: str = "active",
    masked: int = 0,
) -> dict[str, Any]:
    """Anonymization trace of a query result, in the executor's shape."""

    return {
        "semantic": semantic,
        "tokenization": True,
        "masked_fields": masked,
        "tokens": {"HOST": host, "USER": user, "IP-INT": ip, "DATA": data},
    }


def budgets(
    iterations: int,
    queries: int,
    tokens: int,
    seconds: float,
    *,
    limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    lim = {**DEFAULT_BUDGET, **(limits or {})}
    return {
        "iterations": {"used": iterations, "limit": lim["iterations"]},
        "siem_queries": {"used": queries, "limit": lim["siem_queries"]},
        "tokens": {"used": tokens, "limit": lim["tokens"]},
        "duration_seconds": {"used": seconds, "limit": lim["duration"]},
    }


def ioc(
    value: str,
    type_: str,
    source: str,
    url: str,
    *,
    status: str = "validated",
    first_seen: str | None = None,
    confidence: str | None = None,
    validated_by: str | None = None,
    validated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "value": value,
        "type": type_,
        "source_name": source,
        "source_url": url,
        "first_seen": first_seen,
        "confidence": confidence,
        "status": status,
        "validated_by": validated_by if status != "pending_validation" else None,
        "validated_at": validated_at if status != "pending_validation" else None,
    }


def manual_ioc(value: str, type_: str, analyst: str, at: str) -> dict[str, Any]:
    return ioc(
        value,
        type_,
        f"analyst:{analyst}",
        f"internal://analyst/{analyst}",
        confidence="analyst",
        validated_by=analyst,
        validated_at=at,
    )


def ioc_views(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The IOC list as the report carries it (`summarize_for_model` shape)."""

    return [
        {
            "value": row["value"],
            "type": row["type"],
            "source": row["source_name"],
            "source_url": row["source_url"],
            "corroborating_sources": [],
            "first_seen": row["first_seen"],
            "confidence": row["confidence"],
            "status": row["status"],
        }
        for row in rows
    ]


def scope(
    *,
    window: str | None,
    sources: list[str],
    campaign: str | None,
    executed: int,
    max_queries: int = 25,
    max_iterations: int = 30,
) -> str:
    labels = {"sentinel": "Sentinel", "defender": "Defender", "secops": "SecOps"}
    if window:
        start, end = (part.strip() for part in window.split("->"))
        head = f"Investigation window {_dt(start):%d/%m/%Y} -> {_dt(end):%d/%m/%Y}"
    else:
        head = "Default investigation window of each source"
    head += f" on {', '.join(labels[s] for s in sources)}."
    parts = [head]
    if campaign:
        parts.append(f'Hunt guided by the validated indicators of the "{campaign}" campaign.')
    parts.append(
        f"{executed} query(ies) executed out of a budget of {max_queries}, {max_iterations} "
        "iterations at most, each result minimized and pseudonymized before analysis."
    )
    return " ".join(parts)


def event(type_: str, actor: str, at: str, *, hunt_id: str, **fields: Any) -> dict[str, Any]:
    return {"hunt_id": hunt_id, "type": type_, "actor": actor, "timestamp": at, **fields}


def query_events(hunt_id: str, actor: str, queries: list[ExecutedQuery]) -> list[dict[str, Any]]:
    return [
        event(
            "query_executed",
            actor,
            q.executed_at,
            hunt_id=hunt_id,
            siem=q.siem,
            query_id=q.query_id,
            query=q.query,
            rows_returned=q.source_rows,
            truncated=q.truncated,
            duration_ms=q.duration_ms,
        )
        for q in queries
    ]


def finding_events(hunt_id: str, actor: str, findings: list[Finding]) -> list[dict[str, Any]]:
    return [
        event(
            "finding_recorded",
            actor,
            f.recorded_at,
            hunt_id=hunt_id,
            detail={
                "finding_id": f.id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "evidence": f.evidence_query_ids,
            },
        )
        for f in findings
    ]


@dataclass
class DemoHunt:
    hunt_id: str
    hypothesis: str
    analyst: str
    status: HuntStatus
    created_at: str
    updated_at: str
    campaign: str | None = None
    interruption_reason: str | None = None
    playbook: Playbook | None = None
    parent_hunt_id: str | None = None
    resume_context: str | None = None
    iocs: list[dict[str, Any]] = field(default_factory=list)
    report: HuntReport | None = None
    decision: dict[str, Any] | None = None
    audit: list[dict[str, Any]] = field(default_factory=list)


# --------------------------------------------------------------------------- hunt 1
# Volt Typhoon style living-off-the-land intrusion. Closed, escalated. The richest one.


def hunt_volt_typhoon() -> DemoHunt:
    hunt_id = VOLT
    analyst = "robin"
    campaign = "Volt Typhoon"
    hypothesis = (
        "Living-off-the-land lateral movement: WMI remote process creation from file servers "
        "towards domain controllers, followed by netsh port-proxy persistence and NTDS "
        "extraction."
    )
    window = "2026-08-01T00:00:00+00:00 -> 2026-09-15T00:00:00+00:00"
    sources = ["sentinel", "defender"]
    validated_at = "2026-09-02T08:16:27+00:00"

    iocs = [
        ioc(
            "45.155.12.7",
            "ip",
            "ThreatFox",
            "https://threatfox.abuse.ch/ioc/1187342/",
            first_seen="2026-07-18",
            confidence="high",
            validated_by=analyst,
            validated_at=validated_at,
        ),
        ioc(
            "103.56.54.212",
            "ip",
            "AlienVault OTX",
            "https://otx.alienvault.com/pulse/66a1b2c3d4e5f6a7b8c9d0e1",
            first_seen="2026-07-11",
            confidence="medium",
            validated_by=analyst,
            validated_at=validated_at,
        ),
        ioc(
            "update-checker-cdn.net",
            "domain",
            "VirusTotal",
            "https://www.virustotal.com/gui/domain/update-checker-cdn.net",
            first_seen="2026-07-22",
            confidence="malicious (31/94)",
            validated_by=analyst,
            validated_at=validated_at,
        ),
        ioc(
            "3f1e4b2c9a8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f",
            "hash",
            "ThreatFox",
            "https://threatfox.abuse.ch/ioc/1187355/",
            first_seen="2026-07-19",
            confidence="high",
            validated_by=analyst,
            validated_at=validated_at,
        ),
        ioc(
            "9b7c2e4f1a3d5b6c8e0f2a4c6e8b0d1f3a5c7e9b",
            "hash",
            "CIRCL MISP OSINT",
            "https://www.circl.lu/doc/misp/feed-osint/",
            first_seen="2025-11-03",
            confidence="low",
            status="rejected",
            validated_by=analyst,
            validated_at=validated_at,
        ),
        manual_ioc(
            "netsh interface portproxy add v4tov4", "other", analyst, "2026-09-02T08:12:40+00:00"
        ),
    ]

    playbook = Playbook(
        summary=(
            "Start from the validated infrastructure indicators to confirm any contact from "
            "the estate, then pivot to the behaviors that characterize the campaign: remote "
            "process creation through WMI, netsh port-proxy persistence and credential "
            "access on domain controllers. Each lead is closed by a lateral-movement check "
            "between the hosts it surfaces."
        ),
        steps=[
            PlaybookStep(
                order=1,
                siem="defender",
                technique="T1071.001",
                expected_queries=2,
                objective=(
                    "Confirm outbound contacts to the validated command-and-control addresses "
                    "and domain from any managed device."
                ),
            ),
            PlaybookStep(
                order=2,
                siem="sentinel",
                technique="T1047",
                expected_queries=2,
                objective=(
                    "Detect remote process creation through WMI (wmic /node) from file servers, "
                    "with the account and the target host."
                ),
            ),
            PlaybookStep(
                order=3,
                siem="defender",
                technique="T1090.001",
                expected_queries=1,
                objective=(
                    "Look for netsh portproxy persistence and the listening ports it opens."
                ),
            ),
            PlaybookStep(
                order=4,
                siem="defender",
                technique="T1003.003",
                expected_queries=2,
                objective=(
                    "Search for NTDS extraction attempts (ntdsutil, vssadmin) on domain "
                    "controllers and the resulting IFM folders."
                ),
            ),
            PlaybookStep(
                order=5,
                siem="sentinel",
                technique="T1021.002",
                expected_queries=2,
                objective=(
                    "Map network logons of the accounts surfaced above between file servers and "
                    "domain controllers."
                ),
            ),
        ],
        not_covered=(
            "Email delivery and initial access are out of scope: no mail telemetry is "
            "connected to this installation. Fortinet or SOHO router compromise, typical of "
            "this actor, cannot be observed from endpoint and identity logs."
        ),
        estimated_queries=9,
        estimated_iterations=13,
        generated_at="2026-09-02T08:19:03+00:00",
        validated_by=analyst,
        validated_at="2026-09-02T08:22:51+00:00",
        validated_queries=25,
        validated_iterations=30,
    )

    q1, q2, q3, q4, q5, q6, q7 = (
        "q_1a7c3e9f02",
        "q_5b2d8e4a61",
        "q_9c4f1b7d23",
        "q_2e8a6c3f90",
        "q_7d3b9e1a45",
        "q_4f6c2d8b17",
        "q_8a1e5f3c62",
    )
    queries = [
        ExecutedQuery(
            query_id=q3,
            siem="defender",
            executed_at="2026-09-02T08:23:40+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=2210,
            intent="Confirm contacts from managed devices to the validated C2 addresses",
            query=(
                "DeviceNetworkEvents\n"
                "| where Timestamp between (datetime(2026-08-01) .. datetime(2026-09-15))\n"
                '| where RemoteIP in ("45.155.12.7", "103.56.54.212")\n'
                "| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)"
                " by DeviceName, RemoteIP, RemotePort\n"
                "| order by Connections desc"
            ),
            columns=[
                "DeviceName",
                "RemoteIP",
                "RemotePort",
                "Connections",
                "FirstSeen",
                "LastSeen",
            ],
            sample=[
                {
                    "DeviceName": "PAR-FS-03",
                    "RemoteIP": "45.155.12.7",
                    "RemotePort": 443,
                    "Connections": 1284,
                    "FirstSeen": "2026-08-14T02:16:01Z",
                    "LastSeen": "2026-08-25T23:51:12Z",
                },
                {
                    "DeviceName": "PAR-FS-03",
                    "RemoteIP": "103.56.54.212",
                    "RemotePort": 8443,
                    "Connections": 96,
                    "FirstSeen": "2026-08-21T03:03:40Z",
                    "LastSeen": "2026-08-25T22:10:05Z",
                },
                {
                    "DeviceName": "PAR-DC-01",
                    "RemoteIP": "45.155.12.7",
                    "RemotePort": 443,
                    "Connections": 3,
                    "FirstSeen": "2026-08-19T02:00:27Z",
                    "LastSeen": "2026-08-19T02:04:11Z",
                },
            ],
            model_sample=[
                {
                    "DeviceName": "HOST-001",
                    "RemoteIP": "45.155.12.7",
                    "RemotePort": 443,
                    "Connections": 1284,
                    "FirstSeen": "2026-08-14T02:16:01Z",
                    "LastSeen": "2026-08-25T23:51:12Z",
                },
                {
                    "DeviceName": "HOST-001",
                    "RemoteIP": "103.56.54.212",
                    "RemotePort": 8443,
                    "Connections": 96,
                    "FirstSeen": "2026-08-21T03:03:40Z",
                    "LastSeen": "2026-08-25T22:10:05Z",
                },
                {
                    "DeviceName": "HOST-002",
                    "RemoteIP": "45.155.12.7",
                    "RemotePort": 443,
                    "Connections": 3,
                    "FirstSeen": "2026-08-19T02:00:27Z",
                    "LastSeen": "2026-08-19T02:04:11Z",
                },
            ],
            anonymization=anon(host=2),
            interpretation=(
                "Both validated addresses are contacted, almost exclusively from PAR-FS-03: "
                "1,284 connections to 45.155.12.7:443 over eleven days, then a second channel "
                "to 103.56.54.212:8443 from 21 August. PAR-DC-01 reaches the first address "
                "only three times, in a four-minute burst on 19 August. The file server is "
                "the foothold; the domain controller is touched later. I pivot on PAR-FS-03."
            ),
        ),
        ExecutedQuery(
            query_id=q1,
            siem="sentinel",
            executed_at="2026-09-02T08:24:55+00:00",
            returned_rows=4,
            source_rows=4,
            truncated=False,
            duration_ms=1840,
            intent="Remote process creation through WMI from any host of the estate",
            query=(
                "SecurityEvent\n"
                "| where TimeGenerated between (datetime(2026-08-01) .. datetime(2026-09-15))\n"
                "| where EventID == 4688\n"
                '| where NewProcessName endswith "wmic.exe" and CommandLine has "/node:"\n'
                "| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName\n"
                "| take 200"
            ),
            columns=["TimeGenerated", "Computer", "Account", "CommandLine", "ParentProcessName"],
            sample=[
                {
                    "TimeGenerated": "2026-08-14T02:14:07Z",
                    "Computer": "PAR-FS-03.corp.internal",
                    "Account": "CORP\\svc-backup",
                    "CommandLine": 'wmic /node:PAR-DC-01.corp.internal process call create "cmd /c netstat -ano > C:\\Windows\\Temp\\n.txt"',
                    "ParentProcessName": "cmd.exe",
                },
                {
                    "TimeGenerated": "2026-08-14T02:17:52Z",
                    "Computer": "PAR-FS-03.corp.internal",
                    "Account": "CORP\\svc-backup",
                    "CommandLine": 'wmic /node:PAR-DC-01.corp.internal process call create "cmd /c tasklist /v > C:\\Windows\\Temp\\t.txt"',
                    "ParentProcessName": "cmd.exe",
                },
                {
                    "TimeGenerated": "2026-08-19T01:58:10Z",
                    "Computer": "PAR-FS-03.corp.internal",
                    "Account": "CORP\\svc-backup",
                    "CommandLine": 'wmic /node:PAR-DC-01.corp.internal process call create "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAuAC4ALgA="',
                    "ParentProcessName": "cmd.exe",
                },
                {
                    "TimeGenerated": "2026-08-05T11:20:44Z",
                    "Computer": "LYO-ADM-01.corp.internal",
                    "Account": "CORP\\adm-ops",
                    "CommandLine": "wmic /node:LYO-PRT-02.corp.internal printer list brief",
                    "ParentProcessName": "powershell.exe",
                },
            ],
            model_sample=[
                {
                    "TimeGenerated": "2026-08-14T02:14:07Z",
                    "Computer": "HOST-001",
                    "Account": "USER-001",
                    "CommandLine": 'wmic /node:HOST-002 process call create "cmd /c netstat -ano > C:\\Windows\\Temp\\n.txt"',
                    "ParentProcessName": "cmd.exe",
                },
                {
                    "TimeGenerated": "2026-08-14T02:17:52Z",
                    "Computer": "HOST-001",
                    "Account": "USER-001",
                    "CommandLine": 'wmic /node:HOST-002 process call create "cmd /c tasklist /v > C:\\Windows\\Temp\\t.txt"',
                    "ParentProcessName": "cmd.exe",
                },
                {
                    "TimeGenerated": "2026-08-19T01:58:10Z",
                    "Computer": "HOST-001",
                    "Account": "USER-001",
                    "CommandLine": 'wmic /node:HOST-002 process call create "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAuAC4ALgA="',
                    "ParentProcessName": "cmd.exe",
                },
                {
                    "TimeGenerated": "2026-08-05T11:20:44Z",
                    "Computer": "HOST-003",
                    "Account": "USER-002",
                    "CommandLine": "wmic /node:HOST-004 printer list brief",
                    "ParentProcessName": "powershell.exe",
                },
            ],
            anonymization=anon(host=4, user=2),
            interpretation=(
                "Three of the four WMI remote creations come from PAR-FS-03 under svc-backup, "
                "all targeting PAR-DC-01 at night; the third one launches an encoded "
                "PowerShell on the domain controller. The fourth, from an admin workstation "
                "towards a print server during office hours, is consistent with routine "
                "administration. A backup service account has no reason to spawn processes "
                "on a domain controller."
            ),
        ),
        ExecutedQuery(
            query_id=q2,
            siem="defender",
            executed_at="2026-09-02T08:26:12+00:00",
            returned_rows=2,
            source_rows=2,
            truncated=False,
            duration_ms=1520,
            intent="netsh portproxy persistence on the foothold and the ports it exposes",
            query=(
                "DeviceProcessEvents\n"
                "| where Timestamp between (datetime(2026-08-01) .. datetime(2026-09-15))\n"
                '| where FileName =~ "netsh.exe" and ProcessCommandLine has_all ("portproxy", "add")\n'
                "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName"
            ),
            columns=[
                "Timestamp",
                "DeviceName",
                "AccountName",
                "ProcessCommandLine",
                "InitiatingProcessFileName",
            ],
            sample=[
                {
                    "Timestamp": "2026-08-14T02:15:33Z",
                    "DeviceName": "PAR-FS-03",
                    "AccountName": "svc-backup",
                    "ProcessCommandLine": "netsh interface portproxy add v4tov4 listenport=9999 connectaddress=45.155.12.7 connectport=443",
                    "InitiatingProcessFileName": "cmd.exe",
                },
                {
                    "Timestamp": "2026-08-21T03:02:19Z",
                    "DeviceName": "PAR-FS-03",
                    "AccountName": "svc-backup",
                    "ProcessCommandLine": "netsh interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectaddress=103.56.54.212 connectport=8443",
                    "InitiatingProcessFileName": "cmd.exe",
                },
            ],
            model_sample=[
                {
                    "Timestamp": "2026-08-14T02:15:33Z",
                    "DeviceName": "HOST-001",
                    "AccountName": "USER-001",
                    "ProcessCommandLine": "netsh interface portproxy add v4tov4 listenport=9999 connectaddress=45.155.12.7 connectport=443",
                    "InitiatingProcessFileName": "cmd.exe",
                },
                {
                    "Timestamp": "2026-08-21T03:02:19Z",
                    "DeviceName": "HOST-001",
                    "AccountName": "USER-001",
                    "ProcessCommandLine": "netsh interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectaddress=103.56.54.212 connectport=8443",
                    "InitiatingProcessFileName": "cmd.exe",
                },
            ],
            anonymization=anon(host=1, user=1),
            interpretation=(
                "Two port proxies were installed on PAR-FS-03 by svc-backup, each pointing at "
                "one of the validated addresses. The first one, on 14 August, precedes the "
                "1,284 connections seen earlier by thirty seconds: it is the relay. This is "
                "the exact netsh tradecraft documented for the campaign."
            ),
        ),
        ExecutedQuery(
            query_id=q4,
            siem="sentinel",
            executed_at="2026-09-02T08:27:48+00:00",
            returned_rows=4,
            source_rows=4,
            truncated=False,
            duration_ms=2960,
            intent="Sign-in pattern of the service account driving the WMI activity",
            query=(
                "SigninLogs\n"
                "| where TimeGenerated between (datetime(2026-08-01) .. datetime(2026-09-15))\n"
                '| where UserPrincipalName =~ "svc-backup@corp.internal"\n'
                "| summarize count() by IPAddress, ResultType, AppDisplayName\n"
                "| order by count_ desc"
            ),
            columns=["IPAddress", "ResultType", "AppDisplayName", "count_"],
            sample=[
                {
                    "IPAddress": "10.42.3.20",
                    "ResultType": 0,
                    "AppDisplayName": "Azure Backup Agent",
                    "count_": 412,
                },
                {
                    "IPAddress": "10.42.3.20",
                    "ResultType": 0,
                    "AppDisplayName": "Windows Sign In",
                    "count_": 31,
                },
                {
                    "IPAddress": "10.42.8.11",
                    "ResultType": 0,
                    "AppDisplayName": "Windows Sign In",
                    "count_": 17,
                },
                {
                    "IPAddress": "10.42.8.11",
                    "ResultType": 50126,
                    "AppDisplayName": "Windows Sign In",
                    "count_": 9,
                },
            ],
            model_sample=[
                {
                    "IPAddress": "IP-INT-001",
                    "ResultType": 0,
                    "AppDisplayName": "Azure Backup Agent",
                    "count_": 412,
                },
                {
                    "IPAddress": "IP-INT-001",
                    "ResultType": 0,
                    "AppDisplayName": "Windows Sign In",
                    "count_": 31,
                },
                {
                    "IPAddress": "IP-INT-002",
                    "ResultType": 0,
                    "AppDisplayName": "Windows Sign In",
                    "count_": 17,
                },
                {
                    "IPAddress": "IP-INT-002",
                    "ResultType": 50126,
                    "AppDisplayName": "Windows Sign In",
                    "count_": 9,
                },
            ],
            anonymization=anon(ip=2),
            interpretation=(
                "The account's legitimate life is on 10.42.3.20 (the backup server, 443 "
                "events). The 26 interactive sign-ins from 10.42.8.11, nine of them failed "
                "with a wrong password, are a second, human-driven usage that does not "
                "match a backup job. That address is the operator's pivot point."
            ),
        ),
        ExecutedQuery(
            query_id=q5,
            siem="defender",
            executed_at="2026-09-02T08:29:30+00:00",
            returned_rows=2,
            source_rows=2,
            truncated=False,
            duration_ms=1730,
            intent="Credential access on the domain controller: ntdsutil and WMI-spawned PowerShell",
            query=(
                "DeviceProcessEvents\n"
                "| where Timestamp between (datetime(2026-08-01) .. datetime(2026-09-15))\n"
                '| where DeviceName =~ "PAR-DC-01"\n'
                '| where FileName =~ "ntdsutil.exe" or (FileName =~ "powershell.exe" and InitiatingProcessFileName =~ "wmiprvse.exe")\n'
                "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName"
            ),
            columns=[
                "Timestamp",
                "DeviceName",
                "AccountName",
                "ProcessCommandLine",
                "InitiatingProcessFileName",
            ],
            sample=[
                {
                    "Timestamp": "2026-08-19T02:22:48Z",
                    "DeviceName": "PAR-DC-01",
                    "AccountName": "adm-helpdesk",
                    "ProcessCommandLine": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAuAC4ALgA=",
                    "InitiatingProcessFileName": "wmiprvse.exe",
                },
                {
                    "Timestamp": "2026-08-19T02:41:12Z",
                    "DeviceName": "PAR-DC-01",
                    "AccountName": "adm-helpdesk",
                    "ProcessCommandLine": 'ntdsutil "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\ifm" q q',
                    "InitiatingProcessFileName": "powershell.exe",
                },
            ],
            model_sample=[
                {
                    "Timestamp": "2026-08-19T02:22:48Z",
                    "DeviceName": "HOST-002",
                    "AccountName": "USER-003",
                    "ProcessCommandLine": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAuAC4ALgA=",
                    "InitiatingProcessFileName": "wmiprvse.exe",
                },
                {
                    "Timestamp": "2026-08-19T02:41:12Z",
                    "DeviceName": "HOST-002",
                    "AccountName": "USER-003",
                    "ProcessCommandLine": 'ntdsutil "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\ifm" q q',
                    "InitiatingProcessFileName": "powershell.exe",
                },
            ],
            anonymization=anon(host=1, user=1),
            interpretation=(
                "On PAR-DC-01 the WMI-spawned PowerShell runs as adm-helpdesk, not "
                "svc-backup: the operator holds a second, privileged credential. Nineteen "
                "minutes later that PowerShell launches ntdsutil to create a full IFM copy of "
                "the directory in C:\\Windows\\Temp\\ifm. This is domain credential theft."
            ),
        ),
        ExecutedQuery(
            query_id=q7,
            siem="defender",
            executed_at="2026-09-02T08:30:41+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=1390,
            intent="Files produced by the IFM export",
            query=(
                "DeviceFileEvents\n"
                "| where Timestamp between (datetime(2026-08-19) .. datetime(2026-08-20))\n"
                '| where DeviceName =~ "PAR-DC-01" and FolderPath has @"\\Windows\\Temp\\ifm"\n'
                "| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize"
            ),
            columns=["Timestamp", "DeviceName", "ActionType", "FileName", "FolderPath", "FileSize"],
            sample=[
                {
                    "Timestamp": "2026-08-19T02:43:58Z",
                    "DeviceName": "PAR-DC-01",
                    "ActionType": "FileCreated",
                    "FileName": "ntds.dit",
                    "FolderPath": "C:\\Windows\\Temp\\ifm\\Active Directory\\ntds.dit",
                    "FileSize": 50331648,
                },
                {
                    "Timestamp": "2026-08-19T02:44:30Z",
                    "DeviceName": "PAR-DC-01",
                    "ActionType": "FileCreated",
                    "FileName": "SYSTEM",
                    "FolderPath": "C:\\Windows\\Temp\\ifm\\registry\\SYSTEM",
                    "FileSize": 17563648,
                },
                {
                    "Timestamp": "2026-08-19T02:44:31Z",
                    "DeviceName": "PAR-DC-01",
                    "ActionType": "FileCreated",
                    "FileName": "SECURITY",
                    "FolderPath": "C:\\Windows\\Temp\\ifm\\registry\\SECURITY",
                    "FileSize": 65536,
                },
            ],
            model_sample=[
                {
                    "Timestamp": "2026-08-19T02:43:58Z",
                    "DeviceName": "HOST-002",
                    "ActionType": "FileCreated",
                    "FileName": "ntds.dit",
                    "FolderPath": "C:\\Windows\\Temp\\ifm\\Active Directory\\ntds.dit",
                    "FileSize": 50331648,
                },
                {
                    "Timestamp": "2026-08-19T02:44:30Z",
                    "DeviceName": "HOST-002",
                    "ActionType": "FileCreated",
                    "FileName": "SYSTEM",
                    "FolderPath": "C:\\Windows\\Temp\\ifm\\registry\\SYSTEM",
                    "FileSize": 17563648,
                },
                {
                    "Timestamp": "2026-08-19T02:44:31Z",
                    "DeviceName": "HOST-002",
                    "ActionType": "FileCreated",
                    "FileName": "SECURITY",
                    "FolderPath": "C:\\Windows\\Temp\\ifm\\registry\\SECURITY",
                    "FileSize": 65536,
                },
            ],
            anonymization=anon(host=1),
            interpretation=(
                "The export completed: a 48 MB ntds.dit and the SYSTEM hive needed to decrypt "
                "it were written three minutes after the ntdsutil command. Every domain "
                "password hash is recoverable from these two files."
            ),
        ),
        ExecutedQuery(
            query_id=q6,
            siem="sentinel",
            executed_at="2026-09-02T08:31:57+00:00",
            returned_rows=5,
            source_rows=5,
            truncated=False,
            duration_ms=3120,
            intent="Network logons of adm-helpdesk: where does the privileged account come from",
            query=(
                "SecurityEvent\n"
                "| where TimeGenerated between (datetime(2026-08-01) .. datetime(2026-09-15))\n"
                "| where EventID == 4624 and LogonType == 3\n"
                '| where Account has "adm-helpdesk"\n'
                "| summarize Logons=count() by Computer, IpAddress\n"
                "| order by Logons desc\n"
                "| take 50"
            ),
            columns=["Computer", "IpAddress", "Logons"],
            sample=[
                {"Computer": "LYO-HD-07.corp.internal", "IpAddress": "10.42.60.15", "Logons": 231},
                {"Computer": "PAR-HD-02.corp.internal", "IpAddress": "10.42.60.18", "Logons": 198},
                {"Computer": "PAR-DC-01.corp.internal", "IpAddress": "10.42.8.11", "Logons": 6},
                {"Computer": "PAR-FS-03.corp.internal", "IpAddress": "10.42.8.11", "Logons": 4},
                {"Computer": "PAR-DC-01.corp.internal", "IpAddress": "10.42.1.4", "Logons": 2},
            ],
            model_sample=[
                {"Computer": "HOST-005", "IpAddress": "IP-INT-003", "Logons": 231},
                {"Computer": "HOST-006", "IpAddress": "IP-INT-004", "Logons": 198},
                {"Computer": "HOST-002", "IpAddress": "IP-INT-002", "Logons": 6},
                {"Computer": "HOST-001", "IpAddress": "IP-INT-002", "Logons": 4},
                {"Computer": "HOST-002", "IpAddress": "IP-INT-005", "Logons": 2},
            ],
            anonymization=anon(host=4, ip=4),
            interpretation=(
                "adm-helpdesk lives on the two helpdesk servers (429 logons). The ten logons "
                "from 10.42.8.11 onto PAR-DC-01 and PAR-FS-03 are the anomaly: the same "
                "pivot address already seen for svc-backup now carries the privileged "
                "account. Both credentials are operated from a single point. I have enough "
                "to conclude."
            ),
        ),
    ]

    findings = [
        Finding(
            id="f_4d1e9a2b",
            title="Directory database extracted with ntdsutil on PAR-DC-01",
            severity="critical",
            confidence="high",
            recorded_at="2026-09-02T08:31:05+00:00",
            description=(
                "A full IFM copy of the Active Directory database (ntds.dit, 48 MB) and the "
                "SYSTEM hive were written to C:\\Windows\\Temp\\ifm on PAR-DC-01 on 19 August "
                "at 02:41, by ntdsutil launched from a PowerShell that WmiPrvSE had spawned "
                "under adm-helpdesk. Together these files allow every domain password hash "
                "to be recovered offline."
            ),
            entities=[
                Entity(type="host", value="PAR-DC-01"),
                Entity(type="account", value="adm-helpdesk"),
                Entity(type="file_path", value="C:\\Windows\\Temp\\ifm"),
            ],
            evidence_query_ids=[q5, q7],
        ),
        Finding(
            id="f_7b3c8e01",
            title="WMI remote process creation from PAR-FS-03 to PAR-DC-01 under svc-backup",
            severity="high",
            confidence="high",
            recorded_at="2026-09-02T08:25:31+00:00",
            description=(
                "Between 14 and 19 August, svc-backup issued three wmic /node commands from "
                "PAR-FS-03 towards PAR-DC-01 at night: reconnaissance (netstat, tasklist "
                "redirected to Temp) then an encoded PowerShell. A backup service account "
                "never needs to create processes on a domain controller."
            ),
            entities=[
                Entity(type="host", value="PAR-FS-03"),
                Entity(type="host", value="PAR-DC-01"),
                Entity(type="account", value="svc-backup"),
            ],
            evidence_query_ids=[q1, q6],
        ),
        Finding(
            id="f_92ad5f6c",
            title="netsh port proxy on PAR-FS-03 relaying to validated C2 45.155.12.7",
            severity="high",
            confidence="high",
            recorded_at="2026-09-02T08:26:50+00:00",
            description=(
                "Two netsh portproxy rules were added on PAR-FS-03 (listen 9999 -> "
                "45.155.12.7:443 on 14 August, listen 8443 -> 103.56.54.212:8443 on 21 "
                "August). They explain the 1,380 connections observed to the two validated "
                "addresses and turn the file server into an internal relay."
            ),
            entities=[
                Entity(type="host", value="PAR-FS-03"),
                Entity(type="ip", value="45.155.12.7"),
                Entity(type="ip", value="103.56.54.212"),
            ],
            evidence_query_ids=[q2, q3],
        ),
        Finding(
            id="f_e5106bd4",
            title="svc-backup used interactively from 10.42.8.11 outside its backup job",
            severity="medium",
            confidence="medium",
            recorded_at="2026-09-02T08:28:22+00:00",
            description=(
                "26 interactive sign-ins of svc-backup from 10.42.8.11, nine of them with a "
                "wrong password, against 443 legitimate events from the backup server. The "
                "same address later carries adm-helpdesk onto PAR-DC-01: it is the "
                "operator's pivot host and should be identified."
            ),
            entities=[
                Entity(type="account", value="svc-backup"),
                Entity(type="ip", value="10.42.8.11"),
            ],
            evidence_query_ids=[q4, q6],
        ),
        Finding(
            id="f_3a7f2c19",
            title="Sustained beaconing from PAR-FS-03 over eleven days",
            severity="medium",
            confidence="medium",
            recorded_at="2026-09-02T08:24:20+00:00",
            description=(
                "1,284 connections to 45.155.12.7:443 between 14 and 25 August, at a steady "
                "rate consistent with a beacon interval of about twelve minutes, plus a "
                "secondary channel to 103.56.54.212:8443 from 21 August."
            ),
            entities=[
                Entity(type="host", value="PAR-FS-03"),
                Entity(type="ip", value="45.155.12.7"),
            ],
            evidence_query_ids=[q3],
        ),
    ]

    timeline = [
        TimelineEvent(
            timestamp="2026-08-14T02:09:55Z",
            source=q4,
            event="Interactive sign-in of svc-backup from 10.42.8.11, outside its backup schedule",
        ),
        TimelineEvent(
            timestamp="2026-08-14T02:14:07Z",
            source=q1,
            event="wmic /node:PAR-DC-01 reconnaissance (netstat, tasklist) from PAR-FS-03",
        ),
        TimelineEvent(
            timestamp="2026-08-14T02:15:33Z",
            source=q2,
            event="netsh portproxy 9999 -> 45.155.12.7:443 installed on PAR-FS-03",
        ),
        TimelineEvent(
            timestamp="2026-08-14T02:16:01Z",
            source=q3,
            event="First connection from PAR-FS-03 to 45.155.12.7; beaconing starts",
        ),
        TimelineEvent(
            timestamp="2026-08-19T01:58:10Z",
            source=q1,
            event="Encoded PowerShell pushed to PAR-DC-01 through WMI",
        ),
        TimelineEvent(
            timestamp="2026-08-19T02:22:48Z",
            source=q5,
            event="PowerShell spawned by WmiPrvSE on PAR-DC-01 as adm-helpdesk",
        ),
        TimelineEvent(
            timestamp="2026-08-19T02:41:12Z",
            source=q5,
            event="ntdsutil creates a full IFM copy in C:\\Windows\\Temp\\ifm",
        ),
        TimelineEvent(
            timestamp="2026-08-19T02:44:30Z",
            source=q7,
            event="ntds.dit (48 MB) and SYSTEM hive written on PAR-DC-01",
        ),
        TimelineEvent(
            timestamp="2026-08-21T03:02:19Z",
            source=q2,
            event="Second port proxy 8443 -> 103.56.54.212 added on PAR-FS-03",
        ),
        TimelineEvent(
            timestamp="2026-08-25T23:51:12Z",
            source=q3,
            event="Last observed contact with 45.155.12.7",
        ),
    ]

    report = HuntReport(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.CLOSED,
        proposed_verdict=Verdict.ESCALATE,
        summary=(
            "Two hosts hold the chain. PAR-FS-03 issued WMI remote process creations towards "
            "PAR-DC-01 under the svc-backup service account, then installed a netsh port "
            "proxy forwarding port 9999 to 45.155.12.7, one of the validated indicators. On "
            "PAR-DC-01, adm-helpdesk ran an encoded PowerShell command from WmiPrvSE and, "
            "nineteen minutes later, ntdsutil produced a full IFM copy of the directory in "
            "C:\\Windows\\Temp\\ifm. Outbound connections from PAR-FS-03 to the two "
            "validated addresses are confirmed over eleven days. The sequence matches the "
            "hunted tradecraft end to end."
        ),
        limitations=(
            "Sign-in logs for svc-backup only cover Entra ID: on-premises Kerberos "
            "authentications were not queried. The content of the encoded PowerShell command "
            "was not decoded by the platform. No proxy or firewall telemetry was available to "
            "size the volume exchanged with 45.155.12.7."
        ),
        recommendation=(
            "Escalate to incident response: isolate PAR-FS-03 and PAR-DC-01, reset "
            "svc-backup and adm-helpdesk, identify the host behind 10.42.8.11, and treat "
            "every domain credential as compromised until the IFM copy is confirmed not to "
            "have left the estate."
        ),
        iocs=ioc_views(iocs),
        findings=findings,
        timeline=timeline,
        executed_queries=queries,
        budgets=budgets(16, 7, 212_430, 538.4),
        partial=False,
        generated_at="2026-09-02T08:32:44+00:00",
        attack_overview=AttackOverview(
            description=(
                "Living-off-the-land intrusion in the style of Volt Typhoon: no malware "
                "dropped, the operator relies on wmic, netsh and ntdsutil. The observed chain "
                "goes from a file server, through a compromised service account, to a domain "
                "controller where the directory database is extracted."
            ),
            techniques=[
                AttackTechnique(
                    id="T1047",
                    name="Windows Management Instrumentation",
                    description="Remote process creation on the domain controller through wmic /node from the file server.",
                ),
                AttackTechnique(
                    id="T1090.001",
                    name="Internal Proxy",
                    description="netsh portproxy rules on PAR-FS-03 relaying traffic to the command-and-control addresses.",
                ),
                AttackTechnique(
                    id="T1003.003",
                    name="OS Credential Dumping: NTDS",
                    description="Full IFM export of ntds.dit and the SYSTEM hive with ntdsutil.",
                ),
                AttackTechnique(
                    id="T1059.001",
                    name="PowerShell",
                    description="Hidden, encoded PowerShell launched by WmiPrvSE as the execution vehicle on the domain controller.",
                ),
                AttackTechnique(
                    id="T1021.002",
                    name="SMB/Windows Admin Shares",
                    description="Network logons of the privileged account onto the domain controller from the pivot address.",
                ),
            ],
            scope=scope(window=window, sources=sources, campaign=campaign, executed=7),
        ),
        playbook=playbook,
        sources=sources,
        investigation_window=window,
    )

    audit = [
        event(
            "hunt_created",
            analyst,
            "2026-09-02T08:12:40+00:00",
            hunt_id=hunt_id,
            detail={
                "hypothesis": hypothesis,
                "campaign": campaign,
                "manual_iocs": 1,
                "seeded_from_probe": False,
                "sources": sources,
            },
        ),
        event(
            "ioc_search",
            analyst,
            "2026-09-02T08:13:52+00:00",
            hunt_id=hunt_id,
            detail={
                "campaign": campaign,
                "found": 5,
                "sources": ["ThreatFox", "AlienVault OTX", "VirusTotal", "CIRCL MISP OSINT"],
                "dropped_unsourced": 2,
            },
        ),
        event(
            "ioc_validation",
            analyst,
            validated_at,
            hunt_id=hunt_id,
            detail={
                "validated": [
                    "103.56.54.212",
                    "3f1e4b2c9a8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f",
                    "45.155.12.7",
                    "update-checker-cdn.net",
                ],
                "rejected": ["9b7c2e4f1a3d5b6c8e0f2a4c6e8b0d1f3a5c7e9b"],
                "total": 6,
            },
        ),
        event(
            "plan_proposed",
            analyst,
            "2026-09-02T08:19:03+00:00",
            hunt_id=hunt_id,
            detail={
                "steps": 5,
                "estimated_queries": 9,
                "estimated_iterations": 13,
                "instruction": None,
                "requested_by": analyst,
            },
        ),
        event(
            "plan_validated",
            analyst,
            "2026-09-02T08:22:51+00:00",
            hunt_id=hunt_id,
            detail={
                "by": analyst,
                "max_iterations": 30,
                "max_siem_queries": 25,
                "from_playbook": True,
                "adjusted": True,
            },
        ),
        *query_events(hunt_id, "agent", queries),
        event(
            "agent_decision",
            "agent",
            "2026-09-02T08:25:10+00:00",
            hunt_id=hunt_id,
            detail={"iteration": 4, "decision": "pivot on PAR-FS-03 and svc-backup"},
        ),
        *finding_events(hunt_id, "agent", findings),
        event(
            "agent_decision",
            "agent",
            "2026-09-02T08:32:20+00:00",
            hunt_id=hunt_id,
            detail={"iteration": 16, "decision": "conclude"},
        ),
        event(
            "hunt_concluded",
            "agent",
            "2026-09-02T08:32:44+00:00",
            hunt_id=hunt_id,
            detail={"proposed_verdict": "escalate", "findings": 5},
        ),
        event(
            "report_validated",
            analyst,
            "2026-09-02T10:47:18+00:00",
            hunt_id=hunt_id,
            detail={"verdict": "escalate", "proposed_verdict": "escalate", "comment": True},
        ),
    ]

    return DemoHunt(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.CLOSED,
        created_at="2026-09-02T08:12:40+00:00",
        updated_at="2026-09-02T10:47:18+00:00",
        playbook=playbook,
        iocs=iocs,
        report=report,
        decision={
            "human_verdict": "escalate",
            "decided_by": analyst,
            "decided_at": "2026-09-02T10:47:18+00:00",
            "decision_comment": (
                "Confirmed with the IR team: PAR-FS-03 and PAR-DC-01 isolated at 10:30, "
                "incident INC-2026-0912 opened. Follow-up hunt on the fate of the IFM copy."
            ),
        },
        audit=audit,
    )


# --------------------------------------------------------------------------- hunt 2
# Follow-up of hunt 1, resumed as a linked investigation. Closed, suspicious.


def hunt_volt_followup() -> DemoHunt:
    hunt_id = VOLT_FOLLOWUP
    analyst = "robin"
    campaign = "Volt Typhoon"
    hypothesis = (
        "Exfiltration of the NTDS IFM copy from PAR-DC-01: archiving of "
        "C:\\Windows\\Temp\\ifm and transfer towards PAR-FS-03 or an external address after "
        "19 August 2026."
    )
    resume_context = (
        f"Follow-up of {VOLT}: did the IFM copy created on PAR-DC-01 leave the estate? "
        "Check archive creation, SMB transfers and uploads from PAR-DC-01 and PAR-FS-03 "
        "after 2026-08-19."
    )
    window = "2026-08-19T00:00:00+00:00 -> 2026-09-04T00:00:00+00:00"
    sources = ["sentinel", "defender"]
    at = "2026-09-04T09:05:12+00:00"
    iocs = [
        ioc(
            "45.155.12.7",
            "ip",
            "ThreatFox",
            "https://threatfox.abuse.ch/ioc/1187342/",
            first_seen="2026-07-18",
            confidence="high",
            validated_by=analyst,
            validated_at=at,
        ),
        ioc(
            "103.56.54.212",
            "ip",
            "AlienVault OTX",
            "https://otx.alienvault.com/pulse/66a1b2c3d4e5f6a7b8c9d0e1",
            first_seen="2026-07-11",
            confidence="medium",
            validated_by=analyst,
            validated_at=at,
        ),
    ]
    playbook = Playbook(
        summary=(
            "Follow the IFM folder from its creation: look for an archive step on the domain "
            "controller, then for the archive on any other device or share, and finally for "
            "an outbound transfer of comparable volume from the hosts involved."
        ),
        steps=[
            PlaybookStep(
                order=1,
                siem="defender",
                technique="T1560.001",
                expected_queries=2,
                objective="Archive creation on PAR-DC-01 after 19 August (7-Zip, WinRAR, makecab, Compress-Archive).",
            ),
            PlaybookStep(
                order=2,
                siem="defender",
                technique="T1021.002",
                expected_queries=2,
                objective="Movement of the archive to another device or share, in particular PAR-FS-03.",
            ),
            PlaybookStep(
                order=3,
                siem="defender",
                technique="T1041",
                expected_queries=2,
                objective="Outbound transfer from PAR-FS-03 or PAR-DC-01 to the validated addresses or any public address.",
            ),
        ],
        not_covered="Volume actually transferred: endpoint telemetry carries no byte counts, a firewall or proxy export is needed to size the exfiltration.",
        estimated_queries=6,
        estimated_iterations=9,
        instruction=resume_context,
        generated_at="2026-09-04T09:07:40+00:00",
        validated_by=analyst,
        validated_at="2026-09-04T09:09:02+00:00",
        validated_queries=15,
        validated_iterations=20,
    )
    g1, g2, g3 = "q_c3d9e7a1f4", "q_6e2b8f4c09", "q_0a5d7c3e81"
    queries = [
        ExecutedQuery(
            query_id=g1,
            siem="defender",
            executed_at="2026-09-04T09:09:31+00:00",
            returned_rows=1,
            source_rows=1,
            truncated=False,
            duration_ms=1610,
            intent="Archive creation on PAR-DC-01 after the IFM export",
            query=(
                "DeviceProcessEvents\n"
                "| where Timestamp between (datetime(2026-08-19) .. datetime(2026-09-04))\n"
                '| where DeviceName =~ "PAR-DC-01"\n'
                '| where FileName in~ ("7z.exe", "rar.exe", "makecab.exe", "tar.exe") or ProcessCommandLine has "Compress-Archive"\n'
                "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName"
            ),
            columns=[
                "Timestamp",
                "DeviceName",
                "AccountName",
                "ProcessCommandLine",
                "InitiatingProcessFileName",
            ],
            sample=[
                {
                    "Timestamp": "2026-08-19T02:52:16Z",
                    "DeviceName": "PAR-DC-01",
                    "AccountName": "adm-helpdesk",
                    "ProcessCommandLine": "powershell -nop -c Compress-Archive -Path C:\\Windows\\Temp\\ifm -DestinationPath C:\\Windows\\Temp\\ifm.zip",
                    "InitiatingProcessFileName": "powershell.exe",
                }
            ],
            model_sample=[
                {
                    "Timestamp": "2026-08-19T02:52:16Z",
                    "DeviceName": "HOST-001",
                    "AccountName": "USER-001",
                    "ProcessCommandLine": "powershell -nop -c Compress-Archive -Path C:\\Windows\\Temp\\ifm -DestinationPath C:\\Windows\\Temp\\ifm.zip",
                    "InitiatingProcessFileName": "powershell.exe",
                }
            ],
            anonymization=anon(host=1, user=1),
            interpretation="Eleven minutes after the export, adm-helpdesk compressed the whole IFM folder into ifm.zip with Compress-Archive. The staging step is confirmed; I now follow that file.",
        ),
        ExecutedQuery(
            query_id=g2,
            siem="defender",
            executed_at="2026-09-04T09:10:44+00:00",
            returned_rows=2,
            source_rows=2,
            truncated=False,
            duration_ms=1980,
            intent="Where did ifm.zip go",
            query=(
                "DeviceFileEvents\n"
                "| where Timestamp between (datetime(2026-08-19) .. datetime(2026-09-04))\n"
                '| where FileName =~ "ifm.zip"\n'
                "| project Timestamp, DeviceName, ActionType, FolderPath, FileSize, InitiatingProcessFileName, RequestAccountName"
            ),
            columns=[
                "Timestamp",
                "DeviceName",
                "ActionType",
                "FolderPath",
                "FileSize",
                "InitiatingProcessFileName",
                "RequestAccountName",
            ],
            sample=[
                {
                    "Timestamp": "2026-08-19T02:53:40Z",
                    "DeviceName": "PAR-DC-01",
                    "ActionType": "FileCreated",
                    "FolderPath": "C:\\Windows\\Temp\\ifm.zip",
                    "FileSize": 21234567,
                    "InitiatingProcessFileName": "powershell.exe",
                    "RequestAccountName": "adm-helpdesk",
                },
                {
                    "Timestamp": "2026-08-19T03:01:12Z",
                    "DeviceName": "PAR-FS-03",
                    "ActionType": "FileCreated",
                    "FolderPath": "D:\\Shares\\backup$\\staging\\ifm.zip",
                    "FileSize": 21234567,
                    "InitiatingProcessFileName": "System",
                    "RequestAccountName": "adm-helpdesk",
                },
            ],
            model_sample=[
                {
                    "Timestamp": "2026-08-19T02:53:40Z",
                    "DeviceName": "HOST-001",
                    "ActionType": "FileCreated",
                    "FolderPath": "C:\\Windows\\Temp\\ifm.zip",
                    "FileSize": 21234567,
                    "InitiatingProcessFileName": "powershell.exe",
                    "RequestAccountName": "USER-001",
                },
                {
                    "Timestamp": "2026-08-19T03:01:12Z",
                    "DeviceName": "HOST-002",
                    "ActionType": "FileCreated",
                    "FolderPath": "D:\\Shares\\backup$\\staging\\ifm.zip",
                    "FileSize": 21234567,
                    "InitiatingProcessFileName": "System",
                    "RequestAccountName": "USER-001",
                },
            ],
            anonymization=anon(host=2, user=1),
            interpretation="The archive (20 MB) was copied over SMB to the backup$ share of PAR-FS-03 eight minutes after its creation, by the same account. It sits on the host that holds the port proxies to the C2.",
        ),
        ExecutedQuery(
            query_id=g3,
            siem="defender",
            executed_at="2026-09-04T09:12:05+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=2450,
            intent="Outbound connections from PAR-FS-03 after the archive arrived",
            query=(
                "DeviceNetworkEvents\n"
                "| where Timestamp between (datetime(2026-08-19T03:00:00Z) .. datetime(2026-08-26))\n"
                '| where DeviceName =~ "PAR-FS-03" and RemoteIPType == "Public"\n'
                "| summarize Connections=count(), First=min(Timestamp), Last=max(Timestamp) by RemoteIP, RemotePort, InitiatingProcessFileName\n"
                "| order by Connections desc\n"
                "| take 20"
            ),
            columns=[
                "RemoteIP",
                "RemotePort",
                "InitiatingProcessFileName",
                "Connections",
                "First",
                "Last",
            ],
            sample=[
                {
                    "RemoteIP": "45.155.12.7",
                    "RemotePort": 443,
                    "InitiatingProcessFileName": "svchost.exe",
                    "Connections": 812,
                    "First": "2026-08-19T03:00:14Z",
                    "Last": "2026-08-25T23:51:12Z",
                },
                {
                    "RemoteIP": "20.190.160.14",
                    "RemotePort": 443,
                    "InitiatingProcessFileName": "MsMpEng.exe",
                    "Connections": 402,
                    "First": "2026-08-19T03:05:00Z",
                    "Last": "2026-08-25T23:58:41Z",
                },
                {
                    "RemoteIP": "103.56.54.212",
                    "RemotePort": 8443,
                    "InitiatingProcessFileName": "svchost.exe",
                    "Connections": 96,
                    "First": "2026-08-21T03:03:40Z",
                    "Last": "2026-08-25T22:10:05Z",
                },
            ],
            model_sample=[
                {
                    "RemoteIP": "45.155.12.7",
                    "RemotePort": 443,
                    "InitiatingProcessFileName": "svchost.exe",
                    "Connections": 812,
                    "First": "2026-08-19T03:00:14Z",
                    "Last": "2026-08-25T23:51:12Z",
                },
                {
                    "RemoteIP": "20.190.160.14",
                    "RemotePort": 443,
                    "InitiatingProcessFileName": "MsMpEng.exe",
                    "Connections": 402,
                    "First": "2026-08-19T03:05:00Z",
                    "Last": "2026-08-25T23:58:41Z",
                },
                {
                    "RemoteIP": "103.56.54.212",
                    "RemotePort": 8443,
                    "InitiatingProcessFileName": "svchost.exe",
                    "Connections": 96,
                    "First": "2026-08-21T03:03:40Z",
                    "Last": "2026-08-25T22:10:05Z",
                },
            ],
            anonymization=anon(host=1),
            interpretation="The C2 channels stay open after the archive lands on PAR-FS-03, but endpoint telemetry gives no byte counts: I cannot tell whether 20 MB went through. The Microsoft address is Defender's own cloud service. Without network volume data the exfiltration stays a strong hypothesis, not an established fact.",
        ),
    ]
    findings = [
        Finding(
            id="f_b81d4e2f",
            title="IFM copy archived and staged on the PAR-FS-03 backup share",
            severity="high",
            confidence="high",
            recorded_at="2026-09-04T09:11:20+00:00",
            description=(
                "adm-helpdesk compressed C:\\Windows\\Temp\\ifm into a 20 MB ifm.zip on "
                "PAR-DC-01 eleven minutes after the export, and copied it over SMB to "
                "D:\\Shares\\backup$\\staging on PAR-FS-03, the host relaying to the C2."
            ),
            entities=[
                Entity(type="host", value="PAR-DC-01"),
                Entity(type="host", value="PAR-FS-03"),
                Entity(type="account", value="adm-helpdesk"),
                Entity(type="file_path", value="D:\\Shares\\backup$\\staging\\ifm.zip"),
            ],
            evidence_query_ids=[g1, g2],
        ),
        Finding(
            id="f_0c9a7e35",
            title="Exfiltration volume cannot be established from endpoint telemetry",
            severity="info",
            confidence="medium",
            recorded_at="2026-09-04T09:12:50+00:00",
            description=(
                "812 further connections to 45.155.12.7 follow the staging of the archive, "
                "but DeviceNetworkEvents carries no byte counts. Firewall or proxy logs are "
                "required to confirm or rule out the transfer."
            ),
            entities=[
                Entity(type="ip", value="45.155.12.7"),
                Entity(type="host", value="PAR-FS-03"),
            ],
            evidence_query_ids=[g3],
        ),
    ]
    report = HuntReport(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.CLOSED,
        proposed_verdict=Verdict.SUSPICIOUS,
        summary=(
            "The IFM copy was staged for exfiltration: compressed into ifm.zip on PAR-DC-01 "
            "at 02:52 on 19 August, then copied to the backup$ share of PAR-FS-03 at 03:01. "
            "PAR-FS-03 kept its two C2 channels open for the following six days. The "
            "transfer itself cannot be proven or excluded from endpoint data alone."
        ),
        limitations="No byte counts in DeviceNetworkEvents; no firewall, proxy or NetFlow source is connected. The archive's presence on PAR-FS-03 after 25 August was not checked.",
        recommendation="Request the perimeter firewall logs for PAR-FS-03 between 19 and 26 August (destinations 45.155.12.7:443 and 103.56.54.212:8443) and assume the domain hashes are compromised in the meantime.",
        iocs=ioc_views(iocs),
        findings=findings,
        executed_queries=queries,
        timeline=[
            TimelineEvent(
                timestamp="2026-08-19T02:52:16Z",
                source=g1,
                event="Compress-Archive of C:\\Windows\\Temp\\ifm on PAR-DC-01",
            ),
            TimelineEvent(
                timestamp="2026-08-19T02:53:40Z",
                source=g2,
                event="ifm.zip (20 MB) written on PAR-DC-01",
            ),
            TimelineEvent(
                timestamp="2026-08-19T03:01:12Z",
                source=g2,
                event="ifm.zip copied over SMB to PAR-FS-03 backup$ share",
            ),
            TimelineEvent(
                timestamp="2026-08-19T03:00:14Z",
                source=g3,
                event="C2 channel from PAR-FS-03 to 45.155.12.7 resumes",
            ),
        ],
        budgets=budgets(8, 3, 74_210, 201.7, limits={"iterations": 20, "siem_queries": 15}),
        generated_at="2026-09-04T09:13:30+00:00",
        attack_overview=AttackOverview(
            description="Staging of stolen directory data: the IFM export is archived on the domain controller and moved to the compromised file server that already relays traffic to the command-and-control infrastructure.",
            techniques=[
                AttackTechnique(
                    id="T1560.001",
                    name="Archive via Utility",
                    description="Compress-Archive of the IFM folder into a single zip on PAR-DC-01.",
                ),
                AttackTechnique(
                    id="T1074.002",
                    name="Remote Data Staging",
                    description="Copy of the archive to a share on PAR-FS-03, the relay host.",
                ),
                AttackTechnique(
                    id="T1041",
                    name="Exfiltration Over C2 Channel",
                    description="Suspected transfer over the netsh port proxies; not established.",
                ),
            ],
            scope=scope(
                window=window,
                sources=sources,
                campaign=campaign,
                executed=3,
                max_queries=15,
                max_iterations=20,
            ),
        ),
        playbook=playbook,
        parent_hunt_id=VOLT,
        sources=sources,
        investigation_window=window,
    )
    audit = [
        event(
            "hunt_created",
            analyst,
            at,
            hunt_id=hunt_id,
            detail={
                "hypothesis": hypothesis,
                "campaign": campaign,
                "resumed_from": VOLT,
                "from_query_id": "q_8a1e5f3c62",
                "instruction": resume_context,
            },
        ),
        event(
            "plan_proposed",
            analyst,
            "2026-09-04T09:07:40+00:00",
            hunt_id=hunt_id,
            detail={
                "steps": 3,
                "estimated_queries": 6,
                "estimated_iterations": 9,
                "instruction": resume_context,
                "requested_by": analyst,
            },
        ),
        event(
            "plan_validated",
            analyst,
            "2026-09-04T09:09:02+00:00",
            hunt_id=hunt_id,
            detail={
                "by": analyst,
                "max_iterations": 20,
                "max_siem_queries": 15,
                "from_playbook": True,
                "adjusted": True,
            },
        ),
        *query_events(hunt_id, "agent", queries),
        *finding_events(hunt_id, "agent", findings),
        event(
            "hunt_concluded",
            "agent",
            "2026-09-04T09:13:30+00:00",
            hunt_id=hunt_id,
            detail={"proposed_verdict": "suspicious", "findings": 2},
        ),
        event(
            "report_validated",
            analyst,
            "2026-09-04T11:32:40+00:00",
            hunt_id=hunt_id,
            detail={"verdict": "suspicious", "proposed_verdict": "suspicious", "comment": True},
        ),
    ]
    return DemoHunt(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.CLOSED,
        created_at=at,
        updated_at="2026-09-04T11:32:40+00:00",
        playbook=playbook,
        parent_hunt_id=VOLT,
        resume_context=resume_context,
        iocs=iocs,
        report=report,
        decision={
            "human_verdict": "suspicious",
            "decided_by": analyst,
            "decided_at": "2026-09-04T11:32:40+00:00",
            "decision_comment": "Staging confirmed, transfer not provable from endpoints. Firewall export requested from the network team (REQ-4471), to be attached to INC-2026-0912.",
        },
        audit=audit,
    )


# --------------------------------------------------------------------------- hunt 3
# Password spray + MFA fatigue + OAuth consent. Awaiting the analyst's verdict.


def hunt_password_spray() -> DemoHunt:
    hunt_id = SPRAY
    analyst = "m.dubois"
    campaign = "Midnight Blizzard"
    hypothesis = (
        "Password spraying against Entra ID followed by MFA fatigue push notifications and a "
        "malicious OAuth application consent on the account that gave in."
    )
    window = "2026-09-08T00:00:00+00:00 -> 2026-09-22T12:00:00+00:00"
    sources = ["sentinel", "defender"]
    at = "2026-09-22T13:46:10+00:00"
    iocs = [
        ioc(
            "185.220.101.47",
            "ip",
            "AlienVault OTX",
            "https://otx.alienvault.com/pulse/66e4a1f2b3c4d5e6f7a8b9c0",
            first_seen="2026-09-05",
            confidence="high",
            validated_by=analyst,
            validated_at=at,
        ),
        ioc(
            "91.219.236.166",
            "ip",
            "ThreatFox",
            "https://threatfox.abuse.ch/ioc/1201877/",
            first_seen="2026-09-12",
            confidence="medium",
            validated_by=analyst,
            validated_at=at,
        ),
        ioc(
            "sso-verify-portal.com",
            "domain",
            "VirusTotal",
            "https://www.virustotal.com/gui/domain/sso-verify-portal.com",
            first_seen="2026-09-10",
            confidence="malicious (22/94)",
            validated_by=analyst,
            validated_at=at,
        ),
        ioc(
            "login-microsoft-secure.net",
            "domain",
            "CIRCL MISP OSINT",
            "https://www.circl.lu/doc/misp/feed-osint/",
            first_seen="2024-02-14",
            confidence="low",
            status="rejected",
            validated_by=analyst,
            validated_at=at,
        ),
    ]
    playbook = Playbook(
        summary=(
            "Characterize the spray from the two validated addresses (breadth, cadence, "
            "outcome), isolate the accounts that received MFA push storms, confirm any "
            "approval that followed, then check the post-authentication actions of those "
            "accounts: application consents, inbox rules, new devices."
        ),
        steps=[
            PlaybookStep(
                order=1,
                siem="sentinel",
                technique="T1110.003",
                expected_queries=2,
                objective="Measure the spray from the validated addresses: accounts targeted, attempts, failures, time span.",
            ),
            PlaybookStep(
                order=2,
                siem="sentinel",
                technique="T1621",
                expected_queries=2,
                objective="Find accounts with repeated MFA denials followed by a successful approval from the same address.",
            ),
            PlaybookStep(
                order=3,
                siem="sentinel",
                technique="T1528",
                expected_queries=2,
                objective="Application consents granted by those accounts, with the scopes requested.",
            ),
            PlaybookStep(
                order=4,
                siem="defender",
                technique="T1078.004",
                expected_queries=2,
                objective="Privileges and blast radius of the compromised accounts, mailbox rules and new device registrations.",
            ),
        ],
        not_covered="Phishing pages hosted on the validated domains are not inspected: no web proxy log is connected, so clicks cannot be attributed.",
        estimated_queries=8,
        estimated_iterations=12,
        generated_at="2026-09-22T13:48:55+00:00",
        validated_by=analyst,
        validated_at="2026-09-22T13:50:20+00:00",
        validated_queries=25,
        validated_iterations=30,
    )
    b1, b2, b3, b4, b5 = (
        "q_3e7a1d9c56",
        "q_8b4f2e6a03",
        "q_1c9d5b7e28",
        "q_6f0a3c8d94",
        "q_d2e8b4f7a1",
    )
    queries = [
        ExecutedQuery(
            query_id=b1,
            siem="sentinel",
            executed_at="2026-09-22T13:50:48+00:00",
            returned_rows=2,
            source_rows=2,
            truncated=False,
            duration_ms=3410,
            intent="Breadth and cadence of the spray from the validated addresses",
            query=(
                "SigninLogs\n"
                "| where TimeGenerated between (datetime(2026-09-08) .. datetime(2026-09-22T12:00:00Z))\n"
                '| where IPAddress in ("185.220.101.47", "91.219.236.166")\n'
                "| summarize Attempts=count(), Accounts=dcount(UserPrincipalName), Failures=countif(ResultType != 0), Start=min(TimeGenerated), End=max(TimeGenerated) by IPAddress"
            ),
            columns=["IPAddress", "Attempts", "Accounts", "Failures", "Start", "End"],
            sample=[
                {
                    "IPAddress": "185.220.101.47",
                    "Attempts": 158,
                    "Accounts": 143,
                    "Failures": 157,
                    "Start": "2026-09-21T06:31:02Z",
                    "End": "2026-09-21T06:51:40Z",
                },
                {
                    "IPAddress": "91.219.236.166",
                    "Attempts": 61,
                    "Accounts": 61,
                    "Failures": 61,
                    "Start": "2026-09-14T22:10:18Z",
                    "End": "2026-09-14T22:19:55Z",
                },
            ],
            model_sample=[
                {
                    "IPAddress": "185.220.101.47",
                    "Attempts": 158,
                    "Accounts": 143,
                    "Failures": 157,
                    "Start": "2026-09-21T06:31:02Z",
                    "End": "2026-09-21T06:51:40Z",
                },
                {
                    "IPAddress": "91.219.236.166",
                    "Attempts": 61,
                    "Accounts": 61,
                    "Failures": 61,
                    "Start": "2026-09-14T22:10:18Z",
                    "End": "2026-09-14T22:19:55Z",
                },
            ],
            anonymization=anon(),
            interpretation="Classic spray signature: one attempt per account, 143 accounts in twenty minutes from 185.220.101.47, with exactly one success. The earlier wave from 91.219.236.166 failed entirely. I focus on the single success of 21 September.",
        ),
        ExecutedQuery(
            query_id=b2,
            siem="sentinel",
            executed_at="2026-09-22T13:52:03+00:00",
            returned_rows=4,
            source_rows=4,
            truncated=False,
            duration_ms=2870,
            intent="MFA push denials per account from the spray address",
            query=(
                "SigninLogs\n"
                "| where TimeGenerated between (datetime(2026-09-21) .. datetime(2026-09-22T12:00:00Z))\n"
                '| where IPAddress == "185.220.101.47" and ResultType in (500121, 50074)\n'
                "| summarize Denials=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by UserPrincipalName\n"
                "| order by Denials desc\n"
                "| take 20"
            ),
            columns=["UserPrincipalName", "Denials", "First", "Last"],
            sample=[
                {
                    "UserPrincipalName": "j.morel@corp.internal",
                    "Denials": 27,
                    "First": "2026-09-21T06:38:11Z",
                    "Last": "2026-09-21T06:47:29Z",
                },
                {
                    "UserPrincipalName": "s.benali@corp.internal",
                    "Denials": 9,
                    "First": "2026-09-21T06:39:02Z",
                    "Last": "2026-09-21T06:44:51Z",
                },
                {
                    "UserPrincipalName": "k.nguyen@corp.internal",
                    "Denials": 4,
                    "First": "2026-09-21T06:40:15Z",
                    "Last": "2026-09-21T06:42:07Z",
                },
                {
                    "UserPrincipalName": "p.aubert@corp.internal",
                    "Denials": 2,
                    "First": "2026-09-21T06:41:33Z",
                    "Last": "2026-09-21T06:41:58Z",
                },
            ],
            model_sample=[
                {
                    "UserPrincipalName": "USER-001",
                    "Denials": 27,
                    "First": "2026-09-21T06:38:11Z",
                    "Last": "2026-09-21T06:47:29Z",
                },
                {
                    "UserPrincipalName": "USER-002",
                    "Denials": 9,
                    "First": "2026-09-21T06:39:02Z",
                    "Last": "2026-09-21T06:44:51Z",
                },
                {
                    "UserPrincipalName": "USER-003",
                    "Denials": 4,
                    "First": "2026-09-21T06:40:15Z",
                    "Last": "2026-09-21T06:42:07Z",
                },
                {
                    "UserPrincipalName": "USER-004",
                    "Denials": 2,
                    "First": "2026-09-21T06:41:33Z",
                    "Last": "2026-09-21T06:41:58Z",
                },
            ],
            anonymization=anon(user=4),
            interpretation="Four accounts had their password guessed and received push storms. j.morel received 27 prompts in nine minutes, three times more than anyone else: the attacker insisted on that one, which suggests it eventually approved.",
        ),
        ExecutedQuery(
            query_id=b3,
            siem="sentinel",
            executed_at="2026-09-22T13:53:27+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=2140,
            intent="Successful sign-ins of the most targeted account",
            query=(
                "SigninLogs\n"
                "| where TimeGenerated between (datetime(2026-09-21) .. datetime(2026-09-22T12:00:00Z))\n"
                '| where UserPrincipalName =~ "j.morel@corp.internal" and ResultType == 0\n'
                "| project TimeGenerated, IPAddress, Location, AppDisplayName, AuthenticationRequirement, ConditionalAccessStatus"
            ),
            columns=[
                "TimeGenerated",
                "IPAddress",
                "Location",
                "AppDisplayName",
                "AuthenticationRequirement",
                "ConditionalAccessStatus",
            ],
            sample=[
                {
                    "TimeGenerated": "2026-09-21T06:48:31Z",
                    "IPAddress": "185.220.101.47",
                    "Location": "Frankfurt, DE",
                    "AppDisplayName": "Office 365 Exchange Online",
                    "AuthenticationRequirement": "multiFactorAuthentication",
                    "ConditionalAccessStatus": "success",
                },
                {
                    "TimeGenerated": "2026-09-21T08:15:02Z",
                    "IPAddress": "10.42.60.31",
                    "Location": "Paris, FR",
                    "AppDisplayName": "Microsoft Teams",
                    "AuthenticationRequirement": "singleFactorAuthentication",
                    "ConditionalAccessStatus": "success",
                },
                {
                    "TimeGenerated": "2026-09-22T07:02:44Z",
                    "IPAddress": "10.42.60.31",
                    "Location": "Paris, FR",
                    "AppDisplayName": "Office 365 SharePoint Online",
                    "AuthenticationRequirement": "singleFactorAuthentication",
                    "ConditionalAccessStatus": "success",
                },
            ],
            model_sample=[
                {
                    "TimeGenerated": "2026-09-21T06:48:31Z",
                    "IPAddress": "185.220.101.47",
                    "Location": "Frankfurt, DE",
                    "AppDisplayName": "Office 365 Exchange Online",
                    "AuthenticationRequirement": "multiFactorAuthentication",
                    "ConditionalAccessStatus": "success",
                },
                {
                    "TimeGenerated": "2026-09-21T08:15:02Z",
                    "IPAddress": "IP-INT-001",
                    "Location": "Paris, FR",
                    "AppDisplayName": "Microsoft Teams",
                    "AuthenticationRequirement": "singleFactorAuthentication",
                    "ConditionalAccessStatus": "success",
                },
                {
                    "TimeGenerated": "2026-09-22T07:02:44Z",
                    "IPAddress": "IP-INT-001",
                    "Location": "Paris, FR",
                    "AppDisplayName": "Office 365 SharePoint Online",
                    "AuthenticationRequirement": "singleFactorAuthentication",
                    "ConditionalAccessStatus": "success",
                },
            ],
            anonymization=anon(ip=1),
            interpretation="Confirmed: at 06:48, sixty seconds after the last denial, j.morel approved a push from the spray address and a full MFA session was opened on Exchange Online from Frankfurt. The user's normal activity from the office resumes the same morning, unaware.",
        ),
        ExecutedQuery(
            query_id=b4,
            siem="sentinel",
            executed_at="2026-09-22T13:54:50+00:00",
            returned_rows=1,
            source_rows=1,
            truncated=False,
            duration_ms=1960,
            intent="Application consents granted by the compromised account",
            query=(
                "AuditLogs\n"
                "| where TimeGenerated between (datetime(2026-09-21) .. datetime(2026-09-22T12:00:00Z))\n"
                '| where OperationName =~ "Consent to application"\n'
                "| extend Actor = tostring(InitiatedBy.user.userPrincipalName), App = tostring(TargetResources[0].displayName), Scopes = tostring(TargetResources[0].modifiedProperties[4].newValue)\n"
                '| where Actor =~ "j.morel@corp.internal"\n'
                "| project TimeGenerated, Actor, App, Scopes, Result"
            ),
            columns=["TimeGenerated", "Actor", "App", "Scopes", "Result"],
            sample=[
                {
                    "TimeGenerated": "2026-09-21T06:51:09Z",
                    "Actor": "j.morel@corp.internal",
                    "App": "Mail Sync Helper",
                    "Scopes": "Mail.ReadWrite offline_access User.Read",
                    "Result": "success",
                }
            ],
            model_sample=[
                {
                    "TimeGenerated": "2026-09-21T06:51:09Z",
                    "Actor": "USER-001",
                    "App": "Mail Sync Helper",
                    "Scopes": "Mail.ReadWrite offline_access User.Read",
                    "Result": "success",
                }
            ],
            anonymization=anon(user=1),
            interpretation="Three minutes into the session, a consent was granted to an unknown multi-tenant application named Mail Sync Helper with Mail.ReadWrite and offline_access: a refresh token that survives a password reset. This is the persistence step of the campaign.",
        ),
        ExecutedQuery(
            query_id=b5,
            siem="defender",
            executed_at="2026-09-22T13:56:12+00:00",
            returned_rows=1,
            source_rows=1,
            truncated=False,
            duration_ms=1240,
            intent="Privileges of the compromised account, to size the blast radius",
            query=(
                "IdentityInfo\n"
                '| where AccountUpn =~ "j.morel@corp.internal"\n'
                "| project AccountUpn, Department, JobTitle, AssignedRoles, IsAccountEnabled"
            ),
            columns=["AccountUpn", "Department", "JobTitle", "AssignedRoles", "IsAccountEnabled"],
            sample=[
                {
                    "AccountUpn": "j.morel@corp.internal",
                    "Department": "Finance",
                    "JobTitle": "Accounts payable clerk",
                    "AssignedRoles": "[]",
                    "IsAccountEnabled": True,
                }
            ],
            model_sample=[
                {
                    "AccountUpn": "USER-001",
                    "Department": "DATA-001",
                    "JobTitle": "DATA-002",
                    "AssignedRoles": "[]",
                    "IsAccountEnabled": True,
                }
            ],
            anonymization=anon(user=1, data=2),
            interpretation="No directory role: the exposure is the mailbox itself, which for an accounts-payable role means supplier invoices and payment details. Enough for a business email compromise; I conclude.",
        ),
    ]
    findings = [
        Finding(
            id="f_5e2c9a17",
            title="MFA fatigue succeeded on j.morel after 27 push prompts",
            severity="high",
            confidence="high",
            recorded_at="2026-09-22T13:53:58+00:00",
            description="Between 06:38 and 06:47 on 21 September, j.morel received 27 MFA push prompts from 185.220.101.47 and approved one at 06:48, opening a fully authenticated Exchange Online session from Frankfurt.",
            entities=[
                Entity(type="account", value="j.morel@corp.internal"),
                Entity(type="ip", value="185.220.101.47"),
            ],
            evidence_query_ids=[b2, b3],
        ),
        Finding(
            id="f_a93d4f60",
            title="Password spray from 185.220.101.47 across 143 accounts",
            severity="high",
            confidence="high",
            recorded_at="2026-09-22T13:51:20+00:00",
            description="158 attempts against 143 distinct accounts in twenty minutes with a single success, preceded a week earlier by a fully failed wave of 61 attempts from 91.219.236.166. Four accounts had a valid password guessed.",
            entities=[
                Entity(type="ip", value="185.220.101.47"),
                Entity(type="ip", value="91.219.236.166"),
            ],
            evidence_query_ids=[b1, b2],
        ),
        Finding(
            id="f_c17e8b23",
            title="OAuth consent to 'Mail Sync Helper' with Mail.ReadWrite and offline_access",
            severity="medium",
            confidence="high",
            recorded_at="2026-09-22T13:55:15+00:00",
            description="Three minutes after the session opened, the attacker obtained a persistent consent on j.morel's mailbox. The refresh token issued to that application survives a password reset and must be revoked explicitly.",
            entities=[
                Entity(type="account", value="j.morel@corp.internal"),
                Entity(type="application", value="Mail Sync Helper"),
            ],
            evidence_query_ids=[b4],
        ),
        Finding(
            id="f_08f1d6a4",
            title="Compromised account holds no directory role",
            severity="info",
            confidence="high",
            recorded_at="2026-09-22T13:56:40+00:00",
            description="j.morel has no assigned Entra role; the exposure is limited to the mailbox, which in an accounts-payable position carries supplier and payment data.",
            entities=[Entity(type="account", value="j.morel@corp.internal")],
            evidence_query_ids=[b5],
        ),
    ]
    report = HuntReport(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.AWAITING_REVIEW,
        proposed_verdict=Verdict.SUSPICIOUS,
        summary=(
            "The hypothesis is verified on one account. A spray of 143 accounts from "
            "185.220.101.47 on 21 September guessed four passwords; MFA push storms followed, "
            "and j.morel approved a prompt after 27 attempts. Within three minutes the "
            "attacker granted a persistent OAuth consent (Mail Sync Helper, Mail.ReadWrite, "
            "offline_access) on the mailbox. The account has no privileged role; the "
            "exposure is the mailbox of an accounts-payable clerk."
        ),
        limitations="Mailbox activity after the consent (rules, forwarding, reads) was not examined: no Exchange audit source is connected to this installation. The three other accounts with a guessed password were not checked for later successful sign-ins.",
        recommendation="Revoke the Mail Sync Helper consent and the account's refresh tokens, reset j.morel and re-enrol MFA with number matching, block both addresses in conditional access, and force a reset for the three other accounts whose password was guessed.",
        iocs=ioc_views(iocs),
        findings=findings,
        executed_queries=queries,
        timeline=[
            TimelineEvent(
                timestamp="2026-09-14T22:10:18Z",
                source=b1,
                event="First spray wave from 91.219.236.166, 61 accounts, no success",
            ),
            TimelineEvent(
                timestamp="2026-09-21T06:31:02Z",
                source=b1,
                event="Second wave from 185.220.101.47, 143 accounts in twenty minutes",
            ),
            TimelineEvent(
                timestamp="2026-09-21T06:38:11Z",
                source=b2,
                event="MFA push storm starts on j.morel",
            ),
            TimelineEvent(
                timestamp="2026-09-21T06:48:31Z",
                source=b3,
                event="j.morel approves a push; MFA session opened from Frankfurt",
            ),
            TimelineEvent(
                timestamp="2026-09-21T06:51:09Z",
                source=b4,
                event="Consent granted to Mail Sync Helper (Mail.ReadWrite, offline_access)",
            ),
        ],
        budgets=budgets(11, 5, 156_780, 344.2),
        generated_at="2026-09-22T13:57:05+00:00",
        attack_overview=AttackOverview(
            description="Identity-centric intrusion without malware: a low-and-slow password spray, MFA fatigue on the accounts whose password was guessed, then a persistent OAuth consent on the mailbox that gave in.",
            techniques=[
                AttackTechnique(
                    id="T1110.003",
                    name="Password Spraying",
                    description="One attempt per account across 143 accounts in twenty minutes.",
                ),
                AttackTechnique(
                    id="T1621",
                    name="Multi-Factor Authentication Request Generation",
                    description="27 push prompts on a single account until one was approved.",
                ),
                AttackTechnique(
                    id="T1528",
                    name="Steal Application Access Token",
                    description="Consent to a multi-tenant application with offline_access to keep a refresh token.",
                ),
            ],
            scope=scope(window=window, sources=sources, campaign=campaign, executed=5),
        ),
        playbook=playbook,
        sources=sources,
        investigation_window=window,
    )
    audit = [
        event(
            "hunt_created",
            analyst,
            "2026-09-22T13:40:05+00:00",
            hunt_id=hunt_id,
            detail={
                "hypothesis": hypothesis,
                "campaign": campaign,
                "manual_iocs": 0,
                "seeded_from_probe": False,
                "sources": sources,
            },
        ),
        event(
            "ioc_search",
            analyst,
            "2026-09-22T13:41:30+00:00",
            hunt_id=hunt_id,
            detail={
                "campaign": campaign,
                "found": 4,
                "sources": ["AlienVault OTX", "ThreatFox", "VirusTotal", "CIRCL MISP OSINT"],
                "dropped_unsourced": 1,
            },
        ),
        event(
            "ioc_validation",
            analyst,
            at,
            hunt_id=hunt_id,
            detail={
                "validated": ["185.220.101.47", "91.219.236.166", "sso-verify-portal.com"],
                "rejected": ["login-microsoft-secure.net"],
                "total": 4,
            },
        ),
        event(
            "plan_proposed",
            analyst,
            "2026-09-22T13:48:55+00:00",
            hunt_id=hunt_id,
            detail={
                "steps": 4,
                "estimated_queries": 8,
                "estimated_iterations": 12,
                "instruction": None,
                "requested_by": analyst,
            },
        ),
        event(
            "plan_validated",
            analyst,
            "2026-09-22T13:50:20+00:00",
            hunt_id=hunt_id,
            detail={
                "by": analyst,
                "max_iterations": 30,
                "max_siem_queries": 25,
                "from_playbook": True,
                "adjusted": False,
            },
        ),
        *query_events(hunt_id, "agent", queries),
        *finding_events(hunt_id, "agent", findings),
        event(
            "hunt_concluded",
            "agent",
            "2026-09-22T13:57:05+00:00",
            hunt_id=hunt_id,
            detail={"proposed_verdict": "suspicious", "findings": 4},
        ),
    ]
    return DemoHunt(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.AWAITING_REVIEW,
        created_at="2026-09-22T13:40:05+00:00",
        updated_at="2026-09-22T13:57:05+00:00",
        playbook=playbook,
        iocs=iocs,
        report=report,
        audit=audit,
    )


# --------------------------------------------------------------------------- hunt 4
# Behavioral hypothesis with a benign outcome. Closed.


def hunt_scheduled_tasks() -> DemoHunt:
    hunt_id = SCHTASKS
    analyst = "a.leclerc"
    hypothesis = (
        "Scheduled tasks created by non-administrative accounts on workstations, as a "
        "persistence mechanism (T1053.005)."
    )
    sources = ["defender", "secops"]
    playbook = Playbook(
        summary="Enumerate scheduled-task creations on workstations over the last month, separate the ones driven by management tooling from the rest, and inspect what remains: account, parent process, task action.",
        steps=[
            PlaybookStep(
                order=1,
                siem="defender",
                technique="T1053.005",
                expected_queries=2,
                objective="schtasks /create executions on workstations, grouped by account and parent process.",
            ),
            PlaybookStep(
                order=2,
                siem="defender",
                technique="T1053.005",
                expected_queries=2,
                objective="ScheduledTaskCreated events: task names, creators, spread across devices and time.",
            ),
            PlaybookStep(
                order=3,
                siem="secops",
                technique="T1053.005",
                expected_queries=2,
                objective="Same lead on the Linux and macOS fleet ingested in SecOps (cron, launchd, at).",
            ),
        ],
        not_covered="Tasks registered directly through the Task Scheduler COM API without schtasks.exe are only visible through the ScheduledTaskCreated event, which requires the Defender advanced audit setting to be on.",
        estimated_queries=6,
        estimated_iterations=9,
        generated_at="2026-08-19T15:26:02+00:00",
        validated_by=analyst,
        validated_at="2026-08-19T15:27:15+00:00",
        validated_queries=25,
        validated_iterations=30,
    )
    c1, c2, c3, c4 = "q_7a2e4c9b13", "q_e5b1f8d3a7", "q_4c8d2a6f50", "q_92f6e1b4c8"
    queries = [
        ExecutedQuery(
            query_id=c1,
            siem="defender",
            executed_at="2026-08-19T15:27:40+00:00",
            returned_rows=5,
            source_rows=5,
            truncated=False,
            duration_ms=2680,
            intent="Who creates scheduled tasks on workstations, and from which parent process",
            query=(
                "DeviceProcessEvents\n"
                "| where Timestamp > ago(30d)\n"
                '| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"\n'
                '| join kind=inner (DeviceInfo | where OSPlatform startswith "Windows" and DeviceType == "Workstation" | distinct DeviceId) on DeviceId\n'
                "| summarize Tasks=count(), Devices=dcount(DeviceName), Sample=any(ProcessCommandLine) by AccountName, InitiatingProcessFileName\n"
                "| order by Tasks desc"
            ),
            columns=["AccountName", "InitiatingProcessFileName", "Tasks", "Devices", "Sample"],
            sample=[
                {
                    "AccountName": "system",
                    "InitiatingProcessFileName": "AgentExecutor.exe",
                    "Tasks": 412,
                    "Devices": 409,
                    "Sample": 'schtasks /create /tn "Microsoft\\Intune\\EndpointAgentHealth" /xml C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Content\\health.xml /f',
                },
                {
                    "AccountName": "system",
                    "InitiatingProcessFileName": "msiexec.exe",
                    "Tasks": 38,
                    "Devices": 38,
                    "Sample": 'schtasks /create /tn "Adobe Acrobat Update Task" /xml C:\\Windows\\Temp\\acrobat_task.xml /f',
                },
                {
                    "AccountName": "c.roux",
                    "InitiatingProcessFileName": "cmd.exe",
                    "Tasks": 3,
                    "Devices": 1,
                    "Sample": 'schtasks /create /tn "SyncNotes" /tr "C:\\Users\\c.roux\\Tools\\sync.bat" /sc daily /st 09:00',
                },
                {
                    "AccountName": "t.lambert",
                    "InitiatingProcessFileName": "powershell.exe",
                    "Tasks": 1,
                    "Devices": 1,
                    "Sample": 'schtasks /create /tn "PowerBI refresh" /tr "powershell -File C:\\Users\\t.lambert\\refresh.ps1" /sc weekly /d MON',
                },
                {
                    "AccountName": "adm-ws",
                    "InitiatingProcessFileName": "cmd.exe",
                    "Tasks": 1,
                    "Devices": 1,
                    "Sample": 'schtasks /create /tn "Cleanup" /tr "cmd /c del /q C:\\Temp\\*" /sc onlogon',
                },
            ],
            model_sample=[
                {
                    "AccountName": "system",
                    "InitiatingProcessFileName": "AgentExecutor.exe",
                    "Tasks": 412,
                    "Devices": 409,
                    "Sample": 'schtasks /create /tn "Microsoft\\Intune\\EndpointAgentHealth" /xml C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Content\\health.xml /f',
                },
                {
                    "AccountName": "system",
                    "InitiatingProcessFileName": "msiexec.exe",
                    "Tasks": 38,
                    "Devices": 38,
                    "Sample": 'schtasks /create /tn "Adobe Acrobat Update Task" /xml C:\\Windows\\Temp\\acrobat_task.xml /f',
                },
                {
                    "AccountName": "USER-001",
                    "InitiatingProcessFileName": "cmd.exe",
                    "Tasks": 3,
                    "Devices": 1,
                    "Sample": 'schtasks /create /tn "SyncNotes" /tr "C:\\Users\\USER-001\\Tools\\sync.bat" /sc daily /st 09:00',
                },
                {
                    "AccountName": "USER-002",
                    "InitiatingProcessFileName": "powershell.exe",
                    "Tasks": 1,
                    "Devices": 1,
                    "Sample": 'schtasks /create /tn "PowerBI refresh" /tr "powershell -File C:\\Users\\USER-002\\refresh.ps1" /sc weekly /d MON',
                },
                {
                    "AccountName": "USER-003",
                    "InitiatingProcessFileName": "cmd.exe",
                    "Tasks": 1,
                    "Devices": 1,
                    "Sample": 'schtasks /create /tn "Cleanup" /tr "cmd /c del /q C:\\Temp\\*" /sc onlogon',
                },
            ],
            anonymization=anon(user=3),
            interpretation="Of 455 creations, 450 come from SYSTEM through the Intune agent or an MSI installer. Five come from three user accounts on their own workstation, each with a readable, plausible action (a sync batch, a Power BI refresh, a temp cleanup). Nothing hides behind an encoded command or an unusual path. I check the fleet-wide event to see whether the Intune wave is one rollout.",
        ),
        ExecutedQuery(
            query_id=c2,
            siem="defender",
            executed_at="2026-08-19T15:29:05+00:00",
            returned_rows=4,
            source_rows=4,
            truncated=False,
            duration_ms=2310,
            intent="Task names and their spread across devices and time",
            query=(
                "DeviceEvents\n"
                "| where Timestamp > ago(30d)\n"
                '| where ActionType == "ScheduledTaskCreated"\n'
                "| extend TaskName = tostring(AdditionalFields.TaskName)\n"
                "| summarize Devices=dcount(DeviceName), First=min(Timestamp), Last=max(Timestamp) by TaskName, InitiatingProcessAccountName\n"
                "| order by Devices desc\n"
                "| take 20"
            ),
            columns=["TaskName", "InitiatingProcessAccountName", "Devices", "First", "Last"],
            sample=[
                {
                    "TaskName": "\\Microsoft\\Intune\\EndpointAgentHealth",
                    "InitiatingProcessAccountName": "system",
                    "Devices": 409,
                    "First": "2026-08-18T08:02:11Z",
                    "Last": "2026-08-18T17:48:36Z",
                },
                {
                    "TaskName": "\\Adobe Acrobat Update Task",
                    "InitiatingProcessAccountName": "system",
                    "Devices": 38,
                    "First": "2026-07-29T09:10:44Z",
                    "Last": "2026-08-15T14:22:03Z",
                },
                {
                    "TaskName": "\\SyncNotes",
                    "InitiatingProcessAccountName": "c.roux",
                    "Devices": 1,
                    "First": "2026-08-04T07:55:19Z",
                    "Last": "2026-08-06T08:01:40Z",
                },
                {
                    "TaskName": "\\PowerBI refresh",
                    "InitiatingProcessAccountName": "t.lambert",
                    "Devices": 1,
                    "First": "2026-08-11T10:12:58Z",
                    "Last": "2026-08-11T10:12:58Z",
                },
            ],
            model_sample=[
                {
                    "TaskName": "\\Microsoft\\Intune\\EndpointAgentHealth",
                    "InitiatingProcessAccountName": "system",
                    "Devices": 409,
                    "First": "2026-08-18T08:02:11Z",
                    "Last": "2026-08-18T17:48:36Z",
                },
                {
                    "TaskName": "\\Adobe Acrobat Update Task",
                    "InitiatingProcessAccountName": "system",
                    "Devices": 38,
                    "First": "2026-07-29T09:10:44Z",
                    "Last": "2026-08-15T14:22:03Z",
                },
                {
                    "TaskName": "\\SyncNotes",
                    "InitiatingProcessAccountName": "USER-001",
                    "Devices": 1,
                    "First": "2026-08-04T07:55:19Z",
                    "Last": "2026-08-06T08:01:40Z",
                },
                {
                    "TaskName": "\\PowerBI refresh",
                    "InitiatingProcessAccountName": "USER-002",
                    "Devices": 1,
                    "First": "2026-08-11T10:12:58Z",
                    "Last": "2026-08-11T10:12:58Z",
                },
            ],
            anonymization=anon(user=2),
            interpretation="The 409-device task was created in a single business day, 18 August, under the Microsoft\\Intune folder: a rollout, not a lateral spread. The remaining tasks are isolated to one device each.",
        ),
        ExecutedQuery(
            query_id=c3,
            siem="secops",
            executed_at="2026-08-19T15:30:22+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=4120,
            intent="Same lead on the Linux and macOS fleet: cron and launchd registrations by users",
            query=(
                'metadata.event_type = "PROCESS_LAUNCH" AND '
                "(target.process.file.full_path = /crontab$/ OR target.process.file.full_path = /launchctl$/) AND "
                'NOT principal.user.userid = "root"'
            ),
            columns=[
                "metadata.event_timestamp",
                "principal.hostname",
                "principal.user.userid",
                "target.process.command_line",
            ],
            sample=[
                {
                    "metadata.event_timestamp": "2026-08-12T14:03:27Z",
                    "principal.hostname": "mbp-dev-17.corp.internal",
                    "principal.user.userid": "n.garcia",
                    "target.process.command_line": "launchctl load ~/Library/LaunchAgents/com.docker.helper.plist",
                },
                {
                    "metadata.event_timestamp": "2026-08-13T09:41:08Z",
                    "principal.hostname": "lnx-data-04.corp.internal",
                    "principal.user.userid": "etl",
                    "target.process.command_line": "crontab /opt/etl/schedules/nightly.cron",
                },
                {
                    "metadata.event_timestamp": "2026-08-17T16:20:55Z",
                    "principal.hostname": "mbp-dev-22.corp.internal",
                    "principal.user.userid": "f.dubois",
                    "target.process.command_line": "launchctl load ~/Library/LaunchAgents/homebrew.mxcl.postgresql@16.plist",
                },
            ],
            model_sample=[
                {
                    "metadata.event_timestamp": "2026-08-12T14:03:27Z",
                    "principal.hostname": "HOST-001",
                    "principal.user.userid": "USER-004",
                    "target.process.command_line": "launchctl load ~/Library/LaunchAgents/com.docker.helper.plist",
                },
                {
                    "metadata.event_timestamp": "2026-08-13T09:41:08Z",
                    "principal.hostname": "HOST-002",
                    "principal.user.userid": "USER-005",
                    "target.process.command_line": "crontab /opt/etl/schedules/nightly.cron",
                },
                {
                    "metadata.event_timestamp": "2026-08-17T16:20:55Z",
                    "principal.hostname": "HOST-003",
                    "principal.user.userid": "USER-006",
                    "target.process.command_line": "launchctl load ~/Library/LaunchAgents/homebrew.mxcl.postgresql@16.plist",
                },
            ],
            anonymization=anon(host=3, user=3),
            interpretation="Three registrations on the non-Windows fleet, all developer tooling (Docker, Homebrew PostgreSQL) or the ETL service account loading its own schedule. Nothing to pursue.",
        ),
        ExecutedQuery(
            query_id=c4,
            siem="defender",
            executed_at="2026-08-19T15:31:37+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=1870,
            intent="Confirm the Intune wave is one rollout: daily volume of agent-driven task creation",
            query=(
                "DeviceProcessEvents\n"
                "| where Timestamp > ago(30d)\n"
                '| where FileName =~ "schtasks.exe" and InitiatingProcessFileName =~ "AgentExecutor.exe"\n'
                "| summarize Creations=count(), Devices=dcount(DeviceName) by bin(Timestamp, 1d)\n"
                "| order by Timestamp asc"
            ),
            columns=["Timestamp", "Creations", "Devices"],
            sample=[
                {"Timestamp": "2026-08-18T00:00:00Z", "Creations": 409, "Devices": 409},
                {"Timestamp": "2026-08-19T00:00:00Z", "Creations": 2, "Devices": 2},
                {"Timestamp": "2026-08-20T00:00:00Z", "Creations": 1, "Devices": 1},
            ],
            model_sample=[
                {"Timestamp": "2026-08-18T00:00:00Z", "Creations": 409, "Devices": 409},
                {"Timestamp": "2026-08-19T00:00:00Z", "Creations": 2, "Devices": 2},
                {"Timestamp": "2026-08-20T00:00:00Z", "Creations": 1, "Devices": 1},
            ],
            anonymization=anon(),
            interpretation="One day, one task per device, then a trickle for the machines that were offline: the signature of a managed deployment. I conclude benign.",
        ),
    ]
    findings = [
        Finding(
            id="f_6d3a1f8e",
            title="Fleet-wide task creation on 18 August is an Intune rollout",
            severity="info",
            confidence="high",
            recorded_at="2026-08-19T15:32:10+00:00",
            description="409 workstations received the Microsoft\\Intune\\EndpointAgentHealth task on 18 August through the Intune Management Extension, in a single business day. The five user-created tasks on three workstations have plain, readable actions.",
            entities=[
                Entity(type="task", value="\\Microsoft\\Intune\\EndpointAgentHealth"),
                Entity(type="process", value="AgentExecutor.exe"),
            ],
            evidence_query_ids=[c1, c2, c4],
        ),
    ]
    report = HuntReport(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        analyst=analyst,
        status=HuntStatus.CLOSED,
        proposed_verdict=Verdict.BENIGN,
        summary="No persistence through scheduled tasks by non-administrative accounts. 450 of the 455 creations of the month come from SYSTEM via the Intune agent (a one-day rollout on 18 August) or MSI installers; the five remaining tasks belong to three users on their own workstation with readable actions. The non-Windows fleet shows only developer tooling and the ETL account.",
        limitations="Tasks registered through the Task Scheduler API without schtasks.exe are covered only by the ScheduledTaskCreated event; twelve workstations without the advanced audit setting are blind to that event.",
        recommendation="Nothing to escalate. Consider a detection rule on schtasks /create with an encoded or user-profile action, which would have surfaced the interesting cases directly.",
        iocs=[],
        findings=findings,
        executed_queries=queries,
        timeline=[],
        budgets=budgets(7, 4, 61_200, 171.3),
        generated_at="2026-08-19T15:32:44+00:00",
        attack_overview=AttackOverview(
            description="Behavioral hunt for persistence via scheduled tasks created by standard user accounts on workstations, the technique most often used after a phishing foothold.",
            techniques=[
                AttackTechnique(
                    id="T1053.005",
                    name="Scheduled Task",
                    description="Creation of a scheduled task by a non-administrative account to survive reboots.",
                )
            ],
            scope=scope(window=None, sources=sources, campaign=None, executed=4),
        ),
        playbook=playbook,
        sources=sources,
        investigation_window=None,
    )
    audit = [
        event(
            "hunt_created",
            analyst,
            "2026-08-19T15:22:10+00:00",
            hunt_id=hunt_id,
            detail={
                "hypothesis": hypothesis,
                "campaign": None,
                "manual_iocs": 0,
                "seeded_from_probe": False,
                "sources": sources,
            },
        ),
        event(
            "plan_proposed",
            analyst,
            "2026-08-19T15:26:02+00:00",
            hunt_id=hunt_id,
            detail={
                "steps": 3,
                "estimated_queries": 6,
                "estimated_iterations": 9,
                "instruction": None,
                "requested_by": analyst,
            },
        ),
        event(
            "plan_validated",
            analyst,
            "2026-08-19T15:27:15+00:00",
            hunt_id=hunt_id,
            detail={
                "by": analyst,
                "max_iterations": 30,
                "max_siem_queries": 25,
                "from_playbook": True,
                "adjusted": False,
            },
        ),
        *query_events(hunt_id, "agent", queries),
        *finding_events(hunt_id, "agent", findings),
        event(
            "hunt_concluded",
            "agent",
            "2026-08-19T15:32:44+00:00",
            hunt_id=hunt_id,
            detail={"proposed_verdict": "benign", "findings": 1},
        ),
        event(
            "report_validated",
            analyst,
            "2026-08-20T09:14:55+00:00",
            hunt_id=hunt_id,
            detail={"verdict": "benign", "proposed_verdict": "benign", "comment": True},
        ),
    ]
    return DemoHunt(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        analyst=analyst,
        status=HuntStatus.CLOSED,
        created_at="2026-08-19T15:22:10+00:00",
        updated_at="2026-08-20T09:14:55+00:00",
        playbook=playbook,
        report=report,
        audit=audit,
        decision={
            "human_verdict": "benign",
            "decided_by": analyst,
            "decided_at": "2026-08-20T09:14:55+00:00",
            "decision_comment": "Rollout of the endpoint health agent confirmed by the workplace team (CHG-2026-3310). Detection rule proposal forwarded to the detection engineering backlog.",
        },
    )


# --------------------------------------------------------------------------- hunt 5
# Interrupted by budget exhaustion. Partial report, inconclusive.


def hunt_helpdesk() -> DemoHunt:
    hunt_id = HELPDESK
    analyst = "robin"
    campaign = "Scattered Spider"
    hypothesis = (
        "Helpdesk social engineering: password and MFA resets performed by the service desk "
        "followed, within the hour, by a sign-in from a residential VPN address and the "
        "enrolment of a new authentication method."
    )
    window = "2026-08-28T00:00:00+00:00 -> 2026-09-11T00:00:00+00:00"
    sources = ["sentinel", "defender"]
    at = "2026-09-11T10:06:48+00:00"
    reason = "SIEM query budget exhausted (6/6); the analyst declined the extension."
    iocs = [
        ioc(
            "corp-helpdesk-login.com",
            "domain",
            "AlienVault OTX",
            "https://otx.alienvault.com/pulse/66d8c4e2a1b3f5d7c9e0a2b4",
            first_seen="2026-08-26",
            confidence="high",
            validated_by=analyst,
            validated_at=at,
        ),
        ioc(
            "sso-corp-verify.net",
            "domain",
            "VirusTotal",
            "https://www.virustotal.com/gui/domain/sso-corp-verify.net",
            first_seen="2026-08-30",
            confidence="malicious (18/94)",
            validated_by=analyst,
            validated_at=at,
        ),
    ]
    playbook = Playbook(
        summary="Start from the service desk's own actions: list credential and MFA resets, keep the targets that signed in from an unexpected network shortly after, then check whether a new authentication method or device was registered on those accounts.",
        steps=[
            PlaybookStep(
                order=1,
                siem="sentinel",
                technique="T1098",
                expected_queries=3,
                objective="Password and MFA resets performed by helpdesk operators over the last two weeks, per target account.",
            ),
            PlaybookStep(
                order=2,
                siem="sentinel",
                technique="T1078.004",
                expected_queries=3,
                objective="Sign-ins of the reset accounts within two hours of the reset, with location and network type.",
            ),
            PlaybookStep(
                order=3,
                siem="sentinel",
                technique="T1556.006",
                expected_queries=3,
                objective="New authentication method or device registrations on those accounts after the reset.",
            ),
            PlaybookStep(
                order=4,
                siem="defender",
                technique="T1078.004",
                expected_queries=2,
                objective="Identity logon anomalies and Okta or Entra session details for the accounts retained.",
            ),
        ],
        not_covered="The phone calls themselves: no ticketing or telephony export is available, so the pretext used against the service desk cannot be reconstructed.",
        estimated_queries=11,
        estimated_iterations=16,
        generated_at="2026-09-11T10:08:30+00:00",
        validated_by=analyst,
        validated_at="2026-09-11T10:10:02+00:00",
        validated_queries=6,
        validated_iterations=15,
    )
    d1, d2, d3, d4, d5, d6 = (
        "q_b3f7a2e9c1",
        "q_5d1c8e4b76",
        "q_9a6e2f7d30",
        "q_e7c4b1a8f2",
        "q_2f9d6a3c85",
        "q_8e1b5c7f49",
    )
    queries = [
        ExecutedQuery(
            query_id=d1,
            siem="sentinel",
            executed_at="2026-09-11T10:10:35+00:00",
            returned_rows=5,
            source_rows=23,
            truncated=True,
            duration_ms=3540,
            intent="Credential resets performed by the service desk, per target",
            query=(
                "AuditLogs\n"
                "| where TimeGenerated between (datetime(2026-08-28) .. datetime(2026-09-11))\n"
                '| where OperationName in ("Reset password (by admin)", "Admin registered security info", "Admin deleted security info")\n'
                "| extend Initiator = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].userPrincipalName)\n"
                '| where Initiator startswith "hd-"\n'
                "| summarize Resets=count(), Operations=make_set(OperationName), Last=max(TimeGenerated) by Target, Initiator\n"
                "| order by Resets desc"
            ),
            columns=["Target", "Initiator", "Resets", "Operations", "Last"],
            sample=[
                {
                    "Target": "r.perrin@corp.internal",
                    "Initiator": "hd-mlopez@corp.internal",
                    "Resets": 3,
                    "Operations": '["Reset password (by admin)","Admin deleted security info"]',
                    "Last": "2026-09-09T13:22:41Z",
                },
                {
                    "Target": "v.kessler@corp.internal",
                    "Initiator": "hd-tbrun@corp.internal",
                    "Resets": 2,
                    "Operations": '["Reset password (by admin)"]',
                    "Last": "2026-09-03T08:12:09Z",
                },
                {
                    "Target": "a.moreau@corp.internal",
                    "Initiator": "hd-mlopez@corp.internal",
                    "Resets": 1,
                    "Operations": '["Reset password (by admin)"]',
                    "Last": "2026-09-08T15:40:27Z",
                },
                {
                    "Target": "l.fontaine@corp.internal",
                    "Initiator": "hd-jpetit@corp.internal",
                    "Resets": 1,
                    "Operations": '["Admin deleted security info"]',
                    "Last": "2026-09-02T10:05:53Z",
                },
                {
                    "Target": "o.diallo@corp.internal",
                    "Initiator": "hd-tbrun@corp.internal",
                    "Resets": 1,
                    "Operations": '["Reset password (by admin)"]',
                    "Last": "2026-09-10T09:31:15Z",
                },
            ],
            model_sample=[
                {
                    "Target": "USER-001",
                    "Initiator": "USER-002",
                    "Resets": 3,
                    "Operations": '["Reset password (by admin)","Admin deleted security info"]',
                    "Last": "2026-09-09T13:22:41Z",
                },
                {
                    "Target": "USER-003",
                    "Initiator": "USER-004",
                    "Resets": 2,
                    "Operations": '["Reset password (by admin)"]',
                    "Last": "2026-09-03T08:12:09Z",
                },
                {
                    "Target": "USER-005",
                    "Initiator": "USER-002",
                    "Resets": 1,
                    "Operations": '["Reset password (by admin)"]',
                    "Last": "2026-09-08T15:40:27Z",
                },
                {
                    "Target": "USER-006",
                    "Initiator": "USER-007",
                    "Resets": 1,
                    "Operations": '["Admin deleted security info"]',
                    "Last": "2026-09-02T10:05:53Z",
                },
                {
                    "Target": "USER-008",
                    "Initiator": "USER-004",
                    "Resets": 1,
                    "Operations": '["Reset password (by admin)"]',
                    "Last": "2026-09-10T09:31:15Z",
                },
            ],
            anonymization=anon(user=8),
            interpretation="23 targets in two weeks; the result was capped at five. r.perrin stands out: a password reset and an MFA method deletion by the same operator within a single day, the combination that a social engineer asks for. I follow that account first.",
        ),
        ExecutedQuery(
            query_id=d2,
            siem="sentinel",
            executed_at="2026-09-11T10:11:50+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=2210,
            intent="Exact sequence of the resets on the account that stands out",
            query=(
                "AuditLogs\n"
                "| where TimeGenerated between (datetime(2026-09-08) .. datetime(2026-09-11))\n"
                '| where tostring(TargetResources[0].userPrincipalName) =~ "r.perrin@corp.internal"\n'
                "| project TimeGenerated, OperationName, Initiator=tostring(InitiatedBy.user.userPrincipalName), Result"
            ),
            columns=["TimeGenerated", "OperationName", "Initiator", "Result"],
            sample=[
                {
                    "TimeGenerated": "2026-09-09T13:04:12Z",
                    "OperationName": "Reset password (by admin)",
                    "Initiator": "hd-mlopez@corp.internal",
                    "Result": "success",
                },
                {
                    "TimeGenerated": "2026-09-09T13:19:57Z",
                    "OperationName": "Admin deleted security info",
                    "Initiator": "hd-mlopez@corp.internal",
                    "Result": "success",
                },
                {
                    "TimeGenerated": "2026-09-09T13:22:41Z",
                    "OperationName": "Reset password (by admin)",
                    "Initiator": "hd-mlopez@corp.internal",
                    "Result": "success",
                },
            ],
            model_sample=[
                {
                    "TimeGenerated": "2026-09-09T13:04:12Z",
                    "OperationName": "Reset password (by admin)",
                    "Initiator": "USER-002",
                    "Result": "success",
                },
                {
                    "TimeGenerated": "2026-09-09T13:19:57Z",
                    "OperationName": "Admin deleted security info",
                    "Initiator": "USER-002",
                    "Result": "success",
                },
                {
                    "TimeGenerated": "2026-09-09T13:22:41Z",
                    "OperationName": "Reset password (by admin)",
                    "Initiator": "USER-002",
                    "Result": "success",
                },
            ],
            anonymization=anon(user=1),
            interpretation="Two password resets eighteen minutes apart with the MFA method wiped in between: the first password did not let the caller in (MFA still enforced), so the caller asked for the method to be removed and a fresh password. Textbook.",
        ),
        ExecutedQuery(
            query_id=d3,
            siem="sentinel",
            executed_at="2026-09-11T10:13:08+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=2540,
            intent="Sign-ins of r.perrin in the hours after the resets",
            query=(
                "SigninLogs\n"
                "| where TimeGenerated between (datetime(2026-09-09T13:00:00Z) .. datetime(2026-09-09T18:00:00Z))\n"
                '| where UserPrincipalName =~ "r.perrin@corp.internal"\n'
                "| project TimeGenerated, IPAddress, Location, NetworkLocationDetails, AppDisplayName, ResultType"
            ),
            columns=[
                "TimeGenerated",
                "IPAddress",
                "Location",
                "NetworkLocationDetails",
                "AppDisplayName",
                "ResultType",
            ],
            sample=[
                {
                    "TimeGenerated": "2026-09-09T13:25:30Z",
                    "IPAddress": "193.32.127.155",
                    "Location": "Amsterdam, NL",
                    "NetworkLocationDetails": "vpn (Mullvad)",
                    "AppDisplayName": "Microsoft Office",
                    "ResultType": 0,
                },
                {
                    "TimeGenerated": "2026-09-09T13:26:04Z",
                    "IPAddress": "193.32.127.155",
                    "Location": "Amsterdam, NL",
                    "NetworkLocationDetails": "vpn (Mullvad)",
                    "AppDisplayName": "My Signins",
                    "ResultType": 0,
                },
                {
                    "TimeGenerated": "2026-09-09T14:02:19Z",
                    "IPAddress": "10.42.60.44",
                    "Location": "Lyon, FR",
                    "NetworkLocationDetails": "trustedNamedLocation",
                    "AppDisplayName": "Windows Sign In",
                    "ResultType": 50074,
                },
            ],
            model_sample=[
                {
                    "TimeGenerated": "2026-09-09T13:25:30Z",
                    "IPAddress": "193.32.127.155",
                    "Location": "Amsterdam, NL",
                    "NetworkLocationDetails": "vpn (Mullvad)",
                    "AppDisplayName": "Microsoft Office",
                    "ResultType": 0,
                },
                {
                    "TimeGenerated": "2026-09-09T13:26:04Z",
                    "IPAddress": "193.32.127.155",
                    "Location": "Amsterdam, NL",
                    "NetworkLocationDetails": "vpn (Mullvad)",
                    "AppDisplayName": "My Signins",
                    "ResultType": 0,
                },
                {
                    "TimeGenerated": "2026-09-09T14:02:19Z",
                    "IPAddress": "IP-INT-001",
                    "Location": "Lyon, FR",
                    "NetworkLocationDetails": "trustedNamedLocation",
                    "AppDisplayName": "Windows Sign In",
                    "ResultType": 50074,
                },
            ],
            anonymization=anon(ip=1),
            interpretation="Three minutes after the second reset, the account signs in from a Mullvad exit node in Amsterdam and opens the My Signins portal, where authentication methods are managed. Forty minutes later the real user, in Lyon, fails MFA: their method is gone. The account was taken over.",
        ),
        ExecutedQuery(
            query_id=d4,
            siem="sentinel",
            executed_at="2026-09-11T10:14:21+00:00",
            returned_rows=1,
            source_rows=1,
            truncated=False,
            duration_ms=1980,
            intent="New authentication method registered by the attacker",
            query=(
                "AuditLogs\n"
                "| where TimeGenerated between (datetime(2026-09-09T13:00:00Z) .. datetime(2026-09-10))\n"
                '| where OperationName =~ "User registered security info"\n'
                '| where tostring(InitiatedBy.user.userPrincipalName) =~ "r.perrin@corp.internal"\n'
                "| project TimeGenerated, ResultDescription, IPAddress=tostring(InitiatedBy.user.ipAddress)"
            ),
            columns=["TimeGenerated", "ResultDescription", "IPAddress"],
            sample=[
                {
                    "TimeGenerated": "2026-09-09T13:27:48Z",
                    "ResultDescription": "User registered Authenticator App with Notification and Code",
                    "IPAddress": "193.32.127.155",
                }
            ],
            model_sample=[
                {
                    "TimeGenerated": "2026-09-09T13:27:48Z",
                    "ResultDescription": "User registered Authenticator App with Notification and Code",
                    "IPAddress": "193.32.127.155",
                }
            ],
            anonymization=anon(),
            interpretation="An Authenticator app was registered from the VPN address two minutes after the sign-in. The attacker now owns the MFA of this account.",
        ),
        ExecutedQuery(
            query_id=d5,
            siem="defender",
            executed_at="2026-09-11T10:15:40+00:00",
            returned_rows=3,
            source_rows=3,
            truncated=False,
            duration_ms=1720,
            intent="Identity logon view of the account after the takeover",
            query=(
                "IdentityLogonEvents\n"
                "| where Timestamp between (datetime(2026-09-09) .. datetime(2026-09-11))\n"
                '| where AccountUpn =~ "r.perrin@corp.internal"\n'
                "| project Timestamp, LogonType, Application, IPAddress, Location, ActionType"
            ),
            columns=[
                "Timestamp",
                "LogonType",
                "Application",
                "IPAddress",
                "Location",
                "ActionType",
            ],
            sample=[
                {
                    "Timestamp": "2026-09-09T13:25:30Z",
                    "LogonType": "OAuth2:Authorize",
                    "Application": "Microsoft Office",
                    "IPAddress": "193.32.127.155",
                    "Location": "NL",
                    "ActionType": "LogonSuccess",
                },
                {
                    "Timestamp": "2026-09-09T15:44:02Z",
                    "LogonType": "OAuth2:Token",
                    "Application": "Office 365 SharePoint Online",
                    "IPAddress": "193.32.127.155",
                    "Location": "NL",
                    "ActionType": "LogonSuccess",
                },
                {
                    "Timestamp": "2026-09-10T07:12:55Z",
                    "LogonType": "OAuth2:Token",
                    "Application": "Office 365 SharePoint Online",
                    "IPAddress": "193.32.127.155",
                    "Location": "NL",
                    "ActionType": "LogonSuccess",
                },
            ],
            model_sample=[
                {
                    "Timestamp": "2026-09-09T13:25:30Z",
                    "LogonType": "OAuth2:Authorize",
                    "Application": "Microsoft Office",
                    "IPAddress": "193.32.127.155",
                    "Location": "NL",
                    "ActionType": "LogonSuccess",
                },
                {
                    "Timestamp": "2026-09-09T15:44:02Z",
                    "LogonType": "OAuth2:Token",
                    "Application": "Office 365 SharePoint Online",
                    "IPAddress": "193.32.127.155",
                    "Location": "NL",
                    "ActionType": "LogonSuccess",
                },
                {
                    "Timestamp": "2026-09-10T07:12:55Z",
                    "LogonType": "OAuth2:Token",
                    "Application": "Office 365 SharePoint Online",
                    "IPAddress": "193.32.127.155",
                    "Location": "NL",
                    "ActionType": "LogonSuccess",
                },
            ],
            anonymization=anon(),
            interpretation="The session stayed alive into the next day and was used on SharePoint. I still need to check the other 22 reset targets and whether the VPN address touched more accounts; one query left.",
        ),
        ExecutedQuery(
            query_id=d6,
            siem="sentinel",
            executed_at="2026-09-11T10:16:58+00:00",
            returned_rows=2,
            source_rows=2,
            truncated=False,
            duration_ms=2890,
            intent="Other accounts reached from the same VPN exit address",
            query=(
                "SigninLogs\n"
                "| where TimeGenerated between (datetime(2026-08-28) .. datetime(2026-09-11))\n"
                '| where IPAddress == "193.32.127.155"\n'
                "| summarize SignIns=count(), Success=countif(ResultType == 0), First=min(TimeGenerated), Last=max(TimeGenerated) by UserPrincipalName"
            ),
            columns=["UserPrincipalName", "SignIns", "Success", "First", "Last"],
            sample=[
                {
                    "UserPrincipalName": "r.perrin@corp.internal",
                    "SignIns": 14,
                    "Success": 14,
                    "First": "2026-09-09T13:25:30Z",
                    "Last": "2026-09-10T07:12:55Z",
                },
                {
                    "UserPrincipalName": "o.diallo@corp.internal",
                    "SignIns": 2,
                    "Success": 1,
                    "First": "2026-09-10T09:35:02Z",
                    "Last": "2026-09-10T09:36:48Z",
                },
            ],
            model_sample=[
                {
                    "UserPrincipalName": "USER-001",
                    "SignIns": 14,
                    "Success": 14,
                    "First": "2026-09-09T13:25:30Z",
                    "Last": "2026-09-10T07:12:55Z",
                },
                {
                    "UserPrincipalName": "USER-008",
                    "SignIns": 2,
                    "Success": 1,
                    "First": "2026-09-10T09:35:02Z",
                    "Last": "2026-09-10T09:36:48Z",
                },
            ],
            anonymization=anon(user=2),
            interpretation="A second account, o.diallo, also reset by the service desk on 10 September, signed in from the same exit node four minutes after its reset. The pattern repeats; I need more queries to cover the remaining targets.",
        ),
    ]
    findings = [
        Finding(
            id="f_d47b2e93",
            title="Account takeover of r.perrin through the service desk",
            severity="high",
            confidence="high",
            recorded_at="2026-09-11T10:14:55+00:00",
            description="On 9 September the service desk reset r.perrin's password twice and removed the MFA method in between. Three minutes after the second reset the account signed in from a Mullvad VPN exit node (193.32.127.155), registered a new Authenticator app and kept a SharePoint session alive into the next day, while the real user failed MFA from Lyon.",
            entities=[
                Entity(type="account", value="r.perrin@corp.internal"),
                Entity(type="ip", value="193.32.127.155"),
                Entity(type="account", value="hd-mlopez@corp.internal"),
            ],
            evidence_query_ids=[d2, d3, d4, d5],
        ),
        Finding(
            id="f_19c6a5e8",
            title="Same VPN exit node reached a second reset account, o.diallo",
            severity="medium",
            confidence="medium",
            recorded_at="2026-09-11T10:17:30+00:00",
            description="o.diallo, reset by the service desk on 10 September at 09:31, signed in from 193.32.127.155 at 09:35. Only one of the two attempts succeeded; the account was not examined further before the budget ran out.",
            entities=[
                Entity(type="account", value="o.diallo@corp.internal"),
                Entity(type="ip", value="193.32.127.155"),
            ],
            evidence_query_ids=[d6, d1],
        ),
    ]
    report = HuntReport(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.INTERRUPTED,
        proposed_verdict=Verdict.INCONCLUSIVE,
        summary=f"Investigation interrupted before the agent could conclude: {reason} 6 query(ies) executed, 2 finding(s) recorded. The recorded findings stand on their own evidence; the leads not yet examined remain open.",
        limitations="The hunt stopped before the remaining 21 service-desk reset targets were checked and before the last playbook lead (Okta and Entra session details) was examined. Findings are partial. The result of the first query was truncated (5 rows shown out of 23).",
        iocs=ioc_views(iocs),
        findings=findings,
        executed_queries=queries,
        timeline=[],
        budgets=budgets(9, 6, 98_400, 287.9, limits={"iterations": 15, "siem_queries": 6}),
        partial=True,
        interruption_reason=reason,
        generated_at="2026-09-11T10:19:12+00:00",
        attack_overview=AttackOverview(
            description=hypothesis,
            techniques=[],
            scope=scope(
                window=window,
                sources=sources,
                campaign=campaign,
                executed=6,
                max_queries=6,
                max_iterations=15,
            ),
        ),
        playbook=playbook,
        sources=sources,
        investigation_window=window,
    )
    audit = [
        event(
            "hunt_created",
            analyst,
            "2026-09-11T10:03:27+00:00",
            hunt_id=hunt_id,
            detail={
                "hypothesis": hypothesis,
                "campaign": campaign,
                "manual_iocs": 0,
                "seeded_from_probe": True,
                "sources": sources,
            },
        ),
        event(
            "ioc_search",
            analyst,
            "2026-09-11T10:04:40+00:00",
            hunt_id=hunt_id,
            detail={
                "campaign": campaign,
                "found": 2,
                "sources": ["AlienVault OTX", "VirusTotal"],
                "dropped_unsourced": 0,
            },
        ),
        event(
            "ioc_validation",
            analyst,
            at,
            hunt_id=hunt_id,
            detail={
                "validated": ["corp-helpdesk-login.com", "sso-corp-verify.net"],
                "rejected": [],
                "total": 2,
            },
        ),
        event(
            "plan_proposed",
            analyst,
            "2026-09-11T10:08:30+00:00",
            hunt_id=hunt_id,
            detail={
                "steps": 4,
                "estimated_queries": 11,
                "estimated_iterations": 16,
                "instruction": None,
                "requested_by": analyst,
            },
        ),
        event(
            "plan_validated",
            analyst,
            "2026-09-11T10:10:02+00:00",
            hunt_id=hunt_id,
            detail={
                "by": analyst,
                "max_iterations": 15,
                "max_siem_queries": 6,
                "from_playbook": True,
                "adjusted": True,
            },
        ),
        *query_events(hunt_id, "agent", queries),
        *finding_events(hunt_id, "agent", findings),
        event(
            "budget_event",
            "agent",
            "2026-09-11T10:17:45+00:00",
            hunt_id=hunt_id,
            detail={"action": "pause", "budget": "siem_queries"},
        ),
        event(
            "budget_event",
            analyst,
            "2026-09-11T10:19:02+00:00",
            hunt_id=hunt_id,
            detail={"action": "stop", "budget": "siem_queries", "by": analyst},
        ),
        event(
            "hunt_interrupted",
            "agent",
            "2026-09-11T10:19:12+00:00",
            hunt_id=hunt_id,
            detail={
                "reason": reason,
                "budgets": budgets(
                    9, 6, 98_400, 287.9, limits={"iterations": 15, "siem_queries": 6}
                ),
            },
        ),
    ]
    return DemoHunt(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.INTERRUPTED,
        created_at="2026-09-11T10:03:27+00:00",
        updated_at="2026-09-11T10:19:12+00:00",
        interruption_reason=reason,
        playbook=playbook,
        iocs=iocs,
        report=report,
        audit=audit,
    )


# --------------------------------------------------------------------------- hunt 6
# Indicators waiting for the analyst's validation (first human checkpoint).


def hunt_teamcity() -> DemoHunt:
    hunt_id = TEAMCITY
    analyst = "robin"
    campaign = "APT29 TeamCity exploitation (CVE-2023-42793)"
    hypothesis = (
        "Exploitation of exposed JetBrains TeamCity servers (CVE-2023-42793) by APT29, "
        "followed by GraphicalProton backdoor deployment through DLL side-loading and "
        "exfiltration via cloud storage APIs."
    )
    sources = ["sentinel", "defender", "secops"]
    iocs = [
        ioc(
            "6b0d0f8c1b2a3e4d5c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
            "hash",
            "VirusTotal",
            "https://www.virustotal.com/gui/file/6b0d0f8c1b2a3e4d5c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
            first_seen="2026-08-30",
            confidence="malicious (54/72)",
            status="pending_validation",
        ),
        ioc(
            "a7f3c9e1b5d2f8a4c6e0b3d9f1a5c7e2",
            "hash",
            "ThreatFox",
            "https://threatfox.abuse.ch/ioc/1204410/",
            first_seen="2026-09-02",
            confidence="high",
            status="pending_validation",
        ),
        ioc(
            "4c2a8e6f0b1d3579a2c4e6f8b0d2a4c6e8f0b2d4",
            "hash",
            "CIRCL MISP OSINT",
            "https://www.circl.lu/doc/misp/feed-osint/",
            first_seen="2024-01-09",
            confidence="low",
            status="pending_validation",
        ),
        ioc(
            "65.20.97.203",
            "ip",
            "AlienVault OTX",
            "https://otx.alienvault.com/pulse/66f0b3c5d7e9a1b3c5d7e9f1",
            first_seen="2026-08-28",
            confidence="high",
            status="pending_validation",
        ),
        ioc(
            "103.76.128.34",
            "ip",
            "ThreatFox",
            "https://threatfox.abuse.ch/ioc/1204412/",
            first_seen="2026-09-04",
            confidence="medium",
            status="pending_validation",
        ),
        ioc(
            "vps-teamcity-update.com",
            "domain",
            "VirusTotal",
            "https://www.virustotal.com/gui/domain/vps-teamcity-update.com",
            first_seen="2026-08-27",
            confidence="malicious (29/94)",
            status="pending_validation",
        ),
        ioc(
            "static-files-delivery.com",
            "domain",
            "AlienVault OTX",
            "https://otx.alienvault.com/pulse/66f0b3c5d7e9a1b3c5d7e9f1",
            first_seen="2026-08-29",
            confidence="medium",
            status="pending_validation",
        ),
        ioc(
            "https://static-files-delivery.com/upd/agent.dll",
            "url",
            "AlienVault OTX",
            "https://otx.alienvault.com/pulse/66f0b3c5d7e9a1b3c5d7e9f1",
            first_seen="2026-08-29",
            confidence="medium",
            status="pending_validation",
        ),
        ioc(
            "C:\\ProgramData\\TeamCity\\graphicalproton\\Sync.dll",
            "file_path",
            "AlienVault OTX",
            "https://otx.alienvault.com/pulse/66f0b3c5d7e9a1b3c5d7e9f1",
            first_seen="2026-08-29",
            confidence="medium",
            status="pending_validation",
        ),
        manual_ioc("203.0.113.57", "ip", analyst, "2026-09-23T08:47:30+00:00"),
    ]
    audit = [
        event(
            "hunt_created",
            analyst,
            "2026-09-23T08:47:30+00:00",
            hunt_id=hunt_id,
            detail={
                "hypothesis": hypothesis,
                "campaign": campaign,
                "manual_iocs": 1,
                "seeded_from_probe": True,
                "sources": sources,
            },
        ),
        event(
            "ioc_search",
            analyst,
            "2026-09-23T08:48:52+00:00",
            hunt_id=hunt_id,
            detail={
                "campaign": campaign,
                "found": 9,
                "sources": ["VirusTotal", "ThreatFox", "CIRCL MISP OSINT", "AlienVault OTX"],
                "dropped_unsourced": 3,
            },
        ),
    ]
    return DemoHunt(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        campaign=campaign,
        analyst=analyst,
        status=HuntStatus.AWAITING_IOC_VALIDATION,
        created_at="2026-09-23T08:47:30+00:00",
        updated_at="2026-09-23T08:48:52+00:00",
        iocs=iocs,
        audit=audit,
    )


# --------------------------------------------------------------------------- hunt 7
# Playbook proposed, waiting for the analyst (second human checkpoint).


def hunt_kerberoasting() -> DemoHunt:
    hunt_id = KERBEROAST
    analyst = "m.dubois"
    hypothesis = (
        "Kerberoasting: TGS requests with RC4-HMAC encryption (0x17) for service accounts, "
        "issued from workstation accounts outside change windows, followed by a sign-in of "
        "the targeted service account from a new host."
    )
    sources = ["sentinel", "defender"]
    playbook = Playbook(
        summary=(
            "Isolate the service ticket requests that downgrade to RC4 while the requesting "
            "account normally uses AES, rank the requesters by the number of distinct "
            "service principal names they asked for in a short window, then check whether "
            "any targeted service account later authenticated from an unusual host."
        ),
        steps=[
            PlaybookStep(
                order=1,
                siem="sentinel",
                technique="T1558.003",
                expected_queries=2,
                objective="Event 4769 with TicketEncryptionType 0x17 over the last 30 days, grouped by requesting account and number of distinct SPNs.",
            ),
            PlaybookStep(
                order=2,
                siem="sentinel",
                technique="T1558.003",
                expected_queries=2,
                objective="Bursts: requesters asking for more than ten SPNs within five minutes, with the source host.",
            ),
            PlaybookStep(
                order=3,
                siem="defender",
                technique="T1558.003",
                expected_queries=2,
                objective="Tooling on the source hosts around the burst: Rubeus, Invoke-Kerberoast, setspn -Q, PowerView.",
            ),
            PlaybookStep(
                order=4,
                siem="defender",
                technique="T1078.002",
                expected_queries=2,
                objective="Later logons of the targeted service accounts from hosts they never used before.",
            ),
        ],
        not_covered="Offline cracking cannot be observed. Service accounts whose SPN legitimately requires RC4 (legacy applications) will appear in step 1 and must be excluded by hand; the platform has no allow-list of them.",
        estimated_queries=8,
        estimated_iterations=12,
        generated_at="2026-09-24T08:02:17+00:00",
    )
    audit = [
        event(
            "hunt_created",
            analyst,
            "2026-09-24T07:58:41+00:00",
            hunt_id=hunt_id,
            detail={
                "hypothesis": hypothesis,
                "campaign": None,
                "manual_iocs": 0,
                "seeded_from_probe": False,
                "sources": sources,
            },
        ),
        event(
            "plan_proposed",
            analyst,
            "2026-09-24T08:02:17+00:00",
            hunt_id=hunt_id,
            detail={
                "steps": 4,
                "estimated_queries": 8,
                "estimated_iterations": 12,
                "instruction": None,
                "requested_by": analyst,
            },
        ),
    ]
    return DemoHunt(
        hunt_id=hunt_id,
        hypothesis=hypothesis,
        analyst=analyst,
        status=HuntStatus.AWAITING_PLAN_VALIDATION,
        created_at="2026-09-24T07:58:41+00:00",
        updated_at="2026-09-24T08:02:17+00:00",
        playbook=playbook,
        audit=audit,
    )


# --------------------------------------------------------------------------- CTI analyses


def cti_analyses() -> list[dict[str, Any]]:
    return [
        {
            "id": CTI_TEAMCITY,
            "filename": "Mandiant_APT29_TeamCity_CVE-2023-42793_2026-09.pdf",
            "analyzed_by": "robin",
            "analyzed_at": "2026-09-23T08:41:12+00:00",
            "pages": 14,
            "truncated": False,
            "attacks": [
                {
                    "name": "APT29 exploitation of TeamCity (CVE-2023-42793)",
                    "kind": "campaign",
                    "summary": "APT29 exploits an authentication bypass in exposed JetBrains TeamCity servers to obtain code execution as the service account, then deploys the GraphicalProton backdoor and uses the build server as a foothold into software supply chains. The report lists the infrastructure observed between August and September 2026.",
                    "approach": "campaign",
                    "suggested_hypothesis": "",
                    "iocs": [
                        {
                            "value": "6b0d0f8c1b2a3e4d5c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
                            "type": "hash",
                        },
                        {"value": "a7f3c9e1b5d2f8a4c6e0b3d9f1a5c7e2", "type": "hash"},
                        {"value": "65.20.97.203", "type": "ip"},
                        {"value": "103.76.128.34", "type": "ip"},
                        {"value": "vps-teamcity-update.com", "type": "domain"},
                        {"value": "static-files-delivery.com", "type": "domain"},
                        {"value": "https://static-files-delivery.com/upd/agent.dll", "type": "url"},
                        {
                            "value": "C:\\ProgramData\\TeamCity\\graphicalproton\\Sync.dll",
                            "type": "file_path",
                        },
                    ],
                    "probe": {
                        "found": 23,
                        "sources": ["VirusTotal", "AlienVault OTX", "ThreatFox"],
                        "sample": [
                            {"value": "65.20.97.203", "type": "ip"},
                            {"value": "vps-teamcity-update.com", "type": "domain"},
                            {
                                "value": "6b0d0f8c1b2a3e4d5c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
                                "type": "hash",
                            },
                            {"value": "static-files-delivery.com", "type": "domain"},
                        ],
                    },
                },
                {
                    "name": "GraphicalProton backdoor via DLL side-loading",
                    "kind": "malware",
                    "summary": "GraphicalProton is loaded by legitimate signed executables (vcperf.exe, Zabbix and Webroot agents) placed next to a malicious DLL, and communicates through OneDrive and Dropbox APIs to blend into normal traffic. Persistence relies on a scheduled task and a WMI event subscription.",
                    "approach": "hypothesis",
                    "suggested_hypothesis": "Legitimate signed binaries (vcperf.exe, zabbix_agent.exe, WRSA.exe) loading an unsigned DLL from a user-writable folder, followed by outbound HTTPS to OneDrive or Dropbox API endpoints from that process, on servers that have no reason to use consumer cloud storage.",
                    "iocs": [
                        {
                            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            "type": "hash",
                        },
                        {"value": "b1946ac92492d2347c6235b4d2611184", "type": "hash"},
                    ],
                    "probe": {
                        "found": 5,
                        "sources": ["VirusTotal"],
                        "sample": [
                            {
                                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "type": "hash",
                            },
                            {"value": "b1946ac92492d2347c6235b4d2611184", "type": "hash"},
                        ],
                    },
                },
            ],
        },
        {
            "id": CTI_VOLT,
            "filename": "CISA_AA24-038A_Volt_Typhoon_living_off_the_land.pdf",
            "analyzed_by": "a.leclerc",
            "analyzed_at": "2026-09-01T14:05:37+00:00",
            "pages": 45,
            "truncated": False,
            "attacks": [
                {
                    "name": "Volt Typhoon living-off-the-land intrusions",
                    "kind": "actor",
                    "summary": "A state-sponsored actor pre-positions in critical-infrastructure networks using only built-in tools: WMI, netsh port proxies, ntdsutil and vssadmin for credential access, and compromised SOHO routers as relays. Dwell times exceed a year; no custom malware is dropped on hosts.",
                    "approach": "hypothesis",
                    "suggested_hypothesis": "Remote process creation through wmic /node from file or application servers towards domain controllers, netsh interface portproxy rules added on internal servers, and ntdsutil or vssadmin executions on domain controllers outside change windows.",
                    "iocs": [
                        {"value": "45.155.12.7", "type": "ip"},
                        {"value": "103.56.54.212", "type": "ip"},
                        {"value": "update-checker-cdn.net", "type": "domain"},
                    ],
                    "probe": {
                        "found": 41,
                        "sources": [
                            "ThreatFox",
                            "AlienVault OTX",
                            "VirusTotal",
                            "CIRCL MISP OSINT",
                        ],
                        "sample": [
                            {"value": "45.155.12.7", "type": "ip"},
                            {"value": "103.56.54.212", "type": "ip"},
                            {"value": "update-checker-cdn.net", "type": "domain"},
                        ],
                    },
                },
            ],
        },
    ]


# --------------------------------------------------------------------------- persistence


ALL_HUNTS = (
    hunt_volt_typhoon,
    hunt_volt_followup,
    hunt_password_spray,
    hunt_scheduled_tasks,
    hunt_helpdesk,
    hunt_teamcity,
    hunt_kerberoasting,
)


# References the demo hunts carried before the PREFIX-YYMM-NNN format, so that a database
# seeded with an older version of this script is cleaned up too.
LEGACY_HUNT_IDS = (
    "hunt_7f3a9c21d4e8",
    "hunt_e2a6c3f18b07",
    "hunt_2b8e51d4a930",
    "hunt_c41d0e77f5b2",
    "hunt_9e6b2f08c1d5",
    "hunt_5a1c7d93e604",
    "hunt_d08f4b65a2c9",
)


async def remove_demo(database: Database) -> None:
    ids = (*DEMO_HUNT_IDS, *LEGACY_HUNT_IDS)
    async with database.session() as session:
        for model in (HuntStateRow, IocRow, QueryRow, FindingRow, AuditRow):
            await session.execute(delete(model).where(model.hunt_id.in_(ids)))
        await session.execute(delete(ReportRow).where(ReportRow.hunt_id.in_(ids)))
        await session.execute(delete(HuntRow).where(HuntRow.id.in_(ids)))
        await session.execute(delete(CtiAnalysisRow).where(CtiAnalysisRow.id.in_(DEMO_CTI_IDS)))
        await session.commit()


async def insert_hunt(database: Database, hunt: DemoHunt) -> None:
    async with database.session() as session:
        session.add(
            HuntRow(
                id=hunt.hunt_id,
                hypothesis=hunt.hypothesis,
                campaign=hunt.campaign,
                analyst=hunt.analyst,
                status=hunt.status.value,
                created_at=_dt(hunt.created_at),
                updated_at=_dt(hunt.updated_at),
                interruption_reason=hunt.interruption_reason,
                playbook=hunt.playbook.model_dump(mode="json") if hunt.playbook else None,
                parent_hunt_id=hunt.parent_hunt_id,
                resume_context=hunt.resume_context,
            )
        )
        for row in hunt.iocs:
            session.add(IocRow(hunt_id=hunt.hunt_id, **row))
        if hunt.report is not None:
            for query in hunt.report.executed_queries:
                session.add(QueryRow(hunt_id=hunt.hunt_id, **query.model_dump()))
            for finding in hunt.report.findings:
                session.add(
                    FindingRow(
                        id=finding.id,
                        hunt_id=hunt.hunt_id,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity.value,
                        confidence=finding.confidence.value,
                        entities=[entity.model_dump() for entity in finding.entities],
                        evidence_query_ids=finding.evidence_query_ids,
                        recorded_at=finding.recorded_at,
                    )
                )
            session.add(
                ReportRow(
                    hunt_id=hunt.hunt_id,
                    payload=hunt.report.model_dump(mode="json"),
                    proposed_verdict=hunt.report.proposed_verdict.value,
                    partial=hunt.report.partial,
                    generated_at=hunt.report.generated_at,
                    **(hunt.decision or {}),
                )
            )
        for entry in sorted(hunt.audit, key=lambda item: item["timestamp"]):
            session.add(AuditRow(**entry))
        await session.commit()


async def insert_cti(database: Database, analysis: dict[str, Any]) -> None:
    async with database.session() as session:
        session.add(
            CtiAnalysisRow(
                id=analysis["id"],
                filename=analysis["filename"],
                analyzed_by=analysis["analyzed_by"],
                analyzed_at=analysis["analyzed_at"],
                pages=analysis["pages"],
                truncated=analysis["truncated"],
                payload={"attacks": analysis["attacks"]},
            )
        )
        session.add(
            AuditRow(
                hunt_id="-",
                type="cti_report_analyzed",
                actor=analysis["analyzed_by"],
                timestamp=analysis["analyzed_at"],
                detail={
                    "analysis_id": analysis["id"],
                    "filename": analysis["filename"],
                    "pages": analysis["pages"],
                    "attacks": len(analysis["attacks"]),
                    "iocs": sum(len(a["iocs"]) for a in analysis["attacks"]),
                },
            )
        )
        await session.commit()


async def ensure_accounts(database: Database) -> list[str]:
    accounts = AccountRepository(database)
    created: list[str] = []
    for username, roles in ACCOUNTS:
        try:
            await accounts.create(
                username=username,
                password=DEMO_PASSWORD,
                roles=roles,
                created_by="script:seed_demo",
            )
            created.append(username)
        except ValueError:
            continue  # already there: an existing password is never overwritten
    return created


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove", action="store_true", help="delete the demo content")
    args = parser.parse_args()

    settings = Settings()
    if settings.environment != "dev":
        sys.exit("The demo seed only runs with SHL_ENVIRONMENT=dev.")

    database = Database(settings.database_url)
    await database.create_all()

    await remove_demo(database)
    if args.remove:
        print("Demo hunts and CTI analyses removed (accounts kept).")
        await database.dispose()
        return

    created = await ensure_accounts(database)
    hunts = [build() for build in ALL_HUNTS]
    for hunt in hunts:
        await insert_hunt(database, hunt)
    for analysis in cti_analyses():
        await insert_cti(database, analysis)
    await database.dispose()

    print(
        f"Seeded {len(hunts)} hunts and {len(DEMO_CTI_IDS)} CTI analyses into {settings.database_url}."
    )
    for hunt in hunts:
        print(
            f"  {hunt.hunt_id}  {hunt.status.value:<26} {hunt.analyst:<10} {hunt.campaign or hunt.hypothesis[:60]}"
        )
    if created:
        print(f"Accounts created: {', '.join(created)} (password: {DEMO_PASSWORD}).")
    else:
        print("Accounts already present, passwords left unchanged.")


if __name__ == "__main__":
    asyncio.run(main())
