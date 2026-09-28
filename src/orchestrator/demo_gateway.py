# ruff: noqa: E501 - scripted scenario: queries and sentences stay on one line each
"""Scripted stand-in for the AI gateway, for demonstrations without a model.

Explicit mode confined to development, the counterpart of the simulated SIEM
(`SHL_DEMO_SIEM`): it only exists if `SHL_DEMO_GATEWAY=true`, and `create_app` refuses to
enable it outside the `dev` environment. It is not a degraded mode: nothing is produced
behind the analyst's back, the platform simply replays a written investigation instead of
asking a model. Everything else runs for real - the playbook checkpoint, the loop, the
executor, minimization and pseudonymization, the event stream, the budgets, the findings,
the report.

The scenario follows the one served by the simulated SIEM: a living-off-the-land intrusion
in the style of Volt Typhoon (wmic /node, netsh portproxy, ntdsutil on a domain
controller). The reasoning texts are written with the pseudonyms the model would see
(`HOST-001`, `USER-001`), and the platform rehydrates them for the analyst exactly as it
would with a real model.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from orchestrator.gateway import Completion, ToolCall, Usage

_WORKSPACE = "soc-principal"

_PLAYBOOK: dict[str, Any] = {
    "summary": (
        "Start from the behaviors that characterize the hypothesis rather than from "
        "indicators: remote process creation through WMI from file servers, netsh "
        "port-proxy persistence, then credential access on the domain controllers the "
        "first leads point to. Each lead is closed by a check of the accounts involved."
    ),
    "steps": [
        {
            "order": 1,
            "siem": "sentinel",
            "objective": (
                "Detect remote process creation through WMI (wmic /node) from any host, "
                "with the account and the target."
            ),
            "technique": "T1047",
            "expected_queries": 2,
        },
        {
            "order": 2,
            "siem": "defender",
            "objective": "Look for netsh portproxy persistence and the outbound relay it opens.",
            "technique": "T1090.001",
            "expected_queries": 2,
        },
        {
            "order": 3,
            "siem": "defender",
            "objective": (
                "Search for NTDS extraction attempts on the domain controllers surfaced by "
                "the first leads."
            ),
            "technique": "T1003.003",
            "expected_queries": 1,
        },
        {
            "order": 4,
            "siem": "sentinel",
            "objective": "Check the sign-in pattern of the accounts driving the activity.",
            "technique": "T1078",
            "expected_queries": 1,
        },
    ],
    "not_covered": (
        "Email delivery and initial access are out of scope: no mail telemetry is "
        "connected. Router or edge-device compromise, typical of this actor, cannot be "
        "observed from endpoint and identity logs."
    ),
}

_CONCLUSION: dict[str, Any] = {
    "verdict": "escalate",
    "summary": (
        "Two hosts hold the chain. HOST-001 issued WMI remote process creations towards "
        "HOST-002 under the USER-001 service account, then installed a netsh port proxy "
        "relaying port 9999 to an external address, and the network telemetry confirms "
        "the outbound connection. On HOST-002, USER-002 ran an encoded PowerShell from "
        "WmiPrvSE and, twenty minutes later, ntdsutil produced a full IFM copy of the "
        "directory. The sequence matches the hunted tradecraft end to end."
    ),
    "limitations": (
        "Sign-in telemetry only covers the identity provider: on-premises Kerberos "
        "authentications were not queried. The encoded PowerShell command was not "
        "decoded. No proxy or firewall telemetry was available to size the volume "
        "exchanged with the external address."
    ),
    "timeline": [
        {
            "timestamp": "2026-07-20T02:09:55Z",
            "event": "Interactive sign-in of USER-001 from IP-INT-001, outside its backup schedule",
            "source": "sentinel",
        },
        {
            "timestamp": "2026-07-20T02:14:07Z",
            "event": "wmic /node reconnaissance from HOST-001 towards HOST-002",
            "source": "sentinel",
        },
        {
            "timestamp": "2026-07-20T02:15:33Z",
            "event": "netsh portproxy 9999 installed on HOST-001, outbound relay confirmed",
            "source": "defender",
        },
        {
            "timestamp": "2026-07-20T02:22:48Z",
            "event": "Encoded PowerShell spawned by WmiPrvSE on HOST-002 as USER-002",
            "source": "defender",
        },
        {
            "timestamp": "2026-07-20T02:41:12Z",
            "event": "ntdsutil creates a full IFM copy of the directory on HOST-002",
            "source": "defender",
        },
    ],
    "attack_description": (
        "Living-off-the-land intrusion: no malware is dropped, the operator relies on "
        "wmic, netsh and ntdsutil, all legitimate Windows tools. The observed chain goes "
        "from a file server, through a compromised service account, to a domain "
        "controller where the directory database is extracted. Hard to detect because "
        "every step looks like administration."
    ),
    "techniques": [
        {
            "id": "T1047",
            "name": "Windows Management Instrumentation",
            "description": "Remote process creation on the domain controller through wmic /node.",
        },
        {
            "id": "T1090.001",
            "name": "Internal Proxy",
            "description": "netsh portproxy rule relaying traffic to the command-and-control address.",
        },
        {
            "id": "T1003.003",
            "name": "OS Credential Dumping: NTDS",
            "description": "Full IFM export of ntds.dit and the SYSTEM hive with ntdsutil.",
        },
        {
            "id": "T1059.001",
            "name": "PowerShell",
            "description": "Hidden, encoded PowerShell launched by WmiPrvSE on the domain controller.",
        },
    ],
    "recommendation": (
        "Escalate to incident response: isolate HOST-001 and HOST-002, reset USER-001 and "
        "USER-002, identify the host behind IP-INT-001, and treat every domain credential "
        "as compromised until the IFM copy is confirmed not to have left the estate."
    ),
}

_CTI_ATTACKS: list[dict[str, Any]] = [
    {
        "name": "Volt Typhoon living-off-the-land intrusions",
        "kind": "actor",
        "summary": (
            "A state-sponsored actor pre-positions in critical-infrastructure networks "
            "using only built-in tools: WMI, netsh port proxies, ntdsutil for credential "
            "access, and compromised SOHO routers as relays. No custom malware is dropped."
        ),
        "approach": "hypothesis",
        "suggested_hypothesis": (
            "Remote process creation through wmic /node from file or application servers "
            "towards domain controllers, netsh interface portproxy rules added on internal "
            "servers, and ntdsutil executions on domain controllers outside change windows."
        ),
        "iocs": [],
    },
]


def _call(name: str, arguments: dict[str, Any], index: int) -> ToolCall:
    return ToolCall(
        id=f"call_demo_{index}",
        name=name,
        arguments=arguments,
        raw_arguments=json.dumps(arguments),
    )


def _query_ids(messages: list[dict[str, Any]]) -> list[str]:
    """Identifiers of the queries executed so far, read from the tool results the loop
    appended to the transcript: a finding must cite real query ids."""

    found: list[str] = []
    for message in messages:
        if message.get("role") != "tool":
            continue
        try:
            payload = json.loads(str(message.get("content", "")))
        except (TypeError, ValueError):
            continue
        query_id = payload.get("query_id") if isinstance(payload, dict) else None
        if isinstance(query_id, str) and query_id not in found:
            found.append(query_id)
    return found


def _turns_taken(messages: list[dict[str, Any]]) -> int:
    return sum(1 for message in messages if message.get("role") == "assistant")


def _investigation_turn(step: int, query_ids: list[str]) -> Completion:
    """The scripted investigation, one turn per call, in the order a model would take."""

    def qid(index: int) -> str:
        return query_ids[index] if index < len(query_ids) else (query_ids[-1] if query_ids else "")

    turns: list[tuple[str, list[tuple[str, dict[str, Any]]]]] = [
        (
            "The hypothesis names a behavior, not an indicator: I start with remote process "
            "creation through WMI, the first move of this tradecraft, across the whole "
            "estate over the period.",
            [
                (
                    "run_sentinel_kql",
                    {
                        "intent": "Remote process creation through WMI from any host of the estate",
                        "workspace": _WORKSPACE,
                        "kql_query": (
                            "SecurityEvent\n"
                            "| where EventID == 4688\n"
                            '| where NewProcessName endswith "wmic.exe" and CommandLine has "/node:"\n'
                            "| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName"
                        ),
                    },
                )
            ],
        ),
        (
            "Every remote creation comes from HOST-001 under USER-001, all targeting HOST-002 "
            "at night: reconnaissance first, then an encoded PowerShell, then ntdsutil. A "
            "backup service account never needs to create processes on a domain controller. "
            "I check whether HOST-001 also installed a relay, the next step of this playbook.",
            [
                (
                    "run_defender_hunting",
                    {
                        "intent": "netsh portproxy persistence on the foothold and the ports it exposes",
                        "timespan_days": 30,
                        "kql_query": (
                            "DeviceProcessEvents\n"
                            "| where Timestamp > ago(30d)\n"
                            '| where FileName =~ "netsh.exe" and ProcessCommandLine has_all ("portproxy", "add")\n'
                            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName"
                        ),
                    },
                )
            ],
        ),
        (
            "Confirmed: a portproxy rule on HOST-001 forwards port 9999 to an external "
            "address, thirty seconds after the reconnaissance. I look at the network "
            "telemetry to see whether that relay was actually used.",
            [
                (
                    "run_defender_hunting",
                    {
                        "intent": "Outbound connections opened by the relay host",
                        "timespan_days": 30,
                        "kql_query": (
                            "DeviceNetworkEvents\n"
                            "| where Timestamp > ago(30d)\n"
                            '| where DeviceName startswith "PAR-FS" and RemoteIPType == "Public"\n'
                            "| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, ActionType"
                        ),
                    },
                )
            ],
        ),
        (
            "The connection to the external address succeeded on port 443 right after the "
            "rule was added: the relay is live. I record the persistence and the "
            "lateral movement, then turn to the accounts.",
            [
                (
                    "record_finding",
                    {
                        "title": "netsh port proxy on HOST-001 relaying to an external address",
                        "description": (
                            "A netsh portproxy rule (listen 9999, forward to an external "
                            "address on 443) was added on HOST-001 by USER-001, and the network "
                            "telemetry shows the outbound connection succeeding thirty seconds "
                            "later. The file server has been turned into an internal relay."
                        ),
                        "severity": "high",
                        "confidence": "high",
                        "entities": [
                            {"type": "host", "value": "HOST-001"},
                            {"type": "account", "value": "USER-001"},
                        ],
                        "evidence_query_ids": [qid(1), qid(2)],
                    },
                ),
                (
                    "record_finding",
                    {
                        "title": "WMI remote process creation from HOST-001 to HOST-002 under USER-001",
                        "description": (
                            "USER-001 issued wmic /node commands from HOST-001 towards HOST-002 "
                            "at night: reconnaissance (netstat redirected to Temp), then an "
                            "encoded PowerShell. A backup service account never needs to create "
                            "processes on a domain controller."
                        ),
                        "severity": "high",
                        "confidence": "high",
                        "entities": [
                            {"type": "host", "value": "HOST-001"},
                            {"type": "host", "value": "HOST-002"},
                            {"type": "account", "value": "USER-001"},
                        ],
                        "evidence_query_ids": [qid(0)],
                    },
                ),
            ],
        ),
        (
            "The ntdsutil command on HOST-002 ran as USER-002, not USER-001: the operator "
            "holds a second, privileged credential. Before concluding I check where both "
            "accounts signed in from.",
            [
                (
                    "run_sentinel_kql",
                    {
                        "intent": "Sign-in pattern of the two accounts driving the activity",
                        "workspace": _WORKSPACE,
                        "kql_query": (
                            "SigninLogs\n"
                            '| where UserPrincipalName startswith "svc-backup" or UserPrincipalName startswith "adm-helpdesk"\n'
                            "| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, Location"
                        ),
                    },
                )
            ],
        ),
        (
            "Both accounts signed in through Windows Remote Management from the same "
            "internal address, IP-INT-001, ten minutes apart: a single operator drives both "
            "credentials from one pivot host. The directory export is the critical fact; "
            "I record it and conclude.",
            [
                (
                    "record_finding",
                    {
                        "title": "Directory database extracted with ntdsutil on HOST-002",
                        "description": (
                            "A full IFM copy of the Active Directory database was created on "
                            "HOST-002 by ntdsutil, launched from a PowerShell that WmiPrvSE had "
                            "spawned under USER-002. Every domain password hash is recoverable "
                            "from that copy."
                        ),
                        "severity": "critical",
                        "confidence": "high",
                        "entities": [
                            {"type": "host", "value": "HOST-002"},
                            {"type": "account", "value": "USER-002"},
                        ],
                        "evidence_query_ids": [qid(0)],
                    },
                ),
                (
                    "record_finding",
                    {
                        "title": "Both accounts operated from the same pivot address IP-INT-001",
                        "description": (
                            "USER-001 and USER-002 both signed in through Windows Remote "
                            "Management from IP-INT-001 within ten minutes, which is neither "
                            "the backup server nor a helpdesk workstation. That host is the "
                            "operator's pivot point and should be identified."
                        ),
                        "severity": "medium",
                        "confidence": "medium",
                        "entities": [
                            {"type": "ip", "value": "IP-INT-001"},
                            {"type": "account", "value": "USER-001"},
                            {"type": "account", "value": "USER-002"},
                        ],
                        "evidence_query_ids": [qid(3)],
                    },
                ),
            ],
        ),
        (
            "The chain is complete: foothold, relay, privileged execution and credential "
            "theft, all on legitimate tools. I conclude and hand over to the analyst.",
            [("conclude_hunt", _CONCLUSION)],
        ),
    ]

    if step >= len(turns):
        content, calls = turns[-1]
    else:
        content, calls = turns[step]
    return Completion(
        content=content,
        tool_calls=[_call(name, arguments, index) for index, (name, arguments) in enumerate(calls)],
        usage=Usage(prompt_tokens=3200 + 900 * step, completion_tokens=260 + 40 * len(calls)),
    )


class ScriptedGateway:
    """Replays a written investigation with a pause between turns, so the feed reads at
    the pace of a real model. Same `complete` signature as the gateway client."""

    def __init__(self, *, delay_seconds: float = 3.0) -> None:
        self._delay = max(0.0, delay_seconds)

    async def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> Completion:
        _ = (model, temperature, max_tokens)
        if self._delay:
            await asyncio.sleep(self._delay)

        names = {tool.get("function", {}).get("name") for tool in tools or []}
        if "propose_playbook" in names:
            return Completion(
                content="",
                tool_calls=[_call("propose_playbook", _PLAYBOOK, 0)],
                usage=Usage(prompt_tokens=1800, completion_tokens=420),
            )
        if names == {"conclude_hunt"}:
            return Completion(
                content="The file confirms the proposed conclusion.",
                tool_calls=[_call("conclude_hunt", _CONCLUSION, 0)],
                usage=Usage(prompt_tokens=5200, completion_tokens=610),
            )
        if names:
            return _investigation_turn(_turns_taken(messages), _query_ids(messages))

        prompt = " ".join(str(message.get("content", "")) for message in messages)
        if "cyber threat intelligence report" in prompt:
            return Completion(
                content=json.dumps(_CTI_ATTACKS),
                usage=Usage(prompt_tokens=4100, completion_tokens=380),
            )
        return Completion(content="OK", usage=Usage(prompt_tokens=12, completion_tokens=1))

    async def aclose(self) -> None:  # interface parity with the gateway client
        return None
