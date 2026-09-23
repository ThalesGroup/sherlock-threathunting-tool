"""Agentic hunt loop.

The agent explores on its own, but within a bounded frame: each turn consumes an iteration,
each query consumes a budget, and any breach of the frame produces a clean stop followed by
a partial report. There is no path that interrupts a hunt without a report.

The two human checkpoints are not handled here: indicator validation is enforced by the
middleware on every SIEM call, and report validation happens after this loop. The
orchestrator therefore cannot bypass them, even by mistake.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Any

from middleware.audit import AuditEventType, AuditJournal
from middleware.budgets import HuntBudget
from middleware.errors import BudgetExhausted, ErrorCode, ToolError
from middleware.guardrails.ioc import IocType, hash_algorithm
from middleware.tokenization import TokenVault
from orchestrator.events import EventStream, HuntEventType
from orchestrator.gateway import Completion, GatewayClient, ToolCall
from orchestrator.prompts import SYSTEM_PROMPT, final_analysis_prompt, hunt_briefing
from reporting.dossier import Dossier
from reporting.models import HuntReport, HuntStatus
from reporting.report import build_report
from tools.definitions import ToolRegistry

_MAX_SILENT_TURNS = 2
_TOOL_RESULT_PREVIEW_FIELDS = ("query_id", "siem", "returned_rows", "source_rows", "truncated")


@dataclass
class HuntOutcome:
    report: HuntReport
    interrupted: bool
    reason: str | None


class HuntOrchestrator:
    def __init__(
        self,
        *,
        dossier: Dossier,
        registry: ToolRegistry,
        journal: AuditJournal,
        budget: HuntBudget,
        stream: EventStream,
        gateway: GatewayClient,
        model: str,
        analysis_model: str | None = None,
        available_sources: list[str],
        knowledge: dict[str, str] | None = None,
        stop_event: asyncio.Event | None = None,
        vault: TokenVault | None = None,
        investigation_window: str | None = None,
        budget_pause_timeout: float = 0.0,
        workspaces: list[str] | None = None,
    ) -> None:
        self._dossier = dossier
        self._registry = registry
        self._journal = journal
        self._budget = budget
        self._stream = stream
        self._gateway = gateway
        self._model = model
        self._analysis_model = analysis_model
        self._available_sources = available_sources
        self._knowledge = knowledge or {}
        self._stop_event = stop_event or asyncio.Event()
        self._vault = vault
        self._investigation_window = investigation_window
        self._workspaces = workspaces or []
        self._budget_pause_timeout = budget_pause_timeout
        """Budget checkpoint: wait time for the analyst's decision when a budget is
        exhausted. 0 = checkpoint disabled, immediate stop as historically."""
        self._budget_wait: asyncio.Event | None = None
        self._budget_choice: str | None = None
        self._messages: list[dict[str, Any]] = []

    @property
    def awaiting_budget_decision(self) -> bool:
        return self._budget_wait is not None

    def resolve_budget(self, *, extend: bool) -> bool:
        """Analyst's decision at the budget checkpoint. True if a checkpoint was waiting.
        The extension of the limits themselves is done by the caller before this call."""

        if self._budget_wait is None:
            return False
        self._budget_choice = "extend" if extend else "stop"
        self._budget_wait.set()
        return True

    def _display(self, text: Any) -> Any:
        """The investigation thread is read by the analyst: it shows the real values.
        The messages sent to the model, however, stay tokenized."""

        if self._vault is not None and isinstance(text, str):
            return self._vault.detokenize_text(text)
        return text

    def request_stop(self) -> None:
        """The analyst's stop button. Stopping produces a report, never a blank screen."""

        self._stop_event.set()

    def seed_messages(
        self,
        messages: list[dict[str, Any]],
        *,
        instruction: str | None = None,
        after_conclusion: bool = False,
    ) -> None:
        """In-place resume: start again from the saved transcript instead of the briefing,
        with an optional instruction from the analyst. After a conclusion, the model is
        told its report was judged insufficient and that it must conclude again."""

        self._seeded_messages = list(messages)
        self._seed_instruction = (instruction or "").strip() or None
        self._seed_after_conclusion = after_conclusion

    def set_state_saver(self, saver: Callable[[list[dict[str, Any]]], Awaitable[None]]) -> None:
        """State persistence callback, called after each iteration. A save failure must
        never interrupt the hunt."""

        self._state_saver = saver

    async def _save_state(self) -> None:
        saver = getattr(self, "_state_saver", None)
        if saver is None:
            return
        with contextlib.suppress(Exception):
            await saver(list(self._messages))

    async def run(self) -> HuntOutcome:
        self._dossier.status = HuntStatus.RUNNING
        seeded = getattr(self, "_seeded_messages", None)
        if seeded:
            self._messages = seeded
            if getattr(self, "_seed_after_conclusion", False):
                content = (
                    "Resuming the investigation: the analyst judges the conclusion "
                    "insufficient and relaunches the same investigation. Start from what "
                    "you already established, complete what is missing, then conclude "
                    "again with `conclude_hunt`: the report will be rebuilt."
                )
            else:
                content = (
                    "Resuming the investigation: the loop had been interrupted, the "
                    "analyst is restarting it. Carry on where you stopped, with the "
                    "remaining budgets."
                )
            instruction = getattr(self, "_seed_instruction", None)
            if instruction:
                safe = self._vault.tokenize_text(instruction) if self._vault else instruction
                content += f"\n\nAnalyst instruction for what follows: {safe}"
            self._messages.append({"role": "user", "content": content})
            self._stream.publish(
                HuntEventType.AGENT_REASONING,
                text=(
                    "Resuming the investigation where it had stopped."
                    + (f" Analyst instruction: {instruction}" if instruction else "")
                ),
            )
        else:
            self._messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": self._briefing()},
            ]
        self._stream.publish(
            HuntEventType.HUNT_STARTED,
            hypothesis=self._dossier.hypothesis,
            campaign=self._dossier.campaign,
            sources=self._available_sources,
            budgets=self._budget.snapshot(),
        )

        interrupted = False
        reason: str | None = None
        silent_turns = 0

        try:
            while True:
                if self._stop_event.is_set():
                    interrupted, reason = True, "stop requested by the analyst"
                    break

                try:
                    self._budget.consume_iteration()
                except BudgetExhausted as exhausted:
                    if await self._pause_for_budget(exhausted):
                        continue
                    interrupted, reason = True, f"budget exhausted ({exhausted.budget})"
                    break
                self._stream.publish(
                    HuntEventType.ITERATION_STARTED,
                    iteration=self._budget.iterations,
                    budgets=self._budget.snapshot(),
                )

                completion = await self._gateway.complete(
                    model=self._model,
                    messages=self._messages,
                    tools=self._registry.function_schemas(),
                )
                try:
                    self._account_tokens(completion)
                except BudgetExhausted as exhausted:
                    if not await self._pause_for_budget(exhausted):
                        interrupted, reason = True, f"budget exhausted ({exhausted.budget})"
                        break
                    """Extension granted: the response already received is processed
                    normally, its tokens are counted, the hunt goes on."""

                if completion.content:
                    self._attach_interpretation(completion.content)
                    self._stream.publish(
                        HuntEventType.AGENT_REASONING, text=self._display(completion.content)
                    )
                    await self._journal.record(
                        AuditEventType.AGENT_DECISION,
                        detail={"iteration": self._budget.iterations},
                    )

                self._messages.append(self._assistant_message(completion))

                if not completion.tool_calls:
                    silent_turns += 1
                    if silent_turns >= _MAX_SILENT_TURNS:
                        interrupted, reason = True, "the agent did not conclude"
                        break
                    self._messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Carry on the investigation with a tool call, or call "
                                "`conclude_hunt` if you have covered the ground."
                            ),
                        }
                    )
                    continue

                silent_turns = 0
                try:
                    concluded = await self._run_tool_calls(completion.tool_calls)
                except BudgetExhausted as exhausted:
                    if await self._pause_for_budget(exhausted):
                        self._messages.append(
                            {
                                "role": "user",
                                "content": (
                                    "The analyst extended the budget. Carry on the "
                                    "investigation where you left off."
                                ),
                            }
                        )
                        continue
                    interrupted, reason = True, f"budget exhausted ({exhausted.budget})"
                    break
                if concluded:
                    break

        except BudgetExhausted as exhausted:
            interrupted, reason = True, f"budget exhausted ({exhausted.budget})"
        except ToolError as error:
            interrupted, reason = True, f"technical error ({error.code.value})"
            self._stream.publish(HuntEventType.FAILED, error=error.code.value)

        return await self._finish(interrupted=interrupted, reason=reason)

    async def _run_tool_calls(self, tool_calls: list[ToolCall]) -> bool:
        """Execute the tool calls of the turn. Returns true if the hunt is concluded."""

        concluded = False
        executed_results: list[dict[str, Any]] = []
        for call in tool_calls:
            shown_arguments = (
                {key: self._display(value) for key, value in call.arguments.items()}
                if call.arguments_valid
                else {}
            )
            self._stream.publish(
                HuntEventType.TOOL_CALL,
                tool=call.name,
                arguments=shown_arguments,
                tool_call_id=call.id,
            )

            if not call.arguments_valid:
                result = ToolError(
                    ErrorCode.SCHEMA_INVALID,
                    f"Unreadable arguments for {call.name}: invalid JSON.",
                ).to_payload()
            else:
                try:
                    result = await self._registry.dispatch(call.name, call.arguments)
                except BudgetExhausted:
                    # Every call of the turn must receive a response, otherwise the
                    # conversation would resume corrupted after a budget extension.
                    remaining = tool_calls[tool_calls.index(call) :]
                    for open_call in remaining:
                        self._messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": open_call.id,
                                "content": json.dumps(
                                    {
                                        "error": "budget_exhausted",
                                        "message": (
                                            "Budget exhausted: execution suspended, "
                                            "awaiting the analyst's decision."
                                        ),
                                    },
                                    ensure_ascii=False,
                                ),
                            }
                        )
                    raise

            self._publish_result(call, result)
            executed_results.append(result)
            self._messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": json.dumps(result, ensure_ascii=False, default=str),
                }
            )

            if call.name == "conclude_hunt" and result.get("concluded"):
                concluded = True

        self._stream.publish(HuntEventType.BUDGET_UPDATED, budgets=self._budget.snapshot())
        self._pending_interpretation = [
            str(result.get("query_id"))
            for result in executed_results
            if isinstance(result, dict) and result.get("query_id")
        ]
        await self._save_state()
        return concluded

    async def _pause_for_budget(self, exhausted: BudgetExhausted) -> bool:
        """Budget checkpoint: suspends the loop and waits for the analyst's decision.

        True if the budget was extended - the loop resumes with its memory intact.
        On a stop decision, a global hunt stop, or an expired timeout: false, and the
        clean stop with a partial report applies as before. The wait time is not
        deducted from the investigation duration.
        """

        if self._budget_pause_timeout <= 0:
            return False

        self._budget_wait = asyncio.Event()
        self._budget_choice = None
        self._stream.publish(
            HuntEventType.BUDGET_PAUSED,
            budget=exhausted.budget,
            budgets=self._budget.snapshot(),
            timeout_seconds=int(self._budget_pause_timeout),
        )
        await self._journal.record(
            AuditEventType.BUDGET_EVENT,
            detail={"action": "pause", "budget": exhausted.budget},
        )

        waited_from = time.monotonic()
        decision_task = asyncio.create_task(self._budget_wait.wait())
        stop_task = asyncio.create_task(self._stop_event.wait())
        done, pending = await asyncio.wait(
            {decision_task, stop_task},
            timeout=self._budget_pause_timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        self._budget_wait = None

        if self._stop_event.is_set():
            return False
        if not done:
            await self._journal.record(
                AuditEventType.BUDGET_EVENT,
                detail={"action": "timeout expired", "budget": exhausted.budget},
            )
            return False
        if self._budget_choice == "extend":
            self._budget.credit_pause(time.monotonic() - waited_from)
            self._stream.publish(HuntEventType.BUDGET_EXTENDED, budgets=self._budget.snapshot())
            return True
        return False

    def _attach_interpretation(self, content: str) -> None:
        """The model's comment after a result is its reading of that result:
        it is attached to the queries of the previous turn, rehydrated for the analyst,
        and will follow those queries all the way into the report."""

        pending = getattr(self, "_pending_interpretation", None)
        if not pending:
            return
        text = self._display(content)
        for query_id in pending:
            record = self._dossier.ledger.records.get(query_id)
            if record is not None and record.interpretation is None:
                self._dossier.ledger.records[query_id] = replace(record, interpretation=text)
        self._pending_interpretation = []

    def _publish_result(self, call: ToolCall, result: dict[str, Any]) -> None:
        if "error" in result:
            self._stream.publish(
                HuntEventType.TOOL_ERROR,
                tool=call.name,
                tool_call_id=call.id,
                error=result["error"],
                message=result.get("message"),
                hint=result.get("hint"),
            )
            return

        if call.name == "record_finding":
            finding = self._dossier.findings[-1] if self._dossier.findings else None
            self._stream.publish(
                HuntEventType.FINDING_RECORDED,
                finding=finding.model_dump(mode="json") if finding else None,
            )
            return

        preview = {key: result[key] for key in _TOOL_RESULT_PREVIEW_FIELDS if key in result}
        record = self._dossier.ledger.records.get(str(result.get("query_id", "")))
        self._stream.publish(
            HuntEventType.TOOL_RESULT,
            tool=call.name,
            tool_call_id=call.id,
            summary=preview,
            executed_query=self._display(result.get("executed_query")),
            notes=result.get("notes", []),
            intent=record.intent if record else None,
            columns=list(record.columns) if record else [],
            sample=[dict(row) for row in record.sample] if record else [],
            model_sample=[dict(row) for row in record.model_sample] if record else [],
            anonymization=dict(record.anonymization) if record else {},
        )

    async def _finalize_with_analysis(self) -> None:
        """Second look: the analysis model re-reads the file and settles the verdict.

        Exploration runs on the query model, cheaper; the final decision falls to the
        analysis model. The pass is degradable: if it is absent from the configuration,
        fails, or does not return a usable conclusion, we keep the conclusion proposed
        during exploration. Never a blank screen, never a hunt without a verdict.
        """

        if not self._analysis_model or self._analysis_model == self._model:
            return

        prevalidated = self._dossier.conclusion
        proposed = (
            {
                "verdict": prevalidated.verdict.value,
                "summary": prevalidated.summary,
                "limitations": prevalidated.limitations,
                "attack_description": prevalidated.attack_description,
                "techniques": ", ".join(
                    f"{technique.id} {technique.name}" for technique in prevalidated.techniques
                ),
                "recommendation": prevalidated.recommendation,
            }
            if prevalidated
            else None
        )
        prompt = final_analysis_prompt(
            hypothesis=self._dossier.hypothesis,
            campaign=self._dossier.campaign,
            findings=[
                {
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "evidence": finding.evidence_query_ids,
                }
                for finding in self._dossier.findings
            ],
            executed_queries=[
                {
                    "query_id": query.query_id,
                    "siem": query.siem,
                    "rows": query.returned_rows,
                    "truncated": query.truncated,
                }
                for query in self._dossier.executed_queries()
            ],
            proposed=proposed,
        )

        try:
            completion = await self._gateway.complete(
                model=self._analysis_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                tools=self._conclude_only_schema(),
            )
        except ToolError:
            return

        self._account_tokens(completion, allow_over_budget=True)

        call = next(
            (
                item
                for item in completion.tool_calls
                if item.name == "conclude_hunt" and item.arguments_valid
            ),
            None,
        )
        if call is None:
            return

        result = await self._registry.dispatch("conclude_hunt", call.arguments)
        if "error" not in result:
            self._stream.publish(
                HuntEventType.AGENT_REASONING,
                text=(
                    "Final review by the analysis model: verdict settled at "
                    f'"{result.get("proposed_verdict")}".'
                ),
            )

    def _conclude_only_schema(self) -> list[dict[str, Any]]:
        """Offers only `conclude_hunt` to the final pass: it concludes, it does not explore."""

        return [
            schema
            for schema in self._registry.function_schemas()
            if schema.get("function", {}).get("name") == "conclude_hunt"
        ]

    def _account_tokens(self, completion: Completion, *, allow_over_budget: bool = False) -> None:
        billable = completion.usage.billable_tokens(
            cache_read_ratio=self._budget.limits.cache_read_cost_ratio,
            cache_write_ratio=self._budget.limits.cache_write_cost_ratio,
        )
        try:
            self._budget.consume_tokens(billable)
        except BudgetExhausted:
            # The final decision pass must never leave a hunt without a verdict over one
            # last call. The overrun is still journaled via the budget counter.
            if not allow_over_budget:
                raise
        if self._budget.token_alert_triggered():
            self._stream.publish(
                HuntEventType.BUDGET_ALERT,
                budget="tokens",
                used=self._budget.tokens,
                limit=self._budget.limits.max_tokens,
            )

    def _assistant_message(self, completion: Completion) -> dict[str, Any]:
        if completion.raw_message:
            return completion.raw_message
        message: dict[str, Any] = {"role": "assistant", "content": completion.content}
        if completion.tool_calls:
            message["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": call.raw_arguments},
                }
                for call in completion.tool_calls
            ]
        return message

    def _briefing(self) -> str:
        """The hypothesis is typed freely by the analyst: it may cite an internal host or
        IP. It is tokenized like the rest before entering the prompt; the file and the
        report keep the real version."""

        hypothesis = self._dossier.hypothesis
        resume_context = self._dossier.resume_context
        if self._vault is not None:
            hypothesis = self._vault.tokenize_text(hypothesis)
            if resume_context:
                resume_context = self._vault.tokenize_text(resume_context)
        return hunt_briefing(
            hypothesis=hypothesis,
            campaign=self._dossier.campaign,
            iocs_summary=[
                {
                    "value": ioc.value,
                    "type": ioc.type.value,
                    "algo": (hash_algorithm(ioc.value) if ioc.type is IocType.HASH else None),
                    "source": ioc.source_name,
                }
                for ioc in self._dossier.validated_iocs
            ],
            available_sources=self._available_sources,
            budgets={
                "max_iterations": self._budget.limits.max_iterations,
                "max_siem_queries": self._budget.limits.max_siem_queries,
                "max_duration_seconds": self._budget.limits.max_duration_seconds,
            },
            knowledge=self._knowledge,
            investigation_window=self._investigation_window,
            workspaces=self._workspaces,
            playbook=(
                self._dossier.playbook.model_dump(mode="json")
                if self._dossier.playbook is not None
                else None
            ),
            resume_context=resume_context,
        )

    def briefing(self) -> str:
        """Briefing as the agent will receive it, for upstream planning."""

        return self._briefing()

    async def _finish(self, *, interrupted: bool, reason: str | None) -> HuntOutcome:
        if not interrupted and self._dossier.conclusion is not None:
            await self._finalize_with_analysis()

        if interrupted:
            self._dossier.status = HuntStatus.INTERRUPTED
            self._dossier.interruption_reason = reason
            await self._journal.record(
                AuditEventType.HUNT_INTERRUPTED,
                detail={"reason": reason, "budgets": self._budget.snapshot()},
            )

        report = build_report(
            self._dossier,
            self._budget,
            partial=interrupted,
            interruption_reason=reason,
            sources=self._available_sources,
            investigation_window=self._investigation_window,
        )

        if interrupted:
            self._stream.publish(
                HuntEventType.INTERRUPTED,
                reason=reason,
                budgets=self._budget.snapshot(),
            )
        self._stream.publish(
            HuntEventType.CONCLUDED,
            proposed_verdict=report.proposed_verdict.value,
            findings=len(report.findings),
            partial=report.partial,
        )
        self._stream.close()

        return HuntOutcome(report=report, interrupted=interrupted, reason=reason)
