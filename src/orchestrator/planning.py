"""Hunt playbook: the model proposes a plan and an estimate, the analyst decides.

Third human checkpoint, before any SIEM query spend. Here the model has no query tool: it
receives only the briefing and can only propose a plan (forced function call). The estimate
is a proposal; the effective limit is the one the analyst validates, enforced by the
middleware.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from middleware.errors import ErrorCode, ToolError
from orchestrator.prompts import PLANNING_SYSTEM_PROMPT, playbook_prompt
from reporting.models import Playbook, PlaybookStep

PLATFORM_CAP = 100
"""Absolute platform cap, for iterations as for queries: an estimate cannot exceed it,
nor can a validation."""

_MAX_STEPS = 12


class _Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=20, max_length=1500)
    steps: list[PlaybookStep] = Field(min_length=1, max_length=_MAX_STEPS)
    not_covered: str = Field(min_length=5, max_length=1500)


def playbook_tool_schema(available_sources: list[str]) -> dict[str, Any]:
    """Schema of the forced call. Sources are a closed enumeration: a plan cannot cite a
    source that the platform does not have."""

    return {
        "type": "function",
        "function": {
            "name": "propose_playbook",
            "description": (
                "Propose the investigation plan and the estimate of the number of queries "
                "needed. The analyst will validate or adjust before any launch."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "General approach in a few sentences.",
                    },
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": _MAX_STEPS,
                        "items": {
                            "type": "object",
                            "properties": {
                                "order": {"type": "integer", "minimum": 1},
                                "siem": {"type": "string", "enum": list(available_sources)},
                                "objective": {
                                    "type": "string",
                                    "maxLength": 400,
                                    "description": (
                                        "What the lead seeks to establish, in one or two sentences."
                                    ),
                                },
                                "technique": {
                                    "type": "string",
                                    "description": "MITRE ATT&CK identifier (T1234 or T1234.001).",
                                },
                                "expected_queries": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "maximum": 30,
                                    "description": "Queries planned for this lead.",
                                },
                            },
                            "required": ["order", "siem", "objective", "expected_queries"],
                            "additionalProperties": False,
                        },
                    },
                    "not_covered": {
                        "type": "string",
                        "description": "What this plan will not cover and why.",
                    },
                },
                "required": ["summary", "steps", "not_covered"],
                "additionalProperties": False,
            },
        },
    }


_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TEXT_CAPS = {"summary": 1500, "not_covered": 1500}


def _clip(value: object, limit: int) -> object:
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 1].rstrip() + "…"
    return value


def _normalized(arguments: dict[str, Any]) -> dict[str, Any]:
    """Makes the model's plan compliant without rejecting it for excess prose: overly long
    texts are truncated, a malformed technique is discarded. The structure (leads, sources,
    numbers), however, remains strictly validated."""

    cleaned: dict[str, Any] = dict(arguments)
    for key, limit in _TEXT_CAPS.items():
        cleaned[key] = _clip(cleaned.get(key), limit)
    steps = cleaned.get("steps")
    if isinstance(steps, list):
        normalized_steps = []
        for step in steps:
            if not isinstance(step, dict):
                normalized_steps.append(step)
                continue
            step = dict(step)
            step["objective"] = _clip(step.get("objective"), 400)
            technique = step.get("technique")
            if technique is not None and (
                not isinstance(technique, str) or not _TECHNIQUE_RE.match(technique.strip())
            ):
                step["technique"] = None
            elif isinstance(technique, str):
                step["technique"] = technique.strip()
            normalized_steps.append(step)
        cleaned["steps"] = normalized_steps
    return cleaned


def estimate_iterations(queries: int) -> int:
    """Iterations derived from queries: each query is a turn, plus the turns for reasoning,
    recording findings and the conclusion."""

    return min(PLATFORM_CAP, queries + max(3, math.ceil(queries * 0.4)))


async def propose_playbook(
    gateway: Any,
    *,
    model: str,
    briefing: str,
    available_sources: list[str],
    instruction: str | None = None,
) -> Playbook:
    if not available_sources:
        raise ToolError(
            ErrorCode.UPSTREAM_UNAVAILABLE,
            "No active SIEM source: cannot plan a hunt.",
        )
    completion = await gateway.complete(
        model=model,
        messages=[
            {"role": "system", "content": PLANNING_SYSTEM_PROMPT},
            {"role": "user", "content": playbook_prompt(briefing, instruction=instruction)},
        ],
        tools=[playbook_tool_schema(available_sources)],
    )
    call = next(
        (
            item
            for item in completion.tool_calls
            if item.name == "propose_playbook" and item.arguments_valid
        ),
        None,
    )
    if call is None:
        raise ToolError(
            ErrorCode.UPSTREAM_UNAVAILABLE,
            "The model did not propose a usable plan.",
            hint="Re-run the generation, possibly with a more precise instruction.",
        )
    try:
        proposal = _Proposal.model_validate(_normalized(call.arguments))
    except ValidationError as error:
        first = error.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ())) or "plan"
        raise ToolError(
            ErrorCode.SCHEMA_INVALID,
            f"Proposed plan invalid ({location}: {first.get('msg', 'invalid value')}).",
            hint="Re-run the generation.",
        ) from error

    unknown = sorted({step.siem for step in proposal.steps} - set(available_sources))
    if unknown:
        raise ToolError(
            ErrorCode.SCHEMA_INVALID,
            f"The plan cites an unavailable source: {', '.join(unknown)}.",
            hint="Re-run the generation.",
        )

    steps = sorted(proposal.steps, key=lambda step: step.order)
    estimated_queries = min(PLATFORM_CAP, sum(step.expected_queries for step in steps))
    return Playbook(
        summary=proposal.summary,
        steps=[step.model_copy(update={"order": index}) for index, step in enumerate(steps, 1)],
        not_covered=proposal.not_covered,
        estimated_queries=estimated_queries,
        estimated_iterations=estimate_iterations(estimated_queries),
        instruction=instruction.strip() if instruction and instruction.strip() else None,
        generated_at=datetime.now(UTC).isoformat(),
    )
