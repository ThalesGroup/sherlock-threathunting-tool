"""A hunt's budgets: iterations, SIEM queries, tokens, duration.

An overrun raises `BudgetExhausted`, which the orchestrator turns into a clean stop with a
partial report. There is no silent-stop path.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from middleware.config import Budgets
from middleware.errors import BudgetExhausted


@dataclass
class HuntBudget:
    limits: Budgets
    clock: Callable[[], float] = time.monotonic
    started_at: float = field(default=0.0)
    iterations: int = 0
    siem_queries: int = 0
    tokens: int = 0
    _alerted: bool = False

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = self.clock()

    @property
    def elapsed_seconds(self) -> float:
        return self.clock() - self.started_at

    def check_alive(self) -> None:
        """Checks the non-incremental budgets (duration) before each step."""

        if self.elapsed_seconds > self.limits.max_duration_seconds:
            raise BudgetExhausted("duration", self.limits.max_duration_seconds)

    def consume_iteration(self) -> None:
        self.check_alive()
        if self.iterations >= self.limits.max_iterations:
            raise BudgetExhausted("iterations", self.limits.max_iterations)
        self.iterations += 1

    def consume_siem_query(self) -> None:
        if self.siem_queries >= self.limits.max_siem_queries:
            raise BudgetExhausted("SIEM queries", self.limits.max_siem_queries)
        self.siem_queries += 1

    def consume_tokens(self, count: int) -> None:
        self.tokens += max(0, count)
        if self.tokens > self.limits.max_tokens:
            raise BudgetExhausted("tokens", self.limits.max_tokens)

    def token_alert_triggered(self) -> bool:
        """True only once, when the alert threshold is crossed."""

        ratio = self.tokens / self.limits.max_tokens if self.limits.max_tokens else 0.0
        if ratio >= self.limits.token_alert_ratio and not self._alerted:
            self._alerted = True
            return True
        return False

    def extend(
        self,
        *,
        extra_iterations: int = 0,
        extra_siem_queries: int = 0,
        extra_minutes: int = 0,
    ) -> None:
        """Extension granted by the analyst at the budget checkpoint. The hard caps
        remain: never more than 100 iterations or 100 queries, and the token budget is not
        extensible through this path. Extra minutes add to the time already elapsed, not
        to the initial ceiling: a hunt paused on duration for a long while resumes with
        that much time ahead instead of pausing again at once."""

        duration = self.limits.max_duration_seconds
        if extra_minutes > 0:
            duration = max(duration, int(self.elapsed_seconds)) + extra_minutes * 60
        self.limits = self.limits.model_copy(
            update={
                "max_iterations": min(100, self.limits.max_iterations + max(0, extra_iterations)),
                "max_siem_queries": min(
                    100, self.limits.max_siem_queries + max(0, extra_siem_queries)
                ),
                "max_duration_seconds": duration,
            }
        )

    def credit_pause(self, seconds: float) -> None:
        """Time spent waiting for the analyst's decision does not count toward the
        investigation duration."""

        self.started_at += max(0.0, seconds)

    def restore(
        self, *, iterations: int, siem_queries: int, tokens: int, elapsed_seconds: float
    ) -> None:
        """Resumes from the saved counters of an interrupted hunt: the duration already
        consumed stays counted, the caps may have been raised by the analyst."""

        self.iterations = max(0, int(iterations))
        self.siem_queries = max(0, int(siem_queries))
        self.tokens = max(0, int(tokens))
        self.started_at = self.clock() - max(0.0, float(elapsed_seconds))

    def snapshot(self) -> dict[str, Any]:
        return {
            "iterations": {"used": self.iterations, "limit": self.limits.max_iterations},
            "siem_queries": {"used": self.siem_queries, "limit": self.limits.max_siem_queries},
            "tokens": {"used": self.tokens, "limit": self.limits.max_tokens},
            "duration_seconds": {
                "used": round(self.elapsed_seconds, 1),
                "limit": self.limits.max_duration_seconds,
            },
        }
