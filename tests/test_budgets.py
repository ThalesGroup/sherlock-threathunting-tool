"""Budget extension at the checkpoint: granted minutes are time ahead, not a ceiling."""

from __future__ import annotations

import pytest

from middleware.budgets import TOKENS_HARD_CAP, BudgetExhausted, HuntBudget
from middleware.config import Budgets


class TestExtendDuration:
    def test_extra_minutes_count_from_the_time_already_elapsed(self):
        budget = HuntBudget(limits=Budgets(max_duration_seconds=900))
        budget.started_at -= 2_500  # paused for a long time: 41 minutes elapsed
        with pytest.raises(BudgetExhausted):
            budget.check_alive()

        budget.extend(extra_minutes=10)

        assert budget.limits.max_duration_seconds >= 2_500 + 600
        budget.check_alive()  # resumes with ten minutes ahead

    def test_tokens_exhaustion_is_checked_before_the_next_step(self):
        budget = HuntBudget(limits=Budgets(max_tokens=1_000))
        budget.consume_tokens(999)
        budget.check_alive()
        budget.consume_tokens(1)
        with pytest.raises(BudgetExhausted) as info:
            budget.check_alive()
        assert info.value.budget == "tokens"

    def test_extra_tokens_count_from_the_highest_of_ceiling_and_consumption(self):
        budget = HuntBudget(limits=Budgets(max_tokens=1_200_000))
        budget.tokens = 1_234_542  # overrun observed on the last model response
        budget.extend(extra_tokens=300_000)
        assert budget.limits.max_tokens == 1_534_542
        budget.check_alive()

        budget.extend(extra_tokens=10_000_000)
        assert budget.limits.max_tokens == TOKENS_HARD_CAP

    def test_extension_without_minutes_leaves_the_duration_alone(self):
        budget = HuntBudget(limits=Budgets(max_duration_seconds=900))
        budget.extend(extra_iterations=5)
        assert budget.limits.max_duration_seconds == 900
        assert budget.limits.max_iterations == 25
