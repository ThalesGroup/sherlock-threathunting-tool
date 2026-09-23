"""Budget extension at the checkpoint: granted minutes are time ahead, not a ceiling."""

from __future__ import annotations

import pytest

from middleware.budgets import BudgetExhausted, HuntBudget
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

    def test_extension_without_minutes_leaves_the_duration_alone(self):
        budget = HuntBudget(limits=Budgets(max_duration_seconds=900))
        budget.extend(extra_iterations=5)
        assert budget.limits.max_duration_seconds == 900
        assert budget.limits.max_iterations == 25
