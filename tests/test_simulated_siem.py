"""Simulated SIEM mode: explicit, confined to dev, every row marked as simulation."""

import pytest

from api.runtime import build_clients
from middleware.clients.simulated import SimulatedSiemClient
from middleware.config import Settings


class FakeSecrets:
    def get_optional(self, name):
        return None


class TestBuildClientsDemo:
    def test_demo_mode_wires_all_three_simulated_siems(self):
        settings = Settings(_env_file=None, demo_siem=True)
        clients = build_clients(settings, FakeSecrets())

        assert clients.available() == ["sentinel", "defender", "secops"]
        assert isinstance(clients.sentinel, SimulatedSiemClient)

    def test_demo_mode_is_refused_outside_dev(self):
        settings = Settings(_env_file=None, demo_siem=True, environment="production")
        with pytest.raises(RuntimeError, match="dev"):
            build_clients(settings, FakeSecrets())

    def test_disabled_by_default(self):
        settings = Settings(_env_file=None)
        assert build_clients(settings, FakeSecrets()).available() == []


class TestSimulatedClient:
    async def test_every_row_is_marked_as_simulation(self):
        client = SimulatedSiemClient(siem="sentinel")
        outcome = await client.run_query(query="DeviceProcessEvents", row_cap=200)

        assert outcome.rows
        assert all("simulation" in row for row in outcome.rows)
        assert any("SIMULATION" in note for note in outcome.notes)

    async def test_signin_query_returns_identity_rows(self):
        client = SimulatedSiemClient(siem="sentinel")
        outcome = await client.run_query(query="SigninLogs | take 10", row_cap=200)

        assert outcome.rows
        assert all("UserPrincipalName" in row for row in outcome.rows)

    async def test_absorbs_each_real_client_signature(self):
        client = SimulatedSiemClient(siem="secops")
        secops = await client.run_query(
            query="metadata.event_type", start_time="a", end_time="b", row_cap=50
        )
        defender = await client.run_query(query="DeviceEvents", row_cap=50)
        assert secops.rows and defender.rows

    async def test_row_cap_truncates_and_flags(self):
        client = SimulatedSiemClient(siem="sentinel")
        outcome = await client.run_query(query="DeviceProcessEvents", row_cap=1)
        assert len(outcome.rows) == 1
        assert outcome.truncated is True

    async def test_query_indicator_is_echoed_first(self):
        client = SimulatedSiemClient(siem="defender")
        outcome = await client.run_query(
            query="DeviceNetworkEvents | where RemoteIP == '45.155.12.7'", row_cap=200
        )
        first = " ".join(str(v) for v in outcome.rows[0].values())
        assert "45.155.12.7" in first
