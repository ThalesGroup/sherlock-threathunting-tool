import pytest

from middleware.errors import ErrorCode, ToolError
from middleware.guardrails.ioc import (
    Ioc,
    IocStatus,
    IocType,
    ManualIoc,
    assert_checkpoint_passed,
    assert_query_indicators_validated,
    extract_attributable_indicators,
    filter_sourced,
)

ALLOWED = ("virustotal.com", "cisa.gov")


def _ioc(value, ioc_type=IocType.DOMAIN, url="https://www.virustotal.com/gui/domain/x", **kwargs):
    return Ioc(
        value=value,
        type=ioc_type,
        source_name=kwargs.pop("source_name", "VirusTotal"),
        source_url=url,
        **kwargs,
    )


class TestSourceRequired:
    def test_ioc_without_source_url_is_dropped(self):
        kept, dropped = filter_sourced([_ioc("evil.com", url="")], allowed_domains=ALLOWED)
        assert kept == []
        assert dropped[0]["value"] == "evil.com"

    def test_ioc_from_unapproved_source_is_dropped(self):
        kept, dropped = filter_sourced(
            [_ioc("evil.com", url="https://pastebin.example/raw/x")], allowed_domains=ALLOWED
        )
        assert kept == []
        assert dropped

    def test_http_source_is_dropped(self):
        kept, _ = filter_sourced(
            [_ioc("evil.com", url="http://www.virustotal.com/x")], allowed_domains=ALLOWED
        )
        assert kept == []

    def test_subdomain_of_allowed_source_is_kept(self):
        kept, dropped = filter_sourced(
            [_ioc("evil.com", url="https://www.virustotal.com/gui/domain/evil.com")],
            allowed_domains=ALLOWED,
        )
        assert len(kept) == 1
        assert dropped == []

    def test_analyst_provided_ioc_carries_its_own_source(self):
        manual = ManualIoc(value="1.2.3.4", type=IocType.IP, provided_by="j.doe")
        kept, dropped = filter_sourced([manual.to_ioc()], allowed_domains=())
        assert len(kept) == 1
        assert kept[0].status is IocStatus.VALIDATED
        assert dropped == []


class TestCheckpoint:
    def test_pending_ioc_blocks_siem_access(self):
        with pytest.raises(ToolError) as excinfo:
            assert_checkpoint_passed([_ioc("evil.com")], hunt_id="hunt_1")
        assert excinfo.value.code is ErrorCode.IOC_NOT_VALIDATED

    def test_validated_iocs_pass(self):
        assert_checkpoint_passed([_ioc("evil.com", status=IocStatus.VALIDATED)], hunt_id="hunt_1")

    def test_rejected_iocs_do_not_block(self):
        assert_checkpoint_passed([_ioc("evil.com", status=IocStatus.REJECTED)], hunt_id="hunt_1")


class TestIndicatorExtraction:
    def test_field_paths_are_not_indicators(self):
        found = extract_attributable_indicators(
            'metadata.event_type = "NETWORK_CONNECTION" AND principal.hostname != ""'
        )
        assert found == set()

    def test_table_and_column_names_are_not_indicators(self):
        found = extract_attributable_indicators(
            "DeviceNetworkEvents | where RemoteUrl has_any (badUrls) | project Timestamp"
        )
        assert found == set()

    def test_domain_in_literal_is_extracted(self):
        assert "evil.example" in extract_attributable_indicators(
            'DeviceNetworkEvents | where RemoteUrl contains "evil.example"'
        )

    def test_defanged_indicator_is_normalized(self):
        assert "evil.example" in extract_attributable_indicators(
            'DeviceNetworkEvents | where RemoteUrl contains "evil[.]example"'
        )

    def test_private_ip_is_not_an_attributable_indicator(self):
        found = extract_attributable_indicators('SigninLogs | where Ip == "10.0.0.5"')
        assert found == set()

    def test_public_ip_is_extracted(self):
        assert "45.155.205.233" in extract_attributable_indicators(
            'SigninLogs | where Ip == "45.155.205.233"'
        )

    def test_hash_is_extracted(self):
        digest = "a" * 64
        assert digest in extract_attributable_indicators(
            f'DeviceFileEvents | where SHA256 == "{digest}"'
        )


class TestUnsourcedIndicatorBlocked:
    def test_indicator_from_model_memory_is_refused(self):
        validated = [_ioc("known.example", status=IocStatus.VALIDATED)]
        with pytest.raises(ToolError) as excinfo:
            assert_query_indicators_validated(
                'DeviceNetworkEvents | where RemoteUrl contains "made-up.example"', validated
            )
        assert excinfo.value.code is ErrorCode.IOC_UNSOURCED

    def test_validated_indicator_passes(self):
        validated = [_ioc("known.example", status=IocStatus.VALIDATED)]
        assert_query_indicators_validated(
            'DeviceNetworkEvents | where RemoteUrl contains "known.example"', validated
        )

    def test_pending_indicator_does_not_count_as_validated(self):
        with pytest.raises(ToolError):
            assert_query_indicators_validated(
                'DeviceNetworkEvents | where RemoteUrl contains "known.example"',
                [_ioc("known.example")],
            )

    def test_behavioural_query_without_indicators_is_allowed(self):
        assert_query_indicators_validated(
            'DeviceProcessEvents | where FileName =~ "wmic.exe"'
            ' and ProcessCommandLine has "shadowcopy"',
            [],
        )

    def test_url_ioc_authorizes_its_host(self):
        validated = [
            _ioc(
                "https://known.example/payload",
                ioc_type=IocType.URL,
                status=IocStatus.VALIDATED,
            )
        ]
        assert_query_indicators_validated(
            'DeviceNetworkEvents | where RemoteUrl contains "known.example"', validated
        )
