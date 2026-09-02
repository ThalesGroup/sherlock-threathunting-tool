import pytest

from middleware.errors import ErrorCode, ToolError
from middleware.guardrails.kql import validate_kql


def _reject_code(query: str, **kwargs) -> ErrorCode:
    with pytest.raises(ToolError) as excinfo:
        validate_kql(query, row_cap=500, **kwargs)
    return excinfo.value.code


class TestReadOnly:
    @pytest.mark.parametrize(
        "query",
        [
            ".create table Foo (a: string)",
            ".drop table SigninLogs",
            ".ingest inline into table Foo [1]",
            ".show tables",
            "let a = 1; .show version",
        ],
    )
    def test_control_commands_rejected(self, query):
        assert _reject_code(query) is ErrorCode.QUERY_REJECTED

    @pytest.mark.parametrize(
        "query",
        [
            "SigninLogs | take 10 | into Foo",
            "SigninLogs | ingest",
        ],
    )
    def test_write_operators_rejected(self, query):
        assert _reject_code(query) is ErrorCode.QUERY_REJECTED

    def test_set_directive_rejected(self):
        assert _reject_code("set notruncation; SigninLogs | take 5") is ErrorCode.QUERY_REJECTED


class TestEgressAndScope:
    @pytest.mark.parametrize(
        "query",
        [
            'externaldata(x: string) [@"https://evil.example/a.csv"]',
            'SigninLogs | evaluate http_request("https://evil.example")',
            'SigninLogs | evaluate sql_request("Server=x", "select 1")',
        ],
    )
    def test_network_plugins_rejected(self, query):
        assert _reject_code(query) is ErrorCode.QUERY_REJECTED

    @pytest.mark.parametrize(
        "query",
        [
            'cluster("other").database("Sec").SigninLogs',
            'workspace("other-ws").SigninLogs | take 5',
            'app("other").requests',
            'arg("").Resources',
        ],
    )
    def test_cross_scope_rejected(self, query):
        assert _reject_code(query) is ErrorCode.QUERY_REJECTED

    def test_unknown_evaluate_plugin_rejected(self):
        assert _reject_code("SigninLogs | evaluate unknown_plugin()") is ErrorCode.QUERY_REJECTED

    def test_allowed_evaluate_plugin_accepted(self):
        plan = validate_kql("SigninLogs | evaluate bag_unpack(Props)", row_cap=500)
        assert "bag_unpack" in plan.query


class TestLiteralsAreNotCode:
    def test_forbidden_word_inside_a_string_literal_is_ignored(self):
        plan = validate_kql('DeviceEvents | where FileName == "ingest.exe"', row_cap=200)
        assert "ingest.exe" in plan.query

    def test_url_in_literal_is_not_treated_as_comment(self):
        plan = validate_kql('DeviceEvents | where Url == "https://a.example/x"', row_cap=200)
        assert "https://a.example/x" in plan.query

    def test_comment_hiding_an_operator_is_stripped(self):
        plan = validate_kql("SigninLogs // | into Foo\n| take 5", row_cap=200)
        assert "into" not in plan.query.lower()

    def test_unterminated_string_rejected(self):
        assert _reject_code('SigninLogs | where X == "abc') is ErrorCode.QUERY_REJECTED


class TestRowCap:
    def test_take_appended(self):
        plan = validate_kql("SigninLogs | where ResultType == 0", row_cap=500)
        assert plan.query.strip().endswith("take 500")

    def test_cap_wins_over_model_requested_take(self):
        plan = validate_kql("SigninLogs | take 100000", row_cap=500)
        assert plan.query.strip().endswith("take 500")

    def test_take_inserted_before_render(self):
        plan = validate_kql("SigninLogs | summarize c=count() by Ip | render barchart", row_cap=50)
        segments = [segment.strip() for segment in plan.query.split("|")]
        assert segments[-2] == "take 50"
        assert segments[-1] == "render barchart"

    def test_cap_applies_to_last_statement_only(self):
        plan = validate_kql("let ips = dynamic(['1.2.3.4']); SigninLogs | take 10", row_cap=25)
        assert plan.query.count("take 25") == 1
        assert plan.query.strip().endswith("take 25")

    def test_trailing_semicolon_does_not_produce_orphan_statement(self):
        plan = validate_kql("let a = 1; SigninLogs | take 3;", row_cap=25)
        assert not plan.query.rstrip().endswith(";")
        assert plan.query.strip().endswith("take 25")

    def test_pipe_inside_string_is_not_a_segment_boundary(self):
        plan = validate_kql('DeviceEvents | where Cmd has "a | b"', row_cap=10)
        assert 'has "a | b"' in plan.query
        assert plan.query.strip().endswith("take 10")


class TestTimeWindow:
    def test_missing_time_filter_rejected_when_required(self):
        assert (
            _reject_code("DeviceProcessEvents | take 5", require_time_filter_days=30)
            is ErrorCode.WINDOW_TOO_LARGE
        )

    def test_window_beyond_cap_rejected(self):
        assert (
            _reject_code(
                "DeviceProcessEvents | where Timestamp > ago(90d)", require_time_filter_days=30
            )
            is ErrorCode.WINDOW_TOO_LARGE
        )

    def test_window_within_cap_accepted(self):
        plan = validate_kql(
            "DeviceProcessEvents | where Timestamp > ago(14d)",
            row_cap=200,
            require_time_filter_days=30,
        )
        assert any("14" in note for note in plan.notes)

    def test_widest_ago_is_the_one_enforced(self):
        assert (
            _reject_code(
                "DeviceProcessEvents | where Timestamp > ago(1d) or Timestamp > ago(45d)",
                require_time_filter_days=30,
            )
            is ErrorCode.WINDOW_TOO_LARGE
        )

    def test_hours_are_converted_to_days(self):
        plan = validate_kql(
            "DeviceProcessEvents | where Timestamp > ago(48h)",
            row_cap=200,
            require_time_filter_days=30,
        )
        assert plan.row_cap == 200

    def test_sentinel_does_not_require_inline_time_filter(self):
        plan = validate_kql("SigninLogs | take 5", row_cap=200)
        assert plan.query.strip().endswith("take 200")


class TestEmptyInput:
    @pytest.mark.parametrize("query", ["", "   ", "// nothing at all"])
    def test_empty_rejected(self, query):
        assert _reject_code(query) is ErrorCode.QUERY_REJECTED

    def test_query_ending_on_let_rejected(self):
        assert _reject_code("let a = SigninLogs") is ErrorCode.QUERY_REJECTED
