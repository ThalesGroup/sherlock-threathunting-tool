"""Indicator file import: pattern-based extraction, never guessed."""

import io

from middleware.errors import ToolError
from middleware.guardrails.ioc import IocType
from middleware.ioc_import import MAX_INDICATORS, extract_indicators, extract_text


class TestExtraction:
    def test_each_form_is_classified(self):
        text = """
        Incident report — observed indicators:
        7418ffa31f8a51a04274fc8f610fa4d5aa5758746617020ee57493546ae35b70
        5190ef1733183a0dc63fb623357f56d6 ; da39a3ee5e6b4b0d3255bfef95601890afd80709
        evil[.]example, hxxp://evil.example/payload.bin
        contact@phishing.example
        185.220.101.42 and 10.0.0.5 (internal, to ignore)
        C:\\Users\\Public\\payload.exe /tmp/osalogging.zip
        HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Financeiro
        report.pdf some-word 12345
        """
        found = dict(extract_indicators(text))

        assert (
            found["7418ffa31f8a51a04274fc8f610fa4d5aa5758746617020ee57493546ae35b70"]
            is IocType.HASH
        )
        assert found["5190ef1733183a0dc63fb623357f56d6"] is IocType.HASH
        assert found["da39a3ee5e6b4b0d3255bfef95601890afd80709"] is IocType.HASH
        assert found["evil.example"] is IocType.DOMAIN, "defang normalized"
        assert found["http://evil.example/payload.bin"] is IocType.URL, "hxxp normalized"
        assert found["contact@phishing.example"] is IocType.EMAIL
        assert found["185.220.101.42"] is IocType.IP
        assert "10.0.0.5" not in found, "private IP ignored"
        assert found["C:\\Users\\Public\\payload.exe"] is IocType.FILE_PATH, "case preserved"
        assert found["/tmp/osalogging.zip"] is IocType.FILE_PATH  # noqa: S108
        assert any(t is IocType.REGISTRY_KEY for t in found.values())
        assert "report.pdf" not in found, "filename != domain"

    def test_package_list_falls_back_to_other_not_email(self):
        """A list of package names (one per line): those outside the network/host category
        become "other" rather than email (name@version) or being discarded."""

        text = "\n".join(
            [
                "event-stream",
                "flatmap-stream@0.1.1",
                "@scope/malicious-pkg",
                "left-pad",
                "evil.example",
                "contact@phishing.example",
            ]
        )
        found = dict(extract_indicators(text))
        assert found["event-stream"] is IocType.OTHER
        assert found["flatmap-stream@0.1.1"] is IocType.OTHER, "name@version is not an email"
        assert found["@scope/malicious-pkg"] is IocType.OTHER
        assert found["left-pad"] is IocType.OTHER
        assert found["evil.example"] is IocType.DOMAIN, "a real domain stays a domain"
        assert found["contact@phishing.example"] is IocType.EMAIL, "a real email stays an email"

    def test_prose_does_not_produce_other_noise(self):
        """In prose (a report), we do not fabricate an "other" indicator from words."""

        text = (
            "The actor used the event-stream package to compromise the host. "
            "Contact admin@corp.example ; the domain evil.example is malicious."
        )
        found = dict(extract_indicators(text))
        assert IocType.OTHER not in found.values()
        assert found["admin@corp.example"] is IocType.EMAIL
        assert found["evil.example"] is IocType.DOMAIN

    def test_deduplication_and_cap(self):
        text = "\n".join(
            ["dup.example"] * 10 + [f"site-{i}.example" for i in range(MAX_INDICATORS + 100)]
        )
        found = extract_indicators(text)
        assert len(found) == MAX_INDICATORS
        assert sum(1 for value, _ in found if value == "dup.example") == 1

    def test_oversized_file_is_refused(self):
        import pytest

        with pytest.raises(ToolError):
            extract_text(b"x" * (15 * 1024 * 1024 + 1), "big.txt")

    def test_xlsx_cells_are_read(self):
        from openpyxl import Workbook

        workbook = Workbook()
        sheet = workbook.active
        sheet.append(["indicator", "comment"])
        sheet.append(["evil.example", "primary C2"])
        sheet.append(["185.220.101.42", None])
        buffer = io.BytesIO()
        workbook.save(buffer)

        text = extract_text(buffer.getvalue(), "list.xlsx")
        found = dict(extract_indicators(text))
        assert found["evil.example"] is IocType.DOMAIN
        assert found["185.220.101.42"] is IocType.IP
