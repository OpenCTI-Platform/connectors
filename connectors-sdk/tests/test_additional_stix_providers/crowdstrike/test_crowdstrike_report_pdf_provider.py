# pragma: no cover # Do not compute coverage on test files
"""Offer tests for CrowdStrikeReportPdfAdditionalStixProvider."""

import base64
from typing import Any

import pytest
from connectors_sdk.additional_stix_providers import AbstractAdditionalStixProvider
from connectors_sdk.additional_stix_providers.crowdstrike import (
    CrowdStrikeReportKey,
    CrowdStrikeReportPdfAdditionalStixProvider,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import Artifact, OrganizationAuthor, TLPMarking

PDF = b"%PDF-1.7 monthly threat report"
REPORT = CrowdStrikeReportKey(id=123, name="Monthly Threat Report")
OTHER_REPORT = CrowdStrikeReportKey(id=456, name="Other Report")


class FakeReportsClient:
    """Fake client answering per report id and recording calls."""

    def __init__(
        self, responses: dict[str, bytes | dict[str, Any] | Exception]
    ) -> None:
        """Store the response of each report id."""
        self.responses = responses
        self.calls: list[str] = []

    def get_report_pdf(self, report_id: str) -> bytes | dict[str, Any]:
        """Return or raise the configured response."""
        self.calls.append(report_id)
        response = self.responses[report_id]
        if isinstance(response, Exception):
            raise response
        return response


def error(status_code: int | None) -> dict[str, Any]:
    """Return a falconpy-like error response."""
    response: dict[str, Any] = {"headers": {}, "body": {"errors": [{"message": "x"}]}}
    if status_code is not None:
        response["status_code"] = status_code
    return response


def make_provider(
    client: FakeReportsClient, cache: bool = False
) -> CrowdStrikeReportPdfAdditionalStixProvider:
    """Build a provider."""
    return CrowdStrikeReportPdfAdditionalStixProvider(
        client=client,
        author=OrganizationAuthor(name="CrowdStrike"),
        markings=[TLPMarking(level="amber")],
        cache=cache,
    )


def test_provider_name() -> None:
    """Test that the provider follows the naming convention."""
    assert issubclass(
        CrowdStrikeReportPdfAdditionalStixProvider, AbstractAdditionalStixProvider
    )
    assert CrowdStrikeReportPdfAdditionalStixProvider.__name__ == (
        "CrowdStrikeReportPdfAdditionalStixProvider"
    )


def test_report_with_a_pdf() -> None:
    """Test that a PDF becomes one artifact with the connector's file name."""
    client = FakeReportsClient({"123": PDF})

    (artifact,) = make_provider(client).get(REPORT) or []

    assert client.calls == ["123"]
    assert isinstance(artifact, Artifact)
    stix = artifact.to_stix2_object()
    assert base64.b64decode(stix["payload_bin"]) == PDF
    assert stix["mime_type"] == "application/pdf"
    assert stix["x_opencti_additional_names"] == ["monthly-threat-report.pdf"]


@pytest.mark.parametrize("response", [error(404), b""])
def test_report_without_a_pdf(response: bytes | dict[str, Any]) -> None:
    """Test that 'no PDF' (404, or an empty body) gives None."""
    assert make_provider(FakeReportsClient({"123": response})).get(REPORT) is None


@pytest.mark.parametrize("status_code", [401, 403, 429, 500, None])
def test_api_error_raises(status_code: int | None) -> None:
    """Test that any other error response raises a DataRetrievalError."""
    client = FakeReportsClient({"123": error(status_code)})

    with pytest.raises(
        DataRetrievalError, match=f"report 123 \\(status {status_code}\\)"
    ):
        make_provider(client).get(REPORT)


def test_client_exception_raises_with_cause() -> None:
    """Test that a client exception is wrapped with its cause."""
    cause = ConnectionError("network down")
    client = FakeReportsClient({"123": cause})

    with pytest.raises(DataRetrievalError) as raised:
        make_provider(client).get(REPORT)

    assert raised.value.__cause__ is cause


def test_same_pdf_for_two_reports_gives_one_artifact() -> None:
    """Test that the same PDF returned for two reports has one artifact id."""
    provider = make_provider(FakeReportsClient({"123": PDF, "456": PDF}))

    first, second = provider.get(REPORT) or [], provider.get(OTHER_REPORT) or []

    assert first[0].id == second[0].id


def test_get_many() -> None:
    """Test that several reports are grouped by key, without the ones lacking a PDF."""
    client = FakeReportsClient({"123": PDF, "456": error(404)})

    result = make_provider(client).get_many([REPORT, OTHER_REPORT, REPORT])

    assert list(result) == [REPORT]
    assert client.calls == ["123", "456"]


def test_cache() -> None:
    """Test that a cached report, with or without PDF, is downloaded once."""
    client = FakeReportsClient({"123": PDF, "456": error(404)})
    provider = make_provider(client, cache=True)

    provider.get_many([REPORT, OTHER_REPORT])
    provider.get_many([REPORT, OTHER_REPORT])

    assert client.calls == ["123", "456"]
