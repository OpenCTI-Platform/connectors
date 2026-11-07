"""Tests for the Censys API client (censys_enrichment.client)."""

from unittest.mock import patch

import pytest
from censys_enrichment.client import Client
from censys_enrichment.errors import EntityHasNoUsableHashError
from censys_platform import (
    CertificateAsset,
    ResponseEnvelopeSearchQueryResponse,
    SearchQueryHit,
    SearchQueryResponse,
    V3GlobaldataSearchQueryResponse,
)

from .factories import CertificateFactory

# =====================
# Test Cases: fetch_certs
# =====================


def test_fetch_certs_raises_without_a_usable_hash() -> None:
    """Test that fetch_certs rejects a hashes dict with no recognized hash key."""
    client = Client(organisation_id="org", token="tok")
    with pytest.raises(EntityHasNoUsableHashError):
        list(client.fetch_certs(hashes={"SHA-512": "deadbeef"}))


@pytest.mark.parametrize(
    "hashes",
    [
        {"MD5": "aaaa"},
        {"SHA-1": "bbbb"},
        {"SHA-256": "cccc"},
        {"MD5": "aaaa", "SHA-1": "bbbb", "SHA-256": "cccc"},
    ],
)
def test_fetch_certs_yields_matching_certificates(hashes: dict[str, str]) -> None:
    """Test that fetch_certs yields certificates for each recognized hash type."""
    cert = CertificateFactory()
    result = V3GlobaldataSearchQueryResponse(
        headers={},
        result=ResponseEnvelopeSearchQueryResponse(
            result=SearchQueryResponse(
                hits=[
                    SearchQueryHit(
                        certificate_v1=CertificateAsset(extensions={}, resource=cert)
                    )
                ],
                total_hits=1,
                next_page_token="",
                query_duration_millis=1,
                previous_page_token="",
            )
        ),
    )
    client = Client(organisation_id="org", token="tok")
    with patch("censys_platform.global_data.GlobalData.search", return_value=result):
        certs = list(client.fetch_certs(hashes=hashes))
    assert certs == [cert]


def test_fetch_certs_skips_hits_without_certificate() -> None:
    """Test that fetch_certs ignores hits that don't carry a certificate_v1 resource."""
    result = V3GlobaldataSearchQueryResponse(
        headers={},
        result=ResponseEnvelopeSearchQueryResponse(
            result=SearchQueryResponse(
                hits=[SearchQueryHit(certificate_v1=None)],
                total_hits=1,
                next_page_token="",
                query_duration_millis=1,
                previous_page_token="",
            )
        ),
    )
    client = Client(organisation_id="org", token="tok")
    with patch("censys_platform.global_data.GlobalData.search", return_value=result):
        certs = list(client.fetch_certs(hashes={"MD5": "aaaa"}))
    assert certs == []
