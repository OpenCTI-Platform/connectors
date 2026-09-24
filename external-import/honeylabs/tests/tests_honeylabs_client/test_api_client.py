"""How the client follows the TAXII envelope."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from honeylabs_client.api_client import HoneyLabsTaxiiClient, TaxiiPaginationError

INDICATOR = {
    "type": "indicator",
    "id": "indicator--0d0c6a3e-9d2e-5e3b-9a3e-2b3f1c2d3e4f",
    "created": "2026-09-05T14:26:50.000Z",
    "modified": "2026-09-24T04:57:26.000Z",
    "name": "Exploiter: 192.0.2.10",
    "pattern": "[ipv4-addr:value = '192.0.2.10']",
    "pattern_type": "stix",
    "valid_from": "2026-09-05T14:26:50.000Z",
}


def _response(body: dict, date_added_last: str | None) -> MagicMock:
    r = MagicMock()
    r.ok = True
    r.status_code = 200
    r.headers = {"Content-Type": "application/taxii+json;version=2.1"}
    if date_added_last:
        r.headers["X-TAXII-Date-Added-Last"] = date_added_last
    r.json.return_value = body
    return r


def _client(responses: list[MagicMock]) -> HoneyLabsTaxiiClient:
    c = HoneyLabsTaxiiClient(
        api_root="https://honeylabs.test/taxii2/api/",
        api_key="hlk_test",
        logger=MagicMock(),
    )
    c._raw_request = MagicMock(side_effect=responses)
    return c


def test_authenticates_as_taxii_with_basic_auth():
    c = _client([])
    assert c.session_headers["Authorization"] == "Basic dGF4aWk6aGxrX3Rlc3Q="
    assert c.session_headers["Accept"].startswith("application/taxii+json")


def test_follows_next_with_only_the_cursor_and_reports_the_server_date_added():
    c = _client(
        [
            _response(
                {"more": True, "next": "500", "objects": [INDICATOR]},
                "2026-09-24T05:00:00.000Z",
            ),
            _response(
                {"more": False, "objects": [INDICATOR, {"type": "relationship"}]},
                "2026-09-24T06:00:00.000Z",
            ),
        ]
    )
    since = datetime(2026, 9, 17, tzinfo=timezone.utc)
    pages = list(c.iter_objects("attackers", since, 500))

    assert [len(p.objects) for p in pages] == [1, 1]
    assert [p.date_added_last for p in pages] == [
        datetime(2026, 9, 24, 5, 0, tzinfo=timezone.utc),
        datetime(2026, 9, 24, 6, 0, tzinfo=timezone.utc),
    ]
    first, second = c._raw_request.call_args_list
    assert first.kwargs["params"] == {
        "limit": 500,
        "added_after": "2026-09-17T00:00:00.000Z",
    }
    assert second.kwargs["params"] == {"next": "500"}, (
        "a follow-up request carries the opaque cursor only; "
        "the original filters are already part of it"
    )


def test_more_without_a_cursor_raises_instead_of_ending_the_import():
    c = _client([_response({"more": True, "objects": [INDICATOR]}, None)])
    gen = c.iter_objects("attackers", None, 500)
    first = next(gen)
    assert len(first.objects) == 1
    with pytest.raises(TaxiiPaginationError):
        next(gen)
