"""Regression tests for ``wrapper_paginate`` stopping conditions.

API errors are raised by ``handle_api_error`` before the paginator sees the
response (see ``test_connector_api_error.py``). The paginator itself only has
to stop when a response carries no ``meta.pagination``, instead of raising
``KeyError`` or re-querying the same offset forever.
"""

import crowdstrike_feeds_services.utils as utils


def test_paginate_stops_on_response_without_pagination():
    calls = []

    @utils.paginate
    def query(*args, limit=25, offset=0, **kwargs):
        calls.append(offset)
        return {"meta": {"trace_id": "test-trace-id"}}

    assert list(query()) == []
    assert calls == [0]


def test_paginate_yields_last_page_without_pagination_then_stops():
    calls = []

    @utils.paginate
    def query(*args, limit=25, offset=0, **kwargs):
        calls.append(offset)
        return {"resources": [{"id": 1}]}

    assert list(query()) == [[{"id": 1}]]
    assert calls == [0]
