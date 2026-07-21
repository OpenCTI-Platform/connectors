"""Regression tests for ``wrapper_paginate`` error logging.

FalconPy returns API errors as dicts (e.g. ``{"code": 400, "message": "..."}``),
and the ``errors`` payload may be a single dict rather than a list. These tests
guard against the original ``AttributeError: 'dict' object has no attribute
'message'`` crash and against a bare-dict payload being iterated by key.
"""

from unittest.mock import MagicMock

import crowdstrike_feeds_services.utils as utils


def _response(errors):
    # ``meta.pagination.total = 0`` makes ``_next_batch`` stop the paginator
    # after a single iteration.
    return {
        "errors": errors,
        "meta": {"pagination": {"limit": 25, "offset": 0, "total": 0}},
        "resources": [],
    }


def _error_log_calls(monkeypatch, errors):
    mock_logger = MagicMock()
    monkeypatch.setattr(utils, "logger", mock_logger)

    @utils.paginate
    def query(*args, limit=25, offset=0, **kwargs):
        return _response(errors)

    list(query())

    return [
        call
        for call in mock_logger.error.call_args_list
        if call.args and call.args[0] == "Error: %s (code: %s)"
    ]


def test_paginate_logs_list_of_dict_errors(monkeypatch):
    calls = _error_log_calls(monkeypatch, [{"code": 400, "message": "boom"}])
    assert any(c.args[1] == "boom" and c.args[2] == 400 for c in calls)


def test_paginate_normalizes_single_dict_error(monkeypatch):
    # A bare dict (not wrapped in a list) must not be iterated by key.
    calls = _error_log_calls(monkeypatch, {"code": 500, "message": "oops"})
    assert any(c.args[1] == "oops" and c.args[2] == 500 for c in calls)


def test_paginate_falls_back_to_raw_error_when_no_message(monkeypatch):
    calls = _error_log_calls(monkeypatch, [{"code": 502}])
    assert any(c.args[1] == {"code": 502} and c.args[2] == 502 for c in calls)


def test_paginate_handles_non_dict_error_entries(monkeypatch):
    calls = _error_log_calls(monkeypatch, ["plain string error"])
    assert any(c.args[1] == "plain string error" and c.args[2] is None for c in calls)
