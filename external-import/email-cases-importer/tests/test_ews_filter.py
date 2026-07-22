"""Regression test: EWS client must use a valid exchangelib filter.

`Message.sender` is a single-valued Mailbox field — exchangelib does NOT accept
nested lookups like `sender__email_address`, and the older `from_emailaddresses`
path was never valid either. Both raise InvalidField at query time. The
supported form is `sender=Mailbox(email_address=...)`.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("exchangelib")

from exchangelib import Mailbox  # noqa: E402

from email_client.ews_client import EwsClient  # noqa: E402


def _make_client_with_fake_inbox():
    """Build an EwsClient bypassing real connect(); wire up a mock inbox that
    records the filter kwargs it receives."""
    client = EwsClient(
        server="",
        username="u@example.com",
        password="p",
        auth_type="NTLM",
    )

    # Chainable mock: qs = inbox.filter(...).filter(...).order_by(...)[:n]
    qs = MagicMock()
    qs.filter.return_value = qs
    qs.order_by.return_value = qs
    qs.__getitem__.return_value = []  # slice [:max_results] -> empty list

    inbox = MagicMock()
    inbox.filter.return_value = qs

    client._account = SimpleNamespace(inbox=inbox)
    return client, inbox, qs


def test_sender_filter_uses_mailbox_object():
    client, inbox, _qs = _make_client_with_fake_inbox()
    client.fetch_emails(sender="alerts@vendor.com", max_results=5)

    # Must be filter(sender=Mailbox(email_address="alerts@vendor.com"))
    inbox.filter.assert_called_once()
    kwargs = inbox.filter.call_args.kwargs
    assert (
        "sender" in kwargs
    ), f"expected filter kwarg 'sender', got keys: {list(kwargs.keys())}"
    passed = kwargs["sender"]
    assert isinstance(
        passed, Mailbox
    ), f"expected Mailbox instance, got {type(passed).__name__}"
    assert passed.email_address == "alerts@vendor.com"

    # Regression: neither of the previously-broken field paths may appear
    assert "from_emailaddresses" not in kwargs
    assert "from_emailaddresses__contains" not in kwargs
    assert "sender__email_address" not in kwargs


def test_since_filter_passed_as_tz_aware_datetime():
    client, _inbox, qs = _make_client_with_fake_inbox()
    since = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)

    client.fetch_emails(sender="a@b.com", since=since, max_results=5)

    # qs.filter should have been called once for the since clause
    qs.filter.assert_called_once()
    kwargs = qs.filter.call_args.kwargs
    assert "datetime_received__gte" in kwargs
    passed = kwargs["datetime_received__gte"]
    # Must be a tz-aware datetime (UTC)
    assert passed.tzinfo is not None
    assert passed.utcoffset().total_seconds() == 0


def test_no_since_means_no_second_filter_call():
    client, _inbox, qs = _make_client_with_fake_inbox()
    client.fetch_emails(sender="a@b.com", max_results=5)
    # Only the sender filter — no since filter applied
    qs.filter.assert_not_called()
