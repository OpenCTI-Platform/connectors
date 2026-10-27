import datetime
from queue import Queue
from types import SimpleNamespace
from unittest.mock import MagicMock

from intel471.streams.verity471.base import FILTER_MIGRATION_MARGIN_MS
from intel471.streams.verity471.credentials import Verity471CredentialsStream

INITIAL_HISTORY_MILLIS = 1696156471000  # 2023-10-01


class _DummyEmptyBundle(Exception):
    """Stand-in for the backend's EmptyBundle; never raised in these tests."""


def _build_credentials_stream(
    backend_name, enable_plain_password, state=None, affiliation_group=None
):
    """
    Build a credentials stream wired to a fully mocked client so `get_bundles()` can be
    exercised end to end: the first API call returns one credential, the second returns
    an empty page to terminate the loop. `_get_state`/`_set_state` are served from an
    in-memory dict to bypass the queue-based state handler that runs in the connector.
    The returned `settings_class` is the mock used in place of `STIXMapperSettings`, so
    tests can assert what the stream passed to it.
    """
    state = {} if state is None else state
    client_wrapper = MagicMock()
    client_wrapper.backend_name = backend_name
    client_wrapper.empty_bundle_exception = _DummyEmptyBundle
    client_wrapper.auth_exceptions = (_DummyEmptyBundle,)  # never matches here
    settings_class = MagicMock(name="STIXMapperSettings")
    client_wrapper.stix_mapper_settings_class = settings_class

    api_instance = client_wrapper.module.CredentialsApi.return_value
    nonempty = SimpleNamespace(
        credentials=[SimpleNamespace(id="cred--1")],
        cursor_next="c1",
        to_stix=MagicMock(return_value=SimpleNamespace(objects=[object()])),
    )
    empty = SimpleNamespace(credentials=[], cursor_next="c1")
    api_instance.get_credentials_stream.side_effect = [nonempty, empty]

    config_kwargs = {"enable_credentials_plain_password": enable_plain_password}
    if affiliation_group is not None:
        config_kwargs["affiliation_group"] = affiliation_group
    connector_config = SimpleNamespace(**config_kwargs)
    stream = Verity471CredentialsStream(
        client_wrapper,
        MagicMock(),  # helper
        Queue(),
        Queue(),
        initial_history=INITIAL_HISTORY_MILLIS,
        connector_config=connector_config,
    )
    stream._get_state = lambda key: state.get(key)
    stream._set_state = lambda key, value: state.__setitem__(key, value)
    return stream, settings_class, nonempty


def test_credentials_stream_class_attributes_and_api_kwargs():
    """The stream targets the Verity471 credentials endpoint with cursor paging."""
    stream, _, _ = _build_credentials_stream("verity471", False)

    assert stream.label == "credentials"
    assert stream.group_label == "credentials"
    assert stream.api_payload_objects_key == "credentials"
    assert stream.api_class_name == "CredentialsApi"
    assert stream.api_method_name == "get_credentials_stream"

    kwargs = stream._get_api_kwargs(cursor="x")
    assert kwargs["cursor"] == "x"
    assert kwargs["size"] == 100
    assert "var_from" in kwargs


def test_plain_password_flag_enabled_is_passed_to_verity_settings():
    """`enable_credentials_plain_password=True` reaches the Verity STIXMapperSettings."""
    stream, settings_class, response = _build_credentials_stream("verity471", True)

    bundles = list(stream.get_bundles())

    assert bundles == [response.to_stix.return_value]
    kwargs = settings_class.call_args.kwargs
    assert kwargs["credentials_include_plain_password"] is True
    assert kwargs["report_full_content"] is True


def test_plain_password_flag_defaults_off_for_verity():
    """With the flag off, the Verity settings withhold the cleartext password."""
    stream, settings_class, _ = _build_credentials_stream("verity471", False)

    list(stream.get_bundles())

    assert (
        settings_class.call_args.kwargs["credentials_include_plain_password"] is False
    )


def test_plain_password_flag_not_passed_for_titan():
    """
    Titan's STIXMapperSettings has no credentials field, so the core base must not pass
    it for the titan backend (guards the Verity-only conditional in `get_bundles`).
    """
    stream, settings_class, _ = _build_credentials_stream("titan", True)

    list(stream.get_bundles())

    assert "credentials_include_plain_password" not in settings_class.call_args.kwargs


def test_affiliation_group_filter_passed_to_api_kwargs():
    """A configured `affiliation_group` is sent to the API comma-joined."""
    stream, _, _ = _build_credentials_stream(
        "verity471", False, affiliation_group=["my_employees", "my_customers"]
    )

    kwargs = stream._get_api_kwargs(cursor="x")

    assert kwargs["affiliation_group"] == "my_employees,my_customers"
    assert kwargs["cursor"] == "x"
    assert "var_from" in kwargs and "size" in kwargs


def test_affiliation_group_filter_omitted_when_empty():
    """An empty `affiliation_group` adds no filter parameter."""
    stream, _, _ = _build_credentials_stream("verity471", False, affiliation_group=[])

    assert "affiliation_group" not in stream._get_api_kwargs(cursor=None)


def test_affiliation_group_filter_tolerates_missing_config_field():
    """A config without the `affiliation_group` attribute adds no filter parameter."""
    stream, _, _ = _build_credentials_stream("verity471", False)

    assert "affiliation_group" not in stream._get_api_kwargs(cursor=None)


def test_changed_affiliation_group_discards_cursor_and_reanchors():
    """
    Changing `affiliation_group` invalidates the Verity471 cursor, so the stream drops
    it and re-anchors the from-date to the last processed credential minus the margin.
    """
    lastseen = 1_700_000_000_000
    old_initdate = 1_690_000_000_000
    state = {
        "credentials_cursor_v471": "cur1",
        "credentials_filters_v471": "stale-fingerprint",
        "credentials_lastseen_v471": lastseen,
        "credentials_initdate_v471": old_initdate,
    }
    stream, _, _ = _build_credentials_stream(
        "verity471", False, state=state, affiliation_group=["my_employees"]
    )

    assert stream._get_cursor() is None
    assert state["credentials_cursor_v471"] is None
    assert state["credentials_initdate_v471"] == lastseen - FILTER_MIGRATION_MARGIN_MS
    assert state["credentials_filters_v471"] == stream._filters_fingerprint()
    stream.helper.log_warning.assert_called_once()


def test_changed_affiliation_group_after_failed_first_request_keeps_initdate():
    """
    If the first request failed (e.g. no Credentials API access yet), a fingerprint and
    from-date are stored but no cursor or last-seen timestamp. Changing
    `affiliation_group` before retrying must keep the original from-date.
    """
    old_initdate = 1_690_000_000_000
    state = {
        "credentials_filters_v471": "stale-fingerprint",
        "credentials_initdate_v471": old_initdate,
    }
    stream, _, _ = _build_credentials_stream(
        "verity471", False, state=state, affiliation_group=["my_employees"]
    )

    assert stream._get_cursor() is None
    assert state["credentials_initdate_v471"] == old_initdate
    assert state["credentials_filters_v471"] == stream._filters_fingerprint()


def test_unchanged_affiliation_group_keeps_cursor():
    """An unchanged filter set leaves the stored cursor in place."""
    state = {"credentials_cursor_v471": "cur1"}
    stream, _, _ = _build_credentials_stream(
        "verity471", False, state=state, affiliation_group=["my_employees"]
    )
    state["credentials_filters_v471"] = stream._filters_fingerprint()

    assert stream._get_cursor() == "cur1"
    assert state["credentials_cursor_v471"] == "cur1"


def test_lastseen_tracks_last_updated_ts_string_and_persists():
    """
    The high-water mark is read from each credential's `last_updated_ts`, which the API
    returns as a string (epoch milliseconds or ISO-8601); both are normalized to ms.
    """
    state = {}
    stream, _, _ = _build_credentials_stream("verity471", False, state=state)
    api_response = SimpleNamespace(
        credentials=[
            SimpleNamespace(last_updated_ts="1696156471000"),  # epoch ms string
            SimpleNamespace(last_updated_ts="2023-10-02T00:00:00Z"),  # ISO-8601
        ],
        cursor_next="next-cur",
    )

    assert stream._get_cursor_value(api_response) == "next-cur"
    expected = int(
        datetime.datetime(2023, 10, 2, tzinfo=datetime.UTC).timestamp() * 1000
    )
    assert stream._lastseen_ms == expected

    stream._update_cursor("next-cur")
    assert state["credentials_lastseen_v471"] == expected
    assert state["credentials_cursor_v471"] == "next-cur"
