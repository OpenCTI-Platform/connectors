"""Unit tests for ``teamt5_connector.BaseHandler``.

Covers the pagination / failure-handling contract of
``BaseHandler.retrieve_bundle_references``:

* the listing URL is built from the user-configured ``teamt5.api_base_url``
  (not the previously hard-coded ``api.threatvision.org``),
* successful pages accumulate until an empty page closes the loop,
* a transient failure increments the failure counter, which then resets
  to zero on the next successful page,
* after ``_MAX_PAGE_FAILURES`` consecutive failed pages the loop bails
  out so the next scheduled run can resume.
"""

from unittest.mock import Mock

from teamt5_connector.BaseHandler import _MAX_PAGE_FAILURES, BaseHandler


class _StubHandler(BaseHandler):
    """Concrete handler that maps every raw reference to itself."""

    name = "Stub"
    url_suffix = "/api/v2/stub"
    response_key = "stubs"

    def map_bundle_reference(self, raw_bundle_ref: dict) -> dict:
        return raw_bundle_ref

    def create_additional_objects(self, stix_content: list, bundle_ref: dict) -> list:
        return stix_content


def _make_handler(client, base_url="https://custom.teamt5.example.com/"):
    helper = Mock()
    helper.connector_logger = Mock()
    config = Mock()
    config.teamt5.api_base_url = base_url
    author = {"id": "identity--author"}
    tlp_ref = {"id": "marking-definition--tlp"}
    return _StubHandler(
        client=client,
        helper=helper,
        config=config,
        author=author,
        tlp_ref=tlp_ref,
    )


class TestRetrieveBundleReferencesURLConstruction:
    def test_uses_configured_api_base_url(self):
        """The listing URL must respect the user-configured base URL."""
        client = Mock()
        client.request_data.return_value = {"success": True, "stubs": []}
        handler = _make_handler(client, base_url="https://private.teamt5.local/")

        handler.retrieve_bundle_references(last_run_timestamp=0)

        called_url = client.request_data.call_args_list[0].args[0]
        assert called_url == "https://private.teamt5.local/api/v2/stub"

    def test_strips_trailing_slash_on_base_url(self):
        """Trailing slash on the base URL must be normalised away."""
        client = Mock()
        client.request_data.return_value = {"success": True, "stubs": []}
        handler = _make_handler(client, base_url="https://private.teamt5.local///")

        handler.retrieve_bundle_references(last_run_timestamp=0)

        called_url = client.request_data.call_args_list[0].args[0]
        assert called_url == "https://private.teamt5.local/api/v2/stub"


class TestRetrieveBundleReferencesPagination:
    def test_successful_pagination_across_pages(self):
        """Multiple full pages accumulate, an empty page closes the loop."""
        client = Mock()
        client.request_data.side_effect = [
            {"success": True, "stubs": [{"id": 1}, {"id": 2}]},
            {"success": True, "stubs": [{"id": 3}]},
            {"success": True, "stubs": []},
        ]
        handler = _make_handler(client)

        refs = handler.retrieve_bundle_references(last_run_timestamp=1700000000)

        assert refs == [{"id": 1}, {"id": 2}, {"id": 3}]
        assert client.request_data.call_count == 3
        offsets = [
            call.args[1]["offset"] for call in client.request_data.call_args_list
        ]
        assert offsets == [0, 2, 3]
        for call in client.request_data.call_args_list:
            assert call.args[1]["date[from]"] == 1700000000

    def test_transient_failure_then_recovery_resets_counter(self):
        """A successful page after a failure must reset the failure counter."""
        client = Mock()
        client.request_data.side_effect = [
            {"success": False},
            {"success": True, "stubs": [{"id": 1}]},
            {"success": True, "stubs": []},
        ]
        handler = _make_handler(client)

        refs = handler.retrieve_bundle_references(last_run_timestamp=0)

        assert refs == [{"id": 1}]
        assert client.request_data.call_count == 3

    def test_none_response_counts_as_failure(self):
        """``client.request_data`` returning ``None`` (transport error) is a failure page."""
        client = Mock()
        client.request_data.side_effect = [
            None,
            {"success": True, "stubs": []},
        ]
        handler = _make_handler(client)

        refs = handler.retrieve_bundle_references(last_run_timestamp=0)

        assert refs == []
        assert client.request_data.call_count == 2


class TestRetrieveBundleReferencesMaxFailuresAbort:
    def test_bails_after_consecutive_failures(self):
        """After _MAX_PAGE_FAILURES failed pages the loop exits."""
        client = Mock()
        client.request_data.side_effect = [
            {"success": False} for _ in range(_MAX_PAGE_FAILURES)
        ]
        handler = _make_handler(client)

        refs = handler.retrieve_bundle_references(last_run_timestamp=0)

        assert refs == []
        assert client.request_data.call_count == _MAX_PAGE_FAILURES
        handler.helper.connector_logger.error.assert_called_once()

    def test_bails_after_consecutive_none_responses(self):
        """``None`` responses also count toward the cap."""
        client = Mock()
        client.request_data.side_effect = [None for _ in range(_MAX_PAGE_FAILURES)]
        handler = _make_handler(client)

        refs = handler.retrieve_bundle_references(last_run_timestamp=0)

        assert refs == []
        assert client.request_data.call_count == _MAX_PAGE_FAILURES
        handler.helper.connector_logger.error.assert_called_once()
