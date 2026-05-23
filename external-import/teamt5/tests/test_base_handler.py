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

from types import SimpleNamespace
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
    # ``BaseHandler._append_author_and_tlp`` accesses ``self.author.id`` /
    # ``self.tlp_ref.id`` (matching the stix2-object contract used in
    # production by ``TeamT5Connector``). ``SimpleNamespace`` is the
    # minimal stand-in that supports attribute access.
    author = SimpleNamespace(id="identity--author")
    tlp_ref = SimpleNamespace(id="marking-definition--tlp")
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


class TestAppendAuthorAndTlp:
    """Pin the ``_append_author_and_tlp`` field-mapping contract.

    STIX 2.1 splits objects into SDOs/SROs, SCOs, and SMOs:

    * SDOs/SROs accept the standard ``created_by_ref``.
    * SCOs (``ipv4-addr``, ``domain-name``, ``url``, …) reject
      ``created_by_ref``; OpenCTI carries the same concept via the
      ``x_opencti_created_by_ref`` custom property.
    * SMOs — ``marking-definition`` is the only one we encounter
      upstream here — accept neither ``created_by_ref`` nor
      ``object_marking_refs``; tagging the bundle's own TLP onto a
      marking-definition would also produce a self-referential
      relationship when the upstream payload already includes the
      same marking SDO.

    These tests assert each branch so a future refactor cannot
    silently regress the SCO / SMO handling.
    """

    def _handler(self):
        return _make_handler(Mock())

    def test_sdo_gets_standard_created_by_ref(self):
        handler = self._handler()
        out = handler._append_author_and_tlp(
            {"type": "indicator", "id": "indicator--x"}
        )

        assert out["created_by_ref"] == "identity--author"
        assert "x_opencti_created_by_ref" not in out
        assert out["object_marking_refs"] == ["marking-definition--tlp"]

    def test_sco_gets_x_opencti_created_by_ref(self):
        handler = self._handler()
        out = handler._append_author_and_tlp({"type": "ipv4-addr", "value": "1.2.3.4"})

        assert out["x_opencti_created_by_ref"] == "identity--author"
        assert "created_by_ref" not in out
        assert out["object_marking_refs"] == ["marking-definition--tlp"]

    def test_marking_definition_is_skipped_entirely(self):
        """SMO branch: neither field is touched on a ``marking-definition``.

        Tagging the bundle's own TLP onto a ``marking-definition`` is
        invalid STIX 2.1 and would produce a self-reference when the
        upstream bundle already carries the same marking SDO the
        connector is about to append.
        """
        handler = self._handler()
        marking = {
            "type": "marking-definition",
            "id": "marking-definition--tlp",
            "definition_type": "statement",
        }

        out = handler._append_author_and_tlp(dict(marking))

        assert out == marking
        assert "created_by_ref" not in out
        assert "x_opencti_created_by_ref" not in out
        assert "object_marking_refs" not in out

    def test_existing_object_marking_refs_are_preserved(self):
        handler = self._handler()
        out = handler._append_author_and_tlp(
            {
                "type": "indicator",
                "id": "indicator--x",
                "object_marking_refs": ["marking-definition--upstream"],
            }
        )

        assert out["object_marking_refs"] == [
            "marking-definition--upstream",
            "marking-definition--tlp",
        ]


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


class TestRetrieveBundleReferencesAbortedFlag:
    """``handler.aborted`` reflects the success of the latest retrieval pass.

    The connector reads this flag in ``process_message`` to decide whether
    the persisted ``last_run`` cursor can be advanced — a stale ``True``
    from a previous-cycle bail-out would have silently held the cursor
    in place forever, so the flag is reset at the top of every retrieval
    pass and only set when ``_MAX_PAGE_FAILURES`` is actually hit.
    """

    def test_aborted_false_after_clean_run(self):
        client = Mock()
        client.request_data.return_value = {"success": True, "stubs": []}
        handler = _make_handler(client)

        handler.retrieve_bundle_references(last_run_timestamp=0)

        assert handler.aborted is False

    def test_aborted_true_after_max_failures(self):
        client = Mock()
        client.request_data.side_effect = [
            {"success": False} for _ in range(_MAX_PAGE_FAILURES)
        ]
        handler = _make_handler(client)

        handler.retrieve_bundle_references(last_run_timestamp=0)

        assert handler.aborted is True

    def test_aborted_resets_between_runs(self):
        """A clean run after a failed one must reset the flag."""
        client = Mock()
        # First run bails out — flag flips to True.
        client.request_data.side_effect = [
            {"success": False} for _ in range(_MAX_PAGE_FAILURES)
        ]
        handler = _make_handler(client)
        handler.retrieve_bundle_references(last_run_timestamp=0)
        assert handler.aborted is True

        # Second run with the same handler instance completes cleanly —
        # flag must reset (the connector re-uses the handler across
        # ``schedule_iso`` invocations, so a stale True would silently
        # freeze the cursor forever).
        client.request_data.side_effect = None
        client.request_data.return_value = {"success": True, "stubs": []}
        handler.retrieve_bundle_references(last_run_timestamp=0)
        assert handler.aborted is False


class TestRetrieveBundleReferencesUsesThrottle:
    """``request_data`` is called with ``throttle=True`` from the listing loop.

    The throttle is intentionally kept opt-in (it gates pagination only,
    not bundle downloads in ``push_objects``); pinning that the listing
    loop opts in here means a future refactor that removes the
    ``throttle=True`` kwarg on the listing call site will fail this
    test before silently re-introducing the rate-limit risk on tight
    pagination loops.
    """

    def test_listing_loop_passes_throttle_true(self):
        client = Mock()
        client.request_data.return_value = {"success": True, "stubs": []}
        handler = _make_handler(client)

        handler.retrieve_bundle_references(last_run_timestamp=0)

        # Every call to ``request_data`` from the listing loop must
        # opt into the throttle.
        for call in client.request_data.call_args_list:
            assert (
                call.kwargs.get("throttle") is True
            ), f"listing call missing throttle=True: {call}"


class TestPushObjectsPartialPushFlag:
    """``handler.partial_push`` reflects whether every retrieved bundle was pushed.

    Consumed by ``TeamT5Connector.process_message`` to decide whether the
    persisted ``last_run`` cursor can be advanced; a bundle that fell
    through a ``continue`` branch (missing ``stix_url`` / transport error
    / empty body) was skipped, not retried, so advancing past it would
    silently drop it on the next cycle.
    """

    def _make_handler_for_push(self, bundle_responses):
        client = Mock()
        # The first ``request_data`` call inside ``push_objects`` is for the
        # bundle download itself (one per bundle ref).
        client.request_data.side_effect = bundle_responses
        handler = _StubHandler(
            client=client,
            helper=Mock(),
            config=SimpleNamespace(
                teamt5=SimpleNamespace(api_base_url="https://example.invalid/")
            ),
            author=SimpleNamespace(id="identity--stub"),
            tlp_ref=SimpleNamespace(id="marking-definition--stub"),
        )
        handler.helper.stix2_create_bundle.return_value = "<bundle>"
        return handler

    def test_partial_push_false_when_every_bundle_lands(self):
        handler = self._make_handler_for_push(
            [
                {
                    "objects": [
                        {"type": "indicator", "id": "indicator--a"},
                    ]
                },
                {
                    "objects": [
                        {"type": "indicator", "id": "indicator--b"},
                    ]
                },
            ]
        )
        bundle_refs = [
            {"stix_url": "https://example.invalid/a", "created_at": 1700000000},
            {"stix_url": "https://example.invalid/b", "created_at": 1700000001},
        ]

        pushed = handler.push_objects(work_id="work--x", bundle_refs=bundle_refs)

        assert pushed == 2
        assert handler.partial_push is False

    def test_partial_push_true_when_some_bundles_skipped(self):
        # Mix of: missing ``stix_url`` (skipped before any client call),
        # transport-failed bundle download (None), valid bundle.
        handler = self._make_handler_for_push(
            [
                None,  # download failure for the second ref
                {
                    "objects": [
                        {"type": "indicator", "id": "indicator--ok"},
                    ]
                },
            ]
        )
        bundle_refs = [
            # Missing ``stix_url`` — skipped without consuming a side_effect entry.
            {"created_at": 1700000000},
            # Download fails — first side_effect entry consumed, returns None.
            {"stix_url": "https://example.invalid/fail", "created_at": 1700000001},
            # Download succeeds — second side_effect entry consumed.
            {"stix_url": "https://example.invalid/ok", "created_at": 1700000002},
        ]

        pushed = handler.push_objects(work_id="work--x", bundle_refs=bundle_refs)

        assert pushed == 1  # only the third one made it through
        assert handler.partial_push is True

    def test_partial_push_resets_between_calls(self):
        """A clean push after a failed one must reset the flag."""
        # First pass: one bundle skipped.
        handler = self._make_handler_for_push(
            [
                None,  # download failure
            ]
        )
        bundle_refs = [
            {"stix_url": "https://example.invalid/fail", "created_at": 1700000001},
        ]
        handler.push_objects(work_id="work--x", bundle_refs=bundle_refs)
        assert handler.partial_push is True

        # Second pass on the same handler instance with everything green.
        handler.client.request_data.side_effect = [
            {"objects": [{"type": "indicator", "id": "indicator--ok"}]},
        ]
        clean_refs = [
            {"stix_url": "https://example.invalid/ok", "created_at": 1700000002},
        ]
        handler.push_objects(work_id="work--y", bundle_refs=clean_refs)
        assert handler.partial_push is False

    def test_partial_push_false_when_only_missing_stix_url_refs_skipped(self):
        """Refs without ``stix_url`` are non-pushable, NOT partial failures.

        Pins the regression flagged by the Copilot review thread on
        ``BaseHandler.py:242``: the upstream TeamT5 listing can
        legitimately surface bundle references without a ``stix_url``
        (e.g. IOC bundle entries that have not been promoted to a
        downloadable STIX dump yet). Counting those as failures
        against the ``num_bundles_pushed < len(bundle_refs)``
        denominator would (a) treat every cycle that sees one of
        these refs as a partial failure, (b) freeze
        ``last_run`` in place forever in
        ``TeamT5Connector.process_message``, and (c) silently
        re-process every bundle on every subsequent run.
        ``partial_push`` is now computed against the count of refs
        that DID carry a ``stix_url`` (the connector's "pushable"
        set) so a listing dominated by non-pushable refs never
        freezes the cursor.
        """
        # Only the third ref carries a ``stix_url``; the other two
        # are non-pushable listing entries. Push side-effect therefore
        # only consumes one entry — the successful download for the
        # pushable ref.
        handler = self._make_handler_for_push(
            [
                {"objects": [{"type": "indicator", "id": "indicator--ok"}]},
            ]
        )
        bundle_refs = [
            {"created_at": 1700000000},  # no stix_url
            {"created_at": 1700000001},  # no stix_url
            {"stix_url": "https://example.invalid/ok", "created_at": 1700000002},
        ]

        pushed = handler.push_objects(work_id="work--x", bundle_refs=bundle_refs)

        assert pushed == 1
        # Only one ref was actually pushable, and it was pushed —
        # so this is a clean run and the cursor should be allowed
        # to advance.
        assert handler.partial_push is False

    def test_partial_push_false_when_every_ref_is_non_pushable(self):
        """A listing of only non-pushable refs is a clean run, not a failure.

        Edge case: the entire listing came back without ``stix_url``s.
        ``num_bundles_pushed = 0`` and ``pushable_refs = 0``, so the
        ``num_pushed < pushable_refs`` check evaluates ``0 < 0`` =
        False and the cursor is allowed to advance on the next
        cycle — exactly what we want, because none of those refs
        will ever be retryable through this code path. Logging the
        skip is enough; it is a listing-quality issue upstream, not
        a connector failure.
        """
        handler = self._make_handler_for_push([])
        bundle_refs = [
            {"created_at": 1700000000},
            {"created_at": 1700000001},
        ]

        pushed = handler.push_objects(work_id="work--x", bundle_refs=bundle_refs)

        assert pushed == 0
        assert handler.partial_push is False

    def test_partial_push_true_when_pushable_ref_download_fails(self):
        """Transport / decode failures on a *pushable* ref still hold the cursor.

        Mirrors the Copilot review intent: refs the connector
        attempted but failed to download must still be retried on
        the next cycle, so ``partial_push`` flips to ``True`` and
        the persisted ``last_run`` is held at the previous value.
        Refs without ``stix_url`` (non-pushable, see the test above)
        are excluded from the denominator, but a transport failure
        on a downloadable ``stix_url`` keeps the original
        retry semantics.
        """
        handler = self._make_handler_for_push(
            [
                None,  # download failure for the second pushable ref
                {"objects": [{"type": "indicator", "id": "indicator--ok"}]},
            ]
        )
        bundle_refs = [
            {"created_at": 1700000000},  # non-pushable, excluded
            {"stix_url": "https://example.invalid/fail", "created_at": 1700000001},
            {"stix_url": "https://example.invalid/ok", "created_at": 1700000002},
        ]

        pushed = handler.push_objects(work_id="work--x", bundle_refs=bundle_refs)

        assert pushed == 1
        # Of the two pushable refs only one made it through —
        # partial failure, hold the cursor.
        assert handler.partial_push is True
