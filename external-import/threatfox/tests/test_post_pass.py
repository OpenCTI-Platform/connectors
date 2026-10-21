"""Tests for ThreatFox's post-ingestion API pass.

Covers _resolve_via_indicator(), _read_observable_by_stix_id(),
_find_observable_id(), and _attach_external_refs_to_observables(). These
methods only talk to self.helper.api, so a bare ThreatFox instance built via
__new__() with a MagicMock helper is enough -- no live OpenCTI instance or
__init__ (which does talk to one) is needed.
"""

from unittest.mock import MagicMock

from src.__main__ import ThreatFox


def _connector() -> ThreatFox:
    connector = ThreatFox.__new__(ThreatFox)
    connector.identity = {"id": "identity--internal-0000-0000-000000000000"}
    connector.identity_id = "identity--d7f1c1a0-0000-4000-8000-000000000000"
    connector._pending_observables = []
    connector._cache_ext_ref_ids = {}
    connector.helper = MagicMock()
    return connector


class TestResolveViaIndicator:
    def test_finds_via_from_id(self):
        connector = _connector()
        connector.helper.api.stix_core_relationship.list.return_value = [
            {"to": {"id": "observable-internal-id"}}
        ]

        assert connector._resolve_via_indicator("indicator-id") == (
            "observable-internal-id"
        )

    def test_falls_back_to_from_or_to_id(self):
        connector = _connector()
        connector.helper.api.stix_core_relationship.list.side_effect = [
            [],
            [{"to": {"id": "observable-internal-id-2"}}],
        ]

        assert connector._resolve_via_indicator("indicator-id") == (
            "observable-internal-id-2"
        )

    def test_returns_none_when_nothing_found(self):
        connector = _connector()
        connector.helper.api.stix_core_relationship.list.return_value = []

        assert connector._resolve_via_indicator("indicator-id") is None

    def test_swallows_exceptions_and_returns_none(self):
        connector = _connector()
        connector.helper.api.stix_core_relationship.list.side_effect = RuntimeError(
            "boom"
        )

        assert connector._resolve_via_indicator("indicator-id") is None


class TestReadObservableByStixId:
    def test_returns_internal_id(self):
        connector = _connector()
        connector.helper.api.stix_cyber_observable.read.return_value = {
            "id": "internal-id"
        }

        assert connector._read_observable_by_stix_id("stix-id") == "internal-id"

    def test_returns_none_when_missing(self):
        connector = _connector()
        connector.helper.api.stix_cyber_observable.read.return_value = None

        assert connector._read_observable_by_stix_id("stix-id") is None

    def test_swallows_exceptions(self):
        connector = _connector()
        connector.helper.api.stix_cyber_observable.read.side_effect = RuntimeError(
            "boom"
        )

        assert connector._read_observable_by_stix_id("stix-id") is None


class TestFindObservableId:
    def test_finds_stixfile_by_hash_field_on_first_attempt(self, monkeypatch):
        monkeypatch.setattr("src.__main__.time.sleep", lambda *_a, **_k: None)
        connector = _connector()
        connector.helper.api.stix_cyber_observable.read.return_value = {
            "id": "found-id"
        }

        result = connector._find_observable_id(
            "StixFile", "d41d8cd98f00b204e9800998ecf8427e", "hashes.MD5"
        )

        assert result == "found-id"

    def test_finds_url_trailing_slash_variant_via_list_fallback(self, monkeypatch):
        monkeypatch.setattr("src.__main__.time.sleep", lambda *_a, **_k: None)
        connector = _connector()
        connector.helper.api.stix_cyber_observable.read.side_effect = RuntimeError(
            "not supported"
        )
        connector.helper.api.stix_cyber_observable.list.return_value = [
            {"id": "found-via-list"}
        ]

        result = connector._find_observable_id("Url", "http://bad.example.com/", None)

        assert result == "found-via-list"

    def test_finds_domain_case_insensitive_variant(self, monkeypatch):
        monkeypatch.setattr("src.__main__.time.sleep", lambda *_a, **_k: None)
        connector = _connector()
        connector.helper.api.stix_cyber_observable.read.return_value = None
        connector.helper.api.stix_cyber_observable.list.return_value = [
            {"id": "found-domain"}
        ]

        result = connector._find_observable_id("Domain-Name", "Bad.Example.com", None)

        assert result == "found-domain"

    def test_ipv4_not_found_returns_none_after_retries(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(
            "src.__main__.time.sleep", lambda secs, *a, **k: sleeps.append(secs)
        )
        connector = _connector()
        connector.helper.api.stix_cyber_observable.read.return_value = None
        connector.helper.api.stix_cyber_observable.list.return_value = []

        result = connector._find_observable_id(
            "IPv4-Addr", "1.2.3.4", None, max_attempts=2, initial_sleep=0.01
        )

        assert result is None
        assert len(sleeps) == 2


class TestAttachExternalRefsToObservables:
    def test_no_pending_observables_logs_and_returns(self):
        connector = _connector()

        connector._attach_external_refs_to_observables()

        connector.helper.log_info.assert_any_call(
            "[ThreatFox] post-pass: no pending observables to update"
        )

    def test_attaches_refs_and_creates_malware_relationship(self):
        connector = _connector()
        connector._pending_observables = [
            {
                "entity_type": "Domain-Name",
                "value": "bad.example.com",
                "hash_field": None,
                "urls": ["https://threatfox.abuse.ch/ioc/1/"],
                "indicator_id": None,
                "stix_id": "domain-name--0000",
                "malware_stix_id": "malware--0000",
                "confidence": 75,
            }
        ]
        connector.helper.api.stix_cyber_observable.read.return_value = {
            "id": "observable-internal-id"
        }
        connector.helper.api.external_reference.create.return_value = {
            "id": "ext-ref-id"
        }
        connector.helper.api.malware.read.return_value = {"id": "malware-internal-id"}

        connector._attach_external_refs_to_observables()

        connector.helper.api.stix_cyber_observable.add_external_reference.assert_called_once_with(
            id="observable-internal-id", external_reference_id="ext-ref-id"
        )
        connector.helper.api.stix_core_relationship.create.assert_called_once_with(
            fromId="observable-internal-id",
            toId="malware-internal-id",
            relationship_type="related-to",
            createdBy="identity--internal-0000-0000-000000000000",
            confidence=75,
        )
        assert connector._cache_ext_ref_ids["https://threatfox.abuse.ch/ioc/1/"] == (
            "ext-ref-id"
        )

    def test_falls_back_to_plural_attach_method(self):
        connector = _connector()
        connector._pending_observables = [
            {
                "entity_type": "Url",
                "value": "http://bad.example.com/x",
                "hash_field": None,
                "urls": ["https://threatfox.abuse.ch/ioc/2/"],
                "indicator_id": None,
                "stix_id": "url--0000",
                "malware_stix_id": None,
                "confidence": None,
            }
        ]
        connector.helper.api.stix_cyber_observable.read.return_value = {
            "id": "observable-internal-id"
        }
        connector.helper.api.external_reference.create.return_value = {
            "id": "ext-ref-id"
        }
        connector.helper.api.stix_cyber_observable.add_external_reference.side_effect = RuntimeError(
            "unsupported"
        )

        connector._attach_external_refs_to_observables()

        connector.helper.api.stix_cyber_observable.add_external_references.assert_called_once_with(
            id="observable-internal-id", external_references_ids=["ext-ref-id"]
        )

    def test_observable_not_found_is_logged_and_skipped(self, monkeypatch):
        monkeypatch.setattr("src.__main__.time.sleep", lambda *_a, **_k: None)
        connector = _connector()
        connector._pending_observables = [
            {
                "entity_type": "IPv4-Addr",
                "value": "1.2.3.4",
                "hash_field": None,
                "urls": [],
                "indicator_id": None,
                "stix_id": None,
                "malware_stix_id": None,
                "confidence": None,
            }
        ]
        connector.helper.api.stix_cyber_observable.read.return_value = None
        connector.helper.api.stix_cyber_observable.list.return_value = []

        connector._attach_external_refs_to_observables()

        assert connector.helper.log_warning.call_args_list
        connector.helper.api.stix_core_relationship.create.assert_not_called()

    def test_missing_malware_logs_warning_without_creating_relationship(self):
        connector = _connector()
        connector._pending_observables = [
            {
                "entity_type": "Domain-Name",
                "value": "bad.example.com",
                "hash_field": None,
                "urls": [],
                "indicator_id": None,
                "stix_id": "domain-name--0000",
                "malware_stix_id": "malware--missing",
                "confidence": None,
            }
        ]
        connector.helper.api.stix_cyber_observable.read.return_value = {
            "id": "observable-internal-id"
        }
        connector.helper.api.malware.read.return_value = None

        connector._attach_external_refs_to_observables()

        connector.helper.api.stix_core_relationship.create.assert_not_called()
