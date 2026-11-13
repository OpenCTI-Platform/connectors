"""Url observable detonation: refusals, query stripping, SDK submission, results.

Sandbox task shapes come from the SDK's own ``SandboxTask`` resource, fed with
real past URL tasks fetched READ ONLY with ``sandbox_task_status`` on
2026-11-10 (nothing was submitted to record them):

- fixtures/sandbox_url_task_cape.json: CAPE, win-10-build-19041, SUCCEEDED
- fixtures/sandbox_url_task_triage.json: Triage, windows11-21h2-x64, SUCCEEDED
- fixtures/sandbox_url_task_cape_failed.json: CAPE, FAILED_REIMBURSED
"""

import copy
import hashlib
import json
import logging
import os
from unittest.mock import MagicMock, patch

import pytest
from connector import url_utils
from connector.polyswarm_client import PolySwarmAPIError, PolySwarmClient
from connector.stix_builder import StixBuilder
from polyswarm_api import exceptions as ps_exceptions
from polyswarm_api import resources
from pycti import MarkingDefinition, OpenCTIConnectorHelper

from tests.test_connector import make_connector

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
URL_ID = "url--00000000-0000-0000-0000-000000000001"
QUERY_URL = "https://example.com/download/payload.exe?token=SECRET123&user=bob#frag"
STRIPPED_URL = "https://example.com/download/payload.exe"
CAPE_VM = "win-10-build-19041"


def _fixture(name):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def _task(name):
    """Fixture parsed by the SDK's SandboxTask, returned as the client does (.json)."""
    return resources.SandboxTask(_fixture(name)).json


def _url_entity(value=QUERY_URL):
    return {"type": "url", "spec_version": "2.1", "id": URL_ID, "value": value}


def _opencti_url(value=QUERY_URL):
    return {"entity_type": "Url", "observable_value": value, "standard_id": URL_ID}


def _url_connector(**overrides):
    polyswarm = {
        "community": "acme-private",
        "allow_public_community": False,
        "sandbox_enabled": True,
        "sandbox_provider": "cape",
        "sandbox_url_send_query": False,
    }
    polyswarm.update(overrides)
    c = make_connector(polyswarm_overrides=polyswarm)
    c.helper.connect_scope = "Artifact,Url"
    c.polyswarm_client.get_provider_slugs = MagicMock(return_value=["cape", "triage"])
    c.polyswarm_client.get_url_vm_for_provider = MagicMock(return_value=CAPE_VM)
    c.polyswarm_client.submit_sandbox_url_async = MagicMock(return_value="task-1")
    c.polyswarm_client.get_sandbox_results = MagicMock(
        return_value=_task("sandbox_url_task_cape.json")
    )
    c.polyswarm_client.generate_pdf = MagicMock(return_value=b"%PDF-1.4")
    return c


def _logged(c):
    return " ".join(str(call) for call in c.helper.connector_logger.mock_calls)


# -- URL rules (same as the enrichment connector)


class TestUrlRules:
    @pytest.mark.parametrize(
        "url",
        [
            "http://10.0.0.1/a",
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.1.1/",
            "http://192.168.1.1/",
            "http://172.16.0.5/",
            "http://0.0.0.0/",
            "http://240.0.0.1/",
            "http://224.0.0.1/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[::ffff:10.0.0.1]/",
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f.0.0.1/",
            "http://localhost/",
            "http://intranet/",
            "http://files.local/x",
            "https://wiki.corp/x",
            "http://nas.home.arpa/",
            "http://app.internal/",
            "http://box.lan/",
            "http:///no-host",
            "",
        ],
    )
    def test_non_public_hosts_are_refused(self, url):
        assert url_utils.is_non_public_url(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            # Percent-encoded hosts (review threads 4528431174, 4528455047)
            "http://%31%32%37.0.0.1/",
            "http://%31%30.0.0.1/admin",
            "http://%6c%6f%63%61%6c%68%6f%73%74/",
            "http://example%2ecom/",
            # Full-width spellings of loopback, private and internal hosts
            "http://\uff11\uff12\uff17.\uff10.\uff10.\uff11/",
            "http://\uff11\uff10.\uff10.\uff10.\uff11/",
            "http://\uff11\uff10\uff0e0\uff0e0\uff0e1/",
            "http://wiki.c\uff4frp/",
            "http://\uff57\uff49\uff4b\uff49.\uff43\uff4f\uff52\uff50/",
            "http://localho\uff53t/",
            # Backslash in the authority (review thread 4528424208)
            "http://example.com\\@10.0.0.1/",
            "http://127.0.0.1\\example.com/",
            "http://localhost\\evil.com/",
            "http://10.0.0.1\\",
            "http:\\\\127.0.0.1\\x",
            # Not a valid IDNA name
            "http://\u00ad\u00ad/",
        ],
    )
    def test_encoded_and_unicode_hosts_are_refused(self, url):
        assert url_utils.is_non_public_url(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "http://b\u00fccher.de/",
            "http://ex\uff41mple.com/",
            "http://example.com/a\\b",
            "http://example.com/%41",
        ],
    )
    def test_unicode_public_hosts_and_path_escapes_are_allowed(self, url):
        assert url_utils.is_non_public_url(url) is False

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/a",
            "http://8.8.8.8/x",
            "https://[2606:4700:4700::1111]/",
            "example.com/path",
            QUERY_URL,
        ],
    )
    def test_public_hosts_are_allowed(self, url):
        assert url_utils.is_non_public_url(url) is False

    @pytest.mark.parametrize(
        "url",
        [
            "http://user:pass@example.com/",
            "http://example.com\\@10.0.0.1/",
            "http://example.com\\x@10.0.0.1/",
            "http://user@example.com/",
            "http://:pw@example.com/",
            "user:pass@example.com/path",
        ],
    )
    def test_userinfo_is_detected(self, url):
        assert url_utils.url_has_userinfo(url) is True

    def test_no_userinfo(self):
        assert url_utils.url_has_userinfo(QUERY_URL) is False

    def test_query_and_fragment_stripped_by_default(self):
        assert url_utils.url_for_submission(QUERY_URL) == STRIPPED_URL
        assert (
            url_utils.url_for_submission("example.com/p?a=1#f", False)
            == "example.com/p"
        )

    def test_query_kept_when_opted_in(self):
        assert url_utils.url_for_submission(QUERY_URL, True) == QUERY_URL

    def test_loggable_url_is_scheme_and_host(self):
        assert url_utils.loggable_url(QUERY_URL) == "https://example.com"
        assert url_utils.loggable_url("http://[2001:db8::1]/x?q=1") == (
            "http://[2001:db8::1]"
        )


# -- Refusals: a note, and no API call


class TestUrlRefusals:
    @pytest.mark.parametrize(
        "url, category",
        [
            (
                "http://user:pass@example.com/x?token=SECRET123",
                "Submission Refused: URL Contains Credentials",
            ),
            (
                "http://10.0.0.5/admin?token=SECRET123",
                "Submission Refused: Private or Internal Host",
            ),
            (
                "http://intranet/x?token=SECRET123",
                "Submission Refused: Private or Internal Host",
            ),
            (
                "http://%31%30.0.0.1/admin?token=SECRET123",
                "Submission Refused: Private or Internal Host",
            ),
            (
                "http://\uff11\uff12\uff17.\uff10.\uff10.\uff11/?token=SECRET123",
                "Submission Refused: Private or Internal Host",
            ),
            (
                "http://127.0.0.1\\example.com/?token=SECRET123",
                "Submission Refused: Private or Internal Host",
            ),
            (
                "http://example.com\\@10.0.0.1/?token=SECRET123",
                "Submission Refused: URL Contains Credentials",
            ),
            # "@" in the authority without a backslash
            (
                "http://example.com@10.0.0.1/?token=SECRET123",
                "Submission Refused: URL Contains Credentials",
            ),
            (
                "http://login.example.com@example.org/?token=SECRET123",
                "Submission Refused: URL Contains Credentials",
            ),
            ("", "No URL Value"),
        ],
    )
    def test_refused_without_api_call(self, url, category):
        c = _url_connector()
        result = c._enrich_url(URL_ID, _url_entity(url), _opencti_url(url), [])

        assert result["status"] == "error"
        assert c.polyswarm_client.mock_calls == []
        kwargs = c.stix_builder.create_error_note.call_args.kwargs
        assert kwargs["error_category"] == category
        assert kwargs["entity"]["id"] == URL_ID
        assert "SECRET123" not in _logged(c)

    def test_public_community_without_opt_in_is_refused(self):
        c = _url_connector(community="default", allow_public_community=False)
        result = c._enrich_url(URL_ID, _url_entity(), _opencti_url(), [])

        assert result["status"] == "error"
        assert "public community" in result["error"]
        assert c.polyswarm_client.mock_calls == []
        kwargs = c.stix_builder.create_error_note.call_args.kwargs
        assert kwargs["error_category"] == "Upload Refused: Public Community"

    def test_public_community_with_opt_in_is_submitted(self):
        c = _url_connector(community="default", allow_public_community=True)
        with patch("connector.polyswarm_connector.time.sleep"):
            c._enrich_url(URL_ID, _url_entity(), _opencti_url(), [])
        c.polyswarm_client.submit_sandbox_url_async.assert_called_once()

    def test_sandbox_disabled_is_refused(self):
        c = _url_connector(sandbox_enabled=False)
        result = c._enrich_url(URL_ID, _url_entity(), _opencti_url(), [])

        assert result["status"] == "error"
        assert c.polyswarm_client.mock_calls == []
        kwargs = c.stix_builder.create_error_note.call_args.kwargs
        assert kwargs["error_category"] == "Sandbox Disabled"

    @pytest.mark.parametrize(
        "markings, skipped",
        [
            (("TLP:RED",), True),
            (("TLP:GREEN", "TLP:RED"), True),
            (("TLP:AMBER+STRICT",), True),
            (("TLP:GREEN",), False),
            (("PAP:RED",), False),
            ((), False),
        ],
    )
    def test_tlp_check(self, markings, skipped):
        """pycti's real check_max_tlp, given one TLP name per marking (#7955)."""
        c = _url_connector()
        c.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
        c.max_tlp = "TLP:AMBER"
        opencti = _opencti_url()
        opencti["objectMarking"] = [
            {"definition_type": m.split(":")[0], "definition": m} for m in markings
        ]
        with patch("connector.polyswarm_connector.time.sleep"):
            result = c._enrich_url(URL_ID, _url_entity(), opencti, [_url_entity()])

        if skipped:
            assert result["status"] == "skipped"
            assert c.polyswarm_client.mock_calls == []
        else:
            assert result is None
            c.polyswarm_client.submit_sandbox_url_async.assert_called_once()

    @pytest.mark.parametrize(
        "tlp, skipped",
        [("TLP:RED", True), ("TLP:AMBER+STRICT", True), ("TLP:GREEN", False)],
    )
    def test_tlp_check_without_stix_objects(self, tlp, skipped):
        """An empty stix_objects list must not bypass the TLP limit (#8351)."""
        c = _url_connector()
        c.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
        c.max_tlp = "TLP:AMBER"
        opencti = _opencti_url()
        opencti["objectMarking"] = [{"definition_type": "TLP", "definition": tlp}]
        with patch("connector.polyswarm_connector.time.sleep"):
            result = c._enrich_url(URL_ID, _url_entity(), opencti, [])

        if skipped:
            assert result["status"] == "skipped"
            assert c.polyswarm_client.mock_calls == []
        else:
            assert result is None
            c.polyswarm_client.submit_sandbox_url_async.assert_called_once()

    def test_tlp_check_from_bundle_marking_refs(self):
        """A TLP marking only present in the bundle is still enforced."""
        c = _url_connector()
        c.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
        c.max_tlp = "TLP:AMBER"
        marking = {
            "type": "marking-definition",
            "id": "marking-definition--00000000-0000-4000-8000-000000000001",
            "name": "TLP:RED",
        }
        entity = _url_entity()
        entity["object_marking_refs"] = [marking["id"]]
        with patch("connector.polyswarm_connector.time.sleep"):
            result = c._enrich_url(URL_ID, entity, _opencti_url(), [entity, marking])

        assert result["status"] == "skipped"
        assert c.polyswarm_client.mock_calls == []

    @pytest.mark.parametrize(
        "marking, skipped",
        [
            # OpenCTI custom definition carrying only x_opencti_definition
            (
                {
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
                True,
            ),
            # Custom name, TLP in x_opencti_definition
            (
                {
                    "name": "Restricted",
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:RED",
                },
                True,
            ),
            # STIX 2.1 TLP form with no name
            ({"definition_type": "tlp", "definition": {"tlp": "red"}}, True),
            ({"definition_type": "tlp", "definition": {"tlp": "green"}}, False),
            # OpenCTI API shape: definition is the TLP name
            ({"definition_type": "TLP", "definition": "TLP:RED"}, True),
            ({"definition_type": "tlp", "definition": "TLP:AMBER+STRICT"}, True),
            ({"definition_type": "TLP", "definition": "TLP:GREEN"}, False),
            # Upper-case dict key
            ({"definition_type": "TLP", "definition": {"TLP": "red"}}, True),
            ({"name": "TLP:GREEN"}, False),
            ({"name": "PAP:RED"}, False),
        ],
    )
    def test_tlp_check_resolves_bundled_marking_shapes(self, marking, skipped):
        """TLP is read from x_opencti_definition, name or definition.tlp."""
        c = _url_connector()
        c.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
        c.max_tlp = "TLP:AMBER"
        marking = dict(
            marking,
            type="marking-definition",
            id="marking-definition--00000000-0000-4000-8000-000000000002",
        )
        entity = _url_entity()
        entity["object_marking_refs"] = [marking["id"]]
        with patch("connector.polyswarm_connector.time.sleep"):
            result = c._enrich_url(URL_ID, entity, _opencti_url(), [entity, marking])

        if skipped:
            assert result["status"] == "skipped"
            assert c.polyswarm_client.mock_calls == []
        else:
            assert result is None
            c.polyswarm_client.submit_sandbox_url_async.assert_called_once()

    @pytest.mark.parametrize(
        "tlp, skipped",
        [
            ("TLP:RED", True),
            ("TLP:AMBER+STRICT", True),
            ("TLP:AMBER", False),
            ("TLP:CLEAR", False),
        ],
    )
    def test_tlp_check_well_known_ref_without_definition(self, tlp, skipped):
        """A well-known TLP id is enforced even when its object is absent."""
        c = _url_connector()
        c.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
        c.max_tlp = "TLP:AMBER"
        entity = _url_entity()
        entity["object_marking_refs"] = [MarkingDefinition.generate_id("TLP", tlp)]
        with patch("connector.polyswarm_connector.time.sleep"):
            result = c._enrich_url(URL_ID, entity, _opencti_url(), [entity])

        if skipped:
            assert result["status"] == "skipped"
            assert c.polyswarm_client.mock_calls == []
        else:
            assert result is None
            c.polyswarm_client.submit_sandbox_url_async.assert_called_once()

    def test_tlp_check_bundle_cannot_redefine_well_known_id(self):
        """A bundled object reusing the TLP:RED id cannot relabel it."""
        c = _url_connector()
        c.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
        c.max_tlp = "TLP:AMBER"
        marking = {
            "type": "marking-definition",
            "id": MarkingDefinition.generate_id("TLP", "TLP:RED"),
            "name": "TLP:CLEAR",
        }
        entity = _url_entity()
        entity["object_marking_refs"] = [marking["id"]]
        with patch("connector.polyswarm_connector.time.sleep"):
            result = c._enrich_url(URL_ID, entity, _opencti_url(), [entity, marking])

        assert result["status"] == "skipped"
        assert c.polyswarm_client.mock_calls == []

    def test_tlp_check_reads_stix_entity_refs(self):
        """The STIX entity's own refs count even when the OpenCTI ids differ."""
        c = _url_connector()
        c.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
        c.max_tlp = "TLP:AMBER"
        marking = {
            "type": "marking-definition",
            "id": "marking-definition--00000000-0000-4000-8000-000000000003",
            "name": "TLP:RED",
        }
        entity = _url_entity()
        entity["object_marking_refs"] = [marking["id"]]
        opencti = _opencti_url()
        opencti["standard_id"] = "url--00000000-0000-0000-0000-0000000000ff"
        with patch("connector.polyswarm_connector.time.sleep"):
            result = c._enrich_url(URL_ID, entity, opencti, [marking])

        assert result["status"] == "skipped"
        assert c.polyswarm_client.mock_calls == []


# -- Submission: query string, provider and VM


class TestUrlSubmission:
    def _run(self, c, value=QUERY_URL):
        with patch("connector.polyswarm_connector.time.sleep"):
            return c._enrich_url(URL_ID, _url_entity(value), _opencti_url(value), [])

    def test_query_stripped_by_default(self):
        c = _url_connector()
        assert self._run(c) is None
        c.polyswarm_client.submit_sandbox_url_async.assert_called_once_with(
            STRIPPED_URL, provider="cape", vm_slug=CAPE_VM
        )

    def test_query_kept_when_opted_in(self):
        c = _url_connector(sandbox_url_send_query=True)
        self._run(c)
        c.polyswarm_client.submit_sandbox_url_async.assert_called_once_with(
            QUERY_URL, provider="cape", vm_slug=CAPE_VM
        )

    @pytest.mark.parametrize("send_query", [False, True])
    def test_logs_never_contain_the_query(self, send_query):
        c = _url_connector(sandbox_url_send_query=send_query)
        c.config.polyswarm.json_report_enabled = True
        c.config.polyswarm.pdf_report_enabled = True
        self._run(c)
        logged = _logged(c)
        assert "SECRET123" not in logged
        assert "token=" not in logged
        assert "example.com" in logged  # host only

    def test_both_providers_are_submitted(self):
        c = _url_connector(sandbox_provider="both")
        self._run(c)
        providers = [
            call.kwargs["provider"]
            for call in c.polyswarm_client.submit_sandbox_url_async.call_args_list
        ]
        assert providers == ["cape", "triage"]

    def test_provider_without_url_vm_is_skipped(self):
        c = _url_connector()
        c.polyswarm_client.get_url_vm_for_provider = MagicMock(return_value=None)
        result = self._run(c)
        assert result["status"] == "error"
        c.polyswarm_client.submit_sandbox_url_async.assert_not_called()
        kwargs = c.stix_builder.create_error_note.call_args.kwargs
        assert kwargs["error_category"] == "Sandbox Submission Failed"

    def test_preferred_vm_is_passed(self):
        c = _url_connector(sandbox_vm="windows11-21h2-x64")
        self._run(c)
        c.polyswarm_client.get_url_vm_for_provider.assert_called_with(
            "cape", preferred="windows11-21h2-x64"
        )

    def test_second_provider_error_keeps_first_task(self):
        """A failure on Triage must not drop the CAPE task already started."""
        c = _url_connector(sandbox_provider="both")
        quota = PolySwarmAPIError(
            f"{PolySwarmAPIError.QUOTA_CATEGORY} (URL sandbox submit (triage))",
            "quota detail",
        )
        c.polyswarm_client.submit_sandbox_url_async = MagicMock(
            side_effect=lambda url, provider, vm_slug: (
                "task-cape" if provider == "cape" else (_ for _ in ()).throw(quota)
            )
        )
        c._phase_poll_sandboxes = MagicMock(return_value={"cape": None})
        assert self._run(c) is None
        assert c._phase_poll_sandboxes.call_args.args[1] == {"cape": "task-cape"}
        categories = [
            call.kwargs["error_category"]
            for call in c.stix_builder.create_error_note.call_args_list
        ]
        assert categories[0] == quota.category
        detail = c.stix_builder.create_error_note.call_args_list[0].kwargs[
            "error_detail"
        ]
        assert "TRIAGE sandbox was not started" in detail
        assert "quota detail" in detail

    def test_first_provider_error_keeps_second_task(self):
        c = _url_connector(sandbox_provider="both")
        err = PolySwarmAPIError("API Access Denied (URL sandbox submit (cape))", "x")
        c.polyswarm_client.submit_sandbox_url_async = MagicMock(
            side_effect=[err, "task-triage"]
        )
        c._phase_poll_sandboxes = MagicMock(return_value={"triage": None})
        assert self._run(c) is None
        assert c._phase_poll_sandboxes.call_args.args[1] == {"triage": "task-triage"}

    def test_all_providers_error_raises_first_error(self):
        c = _url_connector(sandbox_provider="both")
        first = PolySwarmAPIError(f"{PolySwarmAPIError.QUOTA_CATEGORY} (cape)", "x")
        second = PolySwarmAPIError(f"{PolySwarmAPIError.QUOTA_CATEGORY} (triage)", "y")
        c.polyswarm_client.submit_sandbox_url_async = MagicMock(
            side_effect=[first, second]
        )
        with pytest.raises(PolySwarmAPIError) as excinfo:
            self._run(c)
        assert excinfo.value is first

    def test_polls_with_file_timeouts(self):
        c = _url_connector(poll_interval=7, sandbox_timeout=123)
        c._phase_poll_sandboxes = MagicMock(return_value={"cape": None})
        self._run(c)
        args = c._phase_poll_sandboxes.call_args.args
        assert args[2:4] == (7, 123)


# -- Results: notes, reports, score, observables


def _run_with_builder(task_name, provider="cape", stix_objects=None, **overrides):
    c = _url_connector(sandbox_provider=provider, **overrides)
    c.config.polyswarm.json_report_enabled = True
    c.config.polyswarm.pdf_report_enabled = True
    c.stix_builder = StixBuilder(helper=MagicMock())
    c.polyswarm_client.get_sandbox_results = MagicMock(return_value=_task(task_name))
    # As OpenCTI sends it: stix_objects holds the enriched observable
    with patch("connector.polyswarm_connector.time.sleep"):
        result = c._enrich_url(
            URL_ID,
            _url_entity(),
            _opencti_url(),
            [_url_entity()] if stix_objects is None else stix_objects,
        )
    sent = c.helper.stix2_create_bundle.call_args_list
    objects = sent[-1].args[0] if sent else []
    return c, result, objects


class TestUrlResults:
    def test_cape_results(self):
        c, result, objects = _run_with_builder("sandbox_url_task_cape.json")
        assert result is None

        notes = [o for o in objects if o["type"] == "note"]
        cape = [n for n in notes if n["abstract"] == "PolySwarm Cape Sandbox Analysis"]
        assert cape and cape[0]["object_refs"] == [URL_ID]

        url_obj = [o for o in objects if o["id"] == URL_ID]
        assert len(url_obj) == 1 and url_obj[0]["type"] == "url"
        assert "x_opencti_score" in url_obj[0]

        # Contacted domains and IPs, related to the Url observable
        domains = {o["value"] for o in objects if o["type"] == "domain-name"}
        assert "github.com" in domains
        rels = [o for o in objects if o["type"] == "relationship"]
        assert any(
            r["source_ref"] == URL_ID and r["relationship_type"] == "related-to"
            for r in rels
        )
        # OpenCTI refuses communicates-with from a Url
        assert not any(
            r["source_ref"] == URL_ID and r["relationship_type"] == "communicates-with"
            for r in rels
        )
        # File-hash indicators are for files only
        assert not [o for o in objects if o["type"] == "indicator"]

    @pytest.mark.parametrize(
        "stix_objects",
        [
            [],
            [
                {
                    "type": "domain-name",
                    "spec_version": "2.1",
                    "id": "domain-name--00000000-0000-0000-0000-000000000002",
                    "value": "example.com",
                }
            ],
        ],
    )
    def test_url_object_carries_value_without_bundle(self, stix_objects):
        """The sent url object has its value when the bundle lacks the URL."""
        _, result, objects = _run_with_builder(
            "sandbox_url_task_cape.json", stix_objects=stix_objects
        )
        assert result is None
        url_obj = [o for o in objects if o["id"] == URL_ID]
        assert url_obj
        for obj in url_obj:
            assert obj["type"] == "url"
            assert obj["value"] == QUERY_URL

    def test_reports_attached_and_named_from_hash(self):
        c, _, _ = _run_with_builder("sandbox_url_task_cape.json")
        digest = hashlib.sha256(STRIPPED_URL.encode()).hexdigest()[:16]
        names = [
            call.kwargs["file_name"]
            for call in c.helper.api.stix_cyber_observable.add_file.call_args_list
        ]
        assert f"Sandbox_cape_{digest}.json" in names
        assert f"PolySwarm_Sandbox_cape_url_{digest}.pdf" in names
        for call in c.helper.api.stix_cyber_observable.add_file.call_args_list:
            assert call.kwargs["id"] == URL_ID
            assert "example.com" not in call.kwargs["file_name"]
        c.polyswarm_client.generate_pdf.assert_called_once_with("task-1", "sandbox")

    def test_task_sha256_is_hash_of_submitted_url(self):
        task = _fixture("sandbox_url_task_cape.json")
        target = task["config"]["target"]
        assert hashlib.sha256(target.encode()).hexdigest() == task["sha256"]

    def test_triage_results(self):
        c, result, objects = _run_with_builder(
            "sandbox_url_task_triage.json", provider="triage"
        )
        assert result is None
        notes = [o for o in objects if o["type"] == "note"]
        assert any(n["abstract"] == "PolySwarm Triage Sandbox Analysis" for n in notes)
        assert any(o["type"] == "attack-pattern" for o in objects)
        domains = {o["value"] for o in objects if o["type"] == "domain-name"}
        assert "malware.wicar.org" in domains

    def test_failed_task_gives_failure_note(self):
        c, result, objects = _run_with_builder("sandbox_url_task_cape_failed.json")
        assert result is None
        notes = [o for o in objects if o["type"] == "note"]
        assert notes and all(URL_ID in n["object_refs"] for n in notes)
        c.polyswarm_client.generate_pdf.assert_not_called()

    def test_recorded_tasks_parse_as_sdk_resources(self):
        for name in (
            "sandbox_url_task_cape.json",
            "sandbox_url_task_triage.json",
            "sandbox_url_task_cape_failed.json",
        ):
            task = resources.SandboxTask(_fixture(name))
            assert task.config["artifact_type"] == "URL"
            assert PolySwarmClient.is_sandbox_terminal(str(task.status))


# -- Routing and entity normalisation


class TestUrlRouting:
    def test_url_entity_routes_to_url_path(self):
        c = _url_connector()
        c._enrich_url = MagicMock(return_value=None)
        c._process_message(
            {"enrichment_entity": _opencti_url(), "stix_objects": [], "entity_id": "x"}
        )
        c.artifact_handler.download_artifact.assert_not_called()
        entity = c._enrich_url.call_args.args[1]
        assert entity["type"] == "url"
        assert entity["id"] == URL_ID
        assert entity["value"] == QUERY_URL

    def test_url_entity_not_in_scope(self):
        c = _url_connector()
        c.helper.connect_scope = "Artifact"
        c._enrich_url = MagicMock(return_value=None)
        result = c._process_message(
            {"enrichment_entity": _opencti_url(), "stix_objects": [], "entity_id": "x"}
        )
        assert "not in scope" in result.lower()
        c._enrich_url.assert_not_called()

    def test_artifact_still_routes_to_file_path(self):
        c = _url_connector()
        c._enrich_url = MagicMock(return_value=None)
        c.artifact_handler.download_artifact = MagicMock(
            return_value=(None, "Download disabled")
        )
        c._process_message(
            {
                "enrichment_entity": {"entity_type": "Artifact", "id": "a"},
                "stix_entity": {"type": "artifact", "id": "artifact--1"},
                "stix_objects": [],
                "entity_id": "x",
            }
        )
        c._enrich_url.assert_not_called()
        c.artifact_handler.download_artifact.assert_called_once()


# -- Client: SDK call, VM choice, no URL in logs or errors


def _client():
    return PolySwarmClient(
        api_key="test-key",
        api_url="https://api.polyswarm.network",
        community="acme-private",
        timeout=10,
        helper=MagicMock(),
    )


def _providers_listing():
    """Provider listing as measured from the API on 2026-11-10."""
    return [
        {
            "slug": "cape",
            "name": "cape",
            "tool": "cape_sandbox_v2",
            "vms": {
                "win-10-build-19041": {
                    "supported_artifact_types": ["FILE", "URL"],
                    "supported_browsers": ["firefox"],
                }
            },
        },
        {
            "slug": "triage",
            "name": "triage",
            "tool": "triage_sandbox_v0",
            "vms": {
                "android-11-x64": {
                    "supported_artifact_types": ["FILE"],
                    "supported_browsers": [],
                },
                "ubuntu-22.04-amd64": {
                    "supported_artifact_types": ["FILE", "URL"],
                    "supported_browsers": ["firefox"],
                },
                "windows11-21h2-x64": {
                    "supported_artifact_types": ["FILE", "URL"],
                    "supported_browsers": ["edge"],
                },
            },
        },
    ]


class _FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body

    def raise_for_status(self):
        return None


class TestClientUrlSubmission:
    def test_sdk_logger_is_quiet(self):
        logging.getLogger("polyswarm_api").setLevel(logging.DEBUG)
        _client()
        assert logging.getLogger("polyswarm_api").level == logging.WARNING

    def test_get_url_vm(self):
        c = _client()
        c.get_available_providers = MagicMock(return_value=_providers_listing())
        assert c.get_url_vm_for_provider("cape") == "win-10-build-19041"
        assert c.get_url_vm_for_provider("triage") == "windows11-21h2-x64"
        assert (
            c.get_url_vm_for_provider("triage", preferred="ubuntu-22.04-amd64")
            == "ubuntu-22.04-amd64"
        )
        # A preferred VM that does not accept URLs is not used
        assert (
            c.get_url_vm_for_provider("triage", preferred="android-11-x64")
            == "windows11-21h2-x64"
        )
        assert c.get_url_vm_for_provider("unknown") is None

    def test_get_url_vm_without_vm_details(self):
        c = _client()
        c.get_available_providers = MagicMock(
            return_value=[{"slug": "cape", "name": "Cape", "tool": "cape", "vms": []}]
        )
        assert c.get_url_vm_for_provider("cape") == "win-10-build-19041"

    def test_sdk_call(self):
        c = _client()
        task = resources.SandboxTask(_fixture("sandbox_url_task_cape.json"))
        c.api.sandbox_url = MagicMock(return_value=task)
        assert c.submit_sandbox_url_async(STRIPPED_URL, "cape", CAPE_VM) == task.id
        c.api.sandbox_url.assert_called_once_with(
            STRIPPED_URL, provider_slug="cape", vm_slug=CAPE_VM, browser=None
        )
        assert "example.com" not in str(c.helper.connector_logger.mock_calls)

    def test_sdk_error_is_redacted(self):
        c = _client()
        request = MagicMock(status_code=403)
        err = ps_exceptions.RequestException(
            request,
            f'Error when running the request: {{"artifact_name": "{QUERY_URL}"}}',
        )
        c.api.sandbox_url = MagicMock(side_effect=err)
        with pytest.raises(PolySwarmAPIError) as excinfo:
            c.submit_sandbox_url_async(QUERY_URL, "cape", CAPE_VM)
        assert "SECRET123" not in str(excinfo.value)
        assert "403" in str(excinfo.value)
        assert "SECRET123" not in str(c.helper.connector_logger.mock_calls)

    def test_sdk_error_without_status_is_redacted(self):
        c = _client()
        err = ps_exceptions.RequestException(MagicMock(status_code=None), QUERY_URL)
        c.api.sandbox_url = MagicMock(side_effect=err)
        assert c.submit_sandbox_url_async(QUERY_URL, "cape", CAPE_VM) is None
        c.api.sandbox_url.assert_called_once()  # not retried, no duplicate task
        assert "SECRET123" not in str(c.helper.connector_logger.mock_calls)

    def test_real_sdk_request_and_logs(self, caplog):
        """Run the SDK's own sandbox_url with HTTP mocked: what is sent, what is logged."""
        c = _client()
        task_json = copy.deepcopy(_fixture("sandbox_url_task_cape.json"))
        task_json["upload_url"] = "https://upload.invalid/put"
        requests_made = []

        def fake_request(**kwargs):
            requests_made.append(kwargs)
            return _FakeResponse(200, {"result": task_json, "status": "OK"})

        uploads = []

        def fake_put(url, data=None, **kwargs):
            uploads.append(data.read() if hasattr(data, "read") else data)
            return _FakeResponse(200, {})

        submit_url = url_utils.url_for_submission(QUERY_URL)
        caplog.set_level(logging.DEBUG)
        with (
            patch.object(c.api.session, "request", side_effect=fake_request),
            patch.object(resources.requests, "put", side_effect=fake_put),
        ):
            task_id = c.submit_sandbox_url_async(submit_url, "cape", CAPE_VM)

        assert task_id == task_json["id"]
        create = requests_made[0]
        assert create["method"] == "POST"
        assert create["json"]["artifact_name"] == STRIPPED_URL
        assert create["json"]["artifact_type"] == "URL"
        assert create["json"]["provider_slug"] == "cape"
        assert create["json"]["vm_slug"] == CAPE_VM
        assert create["json"]["community"] == "acme-private"
        assert uploads == [STRIPPED_URL.encode()]
        assert "SECRET123" not in json.dumps(requests_made, default=str)
        assert "example.com" not in caplog.text


# -- Settings


def _settings(monkeypatch, **env):
    settings = pytest.importorskip(
        "connector.models.configs.settings", reason="connectors_sdk unavailable"
    )
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000010")
    monkeypatch.setenv("POLYSWARM_API_KEY", "test-key")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return settings.ConnectorSettings()


class TestUrlSettings:
    def test_defaults(self, monkeypatch):
        config = _settings(monkeypatch)
        assert config.polyswarm.sandbox_url_send_query is False
        assert config.connector.scope == ["Artifact", "StixFile", "Url"]

    def test_send_query_from_env(self, monkeypatch):
        config = _settings(monkeypatch, POLYSWARM_SANDBOX_URL_SEND_QUERY="true")
        assert config.polyswarm.sandbox_url_send_query is True

    def test_scope_from_env(self, monkeypatch):
        config = _settings(monkeypatch, CONNECTOR_SCOPE="Artifact")
        assert config.connector.scope == ["Artifact"]

    def test_helper_config_scope(self, monkeypatch):
        dumped = _settings(monkeypatch).to_helper_config()
        assert "url" in str(dumped["connector"]["scope"]).lower()
