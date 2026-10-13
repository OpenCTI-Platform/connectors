"""The connector refangs the observables of the extracted bundle in both modes.

The bundle comes either from the Import Document AI web service (legacy mode)
or from an XTM One agent through the OpenCTI chatbot proxy, which relays the
same web service: in both cases it must reach OpenCTI refanged, with every
reference resolving, or OpenCTI rejects the observables and the report.
"""

import copy
import json
import sys
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pycti
import pytest
import requests
import stix2
from stix2.utils import STIXdatetime

sys.path.append(str((Path(__file__).resolve().parent.parent / "src")))

from import_doc_ai.connector import Connector
from import_doc_ai.refang import RefangSummary, refang_bundle_observables
from import_doc_ai.util import OpenCTIFileObject

DEFANGED_EMAIL = "admin[at]filigran[dot]io"
DEFANGED_IPV6 = "2001[:]0db8[:]85a3[:]0000[:]0000[:]8a2e[:]0370[:]7334"
REFANGED_EMAIL = "admin@filigran.io"
REFANGED_IPV6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
ALLOWED_RELATIONSHIPS = {("intrusion-set", "related-to", "email-addr")}


class FakeResponse:
    """Minimal ``requests.Response`` stand-in."""

    def __init__(self, json_data: dict, status_code: int = 200):
        self._json_data = json_data
        self.status_code = status_code
        self.text = json.dumps(json_data)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return self._json_data


@pytest.fixture(name="helper")
def fixture_helper() -> Mock:
    helper = Mock()
    helper.api.query.return_value = {
        "data": {"settings": {"id": "opencti-instance-id"}}
    }
    helper.opencti_url = "http://opencti.local"
    helper.api.api_token = "test-token"
    helper.get_only_contextual.return_value = False
    return helper


@pytest.fixture(name="config")
def fixture_config() -> Mock:
    config = Mock()
    config.import_document_ai.api_base_url = "http://import-document-ai.local"
    config.import_document_ai.api_key = "certificate"
    config.import_document_ai.licence_key_base64 = "Y2VydGlmaWNhdGU="
    config.import_document_ai.create_indicator = True
    config.import_document_ai.include_relationships = True
    return config


@pytest.fixture(name="connector")
def fixture_connector(
    monkeypatch: pytest.MonkeyPatch, helper: Mock, config: Mock
) -> Connector:
    imported_file = OpenCTIFileObject(
        path="import/global/defanged.txt",
        buffered_data=BytesIO(b"Contact admin[at]filigran[dot]io"),
        mime_type="text/plain",
        id="import/global/defanged.txt",
    )
    monkeypatch.setattr(
        "import_doc_ai.connector.download_import_file",
        Mock(return_value=imported_file),
    )
    monkeypatch.setattr(
        "import_doc_ai.connector.get_triggering_entity", Mock(return_value=None)
    )
    monkeypatch.setattr(
        "import_doc_ai.connector.fetch_octi_allowed_stix_relations_triplets",
        Mock(return_value=ALLOWED_RELATIONSHIPS),
    )
    return Connector(config=config, helper=helper)


def observable(observable_type: str, value: str, **properties) -> dict:
    """An observable as the extraction returns it, its id derived from its value."""
    return json.loads(
        stix2.parse(
            {
                "type": observable_type,
                "spec_version": "2.1",
                "value": value,
                **properties,
            },
            allow_custom=True,
        ).serialize()
    )


def intrusion_set(name: str) -> dict:
    return {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": pycti.IntrusionSet.generate_id(name),
        "name": name,
    }


def defanged_extraction(with_report: bool) -> dict:
    """What the extraction returns for a document quoting defanged indicators."""
    email = observable("email-addr", DEFANGED_EMAIL, defanged=True)
    ipv6 = observable("ipv6-addr", DEFANGED_IPV6, defanged=True)
    apt = intrusion_set("APT41")
    related_to = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid4()}",
        "relationship_type": "related-to",
        "source_ref": apt["id"],
        "target_ref": email["id"],
    }
    objects = [email, ipv6, apt, related_to]
    if with_report:
        published = "2026-09-01T00:00:00.000Z"
        objects.append(
            {
                "type": "report",
                "spec_version": "2.1",
                "id": pycti.Report.generate_id("Defanged report", published),
                "name": "Defanged report",
                "published": published,
                "report_types": ["threat-report"],
                "object_refs": [obj["id"] for obj in objects],
            }
        )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def clean_extraction(with_report: bool) -> dict:
    """What the extraction returns for a document quoting no defanged indicator.

    Clean values holding brackets are included, URLs whose scheme and host are
    clean but whose path or query holds a notation-like token, and a file
    whose name looks defanged: a file is not a network indicator.
    """
    email = observable("email-addr", REFANGED_EMAIL)
    apt = intrusion_set("APT41")
    objects = [
        email,
        observable("ipv6-addr", REFANGED_IPV6),
        observable("domain-name", "filigran.io"),
        observable("url", "http://[2001:db8::1]:8080/index.html"),
        observable("url", "https://en.wikipedia.org/wiki/Mercury_(planet)"),
        observable("url", "https://example.com/search?q=(at)"),
        observable("url", "https://example.com/a[.]b"),
        json.loads(
            stix2.File(
                name="invoice[.]pdf[.]exe", hashes={"SHA-256": "a" * 64}
            ).serialize()
        ),
        apt,
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "relationship_type": "related-to",
            "source_ref": apt["id"],
            "target_ref": email["id"],
        },
    ]
    if with_report:
        published = "2026-09-01T00:00:00.000Z"
        objects.append(
            {
                "type": "report",
                "spec_version": "2.1",
                "id": pycti.Report.generate_id("Clean report", published),
                "name": "Clean report",
                "published": published,
                "report_types": ["threat-report"],
                "object_refs": [obj["id"] for obj in objects],
            }
        )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


class FrozenDatetime(datetime):
    """A ``datetime`` whose ``now`` never moves."""

    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 9, 1, tzinfo=tz)


@pytest.fixture(name="frozen_clock")
def fixture_frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop the clocks of the connector and of stix2, so two runs are alike.

    The connector dates the report it creates, and stix2 stamps the objects
    that carry no ``created`` / ``modified`` with the time it parses them.
    """
    monkeypatch.setattr("import_doc_ai.util.datetime", FrozenDatetime)
    monkeypatch.setattr(
        "stix2.base.get_timestamp",
        lambda: STIXdatetime(2026, 9, 1, tzinfo=timezone.utc),
    )


def serve_extraction(
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
    connector: Connector,
    extraction: dict,
) -> dict:
    """Serve ``extraction`` through the mode's HTTP call, return the message."""
    if mode == "legacy":
        connector.import_doc_ia_client.session.post = Mock(
            return_value=FakeResponse(extraction)
        )
        return {}
    monkeypatch.setattr(
        "import_doc_ai.client_api.requests.post",
        Mock(
            return_value=FakeResponse(
                {"assistant_message": {"content": json.dumps(extraction)}}
            )
        ),
    )
    return {"configuration": json.dumps({"agent_slug": "cti-stix-harvester"})}


def sent_bundle(helper: Mock) -> dict:
    return json.loads(helper.send_stix2_bundle.call_args.kwargs["bundle"])


@pytest.mark.parametrize("with_report", [True, False], ids=["report", "no-report"])
@pytest.mark.parametrize("mode", ["legacy", "xtm_one"])
def test_process_message_sends_refanged_observables(
    mode: str,
    with_report: bool,
    monkeypatch: pytest.MonkeyPatch,
    connector: Connector,
    helper: Mock,
):
    # Given an extraction returning defanged observables referenced by a
    # relationship and, or not, by a report
    extraction = defanged_extraction(with_report)
    former_ids = [obj["id"] for obj in extraction["objects"][:2]]
    data = serve_extraction(mode, monkeypatch, connector, extraction)

    # When processing the import
    connector.process_message(data=data)

    # Then OpenCTI receives the refanged observables under the ids stix2
    # derives from their values, marked for indicator creation
    bundle = sent_bundle(helper)
    objects_by_type = {obj["type"]: obj for obj in bundle["objects"]}
    email_id = stix2.EmailAddress(value=REFANGED_EMAIL)["id"]
    ipv6_id = stix2.IPv6Address(value=REFANGED_IPV6)["id"]
    assert objects_by_type["email-addr"] == {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": email_id,
        "value": REFANGED_EMAIL,
        "x_opencti_create_indicator": True,
    }
    assert objects_by_type["ipv6-addr"] == {
        "type": "ipv6-addr",
        "spec_version": "2.1",
        "id": ipv6_id,
        "value": REFANGED_IPV6,
        "x_opencti_create_indicator": True,
    }

    # And every reference resolves: the relationship and the report point to
    # the refanged observables, never to their former ids
    serialized = json.dumps(bundle)
    for former_id in former_ids:
        assert former_id not in serialized
    assert objects_by_type["relationship"]["target_ref"] == email_id
    object_ids = {obj["id"] for obj in bundle["objects"]}
    report_refs = set(objects_by_type["report"]["object_refs"])
    assert {email_id, ipv6_id} <= report_refs <= object_ids
    helper.connector_logger.info.assert_any_call(
        "Refanged the defanged observables of the extracted bundle",
        {"refanged": 2, "merged_duplicates": 0},
    )


@pytest.mark.usefixtures("frozen_clock")
@pytest.mark.parametrize("with_report", [True, False], ids=["report", "no-report"])
@pytest.mark.parametrize("mode", ["legacy", "xtm_one"])
def test_process_message_sends_a_bundle_without_defanged_observables_as_before(
    mode: str,
    with_report: bool,
    monkeypatch: pytest.MonkeyPatch,
    connector: Connector,
    helper: Mock,
):
    # Given an extraction holding no defanged observable
    extraction = clean_extraction(with_report)
    refang_calls = []

    def spied_refang(bundle: stix2.Bundle) -> tuple[stix2.Bundle, RefangSummary]:
        refanged_bundle, summary = refang_bundle_observables(bundle)
        refang_calls.append((bundle, refanged_bundle))
        return refanged_bundle, summary

    # When processing the import, then processing it again without the refang
    # step, as the connector did before it
    monkeypatch.setattr(
        "import_doc_ai.connector.refang_bundle_observables", spied_refang
    )
    connector.process_message(
        data=serve_extraction(mode, monkeypatch, connector, copy.deepcopy(extraction))
    )
    monkeypatch.setattr(
        "import_doc_ai.connector.refang_bundle_observables",
        lambda bundle: (bundle, RefangSummary()),
    )
    connector.process_message(
        data=serve_extraction(mode, monkeypatch, connector, copy.deepcopy(extraction))
    )

    # Then the refang step hands the very same bundle on, and OpenCTI receives
    # the same objects, under the same ids and in the same order, with the same
    # send options
    [(received_bundle, handed_on_bundle)] = refang_calls
    assert handed_on_bundle is received_bundle
    with_refang, without_refang = (
        {**call.kwargs, "bundle": json.loads(call.kwargs["bundle"])["objects"]}
        for call in helper.send_stix2_bundle.call_args_list
    )
    assert with_refang == without_refang

    # And nothing is logged about refanging
    logged_messages = [
        call.args[0]
        for log in (
            helper.connector_logger.debug,
            helper.connector_logger.info,
            helper.connector_logger.warning,
        )
        for call in log.call_args_list
    ]
    assert not [
        message
        for message in logged_messages
        if message.startswith(("Refanged", "Observable value looks defanged"))
    ]


@pytest.mark.parametrize(
    "observable_type, value",
    [
        pytest.param("email-addr", "admin[at][dot]io", id="invalid once refanged"),
        pytest.param("domain-name", "filigran[.}io", id="mismatched brackets"),
        pytest.param("domain-name", "evil[at]example.com", id="at in a domain name"),
        pytest.param("url", "https://filigran{.)io/", id="mismatched pair in a host"),
    ],
)
def test_process_message_warns_about_values_that_do_not_refang(
    observable_type: str,
    value: str,
    monkeypatch: pytest.MonkeyPatch,
    connector: Connector,
    helper: Mock,
):
    # Given an extraction returning a defanged value that does not refang: not
    # a valid value once refanged, or holding a notation left in place
    defanged = observable(observable_type, value, defanged=True)
    extraction = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [defanged],
    }
    data = serve_extraction("legacy", monkeypatch, connector, extraction)

    # When processing the import
    connector.process_message(data=data)

    # Then the value is sent unchanged for OpenCTI to report it, with a warning
    sent_observable = next(
        obj for obj in sent_bundle(helper)["objects"] if obj["type"] == observable_type
    )
    assert sent_observable["id"] == defanged["id"]
    assert sent_observable["value"] == value
    helper.connector_logger.warning.assert_any_call(
        "Observable value looks defanged but does not refang into a valid value, "
        "sending it unchanged",
        {"type": observable_type, "id": defanged["id"], "value": value},
    )
