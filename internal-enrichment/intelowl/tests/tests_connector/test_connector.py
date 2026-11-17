from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, IntelOwlConnector
from intelowl_client import IntelOwlClientError


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "IPv4-Addr,Domain-Name,StixFile",
                },
                "intelowl": {
                    "url": "https://intelowl.example.com",
                    "api_key": "test-api-key",
                },
            }
        )


class FakeIntelOwlClient:
    def __init__(
        self, job: dict[str, Any] | None = None, error: Exception | None = None
    ) -> None:
        self.job = job
        self.error = error
        self.analyzed: list[dict[str, Any]] = []

    def analyze_observable(self, **kwargs: Any) -> int:
        if self.error:
            raise self.error
        self.analyzed.append(kwargs)
        return self.job["id"]

    def wait_for_job(
        self, job_id: int, poll_interval: float, timeout: float
    ) -> dict[str, Any]:
        assert (poll_interval, timeout) == (5, 300)
        return self.job

    def job_url(self, job_id: int) -> str:
        return f"https://intelowl.example.com/jobs/{job_id}"


def make_connector(client: FakeIntelOwlClient) -> tuple[IntelOwlConnector, MagicMock]:
    helper = MagicMock()
    helper.connect_scope = "IPv4-Addr,Domain-Name,StixFile"
    helper.check_max_tlp.side_effect = lambda tlp, max_tlp: tlp != "TLP:RED"
    helper.stix2_create_bundle.side_effect = lambda objects: objects
    helper.send_stix2_bundle.side_effect = lambda bundle, **_: [bundle]
    return (
        IntelOwlConnector(config=StubConnectorSettings(), helper=helper, client=client),
        helper,
    )


ENTITY_TYPES = {
    "ipv4-addr": "IPv4-Addr",
    "file": "StixFile",
    "email-addr": "Email-Addr",
}


def make_message(
    stix_entity: dict[str, Any], tlp: str | None = "TLP:AMBER", playbook: bool = False
) -> dict[str, Any]:
    marking = [{"definition_type": "TLP", "definition": tlp}] if tlp else []
    message = {
        "entity_id": stix_entity["id"],
        "enrichment_entity": {
            "entity_type": ENTITY_TYPES[stix_entity["type"]],
            "objectMarking": marking,
        },
        "stix_entity": stix_entity,
        "stix_objects": [stix_entity],
    }
    if not playbook:
        message["event_type"] = "INTERNAL_ENRICHMENT"
    return message


def sent_objects(helper: MagicMock) -> list[dict[str, Any]]:
    return helper.send_stix2_bundle.call_args.args[0]


def test_enriches_an_observable(intelowl_job, ipv4_stix_entity):
    client = FakeIntelOwlClient(job=intelowl_job)
    connector, helper = make_connector(client)

    connector.process_message(make_message(ipv4_stix_entity))

    assert client.analyzed == [
        {
            "value": "198.51.100.7",
            "classification": "ip",
            "playbook": "FREE_TO_USE_ANALYZERS",
            "tlp": "AMBER",
            "tags": ["opencti"],
        }
    ]
    objects = sent_objects(helper)
    assert (
        objects[0] is ipv4_stix_entity
    )  # the original bundle is kept, with the updated observable
    assert {o["type"] for o in objects[1:]} == {
        "identity",
        "marking-definition",
        "note",
        "malware",
        "relationship",
    }


@pytest.mark.parametrize(
    "markings", [["TLP:RED", "TLP:AMBER"], ["TLP:AMBER", "TLP:RED"]]
)
def test_uses_the_strictest_of_several_tlp_markings(
    intelowl_job, ipv4_stix_entity, markings
):
    client = FakeIntelOwlClient(job=intelowl_job)
    connector, _ = make_connector(client)
    message = make_message(ipv4_stix_entity)
    message["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": tlp} for tlp in markings
    ]

    with pytest.raises(ValueError, match="greater than MAX TLP"):
        connector.process_message(message)
    assert client.analyzed == []


def test_uses_tlp_from_the_bundle_marking_refs(intelowl_job, ipv4_stix_entity):
    # A playbook bundle can carry a TLP on the observable that the OpenCTI entity lacks.
    client = FakeIntelOwlClient(job=intelowl_job)
    connector, _ = make_connector(client)
    red = {
        "type": "marking-definition",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "definition_type": "TLP",
        "name": "TLP:RED",
    }
    entity = {**ipv4_stix_entity, "object_marking_refs": [red["id"]]}
    message = make_message(entity, tlp=None)
    message["stix_objects"] = [entity, red]

    with pytest.raises(ValueError, match="greater than MAX TLP"):
        connector.process_message(message)
    assert client.analyzed == []


def test_sends_amber_strict_to_intelowl_as_red(intelowl_job, ipv4_stix_entity):
    client = FakeIntelOwlClient(job=intelowl_job)
    connector, _ = make_connector(client)

    connector.process_message(make_message(ipv4_stix_entity, tlp="TLP:AMBER+STRICT"))

    assert client.analyzed[0]["tlp"] == "RED"


def test_rejects_an_observable_above_max_tlp(intelowl_job, ipv4_stix_entity):
    client = FakeIntelOwlClient(job=intelowl_job)
    connector, helper = make_connector(client)

    with pytest.raises(ValueError, match="greater than MAX TLP"):
        connector.process_message(make_message(ipv4_stix_entity, tlp="TLP:RED"))
    assert client.analyzed == []
    helper.send_stix2_bundle.assert_not_called()


def test_rejects_an_out_of_scope_entity(intelowl_job):
    connector, helper = make_connector(FakeIntelOwlClient(job=intelowl_job))
    email = {"type": "email-addr", "id": "email-addr--1", "value": "a@example.com"}

    with pytest.raises(ValueError, match="Email-Addr is not a supported entity type"):
        connector.process_message(make_message(email))
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize(
    "client_kwargs",
    [
        pytest.param({"error": IntelOwlClientError("HTTP 401")}, id="client_error"),
        pytest.param({"job": {"id": 7, "status": "failed"}}, id="failed_job"),
    ],
)
def test_failures_raise_for_manual_enrichment(client_kwargs, ipv4_stix_entity):
    connector, helper = make_connector(FakeIntelOwlClient(**client_kwargs))

    with pytest.raises(ValueError):
        connector.process_message(make_message(ipv4_stix_entity))
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize(
    "client_kwargs, stix_entity, tlp",
    [
        pytest.param(
            {"error": IntelOwlClientError("HTTP 401")},
            None,
            "TLP:AMBER",
            id="client_error",
        ),
        pytest.param(
            {"job": {"id": 7, "status": "killed"}}, None, "TLP:AMBER", id="killed_job"
        ),
        pytest.param({}, None, "TLP:RED", id="above_max_tlp"),
        pytest.param(
            {},
            {"type": "email-addr", "id": "email-addr--1", "value": "a@example.com"},
            "TLP:AMBER",
            id="out_of_scope",
        ),
    ],
)
def test_playbooks_always_get_their_bundle_back(
    client_kwargs, stix_entity, tlp, ipv4_stix_entity
):
    connector, helper = make_connector(FakeIntelOwlClient(**client_kwargs))
    entity = stix_entity or ipv4_stix_entity

    connector.process_message(make_message(entity, tlp=tlp, playbook=True))

    assert sent_objects(helper) == [entity]


def test_skips_a_file_without_hashes(intelowl_job):
    client = FakeIntelOwlClient(job=intelowl_job)
    connector, helper = make_connector(client)
    file = {"type": "file", "id": "file--1", "name": "invoice.pdf"}

    connector.process_message(make_message(file))

    assert client.analyzed == []
    assert sent_objects(helper) == [file]


def test_enriches_a_file_by_its_strongest_hash(intelowl_job):
    client = FakeIntelOwlClient(job=intelowl_job)
    connector, helper = make_connector(client)
    file = {
        "type": "file",
        "id": "file--5e4f3f0d-3c1b-5b0a-9f0e-1c2d3e4f5a6b",
        "hashes": {
            "MD5": "44d88612fea8a8f36de82e1278abb02f",
            "SHA-256": "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F",
        },
        "extensions": {},
    }

    connector.process_message(make_message(file, tlp=None))

    assert client.analyzed[0]["classification"] == "hash"
    assert (
        client.analyzed[0]["value"]
        == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )
    assert client.analyzed[0]["tlp"] == "CLEAR"
    assert any(o["type"] == "note" for o in sent_objects(helper))
