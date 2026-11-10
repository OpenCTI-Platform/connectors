"""Tests for the opt-in sample download as an Artifact (SDK download mocked).

No live malware is ever downloaded: the SDK call is replaced by a function that
writes harmless bytes into the handle it is given, matching the signature
PolyswarmAPI.download_to_handle(hash_, fh, hash_type=None).
"""

import base64
import hashlib
import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock

from conftest import StubHelper
from polyswarm_api.api import PolyswarmAPI
from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient
from polyswarm_enrichment.connector import ConnectorTemplate
from polyswarm_enrichment.converter_to_stix import ConverterToStix
from polyswarm_enrichment.sample_artifact import build_sample_artifact
from polyswarm_enrichment.settings import PolySwarmConfig

CONTENT = b"harmless test bytes, not malware"
SHA256 = hashlib.sha256(CONTENT).hexdigest()
MARKING = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
FILE_ID = "file--0d6a4c5e-4a2b-5c3d-9e8f-123456789abc"


def _data(**over):
    data = {
        "sha256": SHA256,
        "community": "default",
        "mime_type": "application/x-dosexec",
        "filenames": ["evil.exe"],
        "x_opencti_score": 80,
        "size": len(CONTENT),
    }
    data.update(over)
    return data


def _fake_download(content=CONTENT):
    def _download(hash_, fh, hash_type=None):
        fh.write(content)

    return _download


def _client(max_mb=20, content=CONTENT, community="default"):
    client = object.__new__(ConnectorClient)
    client.helper = StubHelper()
    client.config = SimpleNamespace(download_max_size_mb=max_mb)
    client.polyswarm_community = community
    client.polyswarm = MagicMock()
    client.polyswarm.download_to_handle.side_effect = _fake_download(content)
    client.polyswarm_default = None
    client._circuit_breakers = {community: CircuitBreaker()}
    return client


class TestSettings:
    def test_defaults_off(self):
        cfg = PolySwarmConfig(api_key="k")
        assert cfg.download_sample is False
        assert cfg.download_max_size_mb == 20

    def test_sdk_signature_is_what_we_call(self):
        params = inspect.signature(PolyswarmAPI.download_to_handle).parameters
        assert list(params)[:4] == ["self", "hash_", "fh", "hash_type"]


class TestClientDownload:
    def test_downloads_bytes(self):
        client = _client()
        content, reason = client.download_sample(_data())
        assert content == CONTENT and reason is None
        client.polyswarm.download_to_handle.assert_called_once()
        assert client.polyswarm.download_to_handle.call_args.args[0] == SHA256

    def test_known_oversize_is_skipped_before_download(self):
        client = _client(max_mb=1)
        content, reason = client.download_sample(_data(size=5 * 1024 * 1024))
        assert content is None and "1 MB limit" in reason
        client.polyswarm.download_to_handle.assert_not_called()

    def test_unknown_size_is_capped_after_download(self):
        client = _client(max_mb=1, content=b"x" * (1024 * 1024 + 10))
        content, reason = client.download_sample(_data(size=None))
        assert content is None and "limit" in reason

    def test_streaming_download_is_aborted_at_the_limit(self):
        client = _client(max_mb=1)
        written = []

        def _stream(hash_, fh, hash_type=None):
            for _ in range(10):
                fh.write(b"x" * (512 * 1024))
                written.append(1)

        client.polyswarm.download_to_handle.side_effect = _stream
        content, reason = client.download_sample(_data(size=None))
        assert content is None and "over the 1 MB limit" in reason
        assert len(written) == 2  # third chunk would pass 1 MB and is refused

    def test_error_log_has_no_error_text(self, capsys):
        client = _client()
        client.polyswarm.download_to_handle.side_effect = RuntimeError(
            "https://s3.example/x?X-Amz-Signature=SECRET"
        )
        client.download_sample(_data())
        assert "SECRET" not in capsys.readouterr().out

    def test_download_error_is_reported_not_raised(self):
        client = _client()
        client.polyswarm.download_to_handle.side_effect = RuntimeError("quota")
        content, reason = client.download_sample(_data())
        assert content is None and "RuntimeError" in reason

    def test_uses_default_instance_for_default_community(self):
        client = _client(community="private")
        default_api = MagicMock()
        default_api.download_to_handle.side_effect = _fake_download()
        client.polyswarm_default = default_api
        content, _ = client.download_sample(_data(community="default"))
        assert content == CONTENT
        client.polyswarm.download_to_handle.assert_not_called()


class TestBuildArtifact:
    def test_artifact_has_bytes_hashes_markings_and_description(self):
        art = build_sample_artifact(CONTENT, _data(), "identity--a", [MARKING])
        assert art["type"] == "artifact"
        assert base64.b64decode(art["payload_bin"]) == CONTENT
        assert art["hashes"]["SHA-256"] == SHA256
        assert art["hashes"]["MD5"] == hashlib.md5(CONTENT).hexdigest()
        assert art["hashes"]["SHA-1"] == hashlib.sha1(CONTENT).hexdigest()
        assert art["object_marking_refs"] == [MARKING]
        assert art["mime_type"] == "application/x-dosexec"
        assert art["x_opencti_additional_names"] == ["evil.exe"]
        assert "LIVE MALWARE SAMPLE" in art["x_opencti_description"]
        assert art["x_opencti_created_by_ref"] == "identity--a"

    def test_hash_mismatch_is_refused(self):
        assert build_sample_artifact(b"other bytes", _data(), "identity--a") is None

    def test_missing_expected_hash_is_refused(self):
        assert build_sample_artifact(CONTENT, _data(sha256=None), "identity--a") is None

    def test_file_name_is_sanitized(self):
        art = build_sample_artifact(
            CONTENT, _data(filenames=["../../etc/pass wd\x00.exe"]), "identity--a"
        )
        (name,) = art["x_opencti_additional_names"]
        assert "/" not in name and "\x00" not in name

    def test_bad_mime_falls_back(self):
        art = build_sample_artifact(CONTENT, _data(mime_type="Unknown"), "identity--a")
        assert art["mime_type"] == "application/octet-stream"


def _connector(download=True, client=None):
    connector = object.__new__(ConnectorTemplate)
    connector.helper = StubHelper()
    connector.converter_to_stix = ConverterToStix(connector.helper)
    connector.client = client or MagicMock()
    connector.download_sample = download
    return connector


def _observable():
    return {"id": FILE_ID, "type": "file", "object_marking_refs": [MARKING]}


class TestConnectorWiring:
    def test_objects_artifact_and_marked_relationship(self):
        client = MagicMock()
        client.download_sample.return_value = (CONTENT, None)
        connector = _connector(client=client)
        result = {"data": _data()}
        objects = connector._download_sample_objects(
            _observable(), {"entity_type": "StixFile"}, result
        )
        art, rel = objects
        assert art["type"] == "artifact"
        assert rel["relationship_type"] == "related-to"
        assert rel["source_ref"] == art["id"] and rel["target_ref"] == FILE_ID
        assert rel["object_marking_refs"] == [MARKING]
        assert "Live malware sample" in result["data"]["sample_download"]

    def test_marking_falls_back_to_opencti_entity(self):
        client = MagicMock()
        client.download_sample.return_value = (CONTENT, None)
        connector = _connector(client=client)
        observable = {"id": FILE_ID, "type": "file"}
        entity = {
            "entity_type": "StixFile",
            "objectMarking": [{"standard_id": MARKING}],
        }
        art, rel = connector._download_sample_objects(
            observable, entity, {"data": _data()}
        )
        assert art["object_marking_refs"] == [MARKING]

    def test_existing_artifact_skips_download_and_is_linked(self):
        client = MagicMock()
        connector = _connector(client=client)
        connector.helper.api = MagicMock()
        connector.helper.api.stix_cyber_observable.read.return_value = {
            "standard_id": "artifact--11111111-1111-4111-8111-111111111111"
        }
        result = {"data": _data()}
        objects = connector._download_sample_objects(
            _observable(), {"entity_type": "StixFile"}, result
        )
        client.download_sample.assert_not_called()
        ref, rel = objects
        assert ref["type"] == "artifact" and ref["id"] == rel["source_ref"]
        assert ref["hashes"]["SHA-256"] == SHA256
        assert "object_marking_refs" not in ref
        filters = connector.helper.api.stix_cyber_observable.read.call_args.kwargs[
            "filters"
        ]["filters"]
        assert {"key": "entity_type", "values": ["Artifact"]} in filters
        assert rel["source_ref"].startswith("artifact--")
        assert rel["object_marking_refs"] == [MARKING]
        assert "already in OpenCTI" in result["data"]["sample_download"]

    def test_lookup_failure_still_downloads(self):
        client = MagicMock()
        client.download_sample.return_value = (CONTENT, None)
        connector = _connector(client=client)
        connector.helper.api = MagicMock()
        connector.helper.api.stix_cyber_observable.read.side_effect = RuntimeError("x")
        objects = connector._download_sample_objects(
            _observable(), {}, {"data": _data()}
        )
        assert objects[0]["type"] == "artifact"

    def test_skip_reason_goes_to_the_note_text(self):
        client = MagicMock()
        client.download_sample.return_value = (None, "sample is over the 1 MB limit")
        connector = _connector(client=client)
        result = {"data": _data()}
        assert connector._download_sample_objects(_observable(), {}, result) == []
        assert "over the 1 MB limit" in result["data"]["sample_download"]

    def test_hash_mismatch_stores_nothing(self):
        client = MagicMock()
        client.download_sample.return_value = (b"different", None)
        connector = _connector(client=client)
        result = {"data": _data()}
        assert connector._download_sample_objects(_observable(), {}, result) == []
        assert "did not match" in result["data"]["sample_download"]

    def test_unknown_hash_means_no_download(self):
        client = MagicMock()
        connector = _connector(client=client)
        assert (
            connector._download_sample_objects(_observable(), {}, {"data": None}) == []
        )
        client.download_sample.assert_not_called()

    def test_unexpected_error_never_propagates(self):
        client = MagicMock()
        client.download_sample.side_effect = ValueError("boom")
        connector = _connector(client=client)
        result = {"data": _data()}
        assert connector._download_sample_objects(_observable(), {}, result) == []
        assert "ValueError" in result["data"]["sample_download"]

    def test_note_shows_download_status(self):
        connector = _connector()
        note = connector._create_polyswarm_note(
            FILE_ID,
            {
                "community": "default",
                "detections": {"malicious": 1, "total": 2},
                "sample_download": "Not downloaded: too big.",
            },
        )
        assert "**Sample Download:**" in note["content"]


def _process(download, entity_type, client):
    connector = _connector(download=download, client=client)
    connector.max_tlp = "TLP:RED"
    connector.replace_with_lower_score = True
    connector.ioc_enabled = False
    connector.helper.connect_scope = "stixfile,artifact"
    connector.helper.api = MagicMock()
    connector.stix_objects_list = []
    connector._send_bundle = MagicMock(return_value="sent")
    connector._update_observable_score = MagicMock()
    connector._collect_intelligence = MagicMock(return_value=[_observable()])
    observable = _observable()
    observable["hashes"] = {"SHA-256": SHA256}
    message = {
        "enrichment_entity": {"entity_type": entity_type, "id": "internal"},
        "stix_objects": [observable],
        "stix_entity": observable,
        "event_type": "enrichment",
    }
    connector.process_message(message)
    return connector


class TestProcessMessage:
    def _client(self):
        client = MagicMock()
        client.query_polyswarm.return_value = {"data": _data(), "errors": []}
        client.download_sample.return_value = (CONTENT, None)
        return client

    def test_off_by_default_never_downloads(self):
        client = self._client()
        _process(False, "StixFile", client)
        client.download_sample.assert_not_called()

    def test_on_adds_artifact_to_bundle(self):
        client = self._client()
        connector = _process(True, "StixFile", client)
        sent = connector._send_bundle.call_args[0][0]
        assert any(o.get("type") == "artifact" for o in sent)

    def test_artifact_entities_are_not_downloaded(self):
        client = self._client()
        _process(True, "Artifact", client)
        client.download_sample.assert_not_called()
