"""Unit tests for the error handling of ``accenture_connector.connector.ConnectorAccenture``."""

import base64
import io
import json
import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import boto3
import pytest
import stix2
from accenture_connector import ConnectorAccenture
from accenture_connector.client_api import ConnectorClient
from accenture_connector.converter_to_stix import ConverterToStix
from botocore.exceptions import ClientError
from botocore.response import StreamingBody
from connectors_sdk import (
    Criticity,
    ErrorStore,
    ProviderApiAuthenticationError,
    ProviderApiNotFoundError,
)
from pycti import (
    Location,
    OpenCTIApiClient,
    OpenCTIApiWork,
    OpenCTIConnectorHelper,
)
from pydantic import SecretStr


@pytest.fixture(autouse=True)
def empty_error_store():
    """ErrorStore is a singleton: each test starts and ends with an empty store."""
    ErrorStore().clear()
    yield
    ErrorStore().clear()


@pytest.fixture
def config():
    """The connector settings read by ``ConnectorAccenture``."""
    return SimpleNamespace(
        connector=SimpleNamespace(
            name="Accenture ACTI", duration_period=timedelta(hours=1)
        ),
        accenture_acti=SimpleNamespace(
            s3_bucket_name="acti-bucket",
            s3_bucket_region="eu-west-1",
            s3_bucket_access_key=SecretStr("access-key"),
            s3_bucket_secret_key=SecretStr("secret-key"),
            tlp_level="amber+strict",
            relative_import_start_date=timedelta(days=30),
            threat_actor_as_intrusion_set=True,
        ),
    )


@pytest.fixture
def helper():
    """A mock of ``OpenCTIConnectorHelper``, with the attributes it creates in
    ``__init__`` specced explicitly, since ``spec`` cannot see them."""
    helper = MagicMock(spec=OpenCTIConnectorHelper)
    helper.api = MagicMock(spec=OpenCTIApiClient)
    helper.api.work = MagicMock(spec=OpenCTIApiWork)
    helper.connector_logger = MagicMock()
    helper.connect_id = "connector-id"
    helper.connect_name = "Accenture ACTI"
    helper.get_state.return_value = None
    return helper


@pytest.fixture
def client():
    """A mock of a ``ConnectorClient`` instance, on which a test sets what
    ``get_reports`` returns instead of mocking HTTP responses."""
    return MagicMock(spec=ConnectorClient)


@pytest.fixture
def converter_to_stix():
    """A mock of a ``ConverterToStix`` instance."""
    return MagicMock(spec=ConverterToStix)


@pytest.fixture(scope="session")
def s3_client_spec():
    """A real boto3 S3 client, built once since it takes about 2 seconds: boto3
    builds its methods (``get_object``...) at runtime, so ``spec`` needs one."""
    return boto3.client("s3", region_name="eu-west-1")


@pytest.fixture
def s3_client(s3_client_spec):
    """A mock of a boto3 S3 client."""
    return MagicMock(spec=s3_client_spec)


@pytest.fixture
def connector(config, helper, client, converter_to_stix, s3_client):
    """A ``ConnectorAccenture`` whose client, converter and S3 client are the
    ``client``, ``converter_to_stix`` and ``s3_client`` mocks."""
    with (
        patch(
            "accenture_connector.connector.ConnectorClient", return_value=client
        ) as client_class,
        patch(
            "accenture_connector.connector.ConverterToStix",
            return_value=converter_to_stix,
        ) as converter_class,
        patch(
            "accenture_connector.connector.boto3.client", return_value=s3_client
        ) as boto3_client,
    ):
        connector = ConnectorAccenture(config, helper)
        # The S3 client is built lazily: build it while boto3 is patched.
        assert connector.s3_client is s3_client
    client_class.assert_called_once_with(helper, config)
    converter_class.assert_called_once_with(helper, config)
    boto3_client.assert_called_once_with(
        "s3",
        aws_access_key_id="access-key",
        aws_secret_access_key="secret-key",
        region_name="eu-west-1",
    )
    return connector


def test_connector_uses_the_mocked_dependencies(
    connector, helper, client, converter_to_stix, s3_client
):
    assert connector.helper is helper
    assert connector.client is client
    assert connector.converter_to_stix is converter_to_stix
    assert connector.s3_client is s3_client


@pytest.mark.parametrize(
    "exception, expected_error",
    [
        pytest.param(
            ProviderApiAuthenticationError("[API] Error while retrieving token"),
            {
                "code": "api.authentication",
                "message": "[API] Error while retrieving token",
                "criticity": int(Criticity.CRITICAL),
            },
            id="authentication-error",
        ),
        pytest.param(
            ProviderApiNotFoundError("[API] Error while retrieving reports"),
            {
                "code": "api.not_found",
                "message": "[API] Error while retrieving reports",
                "criticity": int(Criticity.CRITICAL),
            },
            id="not-found-error",
        ),
        pytest.param(
            Exception("Unexpected failure"),
            {
                "code": "other.unknown",
                "message": "[Exception] Unexpected failure",
                "criticity": int(Criticity.CRITICAL),
            },
            id="python-exception",
        ),
    ],
)
def test_process_message_returns_the_error_raised_by_the_client(
    connector, helper, client, exception, expected_error
):
    client.get_reports.side_effect = exception

    errors = connector.process_message()

    assert errors == [expected_error]
    client.get_reports.assert_called_once()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_not_called()


REPORT_ID = "report--0f9a3b2e-6c1d-4b8a-9e2f-3a4b5c6d7e8f"
THREAT_ACTOR_ID = "threat-actor--5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
INDICATOR_ID = "indicator--1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
LOCATION_ID = "location--9c8b7a6d-5e4f-4321-9fed-cba987654321"


@pytest.fixture
def acti_bundle():
    """A STIX 2.1 bundle as ``ConnectorClient.get_reports`` returns it: a report
    with its ACTI custom properties and an HTML description, the threat actor and
    the indicator it covers, and their relationships.

    A new bundle for each test, since ``_process_bundle`` changes it in place.
    """
    return {
        "type": "bundle",
        "id": "bundle--7e6d5c4b-3a2f-4e1d-9c0b-a1b2c3d4e5f6",
        "objects": [
            {
                "type": "report",
                "spec_version": "2.1",
                "id": REPORT_ID,
                "created": "2026-11-27T08:00:00.000Z",
                "modified": "2026-11-27T08:00:00.000Z",
                "name": "Ransomware group targets European manufacturers",
                "description": (
                    "<h1>Summary</h1>"
                    "<p>The group gains access through <b>phishing</b> emails.</p>"
                ),
                "published": "2026-11-27T08:00:00.000Z",
                "report_types": ["threat-report"],
                "labels": ["Ransomware"],
                "x_severity": "high",
                "x_threat_type": ["Cyber Crime"],
                "object_refs": [THREAT_ACTOR_ID],
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": THREAT_ACTOR_ID,
                "created": "2026-11-27T08:00:00.000Z",
                "modified": "2026-11-27T08:00:00.000Z",
                "name": "Example Spider",
                "threat_actor_types": ["crime-syndicate"],
                "roles": ["agent"],
                "sophistication": "advanced",
                "personal_motivations": ["personal-gain"],
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": INDICATOR_ID,
                "created": "2026-11-27T08:00:00.000Z",
                "modified": "2026-11-27T08:00:00.000Z",
                "name": "198.51.100.7",
                "pattern": "[ipv4-addr:value = '198.51.100.7']",
                "pattern_type": "stix",
                "valid_from": "2026-11-27T08:00:00.000Z",
            },
            {
                "type": "location",
                "spec_version": "2.1",
                "id": LOCATION_ID,
                "created": "2026-11-27T08:00:00.000Z",
                "modified": "2026-11-27T08:00:00.000Z",
                "name": "Russia",
                "country": "RU",
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f",
                "created": "2026-11-27T08:00:00.000Z",
                "modified": "2026-11-27T08:00:00.000Z",
                "relationship_type": "related-to",
                "source_ref": REPORT_ID,
                "target_ref": INDICATOR_ID,
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--3d4e5f6a-7b8c-4d9e-8f1a-2b3c4d5e6f7a",
                "created": "2026-11-27T08:00:00.000Z",
                "modified": "2026-11-27T08:00:00.000Z",
                "relationship_type": "indicates",
                "source_ref": INDICATOR_ID,
                "target_ref": THREAT_ACTOR_ID,
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--4e5f6a7b-8c9d-4e0f-9a2b-3c4d5e6f7a8b",
                "created": "2026-11-27T08:00:00.000Z",
                "modified": "2026-11-27T08:00:00.000Z",
                "relationship_type": "located-at",
                "source_ref": THREAT_ACTOR_ID,
                "target_ref": LOCATION_ID,
            },
        ],
    }


# A 1x1 PNG image
PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
S3_IMAGE_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def _with_report_description_suffix(bundle, html):
    """Return ``bundle``, its report's HTML description ending with ``html``."""
    report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    report["description"] += html
    return bundle


@pytest.fixture
def acti_bundle_with_s3_image(acti_bundle):
    """The ``acti_bundle``, its report's description showing an image stored in
    the Accenture ACTI S3 bucket, referenced by its SHA-256 hash."""
    return _with_report_description_suffix(
        acti_bundle,
        f'<p><img src="/api/v1/axon/files/by/sha256/{S3_IMAGE_HASH}" /></p>',
    )


@pytest.fixture
def acti_bundle_with_base64_image(acti_bundle):
    """The ``acti_bundle``, its report's description showing an image embedded
    as a base64 data URI."""
    return _with_report_description_suffix(
        acti_bundle,
        f'<p><img src="data:image/png;base64,{PNG_BASE64}" alt="diagram" /></p>',
    )


@pytest.fixture
def acti_bundle_with_corrupted_base64_image(acti_bundle):
    """The ``acti_bundle``, its report's description showing an image embedded
    as a base64 data URI that was truncated, so that it cannot be decoded."""
    return _with_report_description_suffix(
        acti_bundle,
        '<p><img src="data:image/png;base64,iVBORw0KGgo" alt="diagram" /></p>',
    )


@pytest.fixture
def one_interval_run(helper, converter_to_stix):
    """Set up a run whose last run was 10 minutes ago, so that it collects a
    single 30-minute interval, with the ``converter_to_stix`` mock returning real
    STIX objects. Return the author, marking and country entity it returns."""
    last_run = datetime.now(tz=UTC) - timedelta(minutes=10)
    helper.get_state.return_value = {
        "last_run": last_run.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    stix_objects = SimpleNamespace(
        author=ConverterToStix.create_author(),
        marking=ConverterToStix.create_tlp_marking("amber+strict"),
        country=stix2.Location(
            id=Location.generate_id("France", "Country"),
            name="France",
            country="FR",
        ),
    )
    converter_to_stix.create_author.return_value = stix_objects.author
    converter_to_stix.create_tlp_marking.return_value = stix_objects.marking
    converter_to_stix.generate_entities.return_value = {
        "labels": ["ransomware"],
        "entities": [stix_objects.country],
    }
    return stix_objects


def _sent_objects(helper):
    """Return the objects of the bundle sent to OpenCTI, by id."""
    helper.send_stix2_bundle.assert_called_once()
    sent_bundle = json.loads(helper.send_stix2_bundle.call_args.args[0])
    return {obj["id"]: obj for obj in sent_bundle["objects"]}


def test_process_message_sends_the_bundle_returned_by_the_client(
    connector, helper, client, converter_to_stix, acti_bundle, one_interval_run
):
    client.get_reports.return_value = acti_bundle
    author = one_interval_run.author
    marking = one_interval_run.marking
    country = one_interval_run.country

    errors = connector.process_message()

    assert errors == []
    client.get_reports.assert_called_once()
    converter_to_stix.create_tlp_marking.assert_called_once_with("amber+strict")
    converter_to_stix.generate_entities.assert_called_once_with(["Ransomware"])
    objects = _sent_objects(helper)

    # The related-to relationship of the report becomes one of its object_refs
    assert "relationship--2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f" not in objects
    intrusion_set_id = THREAT_ACTOR_ID.replace("threat-actor", "intrusion-set")
    report = objects[REPORT_ID]
    assert report["object_refs"] == [intrusion_set_id, country.id, INDICATOR_ID]
    # The ACTI custom properties become labels, the HTML description markdown
    assert report["labels"] == ["ransomware", "high", "Cyber Crime"]
    assert "x_severity" not in report
    assert "x_threat_type" not in report
    assert "<p>" not in report["description"]
    assert "**phishing**" in report["description"]
    # The threat actor becomes an intrusion set
    assert THREAT_ACTOR_ID not in objects
    intrusion_set = objects[intrusion_set_id]
    assert intrusion_set["type"] == "intrusion-set"
    assert "threat_actor_types" not in intrusion_set
    located_at = objects["relationship--4e5f6a7b-8c9d-4e0f-9a2b-3c4d5e6f7a8b"]
    assert located_at["relationship_type"] == "originates-from"
    assert located_at["source_ref"] == intrusion_set_id
    assert located_at["target_ref"] == LOCATION_ID
    assert objects[INDICATOR_ID]["x_opencti_create_observables"] is True
    # Every object from the source is authored by Accenture and marked with the
    # connector's TLP. The entities generated from the labels are added after,
    # as the converter made them.
    assert author.id in objects
    assert marking.id in objects
    assert objects[country.id] == json.loads(country.serialize())
    for obj in objects.values():
        if obj["id"] == country.id:
            continue
        assert obj["created_by_ref"] == author.id
        assert obj["object_marking_refs"] == [marking.id]
    assert "x_opencti_files" not in objects[REPORT_ID]
    helper.api.work.to_processed.assert_called_once()
    helper.set_state.assert_called()


def test_process_message_attaches_the_s3_image_of_the_report(
    connector,
    helper,
    client,
    s3_client,
    acti_bundle_with_s3_image,
    one_interval_run,
):
    client.get_reports.return_value = acti_bundle_with_s3_image
    png = base64.b64decode(PNG_BASE64)
    # The image is stored as a PNG: the .jpg and .jpeg keys are tried first
    s3_client.get_object.side_effect = [
        ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject"),
        ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject"),
        {
            "Body": StreamingBody(io.BytesIO(png), len(png)),
            "ContentType": "image/png",
        },
    ]

    errors = connector.process_message()

    assert errors == []
    assert s3_client.get_object.call_args_list == [
        call(Bucket="acti-bucket", Key=f"document-images/{S3_IMAGE_HASH}{ext}")
        for ext in (".jpg", ".jpeg", ".png")
    ]
    report = _sent_objects(helper)[REPORT_ID]
    assert report["x_opencti_files"] == [
        {
            "name": f"{S3_IMAGE_HASH}.png",
            "mime_type": "image/png",
            "data": PNG_BASE64,
            "embedded": True,
        }
    ]
    # The link to the ACTI API now points to the file attached to the report
    assert f"embedded/{S3_IMAGE_HASH}.png" in report["description"]
    assert "/api/v1/axon/files" not in report["description"]


def test_process_message_attaches_the_base64_image_of_the_report(
    connector,
    helper,
    client,
    s3_client,
    acti_bundle_with_base64_image,
    one_interval_run,
):
    client.get_reports.return_value = acti_bundle_with_base64_image

    errors = connector.process_message()

    assert errors == []
    s3_client.get_object.assert_not_called()
    report = _sent_objects(helper)[REPORT_ID]
    [image] = report["x_opencti_files"]
    # The image gets a random name
    assert re.fullmatch(r"[0-9a-f]{32}\.png", image["name"])
    assert image == {
        "name": image["name"],
        "mime_type": "image/png",
        "data": PNG_BASE64,
        "embedded": True,
    }
    # The data URI now points to the file attached to the report
    assert f"embedded/{image['name']}" in report["description"]
    assert "data:image/png;base64" not in report["description"]


def test_process_message_reports_a_warning_when_the_s3_image_is_not_found(
    connector,
    helper,
    client,
    s3_client,
    acti_bundle_with_s3_image,
    one_interval_run,
):
    client.get_reports.return_value = acti_bundle_with_s3_image
    s3_client.get_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey"}}, "GetObject"
    )

    errors = connector.process_message()

    # Each extension is tried: the missing keys are not reported one by one
    assert s3_client.get_object.call_count == 7
    assert errors == [
        {
            "code": "data.not_found",
            "message": (
                f"Image not found in S3 for any extension. Hash: {S3_IMAGE_HASH}"
            ),
            "criticity": int(Criticity.WARNING),
        }
    ]
    # The image is skipped: the report is still sent, without it
    report = _sent_objects(helper)[REPORT_ID]
    assert "x_opencti_files" not in report
    assert f"embedded/{S3_IMAGE_HASH}.jpg" in report["description"]
    helper.set_state.assert_called()


def test_process_message_reports_an_error_when_the_access_to_s3_fails(
    connector,
    helper,
    client,
    s3_client,
    acti_bundle_with_s3_image,
    one_interval_run,
):
    client.get_reports.return_value = acti_bundle_with_s3_image
    s3_client.get_object.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "GetObject"
    )

    errors = connector.process_message()

    assert errors == [
        {
            "code": "api.authentication",
            "message": (
                "Access to S3 failed for "
                f"document-images/{S3_IMAGE_HASH}.jpg: AccessDenied. Check the S3 "
                "credentials: they need s3:GetObject and s3:ListBucket on the bucket"
            ),
            "criticity": int(Criticity.CRITICAL),
        }
    ]
    # The other extensions are not tried
    s3_client.get_object.assert_called_once()
    # The image is skipped: the report is still sent, without it
    report = _sent_objects(helper)[REPORT_ID]
    assert "x_opencti_files" not in report
    helper.set_state.assert_called()


def test_process_message_reports_a_warning_when_the_base64_image_is_corrupted(
    connector,
    helper,
    client,
    acti_bundle_with_corrupted_base64_image,
    one_interval_run,
):
    client.get_reports.return_value = acti_bundle_with_corrupted_base64_image

    errors = connector.process_message()

    assert errors == [
        {
            "code": "data.conversion",
            "message": "Failed to process base64 image/png image: Incorrect padding",
            "criticity": int(Criticity.WARNING),
        }
    ]
    # The image is skipped: the report is still sent, without it
    report = _sent_objects(helper)[REPORT_ID]
    assert "x_opencti_files" not in report
    assert "embedded/" not in report["description"]
    helper.set_state.assert_called()


def test_process_message_closes_the_work_in_error_when_the_bundle_cannot_be_sent(
    connector,
    helper,
    client,
    acti_bundle,
    one_interval_run,
):
    client.get_reports.return_value = acti_bundle
    helper.api.work.initiate_work.return_value = "work-id"
    helper.send_stix2_bundle.side_effect = ConnectionError("Connection reset by peer")

    errors = connector.process_message()

    assert errors == [
        {
            "code": "other.unknown",
            "message": "[ConnectionError] Connection reset by peer",
            "criticity": int(Criticity.CRITICAL),
        }
    ]
    # The work does not stay in progress in OpenCTI
    helper.api.work.to_processed.assert_called_once_with(
        "work-id", "Failed to send the bundle: ConnectionError", in_error=True
    )
    # The interval is not marked as collected: the next run collects it again
    helper.set_state.assert_not_called()


def test_process_message_reports_the_send_error_when_the_work_cannot_be_closed(
    connector,
    helper,
    client,
    acti_bundle,
    one_interval_run,
):
    client.get_reports.return_value = acti_bundle
    helper.api.work.initiate_work.return_value = "work-id"
    helper.send_stix2_bundle.side_effect = ConnectionError("Connection reset by peer")
    helper.api.work.to_processed.side_effect = TimeoutError("OpenCTI API timed out")

    errors = connector.process_message()

    # The error returned is the one that made the work fail, not the close error
    assert errors == [
        {
            "code": "other.unknown",
            "message": "[ConnectionError] Connection reset by peer",
            "criticity": int(Criticity.CRITICAL),
        }
    ]
    helper.api.work.to_processed.assert_called_once_with(
        "work-id", "Failed to send the bundle: ConnectionError", in_error=True
    )
    helper.connector_logger.error.assert_any_call(
        "[CONNECTOR] Failed to close the work in error",
        {
            "work_id": "work-id",
            "error": "Connection reset by peer",
            "close_error": "OpenCTI API timed out",
        },
    )
    helper.set_state.assert_not_called()


def test_process_message_reports_the_error_when_the_sent_work_cannot_be_closed(
    connector,
    helper,
    client,
    acti_bundle,
    one_interval_run,
):
    client.get_reports.return_value = acti_bundle
    helper.api.work.initiate_work.return_value = "work-id"
    helper.api.work.to_processed.side_effect = TimeoutError("OpenCTI API timed out")

    errors = connector.process_message()

    assert errors == [
        {
            "code": "other.unknown",
            "message": "[TimeoutError] OpenCTI API timed out",
            "criticity": int(Criticity.CRITICAL),
        }
    ]
    # The bundle was sent: the work is closed as processed, not in error
    helper.send_stix2_bundle.assert_called_once()
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.args[0] == "work-id"
    assert "in_error" not in helper.api.work.to_processed.call_args.kwargs
    # The interval is not marked as collected: the next run sends it again
    helper.set_state.assert_not_called()
