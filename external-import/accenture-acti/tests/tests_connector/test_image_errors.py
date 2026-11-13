from unittest.mock import MagicMock

import pytest
from accenture_connector import ConnectorAccenture
from botocore.exceptions import ClientError
from connectors_sdk import DataConversionError, DataNotFoundError, ErrorStore


@pytest.fixture(autouse=True)
def empty_error_store():
    """ErrorStore is a singleton: each test starts and ends with an empty store."""
    ErrorStore().clear()
    yield
    ErrorStore().clear()


@pytest.fixture
def connector() -> ConnectorAccenture:
    connector = ConnectorAccenture(config=MagicMock(), helper=MagicMock())
    connector._s3_client = MagicMock()
    return connector


def _s3_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code}}, "GetObject")


def test_process_base64_image_returns_the_image(connector):
    image = connector._process_base64_image("image/jpeg", "aGVsbG8=")

    assert image["mime_type"] == "image/jpeg"
    assert image["name"].endswith(".jpg")
    assert image["data"] == "aGVsbG8="
    assert ErrorStore().get_errors() == []


def test_process_base64_image_records_a_conversion_error(connector):
    # Incorrect padding: b64decode raises binascii.Error
    image = connector._process_base64_image("image/png", "abc")

    assert image is None
    errors = ErrorStore().get_errors()
    assert len(errors) == 1
    assert type(errors[0]) is DataConversionError
    assert "image/png" in str(errors[0])


def test_download_image_from_s3_returns_the_image(connector):
    body = MagicMock()
    body.read.return_value = b"hello"
    connector.s3_client.get_object.return_value = {
        "Body": body,
        "ContentType": "image/png",
    }

    image = connector._download_image_from_s3("abc123")

    assert image["name"] == "abc123.jpg"
    assert image["mime_type"] == "image/png"
    assert image["data"] == "aGVsbG8="
    assert ErrorStore().get_errors() == []


def test_download_image_from_s3_records_a_not_found_error(connector):
    connector.s3_client.get_object.side_effect = _s3_error("NoSuchKey")

    image = connector._download_image_from_s3("abc123")

    assert image is None
    errors = ErrorStore().get_errors()
    assert len(errors) == 1
    assert type(errors[0]) is DataNotFoundError
    assert "abc123" in str(errors[0])


def test_download_image_from_s3_records_each_s3_error(connector):
    connector.s3_client.get_object.side_effect = [_s3_error("AccessDenied")] + [
        _s3_error("NoSuchKey")
    ] * 10

    image = connector._download_image_from_s3("abc123")

    assert image is None
    errors = ErrorStore().get_errors()
    assert [type(error) for error in errors] == [DataNotFoundError, DataNotFoundError]
    assert str(errors[0]) == "Error accessing document-images/abc123.jpg: AccessDenied"
    assert "Image not found in S3" in str(errors[1])
