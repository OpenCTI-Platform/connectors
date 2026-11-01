from unittest.mock import MagicMock

import pytest
from s3 import S3Connector


def _connector(author="ACME"):
    connector = S3Connector.__new__(S3Connector)
    connector.helper = MagicMock()
    connector.s3_author = author
    return connector


def test_no_author_creates_no_identity():
    connector = _connector(author=None)

    assert connector._create_author_identity() is None
    connector.helper.api.identity.create.assert_not_called()


def test_author_identity_is_returned_when_created():
    connector = _connector()
    identity = {"id": "id-1", "standard_id": "identity--1"}
    connector.helper.api.identity.create.return_value = identity

    assert connector._create_author_identity() == identity
    connector.helper.api.identity.create.assert_called_once_with(
        type="Organization", name="ACME"
    )


@pytest.mark.parametrize(
    "create_kwargs",
    [
        {"side_effect": ValueError("You are not allowed to do this.")},
        {"return_value": None},
    ],
)
def test_identity_creation_failure_is_logged_and_stops(create_kwargs):
    """A refused creation gives an explicit error, not a silent termination."""
    connector = _connector()
    connector.helper.api.identity.create.configure_mock(**create_kwargs)

    with pytest.raises(RuntimeError, match="Unable to create the author identity"):
        connector._create_author_identity()

    connector.helper.connector_logger.error.assert_called_once()
    _, context = connector.helper.connector_logger.error.call_args.args
    assert context["author"] == "ACME"
