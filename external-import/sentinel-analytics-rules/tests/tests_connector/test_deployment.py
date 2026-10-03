from unittest.mock import MagicMock

import pytest
from conftest import SCHEMA_WITH_DEPLOYED_ON, SCHEMA_WITHOUT_DEPLOYED_ON
from connector.deployment import is_deployed_on_supported


def _helper(result=None, error=None):
    helper = MagicMock()
    if error is not None:
        helper.api.query.side_effect = error
    else:
        helper.api.query.return_value = result
    return helper


def test_platform_with_deployed_on():
    helper = _helper(SCHEMA_WITH_DEPLOYED_ON)
    assert is_deployed_on_supported(helper) is True
    query = helper.api.query.call_args[0][0]
    assert "schemaRelationsTypesMapping" in query


def test_platform_without_deployed_on():
    assert is_deployed_on_supported(_helper(SCHEMA_WITHOUT_DEPLOYED_ON)) is False


@pytest.mark.parametrize(
    "result",
    [
        None,
        {},
        {"data": None},
        {"data": {"schemaRelationsTypesMapping": None}},
        {"data": {"schemaRelationsTypesMapping": ["not-an-entry"]}},
        {
            "data": {
                "schemaRelationsTypesMapping": [
                    {"key": "Indicator_SecurityPlatform", "values": None}
                ]
            }
        },
    ],
)
def test_unexpected_answers_mean_unsupported(result):
    assert is_deployed_on_supported(_helper(result)) is False


def test_query_errors_never_fail_the_run():
    helper = _helper(error=RuntimeError("Unknown field schemaRelationsTypesMapping"))
    assert is_deployed_on_supported(helper) is False
    helper.connector_logger.warning.assert_called_once()
