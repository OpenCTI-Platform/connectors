import pytest
from src.microsoft_sentinel_incidents_connector.config_variables import ConfigConnector


@pytest.mark.parametrize(
    "input_tags,expected",
    [
        (None, []),
        ("", []),
        ("   ", []),
        ("tag1", ["tag1"]),
        ("tag1,tag2", ["tag1", "tag2"]),
        ("tag1, tag2 ,tag3", ["tag1", "tag2", "tag3"]),
        ("tag1,,tag2", ["tag1", "tag2"]),
        (",tag1,", ["tag1"]),
        ("tag1, , tag2", ["tag1", "tag2"]),
        ("tag1,tag2,tag3", ["tag1", "tag2", "tag3"]),
        ("  tag1  ,  tag2  ", ["tag1", "tag2"]),
        ("tag 1,tag 2", ["tag 1", "tag 2"]),
    ],
)
def test_prepare_tags(input_tags, expected):
    assert ConfigConnector.prepare_tags(input_tags) == expected
