import pytest
from src.microsoft_sentinel_incidents_connector.config_variables import ConfigConnector


@pytest.mark.parametrize(
    "input_filter_labels,expected",
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
def test_prepare_filter_labels(input_filter_labels, expected):
    assert ConfigConnector.prepare_filter_labels(input_filter_labels) == expected
