import json

import pytest
from mock.mock import patch, MagicMock
import titan_client

from mappers import StixMapper
from .conftest import get_fixture, strip_random_values, get_rest_client_get_side_effect


@patch("titan_client.rest.RESTClientObject")
@pytest.mark.parametrize(
    "input_data_filename, results_filename, girs_names, titan_responses",
    [
        ("indicators_input.json", "indicators_stix.json", {}, []),
        (
            "iocs_input.json",
            "iocs_stix.json",
            {},
            ["titan_client_spotrep.json", "titan_client_inforep.json"],
        ),
        ("yara_input.json", "yara_stix.json", {}, []),
        (
            "cves_input.json",
            "cves_stix.json",
            {"1.0": "Foo", "1.0.1": "Bar", "1.0.2": "Baz"},
            [],
        ),
    ],
)
def test_stix_mapping(
    mock_rest_client_cls,
    input_data_filename,
    results_filename,
    girs_names,
    titan_responses,
):
    mock_rest_client_obj = MagicMock()
    mock_rest_client_obj.GET.side_effect = get_rest_client_get_side_effect(
        *[json.dumps(get_fixture(i)) for i in titan_responses]
    )
    mock_rest_client_cls.side_effect = lambda *a, **kw: mock_rest_client_obj

    input_data = get_fixture(input_data_filename)
    results_expected = get_fixture(results_filename)
    mapper = StixMapper(titan_client.Configuration())

    results = strip_random_values(
        json.loads(mapper.map(input_data, girs_names=girs_names).serialize())
    )

    assert results == strip_random_values(results_expected)
