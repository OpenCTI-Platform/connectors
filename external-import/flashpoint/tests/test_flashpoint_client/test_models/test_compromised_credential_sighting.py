import pytest
from pydantic import ValidationError
from flashpoint_client.models.compromised_credential_sighting import Breach


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "_header": {"indexed_at": 1742341950},
                "basetypes": ["breach"],
                "breach_type": "credential",
                "created_at": {
                    "date-time": "2025-03-18T23:52:30Z",
                    "timestamp": 1742341950,
                },
                "first_observed_at": {
                    "date-time": "2025-03-18T23:52:30Z",
                    "timestamp": 1742341950,
                },
                "fpid": "test-breach-flashpoint-id",
                "source": "Analyst Research",
                "source_type": "Communities",
                "title": "Test breach title",
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "basetypes": ["breach"],
                "fpid": "test-flashpoint-id",
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_breach_should_accept_valid_input(input_data):
    breach = Breach.model_validate(input_data)

    assert breach.basetypes == input_data.get("basetypes")
    assert breach.fpid == input_data.get("fpid")


@pytest.mark.parametrize(
    "input_data,error_field",
    [
        pytest.param(
            {
                "basetypes": ["invalid_basetype"],
                "fpid": "test-flashpoint-id",
            },
            "basetypes",
            id="invalid_basetypes",
        ),
        pytest.param(
            {
                "basetypes": ["breach"],
                "fpid": None,
            },
            "fpid",
            id="missing_fpid",
        ),
    ],
)
def test_breach_should_not_accept_invalid_input(input_data, error_field):
    with pytest.raises(ValidationError) as err:
        Breach.model_validate(input_data)
    assert str(error_field) in str(err)
