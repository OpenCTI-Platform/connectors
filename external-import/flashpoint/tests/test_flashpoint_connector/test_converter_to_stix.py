import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import stix2
from flashpoint_client.models import CompromisedCredentialSighting
from flashpoint_connector.converter_to_stix import ConverterToStix


def get_data_sample(file_name):
    file_path = Path(__file__).parent.parent.joinpath("data_samples", file_name)
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
    return data


@pytest.fixture
def mock_converter_to_stix() -> ConverterToStix:
    helper = Mock()
    helper.api = Mock()
    # Fake the creation of Author to reproduce ConverterToStix.create_author() behavior
    helper.api.identity.create = Mock(
        return_value={"standard_id": "identity--50b656b6-8aa0-42e3-acf4-e6a6c9bf0ff1"}
    )

    return ConverterToStix(helper=helper)


def test_converter_to_stix_convert_ccm_alert_to_incident(
    mock_converter_to_stix: ConverterToStix,
):
    search_compromised_credential_sighting_response = get_data_sample(
        "search_compromised_credential_sightings_response.json"
    )
    compromised_credential_sighting_data = (
        search_compromised_credential_sighting_response["hits"]["hits"][0]["_source"]
    )

    compromised_credential_sighting = CompromisedCredentialSighting.model_validate(
        compromised_credential_sighting_data
    )

    stix_objects = mock_converter_to_stix.convert_ccm_alert_to_incident(
        alert=compromised_credential_sighting
    )

    assert any(
        [
            stix_object
            for stix_object in stix_objects
            if isinstance(stix_object, stix2.Incident)
        ]
    )
    assert any(
        [
            stix_object
            for stix_object in stix_objects
            if isinstance(stix_object, stix2.EmailAddress)
        ]
    )
    assert any(
        [
            stix_object
            for stix_object in stix_objects
            if isinstance(stix_object, stix2.DomainName)
        ]
    )
    assert any(
        [
            stix_object
            for stix_object in stix_objects
            if isinstance(stix_object, stix2.URL)
        ]
    )
    assert any(
        [
            stix_object
            for stix_object in stix_objects
            if isinstance(stix_object, stix2.UserAccount)
        ]
    )
    assert any(
        [
            stix_object
            for stix_object in stix_objects
            if isinstance(stix_object, stix2.Malware)
        ]
    )
    assert any(
        [
            stix_object
            for stix_object in stix_objects
            if isinstance(stix_object, stix2.MarkingDefinition)
        ]
    )
