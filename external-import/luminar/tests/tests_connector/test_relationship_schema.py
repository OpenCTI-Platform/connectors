import pytest
from conftest import RecordingLogger
from luminar_connector.relationship_schema import (
    RelationshipSchema,
    resolve_opencti_type,
)


@pytest.mark.parametrize(
    "stix_object, expected",
    [
        ({"type": "malware"}, "Malware"),
        ({"type": "file"}, "StixFile"),
        ({"type": "threat-actor"}, "Threat-Actor-Group"),
        (
            {"type": "threat-actor", "resource_level": "Individual"},
            "Threat-Actor-Individual",
        ),
        (
            {"type": "threat-actor", "x_opencti_type": "threat-actor-individual"},
            "Threat-Actor-Individual",
        ),
        (
            {"type": "threat-actor", "x_opencti_type": "Threat-Actor"},
            "Threat-Actor-Group",
        ),
        ({"type": "identity"}, "Organization"),
        ({"type": "identity", "identity_class": "class"}, "Sector"),
        ({"type": "identity", "identity_class": "individual"}, "Individual"),
        ({"type": "location", "x_opencti_location_type": "Region"}, "Region"),
        ({"type": "location", "x_opencti_location_type": "Planet"}, None),
        ({"type": "location", "city": "Paris"}, "City"),
        ({"type": "location", "country": "FR"}, "Country"),
        ({"type": "location", "region": "europe"}, "Region"),
        ({"type": "location", "latitude": 1.0, "longitude": 2.0}, "Position"),
        ({"type": "x-custom"}, None),
    ],
)
def test_resolve_opencti_type(stix_object, expected):
    assert resolve_opencti_type(stix_object) == expected


class FakeApi:
    def __init__(self, result=None, error=None):
        self.result, self.error = result, error

    def query(self, _query):
        if self.error:
            raise self.error
        return self.result


def test_from_platform_loads_mapping():
    logger = RecordingLogger()
    api = FakeApi(
        {
            "data": {
                "schemaRelationsTypesMapping": [
                    {"key": "Indicator_Malware", "values": ["indicates"]},
                    {"key": "", "values": ["ignored"]},
                    "not-a-dict",
                ]
            }
        }
    )

    schema = RelationshipSchema.from_platform(api, logger)

    assert schema.available is True
    assert schema.mapping == {"Indicator_Malware": {"indicates"}}
    assert "[CONNECTOR] Loaded OpenCTI relationship schema" in logger.messages("info")


def test_from_platform_failure_disables_check():
    logger = RecordingLogger()

    schema = RelationshipSchema.from_platform(
        FakeApi(error=RuntimeError("denied")), logger
    )

    assert schema.available is False
    assert logger.messages("warning")


def test_is_allowed():
    schema = RelationshipSchema({"Indicator_Malware": {"indicates"}})
    indicator, malware, software = (
        {"type": "indicator"},
        {"type": "malware"},
        {"type": "software"},
    )

    assert schema.is_allowed("related-to", indicator, software) is True
    assert schema.is_allowed("revoked-by", indicator, software) is True
    assert schema.is_allowed("indicates", indicator, malware) is True
    assert schema.is_allowed("indicates", indicator, software) is False
    assert schema.is_allowed("indicates", indicator, {"type": "x-custom"}) is None
    assert RelationshipSchema(None).is_allowed("indicates", indicator, malware) is None
