import logging
from datetime import datetime

import pytest
from intelfinder.api import Intelfinder
from intelfinder.tests.constants import generate_random_key, load_fixture
from intelfinder.transform import TransformIntelFinder2Stix
from intelfinder.utils import (
    create_author,
    format_labels,
    get_cursor_id,
    get_tlp_marking,
)
from pycti import CustomObjectCaseIncident, CustomObjectTask
from stix2 import URL, DomainName, IPv4Address, IPv6Address, Note, UserAccount

LOGGER = logging.getLogger(__name__)
DEFAULT_TLP = "TLP:WHITE"
DEFAULT_LABELS = ["intelfinder", "osint"]
SAMPLE_FIXTURE = "response_sample_alert.json"
AUTHOR = create_author()


def validate_stix_objects(stix_objects, stix_object_type_list):
    """Validate that the STIX objects are of the correct type."""
    # # Tested types
    type_list = list(stix_object_type_list)
    pop_list = list(stix_object_type_list)

    # Test that all objects are of the correct type
    for stix_obj in stix_objects:
        LOGGER.info(f"Testing STIX object: {stix_obj}")
        assert type(stix_obj) in type_list
        if type(stix_obj) in pop_list:
            LOGGER.info(f"Removing STIX object: {type(stix_obj)}")
            pop_list.pop(pop_list.index(type(stix_obj)))
        if "object_marking_refs" in stix_obj and stix_obj.object_marking_refs:
            assert stix_obj.object_marking_refs
            assert (
                get_tlp_marking(DEFAULT_TLP).get("id")
                is stix_obj.object_marking_refs[0]
            )
    assert pop_list == []


@pytest.fixture
def client():
    """Create a RecordedFutureClient instance with a mock token."""
    # Use a mock token for testing
    return Intelfinder(author=AUTHOR, api_key=generate_random_key())


@pytest.fixture
def alerts():
    """Return a alerts from Sample Fixture."""
    return load_fixture(SAMPLE_FIXTURE)


@pytest.fixture
def sample_alert(mocker, client: Intelfinder, alerts):
    """Return a single alert for domain hijacking."""
    mocker.patch.object(client, "_request_data", return_value=alerts)
    sample_alert = client.get_alerts()[0]
    return sample_alert


@pytest.fixture
def sample_alert_record(mocker, client: Intelfinder, alerts):
    """Return a single alert for domain hijacking."""
    mocker.patch.object(client, "_request_data", return_value=alerts)
    sample_alert = client.get_alerts()[1]
    return sample_alert


@pytest.fixture
def transformer(sample_alert):
    """Create a transformer instance."""
    return TransformIntelFinder2Stix(
        author=AUTHOR,
        intelfinder=sample_alert,
        labels=DEFAULT_LABELS,
        object_marking_refs=DEFAULT_TLP,
    )


@pytest.fixture
def transform_record(sample_alert_record):
    """Create a transformer instance."""
    return TransformIntelFinder2Stix(
        author=AUTHOR,
        intelfinder=sample_alert_record,
        labels=DEFAULT_LABELS,
        object_marking_refs=DEFAULT_TLP,
    )


class TestTransformIntelFinder2Stix:
    """Class to support tests for IntelFinder API."""

    def test_init(self, transformer: TransformIntelFinder2Stix, sample_alert):
        assert transformer.intelfinder == sample_alert
        assert transformer.id == get_cursor_id(sample_alert)
        assert (
            transformer.name
            == f'Intelfinder - {sample_alert.get("title")} - {transformer.id}'
        )
        assert transformer.labels == format_labels(DEFAULT_LABELS)
        assert transformer.object_marking_refs
        assert transformer.stix_objects == []
        assert transformer.case_id is None
        assert transformer.created is None
        assert transformer.custom_properties == {
            "x_opencti_labels": transformer.labels,
        }

    def test_case_incident(self, transformer: TransformIntelFinder2Stix):
        transformer._transform_case_incident()
        assert isinstance(transformer.case_id, str)
        assert isinstance(transformer.created, datetime)
        assert isinstance(transformer.custom_properties, dict)
        assert isinstance(transformer.stix_objects[0], CustomObjectCaseIncident)

    def test_transform_task(self, transformer: TransformIntelFinder2Stix):
        transformer._transform_case_incident()
        transformer._transform_task()
        assert isinstance(transformer.stix_objects[1], CustomObjectTask)

    def test_transform_note(self, transformer: TransformIntelFinder2Stix):
        transformer._transform_case_incident()
        transformer._transform_task()
        transformer._transform_note()
        assert isinstance(transformer.stix_objects[2], Note)

    def test_create_user_account(self, transformer: TransformIntelFinder2Stix):
        transformer._create_user_account(
            label="test",
            user_id="test@example.com",
            account_login="test",
            credential="test",
        )
        assert isinstance(transformer.stix_objects[0], UserAccount)
        transformer._create_user_account(
            label="test", account_login="test", credential="test"
        )
        assert isinstance(transformer.stix_objects[1], UserAccount)
        transformer._create_user_account(label="test", credential="test")
        assert isinstance(transformer.stix_objects[2], UserAccount)
        transformer._create_user_account(
            label="test",
        )
        assert len(transformer.stix_objects) == 3

    def test_create_url(self, transformer: TransformIntelFinder2Stix):
        transformer._create_url(
            label="test",
            url="https://example.com",
        )
        assert isinstance(transformer.stix_objects[0], URL)

    def test_create_ip(self, transformer: TransformIntelFinder2Stix):
        transformer._create_ip(
            label="test",
            ip="10.0.0.1",
        )
        assert isinstance(transformer.stix_objects[0], IPv4Address)
        transformer._create_ip(
            label="test",
            ip="2001:db8::1",
        )
        assert isinstance(transformer.stix_objects[1], IPv6Address)
        transformer._create_ip(
            label="test",
            ip="INVALID",
        )
        assert len(transformer.stix_objects) == 2

    def test_create_record(self, transformer: TransformIntelFinder2Stix):
        email = "test@example.com"
        email_2 = "asdf@example.com"
        invalid_email = "invalid"
        password = "Password123!"
        account_login = "test"
        url = "https://example.com"
        test_record_1 = f"Email: {email}\nPassword: {password}\nBreach: Stealer Logs"
        transformer._create_record(
            label="test",
            records=test_record_1,
        )
        assert isinstance(transformer.stix_objects[0], UserAccount)
        assert transformer.stix_objects[0].user_id == email
        assert transformer.stix_objects[0].credential == password
        assert transformer.stix_objects[0].account_login == email

        test_record_2 = f"E-mail: {email}\nPassword: {password}\nusername: {account_login}\nBreach: Stealer Logs"
        transformer._create_record(
            label="test",
            records=test_record_2,
        )
        assert isinstance(transformer.stix_objects[1], UserAccount)
        assert transformer.stix_objects[1].user_id == email
        assert transformer.stix_objects[1].credential == password
        assert transformer.stix_objects[1].account_login == account_login

        test_record_3 = f"E-mail: {email}\nPassword: {password}\nURL: {url}\nusername: {account_login}\nBreach: Stealer Logs"
        transformer._create_record(
            label="test",
            records=test_record_3,
        )
        assert isinstance(transformer.stix_objects[2], URL)
        assert isinstance(transformer.stix_objects[3], UserAccount)
        assert transformer.stix_objects[3].user_id == email
        assert transformer.stix_objects[3].credential == password
        assert transformer.stix_objects[3].account_login == account_login

        test_record_4 = f"E-mails: {email}, {email_2}, {invalid_email}"
        transformer._create_record(
            label="test",
            records=test_record_4,
        )
        assert isinstance(transformer.stix_objects[4], UserAccount)
        assert isinstance(transformer.stix_objects[5], UserAccount)
        assert len(transformer.stix_objects) == 6

    def test_transform_elements(self, transformer: TransformIntelFinder2Stix):
        transformer._transform_case_incident()
        transformer._transform_task()
        transformer._transform_note()
        transformer._transform_elements()
        assert isinstance(transformer.stix_objects[3], DomainName)
        assert isinstance(transformer.stix_objects[4], IPv4Address)
        assert isinstance(transformer.stix_objects[5], IPv4Address)
        assert isinstance(transformer.stix_objects[6], IPv4Address)
        assert isinstance(transformer.stix_objects[5], IPv4Address)
        assert isinstance(transformer.stix_objects[6], IPv4Address)
        assert isinstance(transformer.stix_objects[7], IPv4Address)
        assert isinstance(transformer.stix_objects[8], IPv6Address)
        assert isinstance(transformer.stix_objects[9], URL)

    def test_get_stix_objects(self, transformer: TransformIntelFinder2Stix):
        stix_objects = transformer.get_stix_objects()
        assert len(stix_objects) == 10
        validate_stix_objects(
            stix_objects,
            [
                CustomObjectCaseIncident,
                CustomObjectTask,
                Note,
                DomainName,
                IPv4Address,
                IPv6Address,
                URL,
            ],
        )

    def test_get_stix_objects_record(self, transform_record: TransformIntelFinder2Stix):
        stix_objects = transform_record.get_stix_objects()
        assert len(stix_objects) == 38
        validate_stix_objects(
            stix_objects,
            [CustomObjectCaseIncident, CustomObjectTask, UserAccount, URL, Note],
        )
