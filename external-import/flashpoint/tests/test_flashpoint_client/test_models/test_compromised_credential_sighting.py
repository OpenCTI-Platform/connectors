import pytest
from flashpoint_client.models.compromised_credential_sighting import (
    Breach,
    CompromisedCredentialSighting,
    Geopoint,
    InfectedHost,
    InstalledSoftware,
    InternetServiceProvider,
    Location,
    Machine,
    MachineExtraInfo,
    Malware,
    PasswordComplexity,
)
from pydantic import ValidationError


def fake_valid_breach_data() -> dict:
    return {
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
    }


def fake_valid_password_complexity_data() -> dict:
    return {
        "has_lowercase": False,
        "has_number": True,
        "has_symbol": False,
        "has_uppercase": False,
        "length": 10,
        "probable_hash_algorithms": ["Test_hash_algorithm"],
    }


def fake_valid_installed_software() -> list[dict]:
    return [
        {
            "name": "test software",
            "version": "1.2.3.4",
        },
    ]


def fake_valid_internet_service_provider_data() -> dict:
    return {
        "autonomous_system_number": 1234,
        "autonomous_system_organization": "Test autonomous system organization",
        "connection_type": "Test connection type",
        "isp": "Test Internet Service Provider",
        "organization": "Test Organization",
    }


def fake_valid_location_data() -> dict:
    return {
        "accuracy_radius": 20,
        "city_name": "Camaçari",
        "continent_name": "South America",
        "country_name": "Brazil",
        "latitude": -12.619,
        "location": {"lat": -12.619, "lon": -38.2057},
        "longitude": -38.2057,
        "subdivision_1_name": "Bahia",
        "subdivision_2_name": None,
    }


def fake_valid_machine_data() -> dict:
    return {
        "cpu": ["Test CPU"],
        "extra": [
            {
                "key": "cpu cores",
                "value": "6",
            },
        ],
        "gpu": ["Test GPU"],
        "language": ["pt-BR"],
        "os": "Test OS",
        "resolution": "1920x1080",
        "user": "Test User",
    }


def fake_valid_malware_data() -> dict:
    return {
        "family": "Test malware",
        "version": "1.2.3.4",
        "scanned_at": {
            "date-time": "2025-03-18T23:52:30Z",
            "timestamp": 1742341950,
        },
    }


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "basetypes": ["breach"],
                "fpid": "test-flashpoint-id",
            },
            id="minimal_valid_data",
        ),
        pytest.param(
            fake_valid_breach_data(),
            id="full_valid_data",
        ),
    ],
)
def test_breach_should_accept_valid_input(input_data):
    breach = Breach.model_validate(input_data)

    assert breach.basetypes == input_data.get("basetypes")
    assert breach.fpid == input_data.get("fpid")
    assert breach.breach_type == input_data.get("breach_type")  # default is None
    assert breach.source == input_data.get("source")  # default is None
    assert breach.source_type == input_data.get("source_type")  # default is None
    assert breach.title == input_data.get("title")  # default is None


@pytest.mark.parametrize(
    "input_data, error_field",
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
    assert error_field in str(err)


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {},  # all fields are optional
            id="minimal_valid_data",
        ),
        pytest.param(
            fake_valid_password_complexity_data(),
            id="full_valid_data",
        ),
    ],
)
def test_password_complexity_should_accept_valid_input(input_data):
    password_complexity = PasswordComplexity.model_validate(input_data)

    assert password_complexity.has_lowercase == input_data.get(
        "has_lowercase"
    )  # default is None
    assert password_complexity.has_number == input_data.get(
        "has_number"
    )  # default is None
    assert password_complexity.has_symbol == input_data.get(
        "has_symbol"
    )  # default is None
    assert password_complexity.has_uppercase == input_data.get(
        "has_uppercase"
    )  # default is None
    assert password_complexity.length == input_data.get("length")  # default is None
    assert password_complexity.probable_hash_algorithms == input_data.get(
        "probable_hash_algorithms"
    )  # default is None


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "has_lowercase": 1234,  # should be a boolean
                "has_number": True,
                "has_symbol": False,
                "has_uppercase": False,
                "length": 10,
                "probable_hash_algorithms": ["Test_hash_algorithm"],
            },
            "has_lowercase",
            id="invalid_lowercase_type",
        ),
        pytest.param(
            {
                "has_lowercase": True,
                "has_number": True,
                "has_symbol": False,
                "has_uppercase": False,
                "length": 10,
                "probable_hash_algorithms": "Test_hash_algorithm",  # should be a list
            },
            "probable_hash_algorithms",
            id="invalid_probable_hash_algorithms_type",
        ),
    ],
)
def test_password_complexity_should_not_accept_invalid_input(input_data, error_field):
    with pytest.raises(ValidationError) as err:
        PasswordComplexity.model_validate(input_data)
    assert error_field in str(err)


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "fpid": "flashpoint-test-id",
            },
            id="minimal_valid_data",
        ),
        pytest.param(
            {
                "fpid": "flashpoint-test-id",
                "installed_software": fake_valid_installed_software(),
                "isp": fake_valid_internet_service_provider_data(),
                "location": fake_valid_location_data(),
                "machine": fake_valid_machine_data(),
                "malware": fake_valid_malware_data(),
            },
            id="full_valid_data",
        ),
    ],
)
def test_infected_host_should_accept_valid_input(input_data):
    infected_host = InfectedHost.model_validate(input_data)

    assert infected_host.fpid == input_data.get("fpid")

    assert infected_host.installed_software == [] or isinstance(
        infected_host.installed_software[0], InstalledSoftware
    )  # default is []
    assert infected_host.machine is None or isinstance(
        infected_host.machine, Machine
    )  # default is None
    assert infected_host.malware is None or isinstance(
        infected_host.malware, Malware
    )  # default is None
    assert infected_host.isp is None or isinstance(
        infected_host.isp, InternetServiceProvider
    )  # default is None
    assert infected_host.location is None or isinstance(
        infected_host.location, Location
    )  # default is None


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "installed_software": fake_valid_installed_software(),
                "machine": fake_valid_machine_data(),
                "malware": fake_valid_malware_data(),
            },
            "fpid",
            id="missing_fpid",
        ),
        pytest.param(
            {
                "fpid": "flashpoint-test-id",
                "installed_software": 1234,  # should be a list of dicts
            },
            "installed_software",
            id="invalid_installed_software_type",
        ),
    ],
)
def test_infected_host_should_not_accept_invalid_input(input_data, error_field):
    with pytest.raises(ValidationError) as err:
        InfectedHost.model_validate(input_data)
    assert error_field in str(err)


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {},  # all fields are optional
            id="minimal_valid_data",
        ),
        pytest.param(
            fake_valid_internet_service_provider_data(),
            id="full_valid_data",
        ),
    ],
)
def test_internet_service_provider_should_accept_valid_input(input_data):
    internet_service_provider = InternetServiceProvider.model_validate(input_data)

    assert internet_service_provider.autonomous_system_number == input_data.get(
        "autonomous_system_number"
    )  # default is None
    assert internet_service_provider.autonomous_system_organization == input_data.get(
        "autonomous_system_organization"
    )  # default is None
    assert internet_service_provider.connection_type == input_data.get(
        "connection_type"
    )  # default is None
    assert internet_service_provider.isp == input_data.get("isp")  # default is None
    assert internet_service_provider.organization == input_data.get(
        "organization"
    )  # default is None


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "autonomous_system_number": "invalid_number",  # should be a int
                "autonomous_system_organization": "Test autonomous system organization",
                "connection_type": "Test connection type",
                "isp": "Test InternetServiceProvider",
                "organization": "Test Organization",
            },
            "autonomous_system_number",
            id="invalid_autonomous_system_number_type",
        ),
    ],
)
def test_internet_service_provider_should_not_accept_invalid_input(
    input_data, error_field
):
    with pytest.raises(ValidationError) as err:
        InternetServiceProvider.model_validate(input_data)
    assert error_field in str(err)


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {},  # all fields are optional
            id="minimal_valid_data",
        ),
        pytest.param(
            fake_valid_location_data(),
            id="full_valid_data",
        ),
    ],
)
def test_location_should_accept_valid_input(input_data):
    location = Location.model_validate(input_data)

    assert location.accuracy_radius == input_data.get(
        "accuracy_radius"
    )  # default is None
    assert location.city_name == input_data.get("city_name")  # default is None
    assert location.continent_name == input_data.get(
        "continent_name"
    )  # default is None
    assert location.country_name == input_data.get("country_name")  # default is None
    assert location.latitude == input_data.get("latitude")  # default is None
    assert location.longitude == input_data.get("longitude")  # default is None
    assert location.subdivision_1_name == input_data.get(
        "subdivision_1_name"
    )  # default is None
    assert location.subdivision_2_name == input_data.get(
        "subdivision_2_name"
    )  # default is None
    assert location.location is None or isinstance(
        location.location, Geopoint
    )  # default is None


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "accuracy_radius": "invalid_radius",  # should be an int
                "city_name": "Camaçari",
                "continent_name": "South America",
                "country_name": "Brazil",
                "latitude": -12.619,
                "location": {"lat": -12.619, "lon": -38.2057},
                "longitude": -38.2057,
                "subdivision_1_name": "Bahia",
            },
            "accuracy_radius",
            id="invalid_accuracy_radius",
        ),
    ],
)
def test_location_should_not_accept_invalid_input(input_data, error_field):
    with pytest.raises(ValidationError) as err:
        Location.model_validate(input_data)
    assert error_field in str(err)


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {},  # all fields are optional
            id="minimal_valid_data",
        ),
        pytest.param(
            fake_valid_machine_data(),
            id="full_valid_data",
        ),
    ],
)
def test_machine_should_accept_valid_input(input_data):
    machine = Machine.model_validate(input_data)

    assert machine.cpu == input_data.get("cpu", [])  # default is []
    assert machine.gpu == input_data.get("gpu", [])  # default is []
    assert machine.language == input_data.get("language", [])  # default is []
    assert machine.os == input_data.get("os")  # default is None
    assert machine.resolution == input_data.get("resolution")  # default is None
    assert machine.user == input_data.get("user")  # default is None
    assert machine.extra == [] or isinstance(
        machine.extra[0], MachineExtraInfo
    )  # default is []


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "cpu": 1234,  # should be a list of str
                "extra": [
                    {
                        "key": "cpu cores",
                        "value": "6",
                    },
                ],
                "gpu": ["Test GPU"],
                "language": ["pt-BR"],
                "os": "Test OS",
                "resolution": "1920x1080",
                "user": "Test User",
            },
            "cpu",
            id="invalid_cpu_type",
        ),
        pytest.param(
            {
                "cpu": ["Test CPU"],
                "extra": [
                    "invalid_item",  # should be a dict
                ],
                "gpu": ["Test GPU"],
                "language": ["pt-BR"],
                "os": "Test OS",
                "resolution": "1920x1080",
                "user": "Test User",
            },
            "extra",
            id="invalid_extra_item",
        ),
    ],
)
def test_machine_should_not_accept_invalid_input(input_data, error_field):
    with pytest.raises(ValidationError) as err:
        Machine.model_validate(input_data)
    assert error_field in str(err)


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {},  # all fields are optional
            id="minimal_valid_data",
        ),
        pytest.param(
            fake_valid_malware_data(),
            id="full_valid_data",
        ),
    ],
)
def test_malware_should_accept_valid_input(input_data):
    malware = Malware.model_validate(input_data)

    assert malware.family == input_data.get("family")  # default is None
    assert malware.version == input_data.get("version")  # default is None


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "family": "Test malware",
                "version": "1.2.3.4",
                "scanned_at": {
                    "date-time": "invalid_date_time",  # should be ISO 8601
                    "timestamp": 1742341950,
                },
            },
            "scanned_at",
            id="invalid_scanned_at_type",
        ),
        pytest.param(
            {
                "family": "Test malware",
                "version": 12.34,  # should be a str
                "scanned_at": {
                    "date-time": "2025-03-18T23:52:30Z",
                    "timestamp": 1742341950,
                },
            },
            "version",
            id="invalid_version_type",
        ),
    ],
)
def test_malware_should_not_accept_invalid_input(input_data, error_field):
    with pytest.raises(ValidationError) as err:
        Malware.model_validate(input_data)
    assert error_field in str(err)


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "basetypes": ["credential-sighting"],
                "body": {
                    "raw": "https://www.example.com/login:test@example.com:testpassword"
                },
                "breach": fake_valid_breach_data(),
                "credential_record_fpid": "credential-flashpoint-test-id",
                "fpid": "flashpoint-test-id",
                "header_": {},
                "is_fresh": True,
                "password": "testpassword",
                "password_complexity": fake_valid_password_complexity_data(),
                "times_seen": 1,
                "username": "test@example.com",
            },
            id="minimal_valid_data",
        ),
        pytest.param(  # fake response of /search endpoint (contains extra fields)
            {
                "affected_domain": "www.example.com",
                "affected_url": "https://www.example.com/login",
                "basetypes": ["credential-sighting"],
                "body": {
                    "raw": "https://www.example.com/login:test@example.com:testpassword"
                },
                "breach": fake_valid_breach_data(),
                "credential_record_fpid": "credential-flashpoint-test-id",
                "customer_id": "customer-test-id",
                "domain": "example.com",
                "email": "test@example.com",
                "extraction_id": "extraction-test-id",
                "extraction_record_id": "extraction-record-test-id",
                "fpid": "flashpoint-test-id",
                "header_": {"indexed_at": 1742468845, "pipeline_duration": 63909688045},
                "heuristics": {
                    "heuristics_version": "2.18.0",
                    "probable_enterprise_host": False,
                },
                "infected_host_attributes": {
                    "fpid": "flashpoint-test-id",
                    "installed_software": fake_valid_installed_software(),
                    "machine": fake_valid_machine_data(),
                    "malware": fake_valid_malware_data(),
                    "isp": fake_valid_internet_service_provider_data(),
                    "location": fake_valid_location_data(),
                },
                "is_fresh": True,
                "last_observed_at": {
                    "date-time": "2025-03-20T10:01:52Z",
                    "timestamp": 1742464912,
                },
                "password": "testpassword",
                "password_complexity": fake_valid_password_complexity_data(),
                "times_seen": 1,
                "username": "test@example.com",
            },
            id="full_valid_data",
        ),
    ],
)
def test_compromised_credential_sighting_should_accept_valid_input(input_data):
    compromised_credential_sighting = CompromisedCredentialSighting.model_validate(
        input_data
    )

    assert compromised_credential_sighting.fpid == input_data.get(
        "fpid"
    )  # default is None
    assert compromised_credential_sighting.credential_record_fpid == input_data.get(
        "credential_record_fpid"
    )  # default is None
    assert compromised_credential_sighting.password == input_data.get(
        "password"
    )  # default is None
    assert compromised_credential_sighting.username == input_data.get(
        "username"
    )  # default is None
    assert compromised_credential_sighting.times_seen == input_data.get(
        "times_seen"
    )  # default is None
    assert compromised_credential_sighting.is_fresh == input_data.get(
        "is_fresh"
    )  # default is None

    assert isinstance(compromised_credential_sighting.breach, Breach)
    assert isinstance(
        compromised_credential_sighting.password_complexity, PasswordComplexity
    )
    assert compromised_credential_sighting.infected_host is None or isinstance(
        compromised_credential_sighting.infected_host, InfectedHost
    )  # default is None


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "basetypes": ["credential-sighting"],
                "body": {
                    "raw": "https://www.example.com/login:test@example.com:testpassword"
                },
                "breach": fake_valid_breach_data(),
                "credential_record_fpid": "credential-flashpoint-test-id",
                "header_": {"indexed_at": 1742468845, "pipeline_duration": 63909688045},
                "is_fresh": True,
                "password": "testpassword",
                "password_complexity": fake_valid_password_complexity_data(),
                "times_seen": 1,
                "username": "test@example.com",
            },
            "fpid",
            id="missing_fpid",
        ),
        pytest.param(
            {
                "basetypes": ["credential-sighting"],
                "body": {
                    "raw": "https://www.example.com/login:test@example.com:testpassword"
                },
                "breach": 1234,  # should be a valid dict
                "credential_record_fpid": "credential-flashpoint-test-id",
                "fpid": "flashpoint-test-id",
                "header_": {"indexed_at": 1742468845, "pipeline_duration": 63909688045},
                "is_fresh": True,
                "password": "testpassword",
                "password_complexity": fake_valid_password_complexity_data(),
                "times_seen": 1,
                "username": "test@example.com",
            },
            "breach",
            id="invalid_breach",
        ),
        pytest.param(
            {
                "basetypes": ["credential-sighting"],
                "body": {
                    "raw": "https://www.example.com/login:test@example.com:testpassword"
                },
                "breach": fake_valid_breach_data(),
                "credential_record_fpid": "credential-flashpoint-test-id",
                "fpid": "flashpoint-test-id",
                "_header_": {  # key should be header_ and not _header_
                    "indexed_at": 1742468845,
                    "pipeline_duration": 63909688045,
                },
                "is_fresh": True,
                "password": "testpassword",
                "password_complexity": fake_valid_password_complexity_data(),
                "times_seen": 1,
                "username": "test@example.com",
            },
            "header",
            id="invalid_header_key",
        ),
    ],
)
def test_compromised_credential_sighting_should_not_accept_invalid_input(
    input_data, error_field
):
    with pytest.raises(ValidationError) as err:
        CompromisedCredentialSighting.model_validate(input_data)
    assert error_field in str(err)
