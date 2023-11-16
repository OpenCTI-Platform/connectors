import datetime

import crtsh.core.crtsh_utils


def test_configure_logger():
    assert crtsh.core.crtsh_utils.configure_logger("test")


def test_configure_logger_2():
    logger = crtsh.core.crtsh_utils.configure_logger("test")
    assert logger.level == crtsh.core.crtsh_utils.LOG_LEVEL


def test_convert_to_datetime():
    """Test that convert_to_datetime returns a datetime object. %Y-%m-%dT%H:%M:%S is the default format for datetime.strptime."""
    assert isinstance(
        crtsh.core.crtsh_utils.convert_to_datetime("2021-01-01T00:00:00"),
        datetime.datetime,
    )


def test_convert_to_datetime_exception():
    assert crtsh.core.crtsh_utils.convert_to_datetime("invalid") is None


def test_convert_to_datetime_exception_2():
    assert crtsh.core.crtsh_utils.convert_to_datetime("") is None


def test_convert_to_datetime_exception_3():
    assert crtsh.core.crtsh_utils.convert_to_datetime(None) is None


def test_convert_to_datetime_exception_4():
    assert crtsh.core.crtsh_utils.convert_to_datetime(123) is None


def test_is_valid_uuid():
    assert crtsh.core.crtsh_utils.is_valid_uuid("c9bf9e57-1685-4c89-bafb-ff5af830be8a")


def test_is_valid_uuid_2():
    assert not crtsh.core.crtsh_utils.is_valid_uuid("c9bf9e58")


def test_is_valid_uuid_3():
    assert not crtsh.core.crtsh_utils.is_valid_uuid("")


def test_is_valid_uuid_4():
    assert not crtsh.core.crtsh_utils.is_valid_uuid(None)


def test_is_valid_uuid_5():
    assert not crtsh.core.crtsh_utils.is_valid_uuid(123)


def test_is_valid_stix_id():
    assert crtsh.core.crtsh_utils.is_valid_stix_id(
        "indicator--c9bf9e57-1685-4c89-bafb-ff5af830be8a"
    )


def test_is_valid_stix_id_1():
    assert crtsh.core.crtsh_utils.is_valid_stix_id(
        "x509-certificate--79ecd269-b622-550e-aa7f-7074688fe4f8"
    )


def test_is_valid_stix_id_2():
    assert not crtsh.core.crtsh_utils.is_valid_stix_id("indicator--c9bf9e58")


def test_is_valid_stix_id_3():
    assert not crtsh.core.crtsh_utils.is_valid_stix_id("")


def test_is_valid_stix_id_4():
    assert not crtsh.core.crtsh_utils.is_valid_stix_id(None)


def test_is_valid_stix_id_5():
    assert not crtsh.core.crtsh_utils.is_valid_stix_id(123)


def test_is_valid_stix_id_6():
    assert not crtsh.core.crtsh_utils.is_valid_stix_id(
        "c9bf9e57-1685-4c89-bafb-ff5af830be8a"
    )


def test_is_valid_stix_id_7():
    assert not crtsh.core.crtsh_utils.is_valid_stix_id("c9bf9e58")


def test_is_valid_stix_id_8():
    assert not crtsh.core.crtsh_utils.is_valid_stix_id("indicator--")


def test_is_valid_stix_id_9():
    assert not crtsh.core.crtsh_utils.is_valid_stix_id(
        "indicator--c9bf9e57-1685-4c89-bafb-ff5af830be8a--c9bf9e57-1685-4c89-bafb-ff5af830be8a"
    )
