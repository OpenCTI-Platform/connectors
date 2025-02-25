"""Provide tests for dragos.interfaces.config module."""

from abc import ABC
from datetime import datetime, timedelta, timezone

import pytest
from dragos.interfaces.config import (
    ConfigLoader,
    ConfigRetrievalError,
    _ConfigLoaderConnector,
    _ConfigLoaderDragos,
    _ConfigLoaderOCTI,
)
from pydantic import ValidationError


class StubConfigLoaderOCTI(_ConfigLoaderOCTI):
    """Stub adapter for testing purpose."""

    @property
    def _url(self):
        return "http://localhost:8080"

    @property
    def _token(self):
        return "api-token"


class StubConfigLoaderConnector(_ConfigLoaderConnector):
    """Stub adapter for testing purpose."""

    @property
    def _id(self):
        return "uuid"

    @property
    def _name(self):
        return "Stub Connector"

    @property
    def _scope(self):
        return ["stub"]

    @property
    def _log_level(self):
        return "error"

    @property
    def _duration_period(self):
        return "PT5M"

    @property
    def _queue_threshold(self):
        return 0

    @property
    def _run_and_terminate(self):
        return False

    @property
    def _send_to_queue(self):
        return False

    @property
    def _send_to_directory(self):
        return False

    @property
    def _send_to_directory_path(self):
        return "/path/to/dir"

    @property
    def _send_to_directory_retention(self):
        return 0


class StubConfigLoaderDragos(_ConfigLoaderDragos):
    """Stub adapter for testing purpose."""

    @property
    def _api_base_url(self):
        return "http://localhost:8080"

    @property
    def _api_token(self):
        return "api-token"

    @property
    def _import_start_date(self):
        return "1970-01-01T00:00:00Z"

    @property
    def _tlp_level(self):
        return "amber"


class StubConfigLoader(ConfigLoader):
    @property
    def _opencti(self):
        return StubConfigLoaderOCTI()

    @property
    def _connector(self):
        return StubConfigLoaderConnector()

    @property
    def _dragos(self):
        return StubConfigLoaderDragos()


@pytest.mark.parametrize(
    "interface",
    [
        pytest.param(_ConfigLoaderOCTI, id="_ConfigLoaderOCTI"),
        pytest.param(_ConfigLoaderConnector, id="_ConfigLoaderConnector"),
        pytest.param(_ConfigLoaderDragos, id="_ConfigLoaderDragos"),
        pytest.param(ConfigLoader, id="ConfigLoader"),
    ],
)
def test_interface_is_abstract(interface):
    # Given: An interface class
    # When: Checking type of interface
    # Then: It should be a ABC subclass
    assert issubclass(interface, ABC) is True


@pytest.mark.parametrize(
    "implemented_interface_class",
    [
        pytest.param(StubConfigLoaderOCTI, id="_ConfigLoaderOCTI"),
        pytest.param(StubConfigLoaderConnector, id="_ConfigLoaderConnector"),
        pytest.param(StubConfigLoaderDragos, id="_ConfigLoaderDragos"),
        pytest.param(StubConfigLoader, id="ConfigLoader"),
    ],
)
def tests_implemented_interface_attributes_are_read_only(implemented_interface_class):
    """Test that the implemented interface attributes are read-only."""
    # Given: An implemented interface class
    # When: Trying to set an attribute
    # Then: A Validation Error is raised
    with pytest.raises(ValidationError) as exc_info:
        implemented_interface_class().test = "new_type"
        assert "Instance is frozen" in str(  # noqa: S101 we indeed call assert in test
            exc_info.value
        )


def test_config_loader_octi_has_correct_attributes():
    # Given: Valid implementation of _ConfigLoaderOCTI
    # When: Instantiating StubConfigLoaderOCTI
    stub_config_loader_octi = StubConfigLoaderOCTI()

    # Then: The instance should have the correct attributes
    assert (
        str(stub_config_loader_octi.url) == "http://localhost:8080/"
    )  # trailing slash is coming from URL object serialization
    assert stub_config_loader_octi.token.get_secret_value() == "api-token"


def test_config_loader_octi_raises_config_retrieval_error_with_incorrect_attributes():
    # Given: Invalid implementation of _ConfigLoaderOCTI
    class InvalidStubConfigLoaderOCTI(StubConfigLoaderOCTI):
        @property
        def _url(self):
            pass  # should return a string

    # When: instantiating InvalidStubConfigLoaderOCTI
    # Then: A ConfigRetrievalError is raised
    with pytest.raises(ConfigRetrievalError):
        _ = InvalidStubConfigLoaderOCTI()


def test_config_loader_connector_has_correct_attributes():
    # Given: Valid implementation of _ConfigLoaderConnector
    # When: Instantiating StubConfigLoaderConnector
    stub_config_loader_connector = StubConfigLoaderConnector()

    # Then: The instance should have the correct attributes
    assert stub_config_loader_connector.id == "uuid"
    assert stub_config_loader_connector.type == "EXTERNAL_IMPORT"  # hardcoded
    assert stub_config_loader_connector.name == "Stub Connector"
    assert stub_config_loader_connector.scope == ["stub"]
    assert stub_config_loader_connector.log_level == "error"
    assert stub_config_loader_connector.duration_period == timedelta(minutes=5)
    assert stub_config_loader_connector.queue_threshold == 0
    assert stub_config_loader_connector.run_and_terminate is False
    assert stub_config_loader_connector.send_to_queue is False
    assert stub_config_loader_connector.send_to_directory is False
    assert stub_config_loader_connector.send_to_directory_path == "/path/to/dir"
    assert stub_config_loader_connector.send_to_directory_retention == 0


def test_config_loader_connector_raises_config_retrieval_error_with_incorrect_attributes():
    # Given: Invalid implementation of _ConfigLoaderConnector
    class InvalidStubConfigLoaderConnector(StubConfigLoaderConnector):
        @property
        def _id(self):
            pass  # should return a string

    # When: Instantiating InvalidStubConfigLoaderConnector
    # Then: A ConfigRetrievalError is raised
    with pytest.raises(ConfigRetrievalError):
        _ = InvalidStubConfigLoaderConnector()


def test_config_loader_connector_raises_config_retrieval_error_with_incorrect_attributes_combination():
    # Given: Invalid implementation of _ConfigLoaderConnector
    class InvalidStubConfigLoaderConnector(StubConfigLoaderConnector):
        @property
        def _send_to_directory(self):
            return True

        @property
        def _send_to_directory_path(self):
            return None  # A directory path must be provided if send-to-directory flag is True.

    # When: Instantiating InvalidStubConfigLoaderConnector
    # Then: A ConfigRetrievalError is raised
    with pytest.raises(ConfigRetrievalError):
        _ = InvalidStubConfigLoaderConnector()


def test_config_loader_dragos_has_correct_attributes():
    # Given: Valid implementation of _ConfigLoaderDragos
    # When: Instantiating StubConfigLoaderDragos
    stub_config_loader_dragos = StubConfigLoaderDragos()

    # Then: The instance should have the correct attributes
    assert (
        str(stub_config_loader_dragos.api_base_url) == "http://localhost:8080/"
    )  # trailing slash is coming from URL object serialization
    assert stub_config_loader_dragos.api_token.get_secret_value() == "api-token"
    assert stub_config_loader_dragos.import_start_date == datetime(
        1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc
    )
    assert stub_config_loader_dragos.tlp_level == "amber"


def test_config_loader_dragos_raises_config_retrieval_error_with_incorrect_attributes():
    # Given: Invalid implementation of _ConfigLoaderDragos
    class InvalidStubConfigLoaderDragos(StubConfigLoaderDragos):
        @property
        def _api_base_url(self):
            pass  # should return a string

    # When: instantiating InvalidStubConfigLoaderDragos
    # Then: A ConfigRetrievalError is raised
    with pytest.raises(ConfigRetrievalError):
        _ = InvalidStubConfigLoaderDragos()


def test_config_loader_has_correct_attributes():
    # Given: Valida implemenation of ConfigLoader
    # When: Instatiating StubConfig
    stub_config = StubConfigLoader()

    # Then: The instance should have the correct attributes
    assert isinstance(stub_config.opencti, StubConfigLoaderOCTI) is True
    assert isinstance(stub_config.connector, StubConfigLoaderConnector) is True
    assert isinstance(stub_config.dragos, StubConfigLoaderDragos) is True


def test_config_loader_raises_config_retrieval_error_with_incorrect_attributes():
    # Given: Invalid implementation of ConfigLoader
    class InvalidStubConfigLoader(StubConfigLoader):
        @property
        def _opencti(self):
            pass  # should return a _ConfigLoaderOCTI instance

    # When: instantiating InvalidStubConfigLoader
    # Then: A ConfigRetrievalError is raised
    with pytest.raises(ConfigRetrievalError):
        _ = InvalidStubConfigLoader()
