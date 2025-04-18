"""Test the dragos application."""

from unittest.mock import Mock, call

from dragos.app import Connector
from dragos.domain.use_cases.common import UseCaseError
from dragos.interfaces.common import DataRetrievalError


def test_connector_initialization():
    """First simple test to cjheck if connector can be instantiated."""
    # Given mocked init params
    mock_config = Mock()
    mock_config.dragos.tlp_level = "green"
    mock_helper = Mock()
    mock_reports = Mock()
    geocoding = Mock()
    # When initializing the Connector
    # Then the connector should be initialized without errors
    _ = Connector(
        config=mock_config,
        helper=mock_helper,
        reports=mock_reports,
        geocoding=geocoding,
    )


def test_connector_should_handle_data_retrieval_error_with_warning():
    """Test that the Connector handles data retrieval errors with a warning."""
    # Given
    # a reports adapters that fails twice with DataRetrievalError
    mock_reports = Mock()

    # iterator class that raise DataRetrievalError
    class FlakyIterator:
        def __init__(self):
            self.n = 0
            pass

        def __iter__(self):
            return self

        def __next__(self):
            if self.n < 2:
                self.n += 1
                raise DataRetrievalError("Test Data retrieval error")
            else:
                raise StopIteration

    mock_reports.iter.return_value = FlakyIterator()

    # and a connector instance
    mock_config = Mock()
    mock_config.dragos.tlp_level = "green"
    mock_helper = Mock()
    geocoding = Mock()
    connector = Connector(
        config=mock_config,
        helper=mock_helper,
        reports=mock_reports,
        geocoding=geocoding,
    )
    connector._initiate_work = Mock()
    connector._acquire_since = Mock()
    connector._finalize_work = Mock()
    # When using the process method
    _ = connector.work()

    # Then the error should be logged as a warning (twice)
    mock_helper.connector_logger.warning.assert_has_calls(
        [call("Skipping report due to Data retrieval error: Test Data retrieval error")]
        * 2
    )


def test_connector_should_use_case_error_with_warning():
    """Test that the Connector handles use case errors with a warning."""

    # Given
    # a _report_processor.run_on method that fails with UsecaseError
    def run_on(report):
        raise UseCaseError("Test Use Case Error")

    # a mock reports.iter returning 2 items
    mock_reports = Mock()
    mock_reports.iter.return_value = iter([Mock(), Mock()])
    # and a connector instance
    mock_config = Mock()
    mock_config.dragos.tlp_level = "green"
    mock_helper = Mock()
    geocoding = Mock()
    connector = Connector(
        config=mock_config,
        helper=mock_helper,
        reports=mock_reports,
        geocoding=geocoding,
    )
    connector._initiate_work = Mock()
    connector._acquire_since = Mock()
    connector._finalize_work = Mock()
    connector._report_processor.run_on = run_on
    # When using the process method
    _ = connector.work()

    # Then the error should be logged as a warning (twice)
    mock_helper.connector_logger.warning.assert_has_calls(
        [call("Skipping report due to Use case error: Test Use Case Error")] * 2
    )
