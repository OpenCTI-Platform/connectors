import pytest
from connectors_sdk.exceptions.error import DataRetrievalError, UseCaseError


def test_data_retrieval_error():
    """Dummy test for DataRetrievalError."""
    # Given a DataRetrievalError instance
    # When raising the exception
    # Then it should raise DataRetrievalError with the correct message
    with pytest.raises(DataRetrievalError):
        raise DataRetrievalError("Data retrieval error occurred")


def test_use_case_error():
    """Dummy test for UseCaseError."""
    # Given a UseCaseError instance
    # When raising the exception
    # Then it should raise UseCaseError with the correct message
    with pytest.raises(UseCaseError):
        raise UseCaseError("Use case error occurred")
