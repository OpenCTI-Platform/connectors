"""Offers a collection of custom exceptions to develop connectors."""


class ConfigError(Exception):
    """Base class for configuration-related errors.

    This exception is raised when there is an issue with the configuration of the connector.
    It can be used to indicate problems such as missing required fields, invalid values, or
    other configuration-related issues that prevent the connector from starting correctly.
    It signals a actionable problem in configuration and allows the user to respond appropriately immediately.
    """


class DataRetrievalError(Exception):
    """Base class for data retrieval-related errors.

    This exception is raised when there is an issue with retrieving data from the source.
    It can be used to indicate problems such as network issues, authentication failures,
    or other data retrieval-related issues that prevent the connector from accessing the required data.
    It is a potentially recoverable custom error that can be used to indicate that the connector is not
    responsible for the encountered error, but rather the data source is.
    """


class UseCaseError(Exception):
    """Base class for processing-related errors.

    This exception is raised when there is an issue with processing the data.
    It indicates that the connector is not handling the process properly.
    This error can be recoverable or skipped in the application layer,
    especially if it is designed to iterate over entities.
    It signals a problem in the connector's logic or implementation that needs to be addressed.
    """
