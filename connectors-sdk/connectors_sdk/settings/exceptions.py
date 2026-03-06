"""Custom exceptions that are raised during _Config and _Settings classes."""


class ConfigError(Exception):
    """Base class for configuration-related errors.

    This exception is raised when there is an issue with the configuration of the connector.
    It can be used to indicate problems such as missing required fields, invalid values, or
    other configuration-related issues that prevent the connector from starting correctly.
    It signals a actionable problem in configuration and allows the user to respond appropriately immediately.
    """


class ConfigValidationError(ConfigError):
    """Base class for configuration validation-related errors.

    This exception is raised when there is an issue with the configuration validation of the connector.
    It can be used to indicate validation problems on the configuration that prevent
    the connector from starting or working correctly.
    """
