class EntityNotInScopeError(Exception):
    """Custom exception for entity not in scope"""


class MaxTlpError(Exception):
    """Custom exception for exceeding maximum TLP level"""


class EntityTypeNotSupportedError(Exception):
    """Custom exception for unsupported entity type"""


class EntityHasNoUsableHashError(Exception):
    """Custom exception for entity having no usable hash"""
