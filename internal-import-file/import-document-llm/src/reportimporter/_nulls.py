"""
OpenCTI logging helper integration.
"""


class _NullLogger:  # pylint: disable=too-few-public-methods
    """A no-op logger that ignores all logging calls."""

    def __getattr__(self, _name):
        def _noop(*_args, **_kwargs):
            return None

        return _noop


class _NullHelper:  # pylint: disable=too-few-public-methods
    """A no-op helper with a no-op connector_logger."""

    connector_logger = _NullLogger()
