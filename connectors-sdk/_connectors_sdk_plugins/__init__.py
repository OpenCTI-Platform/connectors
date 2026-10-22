"""Plugins of the connectors SDK, for tools such as pytest.

This package is outside `connectors_sdk` because pytest loads its plugins before
pytest-cov starts: a plugin inside `connectors_sdk` would load the whole SDK too early,
and the SDK's coverage would miss it.
"""
