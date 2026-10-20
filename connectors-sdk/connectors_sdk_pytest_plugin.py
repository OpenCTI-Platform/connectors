"""pytest plugin of the SDK, active in any test suite where the SDK is installed.

pytest loads this module through the `pytest11` entry point declared in
`pyproject.toml`: connectors need no import and no `conftest.py` code to use it.

It lives outside the `connectors_sdk` package, and imports it only inside the fixtures:
pytest loads entry-point plugins before `pytest-cov` starts, so importing the package
here would report all of its module-level code as not covered.
"""

import pytest

# Marker of the tests that let the SDK own the logging setup, as in production
SDK_JSON_LOGGING_MARKER = "sdk_json_logging"


def pytest_configure(config: pytest.Config) -> None:
    """Register the marker, so that `--strict-markers` accepts it.

    Args:
        config (pytest.Config): pytest's configuration.
    """
    config.addinivalue_line(
        "markers",
        f"{SDK_JSON_LOGGING_MARKER}: let the SDK own the logging setup, as in "
        "production (see `connectors_sdk_pytest_plugin`)",
    )


@pytest.fixture(autouse=True)
def sdk_json_logging_disabled(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leave the logging setup to pytest in every test, so that `caplog` works.

    With JSON logging (the default), the SDK replaces every root handler, pytest's
    capture handlers included. This fixture prevents it in every test, both for the
    setup made by the first record (from the environment) and for the setup made by
    the settings, whatever `opencti.json_logging` says. It does not change the
    environment, so the settings read the same values as without the fixture.

    To test the logging setup of production, mark the test (or the module) with
    `@pytest.mark.sdk_json_logging`.

    Args:
        request (pytest.FixtureRequest): pytest's fixture, to read the test's markers.
        monkeypatch (pytest.MonkeyPatch): pytest's fixture, to undo the changes after
            the test.
    """
    if request.node.get_closest_marker(SDK_JSON_LOGGING_MARKER):
        return

    # Imported here, not at the top: see the module docstring
    from connectors_sdk.logger import configure_logging

    def configure_logging_without_json(
        log_level: str, json_logging: bool = True
    ) -> None:
        configure_logging(log_level=log_level, json_logging=False)

    # Setup made by the first record, before the settings are parsed: skip it, as if
    # already done (setting `OPENCTI_JSON_LOGGING` would change the settings' values)
    monkeypatch.setattr("connectors_sdk.logger._logger._logging_configured", True)
    # Setup made by the settings, whatever `opencti.json_logging` says
    monkeypatch.setattr(
        "connectors_sdk.settings.base_settings.configure_logging",
        configure_logging_without_json,
    )
