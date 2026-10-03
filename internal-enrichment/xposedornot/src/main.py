# -*- coding: utf-8 -*-
"""Entry point for the XposedOrNot internal-enrichment connector."""

import io
import os
import sys
import traceback

from pycti import OpenCTIConnectorHelper
from src.xposedornot import ConnectorSettings, XposedOrNotConnector
from src.xposedornot.client_api import redact


def configured_secrets() -> list[str | None]:
    """Every secret the connector may have been given, however it was given.

    The environment is read directly, because building the settings is one of
    the things that can fail before `main()` gets anywhere. The settings are
    read as well when they can be, since a token or key supplied through
    `config.yml` never appears in the environment and would otherwise be the
    one secret the redaction did not know about.
    """
    secrets = [os.environ.get("XPOSEDORNOT_API_KEY"), os.environ.get("OPENCTI_TOKEN")]
    try:
        settings = ConnectorSettings()
    except Exception:
        return secrets
    api_key = settings.xposedornot.api_key
    return secrets + [
        settings.opencti.token.get_secret_value(),
        api_key.get_secret_value() if api_key else None,
    ]


def redact_secrets(text: str) -> str:
    """Text with the configured secrets blanked.

    A failure escaping `main()` would otherwise reach stderr without passing
    the redaction every other path goes through, and the connector promises
    that neither the API key nor the platform token appears in anything it
    emits.
    """
    return redact(text, *configured_secrets())


def main() -> None:
    settings = ConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(),
        playbook_compatible=True,
    )
    XposedOrNotConnector(config=settings, helper=helper).run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        captured = io.StringIO()
        traceback.print_exc(file=captured)
        print(redact_secrets(captured.getvalue()), file=sys.stderr)
        sys.exit(1)
