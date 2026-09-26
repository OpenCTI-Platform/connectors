# -*- coding: utf-8 -*-
"""Entry point for the XposedOrNot internal-enrichment connector."""

import io
import os
import sys
import traceback

from pycti import OpenCTIConnectorHelper
from src.xposedornot import ConnectorSettings, XposedOrNotConnector
from src.xposedornot.client_api import redact


def redact_secrets(text: str) -> str:
    """Text with the configured secrets blanked.

    A failure escaping `main()` would otherwise reach stderr without passing
    the redaction every other path goes through, and the connector promises
    that neither the API key nor the platform token appears in anything it
    emits. The values come from the environment rather than from the
    settings, because building the settings is one of the things that can
    fail here.
    """
    return redact(
        text,
        os.environ.get("XPOSEDORNOT_API_KEY"),
        os.environ.get("OPENCTI_TOKEN"),
    )


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
