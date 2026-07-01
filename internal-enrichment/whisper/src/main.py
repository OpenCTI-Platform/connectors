"""Entry point for the Whisper OpenCTI connector.

Constructs:

1. ``ConnectorSettings`` — the connectors-sdk ``BaseConnectorSettings`` model,
   which loads the ``opencti:`` / ``connector:`` / ``whisper:`` config from env
   vars and the optional ``config.yml`` and validates it. ``to_helper_config()``
   produces the dict ``OpenCTIConnectorHelper`` consumes.
2. ``OpenCTIConnectorHelper`` with ``playbook_compatible=True`` — required
   by the v7 internal-enrichment callback contract (issue #65).

Then hands both to ``WhisperConnector.run()``. Wrapped in
``try/traceback/sys.exit(1)`` so Docker reports the container as
``Exited (1)`` on any startup failure rather than silently looping.

``OpenCTIConnectorHelper`` health-checks the platform on construction and
raises ``ValueError`` if it isn't reachable. On a fresh stack the connector
boots before OpenCTI's GraphQL API is ready (Elasticsearch init takes a few
minutes), so we retry that construction quietly via ``_build_helper`` instead
of crash-looping with a full traceback on every restart.
"""

import logging
import os
import sys
import time
import traceback

from connector.connector import WhisperConnector
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

logger = logging.getLogger("whisper.main")

# Startup retry budget for the OpenCTI connection. Defaults give ~10 minutes
# (120 × 5s) — generous enough for a cold OpenCTI/Elasticsearch boot, while
# still surfacing a genuinely misconfigured/unavailable platform eventually.
# Overridable via env for slower or faster environments.
_STARTUP_MAX_RETRIES = int(os.environ.get("OPENCTI_STARTUP_MAX_RETRIES", "120"))
_STARTUP_RETRY_DELAY = int(os.environ.get("OPENCTI_STARTUP_RETRY_DELAY", "5"))


def _build_helper(
    yaml_config: dict,
    max_retries: int | None = None,
    retry_delay: int | None = None,
) -> OpenCTIConnectorHelper:
    """Construct the helper, retrying while the OpenCTI API is still booting.

    pycti raises ``ValueError("OpenCTI API is not reachable...")`` when the
    platform isn't up yet. That's expected on stack startup, so we retry with
    a fixed delay (clean one-line warnings, no traceback) until OpenCTI
    answers or the retry budget is exhausted. Configuration errors (missing
    URL/token) carry a different message and are re-raised immediately rather
    than retried pointlessly.
    """
    max_retries = _STARTUP_MAX_RETRIES if max_retries is None else max_retries
    retry_delay = _STARTUP_RETRY_DELAY if retry_delay is None else retry_delay

    # pycti's health check logs the underlying connection failure at ERROR
    # with a full traceback (logger name "api") on every attempt. Mute it for
    # the duration of the startup wait so the logs show only our clean
    # one-line retry warnings; restore it once OpenCTI answers (or we give up)
    # so genuine API errors during normal operation are still reported.
    api_logger = logging.getLogger("api")
    prior_level = api_logger.level
    api_logger.setLevel(logging.CRITICAL)
    try:
        for attempt in range(1, max_retries + 1):
            try:
                return OpenCTIConnectorHelper(yaml_config, playbook_compatible=True)
            except ValueError as exc:
                transient = "not reachable" in str(exc).lower()
                if not transient or attempt >= max_retries:
                    raise
                logger.warning(
                    "OpenCTI API not reachable yet (attempt %d/%d) — "
                    "retrying in %ds. Detail: %s",
                    attempt,
                    max_retries,
                    retry_delay,
                    exc,
                )
                time.sleep(retry_delay)
    finally:
        api_logger.setLevel(prior_level)
    # The loop either returns or raises; this satisfies type checkers.
    raise RuntimeError("exhausted OpenCTI startup retries")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = ConnectorSettings()
    helper = _build_helper(settings.to_helper_config())
    WhisperConnector(helper=helper, config=settings).run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
