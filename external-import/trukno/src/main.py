import sys
import traceback

from connectors_sdk import ConfigValidationError
from trukno_connector.runtime import main
from trukno_connector.settings import (
    LEGACY_CONFIG_MESSAGE,
    ConnectorSettings,
    LegacyConfigPathError,
)

__all__ = ["ConnectorSettings", "main", "entrypoint"]


def entrypoint() -> int:
    try:
        try:
            settings = ConnectorSettings()
        except LegacyConfigPathError:
            print(LEGACY_CONFIG_MESSAGE, file=sys.stderr)
            return 1
        except (ConfigValidationError, ValueError):
            # SDK validation chains can contain raw inputs, including credentials.
            print(
                "Invalid connector configuration. Check connector-root config.yml "
                "or environment variables against config.yml.sample. "
                "OPENCTI_URL, OPENCTI_TOKEN, CONNECTOR_ID and TRUKNO_API_KEY are required. "
                "CONNECTOR_DURATION_PERIOD must be a positive ISO 8601 duration; "
                "TRUKNO_INTERVAL_MINUTES, if set, must be a positive integer "
                "even when CONNECTOR_DURATION_PERIOD is set.",
                file=sys.stderr,
            )
            return 1
        main(settings=settings)
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(entrypoint())
