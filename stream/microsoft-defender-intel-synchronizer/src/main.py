"""Entry point for the Microsoft Defender Intel Synchronizer connector."""

import sys
import traceback

from microsoft_defender_intel_synchronizer_connector.connector import (
    MicrosoftDefenderIntelSynchronizerConnector,
)

if __name__ == "__main__":
    try:
        connector = MicrosoftDefenderIntelSynchronizerConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
