"""Entry point for the Zetalytics DNS connector.

Also exposes ConfigLoader at the location the config schema generator imports
it from (`src.main`), since the connector code lives in the `zetalytics_dns`
package.
"""

import sys
import traceback

from zetalytics_dns.__main__ import main
from zetalytics_dns.settings import ConfigLoader

__all__ = ["ConfigLoader", "main"]

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
