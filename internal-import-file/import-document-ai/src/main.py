"""
OpenCTI ReportImporter connector entrypoint.

Initializes the connector, handles startup and graceful termination.
"""

import sys
import traceback

from reportimporter import ReportImporter


def main() -> None:
    """Start the AI Import Document connector."""
    print("[INFO] Starting AI Import Document Connector...", flush=True)
    try:
        connector = ReportImporter()
        connector.start()  # Blocks until termination signal
    except KeyboardInterrupt:
        print("[INFO] Connector interrupted by user.", flush=True)
        sys.exit(0)
    except Exception as e:
        print(
            f"[ERROR] Unhandled exception in AI Import Document Connector: {e}",
            file=sys.stderr,
            flush=True,
        )
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    finally:
        print("[INFO] Connector shutting down.", flush=True)


if __name__ == "__main__":
    main()
