# -*- coding: utf-8 -*-
"""Package entry point so the container can launch with `python -m src`."""

import io
import sys
import traceback

from src.main import main, redact_secrets

if __name__ == "__main__":
    try:
        main()
    except Exception:
        captured = io.StringIO()
        traceback.print_exc(file=captured)
        print(redact_secrets(captured.getvalue()), file=sys.stderr)
        sys.exit(1)
