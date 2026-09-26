# -*- coding: utf-8 -*-
"""Package entry point so the container can launch with `python -m src`."""

import sys
import traceback

from src.main import main

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
