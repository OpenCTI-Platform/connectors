"""Package entry point so the container can launch with `python -m src`."""

import traceback

from src.main import main

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        exit(1)
