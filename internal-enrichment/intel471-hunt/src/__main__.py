"""Package entry point so the container can launch with `python -m src`.

The repo-level `tests/test_connector_entrypoint.py` resolves a `python -m X.Y`
command to `X/Y/__main__.py`, so the equivalent `python -m src.main` form reads
as a missing file to it even though it runs. Launching the package instead keeps
that check satisfied.
"""

from .main import main

if __name__ == "__main__":  # pragma: no cover
    main()
