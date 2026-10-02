"""Find the configuration files of the running connector.

This module imports nothing but the standard library. `connectors_sdk.logger` needs to
read a log level before the settings stack (and `pycti`) is available, and
`connectors_sdk.settings` imports `connectors_sdk.logger`. Keeping these helpers here
gives both a single implementation, without creating a circular import.

The connector is expected to be started from a file, with `python main.py` or
`python -m <module>`. `__main__.__file__` may not be set yet while modules are being
imported, so these helpers must be called at runtime, and never at import time.
"""

from __future__ import annotations

import sys
from pathlib import Path


def get_connector_main_path() -> Path | None:
    """Find the path of the running connector's main module.

    Returns:
        Path | None: The absolute path of `__main__`, or `None` when the process was not
            started from a file (interactive interpreter, `python -c`, some test
            runners).
    """
    main_module = sys.modules.get("__main__")
    main_file = getattr(main_module, "__file__", None) if main_module else None

    return Path(main_file).resolve() if main_file else None


def get_config_yml_path() -> Path | None:
    """Find the `config.yml` file of the running connector.

    Both layouts are supported: `config.yml` next to the main module, and `config.yml`
    one directory above it. The first one wins when both exist.

    Returns:
        Path | None: The path of the `config.yml` file, or `None` when there is none.
    """
    main_path = get_connector_main_path()
    if main_path is None:
        return None

    candidates = (
        main_path.parent / "config.yml",  # connector-dir/src/config.yml (legacy layout)
        main_path.parent.parent / "config.yml",  # connector-dir/config.yml (new layout)
    )

    return next((candidate for candidate in candidates if candidate.is_file()), None)


def get_dot_env_path() -> Path | None:
    """Find the `.env` file of the running connector.

    Returns:
        Path | None: The path of the `.env` file, or `None` when there is none.
    """
    main_path = get_connector_main_path()
    if main_path is None:
        return None

    dot_env_path = main_path.parent.parent / ".env"  # connector-dir/.env

    return dot_env_path if dot_env_path.is_file() else None
