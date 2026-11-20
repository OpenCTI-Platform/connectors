"""IOC storage: the IocStore interface and open_store() (SQLite).

The rest of the code does:
    from common.storage import IocStore, open_store
    store = open_store()
and never imports the database module directly. This file and sqlite_store.py are the
only database-specific code.
"""

from __future__ import annotations

import logging
import os

from common import config

from .base import BASE_ATTRIBUTES, IocStore

DATABASE = "sqlite"
DEFAULT_PATH = os.path.join(config.DATA_DIR, "ioc.db")


def open_store() -> IocStore:
    """Open the SQLite database (DB_SQLITE_PATH, default /data/ioc.db on the data volume)."""
    from .sqlite_store import (  # pylint: disable=import-outside-toplevel
        SqliteIocStore,
    )

    path = (os.getenv("DB_SQLITE_PATH") or "").strip() or DEFAULT_PATH
    logging.getLogger(__name__).debug("Opening SQLite database %s", path)
    return SqliteIocStore(path)


__all__ = ["BASE_ATTRIBUTES", "IocStore", "open_store"]
