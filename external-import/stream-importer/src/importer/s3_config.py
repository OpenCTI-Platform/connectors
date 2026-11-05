"""S3 settings, read under their ``STREAM_IMPORTER_S3_*`` names or their former
``MINIO_*`` names.

The names carry the connector's section: pycti already reads ``S3_*`` for its own
bundle upload to OpenCTI's storage. The new name wins when both are set. Each
connector builds its own image, so this module is not shared with the
stream-exporter connector, which has its own copy.
"""

import os

PREFIX = "STREAM_IMPORTER_S3_"
FORMER_PREFIX = "MINIO_"


class S3Settings:
    """Reads the S3 settings and remembers the names met on the way."""

    def __init__(self, environ=os.environ):
        self.environ = environ
        self.former_names_used: list[str] = []
        self.names_ignored: list[str] = []

    def get(self, field: str, default=None):
        new_env, former_env = f"{PREFIX}{field}", f"{FORMER_PREFIX}{field}"
        if new_env in self.environ:
            if former_env in self.environ:
                self.names_ignored.append(former_env)
            return self.environ[new_env]
        if former_env in self.environ:
            self.former_names_used.append(former_env)
            return self.environ[former_env]
        return default
