"""Build-time warm-up: pre-generate the stixmarx "~/.stixmarx" cache.

Importing stix2-elevator makes stixmarx build its cache under ``$HOME``. Doing it
at image-build time lets the connector import stix2-elevator at runtime as any
non-root UID without writing to the filesystem (see issue #7152).

All three image variants use this script: the Alpine and FIPS Dockerfiles run it
directly, and the shared UBI9 image runs it via the ``POST_INSTALL`` build hook
declared in ``.build.env``.
"""

from stix2elevator import elevate  # noqa: F401  # pylint: disable=unused-import
