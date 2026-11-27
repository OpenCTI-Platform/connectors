"""Record each STIX bundle to a JSON file named after its id."""

import os
import tempfile
from pathlib import Path

from stix2.v21 import Bundle

from shared.loader import AbstractLoader


class RecordToFile(AbstractLoader):
    """Write each bundle to ``<directory>/<bundle id>.json``.

    The file holds the bundle's STIX JSON, indented, UTF-8, ending with a
    newline; the same bundle always gives the same bytes. The directory is
    created when missing. The write goes through a temporary file renamed
    into place, so a reader never sees a partial file and a failure leaves the
    destination as it was. An existing file for the same bundle is replaced.
    Write errors (``OSError``) are raised unchanged.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    def path_for(self, bundle: Bundle) -> Path:
        """Return the file ``bundle`` is recorded to."""
        return self.directory / f"{bundle.id}.json"

    def load(self, bundle: Bundle) -> None:
        """Record ``bundle``.

        :raises OSError: if the directory cannot be created or the file
            cannot be written.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self.path_for(bundle)
        text = bundle.serialize(pretty=True) + "\n"
        handle = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.directory,
            prefix=f".{bundle.id}.",
            suffix=".tmp",
            delete=False,
        )
        temporary = Path(handle.name)
        try:
            with handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
