import os
from pathlib import Path


def find_file_path(connector_path: Path, file_name: str) -> Path | None:
    for rootdir, _, files in os.walk(connector_path):
        for file in files:
            if file == file_name:
                return Path(rootdir) / file
