import os
from pathlib import Path


def get_content(connector_path: Path, connector_tests_directory_path: Path) -> str:
    tests_relative_path_segments = os.path.split(
        os.path.relpath(connector_path / "src", connector_tests_directory_path)
    )
    tests_relative_path_segments_strings = [
        f'"{segment}"' for segment in tests_relative_path_segments
    ]

    return """import os
import sys


sys.path.append(os.path.join(os.path.dirname(__file__), {path_segments}))
""".format(
        path_segments=", ".join(tests_relative_path_segments_strings)
    )
