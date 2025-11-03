import os
from pathlib import Path


def get_content(connector_path: Path, init_path: Path) -> str:
    absolute_init_path = os.path.dirname(
        os.path.relpath(init_path, connector_path / "src")
    )
    absolute_init_import_path = absolute_init_path.replace(os.sep, ".")
    absolute_init_import_path = absolute_init_import_path.replace("-", "_")

    return """from {absolute_init_import_path} import ConnectorSettings

__all__ = ["ConnectorSettings"]

    """.format(
        absolute_init_import_path=absolute_init_import_path,
    )
