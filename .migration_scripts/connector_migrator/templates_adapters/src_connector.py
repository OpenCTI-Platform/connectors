import os
from pathlib import Path


def get_content(connector_path: Path, settings_path: Path) -> str:
    relative_settings_path = os.path.relpath(settings_path, connector_path.parent)
    relative_settings_import_path = relative_settings_path.replace(os.sep, ".")
    relative_settings_import_path = relative_settings_import_path.replace("-", "_")
    relative_settings_import_path = relative_settings_import_path.rstrip(".py.tmp")
    relative_settings_import = (
        f"from .{relative_settings_import_path} import ConnectorSettings"
    )

    current_content = connector_path.read_text("utf-8")

    return relative_settings_import + "\n" + current_content
