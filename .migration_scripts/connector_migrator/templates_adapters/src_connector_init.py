import os
from pathlib import Path
import warnings

from connector_migrator.utils.ast import get_connector_class_name_in_connector
from connector_migrator.utils.path import find_file_path

CONNECTOR_IGNORED_SUBDIRECTORIES = [
    "__pycache__",
    "venv",
    "tests",
]


def _get_updated_init_content(
    init_path: Path,
    relative_settings_import: str,
    relative_class_import: str,
    connector_class_name: str,
) -> str:
    init_content = init_path.read_text("utf-8")

    lines = init_content.splitlines()
    if not relative_class_import in init_content:
        lines.insert(0, relative_class_import)
    if not relative_settings_import in init_content:
        lines.insert(0, relative_settings_import)

    # TODO: replace by AST, not working for a lot of connectors
    all_var_index = next(
        (index for index, line in enumerate(lines) if "__all__ =" in line)
    )
    all_vars_str = "\n".join(lines[all_var_index:])

    if connector_class_name not in all_vars_str:
        insert_index = all_vars_str.rfind('"') + 1
        all_vars_str = (
            all_vars_str[:insert_index]
            + f', "{connector_class_name}"'  # add class to __all__ variables
            + all_vars_str[insert_index:]
        )
    if "ConnectorSettings" not in all_vars_str:
        insert_index = all_vars_str.rfind('"') + 1
        all_vars_str = (
            all_vars_str[:insert_index]
            + ', "ConnectorSettings"'  # add ConnectorSettings to __all__ variables
            + all_vars_str[insert_index:]
        )

    lines[all_var_index:] = all_vars_str.split("\n")

    return "\n".join(lines) + "\n"


def _get_init_template_content(
    relative_settings_import: str,
    relative_class_import: str,
    connector_class_name: str,
) -> str:
    return """{relative_class_import}
{relative_settings_import}

__all__ = [
    "{connector_class_name}",
    "ConnectorSettings",
]

""".format(
        relative_settings_import=relative_settings_import,
        relative_class_import=relative_class_import,
        connector_class_name=connector_class_name,
    )


def get_content(connector_path: Path, init_path: Path) -> str:
    connector_class_path = find_file_path(connector_path, "connector.py.tmp")
    settings_path = find_file_path(connector_path, "settings.py.tmp")
    if not connector_class_path or not settings_path:
        raise RuntimeError(
            "Could not find 'connector.py.tmp' or 'settings.py.tmp' file"
        )

    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        connector_class_name = get_connector_class_name_in_connector(connector_path)
        if not connector_class_name:
            raise RuntimeError("Connector's main class not found")

    relative_class_path = os.path.relpath(connector_class_path, init_path.parent)
    relative_class_import_path = relative_class_path.replace(os.sep, ".")
    relative_class_import_path = relative_class_import_path.replace("-", "_")
    relative_class_import_path = relative_class_import_path.rstrip(".py.tmp")
    relative_class_import = (
        f"from .{relative_class_import_path} import {connector_class_name}"
    )

    relative_settings_path = os.path.relpath(settings_path, init_path.parent)
    relative_settings_import_path = relative_settings_path.replace(os.sep, ".")
    relative_settings_import_path = relative_settings_import_path.replace("-", "_")
    relative_settings_import_path = relative_settings_import_path.rstrip(".py.tmp")
    relative_settings_import = (
        f"from .{relative_settings_import_path} import ConnectorSettings"
    )

    if os.path.exists(init_path):
        return _get_updated_init_content(
            init_path,
            relative_settings_import=relative_settings_import,
            relative_class_import=relative_class_import,
            connector_class_name=connector_class_name,
        )
    else:
        return _get_init_template_content(
            relative_settings_import=relative_settings_import,
            relative_class_import=relative_class_import,
            connector_class_name=connector_class_name,
        )
