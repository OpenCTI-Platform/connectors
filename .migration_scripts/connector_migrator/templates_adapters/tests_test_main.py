import os
import warnings
from pathlib import Path

from connector_migrator.utils.ast import get_connector_class_name
from connector_migrator.utils.yaml import get_custom_env_var_prefix

ROOT_PATH = Path(__file__).parent.parent.parent.parent  # root of the repo


def _connector_name_lower_snake_case(connector_path: Path) -> str:
    return os.path.basename(connector_path).replace("-", "_").lower()


def _get_test_main_content(connector_parent_directory: str) -> str:
    template_test_main_path = (
        Path(ROOT_PATH)
        / "templates"
        / connector_parent_directory
        / "tests"
        / "test_main.py"
    )

    return template_test_main_path.read_text("utf-8")


def get_content(connector_path: Path, entrypoint_path: Path, init_path: Path) -> str:
    connector_parent_directory = os.path.basename(connector_path.parent)

    connector_config_name = (
        # Get config name from env vars common prefix
        get_custom_env_var_prefix(connector_path)
        # Fallback to connector's basename
        or _connector_name_lower_snake_case(connector_path)
    )

    # Start from main module and try to find connector's main class name from the entrypoint
    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        connector_class_name = get_connector_class_name(connector_path, entrypoint_path)

    absolute_init_path = (
        # Try to find the first common parent directory
        os.path.dirname(os.path.relpath(init_path, entrypoint_path.parent))
        # If not found, then the two files are in the same directory
        or init_path.parent.name
    )
    absolute_init_import_path = absolute_init_path.replace(os.sep, ".")
    absolute_init_import_path = absolute_init_import_path.replace("-", "_")

    test_main_text = _get_test_main_content(connector_parent_directory)
    test_main_text = (
        test_main_text.replace(
            "from connector import ",
            f"from {absolute_init_import_path} import ",
        )
        .replace(
            '"template"',
            f'"{connector_config_name}"',
        )
        .replace(
            "TemplateConnector",
            connector_class_name or "",
        )
    )

    return test_main_text
