import os
import warnings
from pathlib import Path

from connector_migrator.utils.ast import get_connector_class_name_in_connector


def get_content(connector_path: Path, init_path: Path, entrypoint_path: Path) -> str:
    # Start from main module and try to find connector's main class name from the entrypoint
    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        connector_class_name = get_connector_class_name_in_connector(connector_path)

    absolute_init_path = os.path.dirname(
        os.path.relpath(init_path, entrypoint_path.parent)
    )
    absolute_init_import_path = absolute_init_path.replace(os.sep, ".")
    absolute_init_import_path = absolute_init_import_path.replace("-", "_")
    absolute_init_import = f"from {absolute_init_import_path} import {connector_class_name}, ConnectorSettings"

    connector_type_upper_snake_case = (
        os.path.basename(os.path.dirname(connector_path)).replace("-", "_").upper()
    )

    if os.path.basename(entrypoint_path).endswith("__main__.py"):
        return """import traceback

from pycti import OpenCTIConnectorHelper
{absolute_init_import}

\"\"\"
Entry point of the script

- traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
The traceback includes information about the point in the program where the exception occurred,
which is very useful for debugging purposes.
- exit(1): effective way to terminate a Python program when an error is encountered.
It signals to the operating system and any calling processes that the program did not complete successfully.
\"\"\"
try:
    settings = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config(){connector_playbook_compatible})

    connector = {connector_class_name}(config=settings, helper=helper)
    connector.run()
except Exception:
    traceback.print_exc()
    exit(1)

""".format(
            absolute_init_import=absolute_init_import,
            connector_class_name=connector_class_name or "Connector",
            connector_playbook_compatible=(
                ", playbook_compatible=True"
                if connector_type_upper_snake_case == "INTERNAL_ENRICHMENT"
                else ""
            ),
        )
    else:
        return """import traceback

from pycti import OpenCTIConnectorHelper
{absolute_init_import}

if __name__ == "__main__":
    \"\"\"
    Entry point of the script

    - traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
    The traceback includes information about the point in the program where the exception occurred,
    which is very useful for debugging purposes.
    - exit(1): effective way to terminate a Python program when an error is encountered.
    It signals to the operating system and any calling processes that the program did not complete successfully.
    \"\"\"
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config(){connector_playbook_compatible})

        connector = {connector_class_name}(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)

    """.format(
            absolute_init_import=absolute_init_import,
            connector_class_name=connector_class_name or "Connector",
            connector_playbook_compatible=(
                ", playbook_compatible=True"
                if connector_type_upper_snake_case == "INTERNAL_ENRICHMENT"
                else ""
            ),
        )
