import ast
import os
import warnings
from pathlib import Path

from connector_migrator.utils.ast import (
    get_connector_class_name,
    get_connector_class_file_path,
)


def _get_connector_extra_keyword_args(
    entrypoint_path: Path,
    connector_class_path: Path,
    connector_class_name: str,
) -> list[ast.keyword]:
    connector_content = connector_class_path.read_text("utf-8")
    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        connector_ast = ast.parse(connector_content)

    connector_extra_args: list[ast.arg] = []
    for root_node in connector_ast.body:
        # Look for the class definition
        if (
            isinstance(root_node, ast.ClassDef)
            and root_node.name == connector_class_name
        ):
            # Get class `__init__` function
            for class_node in root_node.body:
                if (
                    isinstance(class_node, ast.FunctionDef)
                    and class_node.name == "__init__"
                ):
                    # Get the extra arguments of the `__init__` function
                    for arg in class_node.args.args:
                        if arg.arg not in ["self", "config", "helper"]:
                            connector_extra_args.append(arg)
                    break

    if not connector_extra_args:
        return []

    entrypoint_content = entrypoint_path.read_text("utf-8")
    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        entrypoint_ast = ast.parse(entrypoint_content)

    def get_connector_args_recursively(tree: ast.AST) -> list[ast.keyword]:
        # Get the variables injected to connector's class during its instantiation
        tree_body = getattr(tree, "body", None)
        if tree_body and isinstance(tree_body, list):
            for node in tree_body:
                if isinstance(node, ast.Assign):
                    # Get the instantiation of the connector class
                    if (
                        isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Name)
                        and node.value.func.id == connector_class_name
                    ):
                        injected_args = []
                        # Get the variables names corresponding to the extra args
                        for keyword in node.value.keywords:
                            if isinstance(keyword.value, ast.Name) and (
                                keyword.arg in [arg.arg for arg in connector_extra_args]
                            ):
                                injected_args.append(keyword)
                        if injected_args:
                            return injected_args
                injected_args = get_connector_args_recursively(node)
                if injected_args:
                    return injected_args
        return []

    return get_connector_args_recursively(entrypoint_ast)


def _get_required_extra_assigments(
    entrypoint_path: Path,
    connector_class_path: Path,
    connector_class_name: str,
) -> list[ast.Assign]:
    injected_args = _get_connector_extra_keyword_args(
        entrypoint_path, connector_class_path, connector_class_name
    )
    assignments_variables_names = [
        keyword.value.id
        for keyword in injected_args
        if isinstance(keyword.value, ast.Name)
    ]
    if not assignments_variables_names:
        return []

    entrypoint_content = entrypoint_path.read_text("utf-8")
    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        entrypoint_ast = ast.parse(entrypoint_content)

    def get_required_assignments_recursively(
        tree: ast.AST, variables_names: list[str]
    ) -> list[ast.Assign]:
        # Get the variables assignments corresponding to the connector's extra args
        required_assignments = []
        tree_body = getattr(tree, "body", None)
        if tree_body and isinstance(tree_body, list):
            for node in tree_body:
                # Get variable assignment where variable name is in injected variables
                if isinstance(node, ast.Assign) and any(
                    [
                        isinstance(target, ast.Name) and target.id in variables_names
                        for target in node.targets
                    ]
                ):
                    required_assignments.append(node)
                else:
                    nested_required_assignments = get_required_assignments_recursively(
                        node, variables_names
                    )
                    if nested_required_assignments:
                        required_assignments.extend(nested_required_assignments)
        return required_assignments

    return get_required_assignments_recursively(
        entrypoint_ast, assignments_variables_names
    )


def _get_extra_imports(
    entrypoint_path: Path,
    connector_class_path: Path,
    connector_class_name: str,
):
    required_assignments = _get_required_extra_assigments(
        entrypoint_path, connector_class_path, connector_class_name
    )
    if not required_assignments:
        return []

    entrypoint_content = entrypoint_path.read_text("utf-8")
    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        entrypoint_ast = ast.parse(entrypoint_content)

    required_imports = []
    for required_assignment in required_assignments:
        if isinstance(required_assignment, ast.Assign):
            if isinstance(required_assignment.value, ast.Call):
                # Get the import corresponding to the required assignments
                if isinstance(required_assignment.value.func, ast.Name):
                    for root_node in entrypoint_ast.body:
                        if isinstance(root_node, ast.ImportFrom) and any(
                            [
                                alias.name == required_assignment.value.func.id
                                for alias in root_node.names
                            ]
                        ):
                            required_imports.append(root_node)

    return [ast.unparse(required_import) for required_import in required_imports]


def _get_extra_variables(
    entrypoint_path: Path,
    connector_class_path: Path,
    connector_class_name: str,
) -> list[str]:
    required_assignments = _get_required_extra_assigments(
        entrypoint_path, connector_class_path, connector_class_name
    )
    if not required_assignments:
        return []

    for required_assignment in required_assignments:
        if isinstance(required_assignment, ast.Assign):
            if isinstance(required_assignment.value, ast.Call):
                # Replace `config` references with `settings`
                for keyword in required_assignment.value.keywords:
                    if (
                        isinstance(keyword.value, ast.Name)
                        and keyword.value.id == "config"
                    ):
                        keyword.value.id = "settings"

    return [
        ast.unparse(required_assignment) for required_assignment in required_assignments
    ]


def _get_extra_keyword_args(
    entrypoint_path: Path,
    connector_class_path: Path,
    connector_class_name: str,
) -> list[str]:
    injected_args = _get_connector_extra_keyword_args(
        entrypoint_path, connector_class_path, connector_class_name
    )

    return [ast.unparse(keyword) for keyword in injected_args]


def _get_main_content(
    absolute_init_import_path: str,
    extra_imports: list[str],
    connector_class_name: str,
    connector_type_upper_snake_case: str,
    extra_variables: list[str],
    extra_connector_keyword_args: list[str],
) -> str:
    return """import traceback

from pycti import OpenCTIConnectorHelper
from {absolute_init_import_path} import {connector_class_name}, ConnectorSettings
{extra_imports}

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
{extra_variables}

        connector = {connector_class_name}(config=settings, helper=helper{extra_connector_keyword_args})
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)

    """.format(
        absolute_init_import_path=absolute_init_import_path,
        extra_imports="\n".join(extra_imports),
        connector_class_name=connector_class_name,
        connector_playbook_compatible=(
            ", playbook_compatible=True"
            if connector_type_upper_snake_case == "INTERNAL_ENRICHMENT"
            else ""
        ),
        extra_variables="\n".join(
            # Indent with 8 spaces to fit in the try block
            ["        " + extra_var for extra_var in extra_variables]
        ),
        extra_connector_keyword_args=(
            ", " + ", ".join(extra_connector_keyword_args)
            if extra_connector_keyword_args
            else ""
        ),
    )


def get_content(connector_path: Path, init_path: Path, entrypoint_path: Path) -> str:
    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        connector_class_name = (
            get_connector_class_name(connector_path, entrypoint_path) or "Connector"
        )
        connector_class_path = get_connector_class_file_path(
            connector_path, entrypoint_path
        )

    if not connector_class_path:
        raise RuntimeError("Could not find connector's main class file path")

    absolute_init_path = (
        # Try to find the first common parent directory
        os.path.dirname(os.path.relpath(init_path, entrypoint_path.parent))
        # If not found, then the two files are in the same directory
        or init_path.parent.name
    )
    absolute_init_import_path = absolute_init_path.replace(os.sep, ".")
    absolute_init_import_path = absolute_init_import_path.replace("-", "_")

    extra_imports = _get_extra_imports(
        entrypoint_path, connector_class_path, connector_class_name
    )

    connector_type_upper_snake_case = (
        os.path.basename(os.path.dirname(connector_path)).replace("-", "_").upper()
    )

    extra_variables = _get_extra_variables(
        entrypoint_path, connector_class_path, connector_class_name
    )
    extra_connector_keyword_args = _get_extra_keyword_args(
        entrypoint_path, connector_class_path, connector_class_name
    )

    return _get_main_content(
        absolute_init_import_path=absolute_init_import_path,
        extra_imports=extra_imports,
        connector_class_name=connector_class_name,
        connector_type_upper_snake_case=connector_type_upper_snake_case,
        extra_variables=extra_variables,
        extra_connector_keyword_args=extra_connector_keyword_args,
    )
