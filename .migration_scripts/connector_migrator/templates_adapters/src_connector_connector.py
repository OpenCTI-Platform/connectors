import os
import ast
from pathlib import Path
import warnings

from connector_migrator.utils.ast import get_connector_class_name
from connector_migrator.utils.path import find_file_path


def get_content(
    connector_path: Path, settings_path: Path, init_path: Path, entrypoint_path: Path
) -> str:
    connector_class_path = find_file_path(connector_path, "connector.py.tmp")
    if not connector_class_path:
        raise RuntimeError("Could not find 'connector.py.tmp' file")

    connector_class_name = get_connector_class_name(connector_path, entrypoint_path)
    if not connector_class_name:
        raise RuntimeError("Could not find connector's main class name")

    absolute_settings_path = os.path.relpath(settings_path, connector_path / "src")
    absolute_settings_import_path = absolute_settings_path.replace(os.sep, ".")
    absolute_settings_import_path = absolute_settings_import_path.replace("-", "_")
    absolute_settings_import_path = absolute_settings_import_path.rstrip(".py.tmp")

    absolute_init_path = os.path.dirname(
        os.path.relpath(init_path, connector_path / "src")
    )
    absolute_init_import_path = absolute_init_path.replace(os.sep, ".")
    absolute_init_import_path = absolute_init_import_path.replace("-", "_")

    class ConnectorTransformer(ast.NodeTransformer):
        def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.ImportFrom | None:
            # Remove existing imports of ConnectorSettings
            if any([alias.name == "ConnectorSettings" for alias in node.names]):
                return None  # remove node

            # Update absolute imports of classes declared in __init__.py (replaced by common.py.tmp)
            if node.module == absolute_init_import_path and node.level == 0:
                common_path = find_file_path(connector_path, "common.py.tmp")
                if common_path:
                    absolute_common_path = os.path.relpath(
                        common_path, connector_path / "src"
                    )
                    absolute_common_import_path = absolute_common_path.replace(
                        os.sep, "."
                    )
                    absolute_common_import_path = absolute_common_import_path.replace(
                        "-", "_"
                    )
                    absolute_common_import_path = absolute_common_import_path.rstrip(
                        ".py.tmp"
                    )
                    node.module = absolute_common_import_path

            # Update relative imports of classes declared in __init__.py (replaced by common.py.tmp)
            if node.module is None and node.level == 1:
                common_path = find_file_path(connector_path, "common.py.tmp")
                if common_path:
                    relative_common_path = os.path.relpath(
                        common_path, connector_class_path.parent
                    )
                    relative_common_import_path = relative_common_path.replace(
                        os.sep, "."
                    )
                    relative_common_import_path = relative_common_import_path.replace(
                        "-", "_"
                    )
                    relative_common_import_path = relative_common_import_path.rstrip(
                        ".py.tmp"
                    )
                    node.module = relative_common_import_path

            return node

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
            # Update existing connector's main class
            if node.name != connector_class_name:
                return node

            for class_node in node.body:
                if (
                    isinstance(class_node, ast.FunctionDef)
                    and class_node.name == "__init__"
                ):
                    init_args = []

                    # Re-order existing arguments
                    for function_arg in class_node.args.args:
                        if function_arg.arg == "self":
                            init_args.insert(0, function_arg)
                        elif function_arg.arg == "config":
                            function_arg.annotation = ast.Name("ConnectorSettings")
                            init_args.insert(1, function_arg)
                        elif function_arg.arg == "helper":
                            function_arg.annotation = ast.Name("OpenCTIConnectorHelper")
                            init_args.insert(2, function_arg)
                        else:
                            init_args.append(function_arg)

                    # Add missing `config` and `helper` arguments if not present
                    if not any([arg.arg == "config" for arg in init_args]):
                        init_args.append(
                            ast.arg("config", ast.Name("ConnectorSettings"))
                        )
                    if not any([arg.arg == "helper" for arg in init_args]):
                        init_args.append(
                            ast.arg("helper", ast.Name("OpenCTIConnectorHelper"))
                        )

                    class_node.args.args = init_args

            return node

    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(connector_class_path.read_text("utf-8", errors="ignore"))

    new_tree = ConnectorTransformer().visit(tree)

    if isinstance(new_tree, ast.Module):
        # Add ConnectorSettings import
        new_tree.body.insert(
            1,  # after potential leading docstring
            ast.ImportFrom(
                absolute_settings_import_path,
                [ast.alias("ConnectorSettings")],
            ),  # type: ignore
        )
        # Add OpenCTIConnectorHelper import if missing
        if not any(
            [
                connector_node
                for connector_node in new_tree.body
                if (
                    isinstance(connector_node, ast.ImportFrom)
                    and any(
                        [
                            alias
                            for alias in connector_node.names
                            if alias.name == "OpenCTIConnectorHelper"
                        ]
                    )
                )
            ]
        ):
            new_tree.body.insert(
                1,  # after potential leading docstring
                ast.ImportFrom(
                    "pycti",
                    [ast.alias("OpenCTIConnectorHelper")],
                ),  # type: ignore
            )

    return ast.unparse(ast.fix_missing_locations(new_tree))
