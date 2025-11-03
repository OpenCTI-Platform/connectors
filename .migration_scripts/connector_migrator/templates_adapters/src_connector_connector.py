import os
import ast
from pathlib import Path
import warnings

from connector_migrator.utils.ast import (
    get_connector_class_name,
    get_variable_definition_file_path,
)
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

    class ConnectorRemoveTransformer(ast.NodeTransformer):
        def __init__(self):
            super().__init__()
            self.variables_imports: list[ast.ImportFrom] = []

        def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.ImportFrom | None:
            # Remove existing imports of ConnectorSettings
            if any([alias.name == "ConnectorSettings" for alias in node.names]):
                return None  # remove node

            # Remove absolute imports that would cause circular imports
            if node.module == absolute_init_import_path and node.level == 0:
                for alias in node.names:
                    variable_declaration_file_path = get_variable_definition_file_path(
                        connector_path, alias.name
                    )
                    if variable_declaration_file_path:
                        absolute_variable_declaration_file_path = os.path.relpath(
                            variable_declaration_file_path, connector_path / "src"
                        )
                        absolute_variable_import_path = (
                            absolute_variable_declaration_file_path.replace(os.sep, ".")
                        )
                        absolute_variable_import_path = (
                            absolute_variable_import_path.replace("-", "_")
                        )
                        absolute_variable_import_path = (
                            absolute_variable_import_path.rstrip(".py.tmp")
                        )
                        self.variables_imports.append(
                            ast.ImportFrom(
                                absolute_variable_import_path,
                                [ast.alias(alias.name)],
                            ),  # type: ignore
                        )
                return None  # remove node (old import)

            # Remove relative imports that would cause circular imports
            if node.module is None and node.level == 1:
                for alias in node.names:
                    variable_declaration_file_path = get_variable_definition_file_path(
                        connector_path, alias.name
                    )
                    if variable_declaration_file_path:
                        relative_variable_declaration_file_path = os.path.relpath(
                            variable_declaration_file_path, connector_class_path.parent
                        )
                        relative_variable_import_path = (
                            relative_variable_declaration_file_path.replace(os.sep, ".")
                        )
                        relative_variable_import_path = (
                            relative_variable_import_path.replace("-", "_")
                        )
                        relative_variable_import_path = (
                            relative_variable_import_path.rstrip(".py.tmp")
                        )
                        self.variables_imports.append(
                            ast.ImportFrom(
                                relative_variable_import_path,
                                [ast.alias(alias.name)],
                                level=1,
                            ),  # type: ignore
                        )
                return None  # remove node (old import)

            return node

    class ConnectorAddTransformer(ast.NodeTransformer):
        def __init__(self, imports: list[ast.ImportFrom]):
            super().__init__()
            self.variables_imports = imports
            self._root: ast.Module | None = None

        def visit_Module(self, node: ast.Module) -> ast.Module:
            # Add ConnectorSettings import
            node.body.insert(
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
                    for connector_node in node.body
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
                node.body.insert(
                    1,  # after potential leading docstring
                    ast.ImportFrom(
                        "pycti",
                        [ast.alias("OpenCTIConnectorHelper")],
                    ),  # type: ignore
                )

            # Add other variables imports
            for import_node in self.variables_imports:
                node.body.insert(
                    1,  # after potential leading docstring
                    import_node,
                )

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

    # Remove invalid imports
    transformer = ConnectorRemoveTransformer()
    new_tree = transformer.visit(tree)

    # Add required imports and update connector's main class args
    transformer = ConnectorAddTransformer(transformer.variables_imports)
    new_tree = transformer.visit(new_tree)

    return ast.unparse(ast.fix_missing_locations(new_tree))
