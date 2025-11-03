import ast
from copy import deepcopy
import os
from pathlib import Path
import warnings

from connector_migrator.utils.ast import get_connector_class_name
from connector_migrator.utils.path import find_file_path

CONNECTOR_IGNORED_SUBDIRECTORIES = [
    "__pycache__",
    "venv",
    "tests",
]


def _get_updated_init_content(
    connector_path: Path,
    init_path: Path,
    absolute_settings_import_path: str,
    absolute_class_import_path: str,
    connector_class_name: str,
) -> str:
    class InitRemoveTransformer(ast.NodeTransformer):
        def __init__(self):
            super().__init__()
            self.class_defs_imports: list[ast.ImportFrom] = []

        def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.AST | None:
            # Remove existing imports of ConnectorSettings and connector class
            if any(
                [
                    alias.name in ["ConnectorSettings", connector_class_name]
                    for alias in node.names
                ]
            ):
                return None  # remove node
            return node

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef | None:
            common_path = find_file_path(connector_path, "common.py.tmp")
            if common_path:
                absolute_common_path = os.path.relpath(
                    common_path, connector_path / "src"
                )
                absolute_common_import_path = absolute_common_path.replace(os.sep, ".")
                absolute_common_import_path = absolute_common_import_path.replace(
                    "-", "_"
                )
                absolute_common_import_path = absolute_common_import_path.rstrip(
                    ".py.tmp"
                )
                # Store imports for each class defined in common.py.tmp
                # Will be added in InitAddTransformer.visit_Module
                self.class_defs_imports.append(
                    ast.ImportFrom(
                        absolute_common_import_path,
                        [ast.alias(node.name)],
                    ),  # type: ignore
                )

                return None  # remove node (copied in common.py.tmp)
            return node

    class InitAddTransformer(ast.NodeTransformer):
        def __init__(self, imports: list[ast.ImportFrom]):
            super().__init__()
            self.class_defs_imports = imports
            self._root: ast.Module | None = None

        def visit_Module(self, node: ast.Module) -> ast.Module | None:
            self._root = node

            # Add ConnectorSettings and connector class imports
            node.body.insert(
                1,  # after potential leading docstring
                ast.ImportFrom(
                    absolute_settings_import_path,
                    [ast.alias("ConnectorSettings")],
                ),  # type: ignore
            )
            node.body.insert(
                1,  # after potential leading docstring
                ast.ImportFrom(
                    absolute_class_import_path,
                    [ast.alias(connector_class_name)],
                ),  # type: ignore
            )
            # Add imports for each class defined in common.py.tmp
            for import_node in self.class_defs_imports:
                node.body.insert(
                    1,  # after potential leading docstring
                    import_node,
                )

            # Add __all__ var if missing
            if not any(
                [
                    init_node
                    for init_node in node.body
                    if (
                        isinstance(init_node, ast.Assign)
                        and any(
                            [
                                isinstance(target, ast.Name) and target.id == "__all__"
                                for target in init_node.targets
                            ]
                        )
                    )
                ]
            ):
                node.body.insert(
                    len(node.body),  # at the end of the module
                    ast.Assign(
                        [ast.Name("__all__")],
                        ast.List(
                            [
                                ast.Constant("ConnectorSettings"),
                                ast.Constant(connector_class_name),
                            ]
                        ),
                    ),
                )

            self.generic_visit(node)
            return node

        def visit_Assign(self, node: ast.Assign) -> ast.Assign | None:
            # Update existing __all__ variable
            if any(
                [
                    isinstance(target, ast.Name) and target.id == "__all__"
                    for target in node.targets
                ]
            ):
                if isinstance(node.value, ast.List):
                    # Upsert "ConnectorSettings"
                    if not any(
                        [
                            isinstance(elt, ast.Constant)
                            and elt.value == "ConnectorSettings"
                            for elt in node.value.elts
                        ]
                    ):
                        node.value.elts.append(ast.Constant("ConnectorSettings"))
                    # Upsert connector class name
                    if not any(
                        [
                            isinstance(elt, ast.Constant)
                            and elt.value == connector_class_name
                            for elt in node.value.elts
                        ]
                    ):
                        node.value.elts.append(ast.Constant(connector_class_name))
                    # Upsert classes imported from common.py.tmp
                    if self._root:
                        for root_node in self._root.body:
                            if (
                                isinstance(root_node, ast.ImportFrom)
                                and root_node.module
                                and root_node.module.endswith(".common")
                            ):
                                import_alias = root_node.names[0]
                                if not any(
                                    [
                                        isinstance(elt, ast.Constant)
                                        and elt.value == import_alias.name
                                        for elt in node.value.elts
                                    ]
                                ):
                                    node.value.elts.append(
                                        ast.Constant(import_alias.name)
                                    )
            return node

    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(init_path.read_text("utf-8", errors="ignore"))

    # Remove existing imports and class defs
    transformer = InitRemoveTransformer()
    new_tree = transformer.visit(tree)

    # Add required imports and __all__ var
    transformer = InitAddTransformer(transformer.class_defs_imports)
    new_tree = transformer.visit(new_tree)

    return ast.unparse(ast.fix_missing_locations(tree))


def _get_init_template_content(
    absolute_settings_import: str,
    absolute_class_import: str,
    connector_class_name: str,
) -> str:
    return """from {absolute_class_import} import {connector_class_name}
from {absolute_settings_import} import ConnectorSettings

__all__ = [
    "{connector_class_name}",
    "ConnectorSettings",
]

""".format(
        absolute_settings_import=absolute_settings_import,
        absolute_class_import=absolute_class_import,
        connector_class_name=connector_class_name,
    )


def get_content(connector_path: Path, entrypoint_path: Path, init_path: Path) -> str:
    connector_class_path = find_file_path(connector_path, "connector.py.tmp")
    settings_path = find_file_path(connector_path, "settings.py.tmp")
    if not connector_class_path or not settings_path:
        raise RuntimeError(
            "Could not find 'connector.py.tmp' or 'settings.py.tmp' file"
        )

    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)

        connector_class_name = get_connector_class_name(connector_path, entrypoint_path)
        if not connector_class_name:
            raise RuntimeError("Connector's main class not found")

    absolute_class_path = os.path.relpath(connector_class_path, connector_path / "src")
    absolute_class_import_path = absolute_class_path.replace(os.sep, ".")
    absolute_class_import_path = absolute_class_import_path.replace("-", "_")
    absolute_class_import_path = absolute_class_import_path.rstrip(".py.tmp")

    absolute_settings_path = os.path.relpath(settings_path, connector_path / "src")
    absolute_settings_import_path = absolute_settings_path.replace(os.sep, ".")
    absolute_settings_import_path = absolute_settings_import_path.replace("-", "_")
    absolute_settings_import_path = absolute_settings_import_path.rstrip(".py.tmp")

    if os.path.exists(init_path):
        return _get_updated_init_content(
            connector_path,
            init_path,
            absolute_settings_import_path=absolute_settings_import_path,
            absolute_class_import_path=absolute_class_import_path,
            connector_class_name=connector_class_name,
        )
    else:
        return _get_init_template_content(
            absolute_settings_import=absolute_settings_import_path,
            absolute_class_import=absolute_class_import_path,
            connector_class_name=connector_class_name,
        )
