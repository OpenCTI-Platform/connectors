import ast
from pathlib import Path


def _get_connector_class_name_in_main(main_path: Path) -> str | None:
    module_ast = ast.parse(main_path.read_text("utf-8", errors="ignore"))

    def get_connector_class_recursively(tree: ast.AST) -> ast.Call | None:
        tree_body = getattr(tree, "body", None)
        if tree_body and isinstance(tree_body, list):
            for node in tree_body:
                if isinstance(node, ast.Assign):
                    if any(
                        [
                            isinstance(target, ast.Name)
                            and target.id.lower() == "connector"
                            for target in node.targets
                        ]
                    ):
                        if isinstance(node.value, ast.Call) and isinstance(
                            node.value.func, ast.Name
                        ):
                            return node.value
                class_call = get_connector_class_recursively(node)
                if class_call:
                    return class_call

    class_call = get_connector_class_recursively(module_ast)
    if class_call and isinstance(class_call.func, ast.Name):
        return class_call.func.id


def _get_connector_class_name_in_package(connector_path: Path) -> str | None:
    modules_ast = [
        ast.parse(file_path.read_text("utf-8", errors="ignore"))
        for file_path in connector_path.rglob("src/**/*")
        if file_path.name.endswith((".py", ".py.tmp"))
    ]

    def find_connector_class_recursively(
        base_class_name: str | None = None,
    ) -> ast.ClassDef | None:
        for module_ast in modules_ast:
            # Try to find a class that set `self.helper = OpenCTIConnectorHelper()`
            for module_node in module_ast.body:
                # Look for a class definition, e.g. `class TemplateConnector:`
                if isinstance(module_node, ast.ClassDef) and (
                    base_class_name is None or module_node.name == base_class_name
                ):
                    # Get class `__init__` function
                    for class_node in module_node.body:
                        if (
                            isinstance(class_node, ast.FunctionDef)
                            and class_node.name == "__init__"
                        ):
                            for function_node in class_node.body:
                                # Check that `__init__` contains `self.helper = ...`
                                if isinstance(function_node, ast.Assign):
                                    if any(
                                        (
                                            isinstance(target, ast.Attribute)
                                            and target.attr.lower()
                                            in ["helper", "_helper"]
                                        )
                                        for target in function_node.targets
                                    ):
                                        # If all the condtions are true, return connector's main class
                                        return module_node
                                # If not found, check that `__init__` contains `self.helper = ...` in try/except
                                if isinstance(function_node, ast.Try):
                                    for try_node in function_node.body:
                                        if isinstance(try_node, ast.Assign):
                                            if any(
                                                (
                                                    isinstance(target, ast.Attribute)
                                                    and target.attr.lower()
                                                    in ["helper", "_helper"]
                                                )
                                                for target in try_node.targets
                                            ):
                                                # If all the condtions are true, return connector's main class
                                                return module_node
                    # Get the base class if it exists
                    for base_node in module_node.bases:
                        if (
                            isinstance(base_node, ast.Name)
                            and base_node.id != "Exception"
                        ):
                            base_class = find_connector_class_recursively(base_node.id)
                            if base_class:
                                return module_node

    class_def = find_connector_class_recursively()
    if class_def and isinstance(class_def, ast.ClassDef):
        return class_def.name


def get_connector_class_name_in_connector(connector_path: Path) -> str | None:
    connector_files_paths = [
        file_path for file_path in connector_path.rglob("connector.py.tmp")
    ]

    if len(connector_files_paths) == 1:
        file_path = connector_files_paths[0]
        file_ast = ast.parse(file_path.read_text("utf-8", errors="ignore"))

        class_nodes: list[ast.ClassDef] = [
            file_node
            for file_node in file_ast.body
            if isinstance(file_node, ast.ClassDef)
        ]
        if len(class_nodes) == 1:
            return class_nodes[0].name


def get_connector_class_file_path(connector_path: Path, main_path: Path) -> Path | None:
    connector_class_name = (
        # Try to find the unique class in the unique file of the connector
        get_connector_class_name_in_connector(connector_path)
        # Try to find connector class name in entrypoint
        or _get_connector_class_name_in_main(main_path)
        # If not found, try to find it in the whole package
        or _get_connector_class_name_in_package(connector_path)
    )
    if not connector_class_name:
        return None

    for file_path in connector_path.rglob("src/**/*"):
        if file_path.name.endswith((".py", ".py.tmp")):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if (
                        # Try to find `class TemplateConnector:`
                        f"class {connector_class_name}:" in line
                        # If not found, try to find `class TemplateConnector(BaseConnector):`
                        or f"class {connector_class_name}(" in line
                    ):
                        return file_path
