import ast
from pathlib import Path
import warnings

from vulture import Vulture  # if not found run `pip install vulture`
from vulture.core import Item  # for typing only


def _get_connector_class_name_in_main(main_path: Path) -> str | None:
    class MainVisitor(ast.NodeVisitor):
        def __init__(self):
            super().__init__()
            self.connector_assign_node: ast.Assign | None = None

        def visit_Assign(self, node: ast.Assign) -> ast.Assign | None:
            # Look for assignment to variable named `connector`
            if any(
                [
                    isinstance(target, ast.Name) and target.id.lower() == "connector"
                    for target in node.targets
                ]
            ):
                # Check that the assigned value is a function call, e.g. `connector = TemplateConnector()`
                if isinstance(node.value, ast.Call) and isinstance(
                    node.value.func, ast.Name
                ):
                    self.connector_assign_node = node
                    return node

    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(main_path.read_text("utf-8", errors="ignore"))

    visitor = MainVisitor()
    visitor.visit(tree)
    if visitor.connector_assign_node:
        if isinstance(visitor.connector_assign_node.value, ast.Call):
            if isinstance(visitor.connector_assign_node.value.func, ast.Name):
                return visitor.connector_assign_node.value.func.id


def _get_connector_class_name_in_package(connector_path: Path) -> str | None:
    class PackageVisitor(ast.NodeVisitor):
        def __init__(self):
            super().__init__()
            self.base_class_name: str | None = None
            self.base_class_child_def: ast.ClassDef | None = None
            self.connector_class_def: ast.ClassDef | None = None

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef | None:
            # Look for a class def that set `self.helper = OpenCTIConnectorHelper()`
            if self.base_class_name and node.name != self.base_class_name:
                return None

            # Get class `__init__` function
            for class_node in node.body:
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
                                    and target.attr.lower() in ["helper", "_helper"]
                                )
                                for target in function_node.targets
                            ):
                                # If all the condtions are true, return ClassDef node
                                self.connector_class_def = (
                                    self.base_class_child_def
                                    if self.base_class_name
                                    else node
                                )
                                return node
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
                                        # If all the condtions are true, return ClassDef node
                                        self.connector_class_def = (
                                            self.base_class_child_def
                                            if self.base_class_name
                                            else node
                                        )
                                        return node
            # If not found, look for a class that inherits from a base class
            # that set `self.helper = OpenCTIConnectorHelper()`
            for base_node in node.bases:
                if isinstance(base_node, ast.Name) and base_node.id != "Exception":
                    self.base_class_name = base_node.id
                    self.base_class_child_def = node
                    return None

    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)
        trees = [
            ast.parse(file_path.read_text("utf-8", errors="ignore"))
            for file_path in connector_path.rglob("src/**/*")
            if file_path.name.endswith((".py", ".py.tmp"))
        ]

    # Browse each file AST to find the connector class
    for tree in trees:
        visitor = PackageVisitor()
        # Browse each file AST to find the connector _base_ class if any
        for tree in trees:
            visitor.visit(tree)
            if visitor.connector_class_def:
                return visitor.connector_class_def.name


def _get_connector_class_name_in_connector(connector_path: Path) -> str | None:
    class ConnectorVisitor(ast.NodeVisitor):
        def __init__(self):
            super().__init__()
            self.connector_class_defs: list[ast.ClassDef] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef | None:
            # Look for any class definition
            self.connector_class_defs.append(node)

    connector_files_paths = [
        file_path for file_path in connector_path.rglob("connector.py.tmp")
    ]

    if len(connector_files_paths) == 1:
        file_path = connector_files_paths[0]

        with warnings.catch_warnings():
            # Ignore SyntaxWarning during AST parsing to avoid noise in logs
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(file_path.read_text("utf-8", errors="ignore"))

        visitor = ConnectorVisitor()
        visitor.visit(tree)
        if len(visitor.connector_class_defs) == 1:
            return visitor.connector_class_defs[0].name


def get_variable_definition_file_path(
    connector_path: Path, variable_name: str
) -> Path | None:
    class FileVisitor(ast.NodeVisitor):
        def __init__(self):
            super().__init__()
            self.variable_definition: (
                ast.ClassDef | ast.FunctionDef | ast.Assign | None
            ) = None

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef | None:
            if node.name == variable_name:
                self.variable_definition = node

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef | None:
            if node.name == variable_name:
                self.variable_definition = node

        def visit_Assign(self, node: ast.Assign) -> ast.Assign | None:
            if any([target == variable_name for target in node.targets]):
                self.variable_definition = node

    with warnings.catch_warnings():
        # Ignore SyntaxWarning during AST parsing to avoid noise in logs
        warnings.simplefilter("ignore", SyntaxWarning)
        trees = [
            (ast.parse(file_path.read_text("utf-8", errors="ignore")), file_path)
            for file_path in connector_path.rglob("src/**/*")
            if file_path.name.endswith((".py", ".py.tmp"))
        ]

    # Browse each file AST to find the variable declaration if any
    for tree, file_path in trees:
        visitor = FileVisitor()
        visitor.visit(tree)
        if visitor.variable_definition:
            return file_path


def get_connector_class_name(connector_path: Path, main_path: Path) -> str | None:
    return (
        # Try to find the unique class in the unique file of the connector
        _get_connector_class_name_in_connector(connector_path)
        # Try to find connector class name in entrypoint
        or _get_connector_class_name_in_main(main_path)
        # If not found, try to find it in the whole package
        or _get_connector_class_name_in_package(connector_path)
    )


def get_connector_class_file_path(connector_path: Path, main_path: Path) -> Path | None:
    connector_class_name = get_connector_class_name(connector_path, main_path)
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


def remove_dead_code(connector_path: Path):
    v = Vulture()
    v.scavenge([(connector_path / "src").as_posix()])

    vulture_results: list[Item] = []
    for unused_code in v.get_unused_code():
        if unused_code.confidence >= 90:
            if unused_code.filename.name == "settings.py":
                continue  # skip unused variables in settings.py (often false positive)
            if unused_code.typ == "variable" and unused_code.name in ["self", "cls"]:
                continue  # skip unused 'self' and 'cls' variables (often false positive)
            if unused_code.typ == "import" and unused_code.message.startswith(
                "unused import"
            ):
                continue  # skip unused imports (handled by `autoflake`)

            vulture_results.append(unused_code)

    for vulture_result in vulture_results:
        file_path = vulture_result.filename

        with warnings.catch_warnings():
            # Ignore SyntaxWarning during AST parsing to avoid noise in logs
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(file_path.read_text("utf-8", errors="ignore"))

        class DeadCodeRemover(ast.NodeTransformer):
            def visit_ClassDef(self, node):
                if vulture_result.typ == "class" and node.name == vulture_result.name:
                    return None
                return node

            def visit_FunctionDef(self, node):
                if vulture_result.typ == "func" and node.name == vulture_result.name:
                    return None
                return node

            def visit_Assign(self, node):
                if vulture_result.typ == "variable":
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id == vulture_result.name
                        ):
                            return None
                return node

        new_tree = DeadCodeRemover().visit(tree)
        new_file_content = ast.unparse(ast.fix_missing_locations(new_tree))
        file_path.write_text(new_file_content, encoding="utf-8")
