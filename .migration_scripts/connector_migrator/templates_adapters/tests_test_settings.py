import ast
import os
from pathlib import Path
from typing import Any

from connector_migrator.utils.yaml import get_custom_env_var_prefix

ROOT_PATH = Path(__file__).parent.parent.parent.parent  # root of the repo


def _connector_name_pascal_case(connector_path: Path) -> str:
    connector_directory_name = os.path.basename(connector_path)
    return connector_directory_name.replace("-", " ").title().replace(" ", "")


def _get_custom_config_dict_ast(config_fields: list[tuple[str, str, Any]]) -> ast.Dict:
    config_dict_keys = [config_field[0] for config_field in config_fields]
    config_dict_values = [config_field[1] for config_field in config_fields]

    config_dict_keys = []
    config_dict_values = []
    for config_field in config_fields:
        config_dict_key = config_field[0]
        config_dict_value = config_field[2] or config_field[1]  # default or type

        match config_dict_value:
            case "int":
                config_dict_value = 42
            case "bool":
                config_dict_value = True
            case "list":
                config_dict_value = ["item_1", "item_2"]
            case _:
                pass  # leave 'str' for strings

        config_dict_keys.append(config_dict_key)
        config_dict_values.append(config_dict_value)

    return ast.Dict(
        keys=[
            ast.Constant(value=config_dict_key) for config_dict_key in config_dict_keys
        ],
        values=[
            ast.Constant(value=config_dict_value)
            for config_dict_value in config_dict_values
        ],
    )


def _get_test_settings_content(
    connector_parent_directory: str, config_fields: list[tuple[str, str, Any]]
) -> str:
    template_test_settings_path = (
        Path(ROOT_PATH)
        / "templates"
        / connector_parent_directory
        / "tests"
        / "tests_connector"
        / "test_settings.py"
    )

    module_ast = ast.parse(
        template_test_settings_path.read_text("utf-8", errors="ignore")
    )
    for module_node in module_ast.body:
        # Get `def test_...` functions
        if isinstance(module_node, ast.FunctionDef) and module_node.decorator_list:
            # Get `@pytest.mark.parametrize` decorators
            for function_node in module_node.decorator_list:
                if (
                    isinstance(function_node, ast.Call)
                    and isinstance(function_node.func, ast.Attribute)
                    and function_node.func.attr == "parametrize"
                ):
                    # Get `pytest.param` arguments
                    for arg_node in function_node.args:
                        if isinstance(arg_node, ast.List):
                            for elt in arg_node.elts:
                                if (
                                    isinstance(elt, ast.Call)
                                    and isinstance(elt.func, ast.Attribute)
                                    and elt.func.attr == "param"
                                ):
                                    for elt_arg_node in elt.args:
                                        # Get `pytest.param` first argument (data dict)
                                        if isinstance(elt_arg_node, ast.Dict):
                                            for index, key_node in enumerate(
                                                elt_arg_node.keys
                                            ):
                                                # Get `dict["template"]`
                                                if (
                                                    isinstance(key_node, ast.Constant)
                                                    and key_node.value == "template"
                                                ):
                                                    # Update value to the right config dict
                                                    ast_custom_config_dict = (
                                                        _get_custom_config_dict_ast(
                                                            config_fields
                                                        )
                                                    )

                                                    elt_arg_node.values[index] = (
                                                        ast_custom_config_dict
                                                    )

    return ast.unparse(ast.fix_missing_locations(module_ast))


def _get_custom_config_fields(
    connector_path: Path, settings_path: Path
) -> list[tuple[str, str, Any]]:
    fields_nodes: list[ast.AnnAssign] = []

    connector_name_pascal_case = _connector_name_pascal_case(connector_path)

    module_ast = ast.parse(settings_path.read_text("utf-8", errors="ignore"))
    # Try to find a class that use `TemplateConfig(BaseConfigModel)` pattern
    for module_node in module_ast.body:
        # Look for a class definition, e.g. `class TemplateConnector:`
        if isinstance(module_node, ast.ClassDef):
            if module_node.name == f"{connector_name_pascal_case}Config":
                # Get class annotations
                for class_node in module_node.body:
                    if isinstance(class_node, ast.AnnAssign):
                        if isinstance(class_node.target, ast.Name) and isinstance(
                            class_node.annotation, ast.Name
                        ):
                            fields_nodes.append(class_node)

    config_fields: list[tuple[str, str, Any]] = []
    for field_node in fields_nodes:
        # If `url :str = Field(...)`
        if isinstance(field_node.value, ast.Call):
            if (
                isinstance(field_node.value.func, ast.Name)
                and field_node.value.func.id == "Field"
            ):
                default_value = None
                default_keyword = next(
                    (
                        keyword
                        for keyword in field_node.value.keywords
                        if keyword.arg == "default"
                    ),
                    None,
                )
                if default_keyword and isinstance(default_keyword.value, ast.Constant):
                    default_value = default_keyword.value.value

                if isinstance(field_node.target, ast.Name) and isinstance(
                    field_node.annotation, ast.Name
                ):
                    config_fields.append(
                        (
                            field_node.target.id,
                            field_node.annotation.id,
                            default_value,
                        )
                    )
        # If `url :str`
        else:
            if isinstance(field_node.target, ast.Name) and isinstance(
                field_node.annotation, ast.Name
            ):
                config_fields.append(
                    (
                        field_node.target.id,
                        field_node.annotation.id,
                        None,
                    )
                )

    return config_fields


def get_content(
    connector_path: Path, entrypoint_path: Path, init_path: Path, settings_path: Path
) -> str:
    connector_parent_directory = os.path.basename(connector_path.parent)

    config_name = get_custom_env_var_prefix(connector_path)
    config_fields = _get_custom_config_fields(connector_path, settings_path)

    absolute_init_path = (
        # Try to find the first common parent directory
        os.path.dirname(os.path.relpath(init_path, entrypoint_path.parent))
        # If not found, then the two files are in the same directory
        or init_path.parent.name
    )
    absolute_init_import_path = absolute_init_path.replace(os.sep, ".")
    absolute_init_import_path = absolute_init_import_path.replace("-", "_")
    absolute_init_import = f"from {absolute_init_import_path} import "

    test_settings_text = _get_test_settings_content(
        connector_parent_directory, config_fields
    )
    test_settings_text = (
        test_settings_text.replace(
            "from connector import ",
            absolute_init_import,
        )
        .replace(
            '"template"',
            f'"{config_name}"',
        )
        .replace(
            "'template'",
            f'"{config_name}"',
        )
        .replace(
            "settings.template",
            f"settings.{config_name}",
        )
    )

    return test_settings_text
