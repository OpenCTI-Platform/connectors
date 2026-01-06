import warnings
from typing import Annotated, Any, Callable

from pydantic import Field
from pydantic.fields import FieldInfo


def migrate_deprecated_namespace(data, old_namespace: str, new_namespace: str):
    """Migrate settings from a deprecated namespace to a new one.
    Args:
        data (dict): The configuration data.
        old_namespace (str): The old namespace.
        new_namespace (str): The new namespace.
    """
    if not data:
        return

    old_config = data.get(old_namespace, {})
    new_config = data.get(new_namespace, {})

    # case: new namespace shorten old namespace
    # ex: 'settings' replace 'settings_bad'
    old_startswith_new = old_namespace.startswith(new_namespace)
    if old_startswith_new:
        diff_namespace = old_namespace[
            len(new_namespace) + 1 :
        ]  # extract 'bad' from 'settings_bad'

    # case: new namespace extend old namespace
    # ex: 'settings_good' replace 'settings'
    new_startswith_old = new_namespace.startswith(old_namespace)
    if new_startswith_old:
        diff_namespace = new_namespace[
            len(old_namespace) + 1 :
        ]  # extract 'good' from 'settings_good'

    for key in list(old_config.keys()):
        value = old_config.pop(key)
        if new_startswith_old and key.startswith(diff_namespace + "_"):
            # Skip keys that are already prefixed as they belong to new namespace.
            # ex: 'settings_good_api_key', mapped in 'settings' as 'good_api_key', can be skipped.
            continue

        if key in new_config:
            warnings.warn(
                f"Deprecated setting '{old_namespace}.{key}' found. Using only '{new_namespace}.{key}'"
            )
        else:
            warnings.warn(
                f"Deprecated setting '{old_namespace}.{key}' found. Migrating to '{new_namespace}.{key}'"
            )
            new_config[key] = value
        if old_startswith_new and f"{diff_namespace}_{key}" in new_config:
            # Remove potential wrong prefixed keys in new config.
            # ex: 'settings_bad_api_key', mapped in 'settings' as 'bad_api_key', can be removed.
            new_config.pop(f"{diff_namespace}_{key}")


def migrate_deprecated_variable(
    data,
    old_name: str,
    new_name: str,
    current_namespace: str,
    new_namespace: str | None = None,
    change_value: Callable | None = None,
):
    """Migrate a deprecated variable to a new one, potentially in a new namespace.
    Args:
        data (dict): The configuration data.
        old_name (str): The old variable name.
        new_name (str): The new variable name.
        current_namespace (str): The current namespace of the variable.
        new_namespace (str | None): The new namespace of the variable. If None, use current_namespace.
        change_value (Callable | None): A function to change the value before setting it to the new variable.
    """
    if not data:
        return

    destination_namespace = new_namespace or current_namespace

    old_config = data.get(current_namespace, {})
    new_config = data.get(destination_namespace, {})

    if old_name in old_config:
        value = old_config.pop(old_name)
        if new_name in new_config:
            warnings.warn(
                f"Deprecated setting '{current_namespace}.{old_name}' found. Using only '{destination_namespace}.{new_name}'"
            )
        else:
            warnings.warn(
                f"Deprecated setting '{current_namespace}.{old_name}' found. Migrating to '{destination_namespace}.{new_name}'"
            )
            new_config[new_name] = change_value(value) if change_value else value


def LegacyField(
    *,
    deprecated: str | bool = True,
    new_namespace: str | None = None,
    new_variable_name: str | None = None,
    change_value: Callable | None = None,
    set_to_empty_dict: bool = False,
) -> FieldInfo:
    """Define a deprecated field with migration information.
    The migration information is used in the BaseConnectorSettings to automatically
    migrate deprecated fields to their new names or namespaces.
    Args:
        deprecated (str | bool): Reason for deprecation or True if no reason.
        new_namespace (str | None): The new namespace for the variable.
        new_variable_name (str | None): The new variable name.
        change_value (Callable | None): A function to change the value when migrating.
        set_to_empty_dict (bool): If True, set the deprecated field to an empty dict.
    Returns:
        FieldInfo: A Pydantic FieldInfo object with deprecation metadata.
    """
    return Field(
        default=None,
        new_namespace=new_namespace,
        new_variable_name=new_variable_name,
        change_value=change_value,
        deprecated=deprecated,
        set_to_empty_dict=set_to_empty_dict,
    )


DeprecatedNameSpace = Annotated[
    dict, LegacyField(deprecated="This field is deprecated.", set_to_empty_dict=True)
]
"""Annotated dict representing a deprecated namespace.
When used in the BaseConnectorSettings, this annotation indicates that the entire
namespace is deprecated. The `LegacyField` metadata provides details about the
deprecation, including a message and an instruction to set the field to an empty
dictionary.
"""
DeprecatedVariable = Annotated[Any, LegacyField(deprecated="This field is deprecated.")]
"""Annotated Any representing a deprecated variable.
When used in a BaseConfigModel under the BaseConnectorSettings, this annotation indicates that the variable is
deprecated. The `LegacyField` metadata provides details about the deprecation,
including a message."""
