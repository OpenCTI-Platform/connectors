"""Utilities for handling deprecated configuration settings."""

import warnings
from datetime import date
from typing import Any, Callable

from pydantic import Field
from pydantic.fields import FieldInfo


def migrate_deprecated_namespace(
    data: dict[str, Any],
    old_namespace: str,
    new_namespace: str,
    removal_date: str | None = None,
) -> None:
    """Migrate settings from a deprecated namespace to a new one.

    Args:
        data (dict): The configuration data.
        old_namespace (str): The old namespace.
        new_namespace (str): The new namespace.
        removal_date (str | None): Optional date when the deprecated setting will be removed.
    """
    if not data:
        return

    old_config = data.get(old_namespace, {})
    new_config = data.get(new_namespace, {})

    # case: new namespace shorten old namespace
    # ex: 'settings' replace 'settings_bad'
    if old_startswith_new := old_namespace.startswith(new_namespace):
        diff_namespace = old_namespace[
            len(new_namespace) + 1 :
        ]  # extract 'bad' from 'settings_bad'

    # case: new namespace extend old namespace
    # ex: 'settings_good' replace 'settings'
    if new_startswith_old := new_namespace.startswith(old_namespace):
        diff_namespace = new_namespace[
            len(old_namespace) + 1 :
        ]  # extract 'good' from 'settings_good'

    for key, value in old_config.items():
        if new_startswith_old and key.startswith(diff_namespace + "_"):
            # Skip keys that are already prefixed as they belong to new namespace.
            # ex: 'settings_good_api_key', mapped in 'settings' as 'good_api_key', can be skipped.
            continue

        removal_msg = (
            f" This setting will be removed on {removal_date}." if removal_date else ""
        )
        if key in new_config:
            warnings.warn(
                f"Deprecated setting '{old_namespace}.{key}' found. Using only '{new_namespace}.{key}'.{removal_msg}",
                stacklevel=2,
            )
        else:
            warnings.warn(
                f"Deprecated setting '{old_namespace}.{key}' found. Migrating to '{new_namespace}.{key}'.{removal_msg}",
                stacklevel=2,
            )
            new_config[key] = value
        if old_startswith_new and f"{diff_namespace}_{key}" in new_config:
            # Remove potential wrong prefixed keys in new config.
            # ex: 'settings_bad_api_key', mapped in 'settings' as 'bad_api_key', can be removed.
            new_config.pop(f"{diff_namespace}_{key}")

    data.pop(old_namespace, None)
    data[new_namespace] = new_config


def migrate_deprecated_variable(
    data: dict[str, Any],
    old_name: str,
    new_name: str,
    current_namespace: str,
    new_namespace: str | None = None,
    new_value_factory: Callable[[Any], Any] | None = None,
    removal_date: str | None = None,
) -> None:
    """Migrate a deprecated variable to a new one, potentially in a new namespace.

    Args:
        data (dict): The configuration data.
        old_name (str): The old variable name.
        new_name (str): The new variable name.
        current_namespace (str): The current namespace of the variable.
        new_namespace (str | None): The new namespace of the variable. If None, use current_namespace.
        new_value_factory (Callable | None): A function to change the value before setting it to the new variable.
        removal_date (str | None): Optional date when the deprecated setting will be removed.
    """
    if not data:
        return

    destination_namespace = new_namespace or current_namespace

    old_config = data.get(current_namespace, {})
    new_config = data.get(destination_namespace, {})

    if old_name not in old_config:
        return

    value = old_config.pop(old_name)
    removal_msg = (
        f" This setting will be removed on {removal_date}." if removal_date else ""
    )
    if new_name in new_config:
        warnings.warn(
            f"Deprecated setting '{current_namespace}.{old_name}' found. Using only '{destination_namespace}.{new_name}'.{removal_msg}",
            stacklevel=2,
        )
    else:
        warnings.warn(
            f"Deprecated setting '{current_namespace}.{old_name}' found. Migrating to '{destination_namespace}.{new_name}'.{removal_msg}",
            stacklevel=2,
        )
        new_config[new_name] = new_value_factory(value) if new_value_factory else value

    data[destination_namespace] = new_config


class DeprecatedField:
    """Define a deprecated field with migration information.

    The migration information is used in the BaseConnectorSettings to automatically
    migrate deprecated fields to their new names or namespaces.

    Args:
        deprecated (str | bool): `True` to mark the field as deprecated, or a deprecation message to be displayed in warnings and JSON schemas.
        new_namespace (str | None): The new namespace to migrate to.
        new_namespaced_var (str | None): The new variable name when migrating a variable.
        new_value_factory (Callable | None): A function to change the value when migrating.
        removal_date (date | str | None): Date when the deprecated setting will be removed.

    Returns:
        FieldInfo: A Pydantic FieldInfo object with deprecation metadata.
    """

    def __new__(  # type: ignore[misc]
        cls,
        *,
        deprecated: str | bool = True,
        new_namespace: str | None = None,
        new_namespaced_var: str | None = None,
        new_value_factory: Callable[[Any], Any] | None = None,
        removal_date: date | str | None = None,
    ) -> FieldInfo:
        """Create a Pydantic Field with deprecation metadata."""
        if not deprecated:
            raise ValueError(
                "DeprecatedField must have a deprecation reason or be set to True."
            )
        if isinstance(removal_date, str):
            removal_date = date.fromisoformat(removal_date)
        if removal_date:
            removal_date = removal_date.strftime("%Y-%m-%d")
        return Field(
            default=None,
            deprecated=deprecated,
            json_schema_extra={
                "new_namespace": new_namespace,
                "new_namespaced_var": new_namespaced_var,
                "new_value_factory": new_value_factory,  # type: ignore[dict-item]
                "removal_date": removal_date,  # type: ignore[dict-item]
            },
        )  # type: ignore[return-value]
