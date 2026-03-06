"""Utilities for handling deprecated configuration settings."""

import warnings
from datetime import date
from typing import Any, Callable, Literal

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


class Deprecate:
    """A metadata class that indicates that a field is deprecated and may be migrated
    to a new variable during `BaseConnectorSettings` validation.

    Args:
        new_namespace (str | None): The new namespace to migrate to.
        new_namespaced_var (str | None): The new variable name when migrating a variable.
        new_value_factory (Callable | None): A function to change the value when migrating.
        removal_date (date | str | None): Date when the deprecated setting will be removed.

    Notes:
        - If this is applied as an annotation (e.g., via `x: Annotated[int, Deprecate(removal_date="2027-01-01")]`),
        the field will be marked as deprecated and no validation will be applied.

        - Because this sets the field as optional (i.e., sets its default to `None`), subsequent annotation-applied transformations
        may be impacted. Additionally, IDE and static type checkers may ignore that the field can be set to `None`,
        which can lead to issues if the field is accessed without checking for `None` first.
    """

    def __init__(
        self,
        new_namespace: str | None = None,
        new_namespaced_var: str | None = None,
        new_value_factory: Callable[[Any], Any] | None = None,
        removal_date: date | str | None = None,
    ):
        """Instantiate a `Deprecate` metadata."""
        self.new_namespace = new_namespace
        self.new_namespaced_var = new_namespaced_var
        self.new_value_factory = new_value_factory
        if isinstance(removal_date, str):
            removal_date = date.fromisoformat(removal_date)
        self.removal_date = removal_date.strftime("%Y-%m-%d") if removal_date else None


def DeprecatedField(  # noqa: N802 (using pydantic.Field naming convention)
    *,
    deprecated: str | Literal[True] = True,
    new_namespace: str | None = None,
    new_namespaced_var: str | None = None,
    new_value_factory: Callable[[Any], Any] | None = None,
    removal_date: date | str | None = None,
    **kwargs: Any,
) -> Any:
    """Define a deprecated field with migration information.

    The migration information is used in the `BaseConnectorSettings` to automatically
    migrate deprecated fields to their new names or namespaces.

    Args:
        deprecated (str | Literal[True]): `True` to mark the field as deprecated, or
        a deprecation message to be displayed in warnings and JSON schemas.
        new_namespace (str | None): The new namespace to migrate to.
        new_namespaced_var (str | None): The new variable name when migrating a variable.
        new_value_factory (Callable | None): A function to change the value when migrating.
        removal_date (date | str | None): Date when the deprecated setting will be removed.
        **kwargs: Additional keyword arguments to be passed to the underlying `Field` definition.

    Returns:
        FieldInfo: A Pydantic FieldInfo object with deprecation metadata.

    Notes:
        - The return annotation is `Any` so `DeprecatedField` can be used on any type-annotated
        fields without causing a type error (same as `Field` from Pydantic).
        - See `pydantic.Field` (https://docs.pydantic.dev/latest/api/fields/) for more information
        on the available parameters to define a field, as they can be used in conjunction with the deprecation parameters.
    """
    if not deprecated:
        raise ValueError(
            "DeprecatedField must have a deprecation reason or be set to True."
        )

    field_info: FieldInfo = Field(deprecated=deprecated, **kwargs)
    # Add Deprecate metadata so it can be used for migration in BaseConnectorSettings
    field_info.metadata.append(
        Deprecate(
            new_namespace=new_namespace,
            new_namespaced_var=new_namespaced_var,
            new_value_factory=new_value_factory,
            removal_date=removal_date,
        )
    )

    return field_info
