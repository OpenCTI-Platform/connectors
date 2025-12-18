import warnings
from typing import Callable


def migrate_deprecated_namespace(*, old: str, new: str):
    """
    Decorator to migrate configuration from a deprecated namespace to a new one using Pydantic model validators.
    This decorator handles three migration scenarios:
    1. New namespace is shorter than old (e.g., 'christmas' replaces 'christmas_old')
    2. New namespace extends old (e.g., 'reversinglabs_spectra_analyse' replaces 'reversinglabs')
    3. New and old namespaces are completely different (e.g., 'patati' replaces 'patatartiner')
    Args:
        old (str): The deprecated namespace key to migrate from
        new (str): The new namespace key to migrate to
    Returns:
        Callable: A decorator function that wraps the target function
    Usage:
        @model_validator(mode="before")
        @classmethod
        @migrate_deprecated_namespace(old='old_config', new='new_config')
        def migrate_config(cls, data: dict):
            return data
    Behavior:
        - Moves configuration values from old namespace to new namespace
        - Issues warnings when deprecated settings are found
        - Avoids overwriting existing values in new namespace
        - Removes keys from old namespace after migration
        - Handles namespace prefix conflicts automatically
    Warnings:
        - Issues deprecation warnings for each migrated setting
        - Notifies when existing new namespace values take precedence
    """

    def decorator(func: Callable):
        def wrapper(cls, data: dict):
            if not data:
                return

            old_config = data.get(old, {})
            new_config = data.get(new, {})

            # new namespace shorten old namespace
            # ex: christmas replace christmas_old
            if old.startswith(new):
                diff_namespace = old[len(new) + 1 :]
                for key in list(old_config.keys()):
                    value = old_config.pop(key)
                    if key in new_config:
                        warnings.warn(
                            f"Deprecated setting '{old}.{key}' found. Using only '{new}.{key}'"
                        )
                    else:
                        warnings.warn(
                            f"Deprecated setting '{old}.{key}' found. Migrating to '{new}.{key}'"
                        )
                        new_config[key] = value
                    if f"{diff_namespace}_{key}" in new_config:
                        # Remove potential wrong prefixed keys in new config
                        new_config.pop(f"{diff_namespace}_{key}")

            # new namespace extend old namespace
            # ex: reversinglabs_spectra_analyse replace reversinglabs
            elif new.startswith(old):
                diff_namespace = new[len(old) + 1 :]
                for key in list(old_config.keys()):
                    value = old_config.pop(key)
                    if key.startswith(diff_namespace + "_"):
                        # Skip keys that are already prefixed
                        continue

                    if key in new_config:
                        warnings.warn(
                            f"Deprecated setting '{old}.{key}' found. Using only '{new}.{key}'"
                        )
                    else:
                        warnings.warn(
                            f"Deprecated setting '{old}.{key}' found. Migrating to '{new}.{key}'"
                        )
                        new_config[key] = value

            # new and old namespace are different
            # ex: patati replace patatartiner
            else:
                for key in list(old_config.keys()):
                    value = old_config.pop(key)
                    if key in new_config:
                        warnings.warn(
                            f"Deprecated setting '{old}.{key}' found. Using only '{new}.{key}'"
                        )
                    else:
                        warnings.warn(
                            f"Deprecated setting '{old}.{key}' found. Migrating to '{new}.{key}'"
                        )
                        new_config[key] = value

            return func(cls, data)

        return wrapper

    return decorator


# TODO: add change_value parameter to recalculate the value while migrating
def rename_deprecated_variable(
    *, namespace: str, old: str, new: str, first_namespace: str = None
):
    def decorator(func: Callable):
        def wrapper(cls, data: dict):
            if not data:
                return

            old_namespace = namespace or first_namespace

            old_config = data.get(old_namespace, {})
            new_config = data.get(namespace, {})

            if old in old_config:
                value = old_config.pop(old)
                if new in new_config:
                    warnings.warn(
                        f"Deprecated setting '{old_namespace}.{old}' found. Using only '{namespace}.{new}'"
                    )
                else:
                    warnings.warn(
                        f"Deprecated setting '{namespace}.{old}' found. Migrating to '{namespace}.{new}'"
                    )
                    new_config[new] = value

            return func(cls, data)

        return wrapper

    return decorator
