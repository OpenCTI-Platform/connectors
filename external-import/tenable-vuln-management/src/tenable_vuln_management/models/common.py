"""
Offer common tools for connector's model.
"""

import warnings
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict


class FieldWarning(Warning):
    """Base class for field warnings;"""

    def __init__(
        self,
        type_: str,
        loc: tuple[str],
        msg: str,
        input_: Any,
    ) -> None:
        self.type = type_
        self.loc = loc
        self.msg = msg
        self.input = input_

    def __str__(self) -> str:
        return f"{'.'.join(self.loc)}\n  {self.msg} ['type':'{self.type}', 'input_value': {self.input}]"


class ValidationWarning(Warning):
    """Base class for validation warnings"""

    def __init__(self, model: type[BaseModel], warnings: list[FieldWarning]) -> None:
        self.model = model
        self.warnings = warnings

    @property
    def warnings_count(self) -> int:
        """Count sub warning.

        Returns
                (int): The number of warnings.
        """
        return len(self.warnings)

    def __str__(self) -> str:
        warnings_repr = "\n".join(str(warning) for warning in self.warnings)
        return (
            f"{self.warnings_count} validation warning{'s' if self.warnings_count>1 else ''} for {self.model.__name__}\n"
            f"{warnings_repr}"
        )


class BaseModelExtraWarning(BaseModel):
    model_config = ConfigDict(extra="allow")

    def model_post_init(self, __context: Any) -> None:
        """Define the post initialization method, automatically called after __init__ in a pydantic model initialization.

        Args:
            context__(Any): The pydantic context used by pydantic framework.

        References:
            https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel.model_parametrized_name [consulted on
                October 4th, 2024]

        """
        if self.model_extra is not None and len(self.model_extra) > 0:
            field_warnings = [
                FieldWarning(
                    type_="extra_warn",
                    loc=[key],
                    msg="Unexpected extra field",
                    input_=value,
                )
                for key, value in self.model_extra.items()
            ]
            warning = ValidationWarning(model=self.__class__, warnings=field_warnings)
            warnings.warn(warning, stacklevel=2)


class HashableBaseModel(BaseModel):
    """
    Represent a Pydantic BaseModel that can be hashed and compared.
    """

    def __hash__(self):
        """Create a hash based on the model's json representation dynamically."""
        return hash(self.model_dump_json())

    def __eq__(self, other: "HashableBaseModel"):
        """Implement comparison between similar object."""
        if not isinstance(other, self.__class__):
            raise NotImplementedError("Cannot compare objects from different type.")
        # Compare the attributes by converting them to a dictionary
        return self.model_dump_json() == other.model_dump_json()


class FrozenBaseModelWithoutExtra(HashableBaseModel):
    """
    Represent a Pydantic BaseModel where non explicitly define fields are forbidden.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )


class FrozenBaseModelWithWarnedExtra(HashableBaseModel, BaseModelExtraWarning):
    """
    Represent a Pydantic BaseModel where non explicitly define fields are allowed with a warning.
    """

    model_config = ConfigDict(
        extra="allow",
        frozen=True,
    )


def make_validator(field_name: str, validator: Callable[..., bool] | dict[str, Any]):
    """Factory of field validator to use in pydantic models.

    This version supports simple validator callables and compound validators
    expressed as dictionaries using "and"/"or" logical operations.

    Args:
        field_name(str): name of the validated field. For error message purpose only.
        validator(Callable[..., bool] or dict): A single validator or a compound logical dictionary representing
            "and" or "or" logical validator combinations.

    Returns:
        (Callable[..., Any): The validator to be used.

    Raises:
        ValueError: if validator call returns False. Note: used with Pydantic field_validator this will finally raise a
            Pydantic ValidationError

    Examples:
        >>> import validators
        >>> my_validator = make_validator("blah", validators.ipv4)
        >>> print(my_validator("127.0.0.1"))
        >>> try: my_validator("whatever"); except ValueError as err: print(err)

        >>> compound_validator = make_validator("blah", {"or": [validators.ipv4, validators.ipv6]})
        >>> print(compound_validator("127.0.0.1"))  # Passes ipv4
        >>> print(compound_validator("::1"))  # Passes ipv6
        >>> try: compound_validator("whatever"); except ValueError as err: print(err)

    References:
        https://docs.pydantic.dev/2.9/examples/validators/ [consulted on September 30th, 2024]

    """

    def evaluate_validator(
        evaluated_validator: Callable[..., bool | dict[str, Any]], value: Any
    ) -> bool:
        """Recursively evaluate validators based on boolean logic in the dictionary format."""
        if isinstance(evaluated_validator, dict):
            # Handling "or" and "and" logical operators
            if "or" in evaluated_validator:
                # Any one of the validators in the list should pass
                return any(
                    evaluate_validator(sub_validator, value)
                    for sub_validator in evaluated_validator["or"]
                )
            if "and" in evaluated_validator:
                # All validators in the list should pass
                return all(
                    evaluate_validator(sub_validator, value)
                    for sub_validator in evaluated_validator["and"]
                )
            raise ValueError(
                f"Unsupported logical operation in validator: {evaluated_validator}"
            )
        else:
            # Regular callable validator
            return evaluated_validator(value)

    def field_validator(value: Any) -> Any:
        if evaluate_validator(validator, value):
            return value
        validator_name = getattr(validator, "__name__", repr(validator))
        message = f"Field: {field_name} with value: {str(value)} does not pass {validator_name} validation."
        raise ValueError(message)

    return field_validator
