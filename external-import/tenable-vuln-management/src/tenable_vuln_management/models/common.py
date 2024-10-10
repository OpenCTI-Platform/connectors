"""
Offer common tools for connector's model.
"""

from typing import Any, Callable

from pydantic import BaseModel, ConfigDict


class FrozenBaseModelWithoutExtra(BaseModel):
    """
    Represent a Pydantic BaseModel where non explicitly define fields are forbidden.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    def __hash__(self):
        """Create a hash based on the model's json representation dynamically."""
        return hash(self.model_dump_json())

    def __eq__(self, other: "FrozenBaseModelWithoutExtra"):
        """Implement comparison between similar object."""
        if not isinstance(other, self.__class__):
            raise NotImplementedError("Cannot compare objects from different type.")
        # Compare the attributes by converting them to a dictionary
        return self.model_dump_json() == other.model_dump_json()


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
            elif "and" in evaluated_validator:
                # All validators in the list should pass
                return all(
                    evaluate_validator(sub_validator, value)
                    for sub_validator in evaluated_validator["and"]
                )
            else:
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
