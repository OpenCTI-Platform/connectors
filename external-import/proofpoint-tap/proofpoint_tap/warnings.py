"""Offer python warnings and tools."""

import os
import warnings
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FieldWarning(Warning):
    """Base class for field warnings."""

    def __init__(
        self,
        type_: str,
        loc: tuple[str],
        msg: str,
        input_: Any,
    ) -> None:
        """Initialize the field warning."""
        self.type = type_
        self.loc = loc
        self.msg = msg
        self.input = input_

    def __str__(self) -> str:
        """Return the string representation of the field warning."""
        return f"{'.'.join(self.loc)}{os.linesep}  {self.msg} ['type':'{self.type}', 'input_value': {self.input}]"


class ValidationWarning(Warning):
    """Base class for validation warnings."""

    def __init__(self, model: type[BaseModel], warnings: list[FieldWarning]) -> None:
        """Initialize the validation warning."""
        self.model = model
        self.warnings = warnings

    @property
    def warnings_count(self) -> int:
        """Count sub warning.

        Returns:
            (int): The number of warnings.

        """
        return len(self.warnings)

    def __str__(self) -> str:
        """Return the string representation of the validation warning."""
        warnings_repr = os.linesep.join(str(warning) for warning in self.warnings)
        return (
            f"{self.warnings_count} validation warning{'s' if self.warnings_count>1 else ''} for {self.model.__name__}{os.linesep}"
            f"{warnings_repr}"
        )


class BaseModelExtraWarning(BaseModel):
    """Base model that warns on extra fields."""

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="after")
    def check_extra_fields(
        self: "BaseModelExtraWarning",
    ) -> "BaseModelExtraWarning":
        """Check for extra fields, after model validation."""
        model_extra = self.model_extra
        if model_extra is not None and len(model_extra) > 0:
            field_warnings = [
                FieldWarning(
                    type_="extra_warn",
                    loc=(key,),
                    msg="Unexpected extra field",
                    input_=value,
                )
                for key, value in model_extra.items()
            ]
            warning = ValidationWarning(model=type(self), warnings=field_warnings)
            warnings.warn(warning, stacklevel=2)

        return self


class BaseModelWithRecommendedField(BaseModel):
    """Base model that alerts on absent fields."""

    recommended_key: ClassVar[str] = "is_recommended"

    @model_validator(mode="after")
    def check_recommended_fields(
        self: "BaseModelWithRecommendedField",
    ) -> "BaseModelWithRecommendedField":
        """Check for missing recommended fields and issue warnings."""
        field_warnings = []
        for field_name, field_info in self.model_fields.items():
            if callable(field_info.json_schema_extra):
                raise NotImplementedError
            else:
                json_schema_extra = field_info.json_schema_extra or {}
            is_recommended = json_schema_extra.get(self.recommended_key, False)

            # Check if the field is explicitly set or has a non-None value
            if is_recommended and (
                field_name not in self.model_fields_set
                or self.model_dump().get(field_name) is None
            ):
                field_warnings.append(
                    FieldWarning(
                        type_="missing_recommended",
                        loc=(field_name,),
                        msg="Recommended field is missing.",
                        input_=None,
                    )
                )

        if field_warnings:
            warning = ValidationWarning(model=type(self), warnings=field_warnings)
            warnings.warn(warning, stacklevel=2)
        return self


def RecommendedField(  # noqa: N802 # match Field naming style.
    default: Any = None, **kwargs: Any
) -> Any:
    """Define a recommended field with extra metadata."""
    return Field(
        default,
        json_schema_extra={BaseModelWithRecommendedField.recommended_key: True},
        **kwargs,
    )


class BaseModelWithRecommendedFieldAndExtraWarning(
    BaseModelWithRecommendedField, BaseModelExtraWarning
):
    """Combine BaseModelWithRecommendedField and BaseModelExtraWarning."""
