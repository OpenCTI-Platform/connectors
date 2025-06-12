"""Unit tests for warning tools."""

from typing import Literal

import pytest
from connectors_sdk.exceptions.warning import (
    FieldWarning,
    PermissiveBaseModel,
    PermissiveLiteral,
    Recommended,
    ValidationWarning,
)
from pydantic import ValidationError

### TEST FIELDWARNING


def test_field_warning_should_have_correct_string_representation():
    """Test that FieldWarning has the correct string representation."""
    # Given a FieldWarning instance
    warning = FieldWarning(
        type_="missing_recommended",
        loc=("field_name",),
        msg="Recommended field is missing.",
        input_=None,
    )
    # When converting it to a string
    warning_str = str(warning)
    # Then the string representation should be correct
    assert all(
        sentence_part in warning_str
        for sentence_part in (
            "field_name",
            "Recommended field is missing.",
            "['type':'missing_recommended', 'input_value': None]",
        )
    )


### TEST VALIDATIONWARNING


def test_validation_warning_should_aggregate_field_warnings():
    """Test that ValidationWarning aggregates FieldWarnings."""
    # Given multiple FieldWarnings
    warnings_list = [
        FieldWarning(
            type_="missing_recommended",
            loc=("field1",),
            msg="Recommended field is missing.",
            input_=None,
        ),
        FieldWarning(
            type_="extra_warn",
            loc=("field2",),
            msg="Unexpected extra field.",
            input_="extra_value",
        ),
    ]
    # When creating a ValidationWarning with these warnings
    validation_warning = ValidationWarning(
        model=PermissiveBaseModel, warnings=warnings_list
    )
    # Then ValidationWarning should aggregate the warnings
    assert validation_warning.warnings_count == len(validation_warning.warnings) == 2


### TEST RECOMMENDED


def test_recommended_should_emit_warning_for_missing_field():
    """Test that Recommended emits a warning for missing fields."""

    # Given a model with a Recommended field
    class MyModel(PermissiveBaseModel):
        recommended_field: Recommended[int]

    # When creating an instance with the field missing
    # Then a ValidationWarning is emitted
    with pytest.warns(ValidationWarning):
        MyModel(recommended_field=None)


### TEST PERMISSIVELITERAL


def test_permissive_literal_should_allow_values_not_in_literal():
    """Test that PermissiveLiteral allows values not in the Literal."""

    # Given a model with a PermissiveLiteral field
    class MyModel(PermissiveBaseModel):
        literal_field: PermissiveLiteral[Literal["foo", "bar"]]

    # When creating an instance with a value not in the Literal
    with pytest.warns(ValidationWarning):
        instance = MyModel(literal_field="baz")
        # Then the instance should be created successfully
        assert instance.literal_field == "baz"


### TEST PERMISSIVEBASEMODEL


def test_permissive_base_model_should_allow_extra_fields():
    """Test that PermissiveBaseModel allows extra fields but emits warnings."""

    # Given a model with specific fields
    class MyModel(PermissiveBaseModel):
        foo: str
        bar: Recommended[int]

    # When creating an instance with extra fields
    # Then a warning is emmited
    with pytest.warns(ValidationWarning):
        instance = MyModel(foo="hello", bar=123, extra_field="extra_value")
        # And the extra field should not be stored in extra
        assert not hasattr(instance, "extra_field")
        assert instance.model_extra.get("extra_field") is None


def test_permissive_base_model_should_aggregate_warnings():
    """Test that PermissiveBaseModel aggregates warnings."""

    # Given a model with multiple warnings
    class MyModel(PermissiveBaseModel):
        foo: str
        bar: Recommended[int]
        baz: PermissiveLiteral[Literal["a", "b", "c"]]

    # When creating an instance with multiple issues
    with pytest.warns(ValidationWarning) as validation_warning:
        _ = MyModel(foo="hello", bar=None, baz="d", extra_field="extra_value")
        assert len(validation_warning[0].message.warnings) == 3


def test_permissive_base_model_should_raise_validation_error_for_invalid_field():
    """Test that PermissiveBaseModel raises ValidationError for invalid fields."""

    # Given a model with specific fields
    class MyModel(PermissiveBaseModel):
        foo: str
        bar: Recommended[int]

    # When creating an instance with an invalid field value
    # Then it should raise a ValidationError
    with pytest.raises(ValidationError):
        _ = MyModel(foo="hello", bar="invalid_value")
