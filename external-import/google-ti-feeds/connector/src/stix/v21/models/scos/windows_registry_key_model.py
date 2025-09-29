"""The module defines the WindowsRegistryKeyModel class, which represents a STIX 2.1 Windows Registry Key object."""

from datetime import datetime

from connector.src.stix.v21.models.ovs.windows_registry_datatype_ov_enums import (
    WindowsRegistryDatatypeOV,
)
from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import BaseModel, Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    WindowsRegistryKey,
    _STIXBase21,
)


class WindowsRegistryValueModel(BaseModel):
    """Model representing a Windows Registry Value."""

    name: str | None = Field(
        default=None,
        description="Name of the registry value. Use empty string for default value.",
    )
    data: str | None = Field(
        default=None, description="String data stored in the registry value."
    )
    data_type: WindowsRegistryDatatypeOV | None = Field(
        default=None,
        description="The data type of the registry value (e.g., REG_SZ, REG_DWORD).",
    )

    model_config = {"use_enum_values": True}

    @model_validator(mode="after")
    def at_least_one_field_required(self) -> "WindowsRegistryValueModel":
        """Ensure at least one of name, data, or data_type is set."""
        if self.name is None and self.data is None and self.data_type is None:
            raise ValueError(
                "At least one of 'name', 'data', or 'data_type' must be set for WindowsRegistryValueModel."
            )
        return self


class WindowsRegistryKeyModel(BaseSCOModel):
    """Model representing a Windows Registry Key in STIX 2.1 format."""

    key: str | None = Field(
        default=None,
        description="Full registry key path including hive (e.g., HKEY_LOCAL_MACHINE\\System\\Foo).",
    )
    values: list[WindowsRegistryValueModel] | None = Field(
        default=None,
        description="list of values found under the registry key. Each must include name, data, and data_type.",
    )

    modified_time: datetime | None = Field(
        default=None,
        description="Timestamp when the registry key was last modified.",
    )
    creator_user_ref: str | None = Field(
        default=None,
        description="Reference to the user-account object that created this key.",
    )
    number_of_subkeys: int | None = Field(
        default=None, ge=0, description="Number of subkeys under this key."
    )

    model_config = {
        "use_enum_values": True,
    }

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return WindowsRegistryKey(**self.model_dump(exclude_none=True))
