"""Models"""

from __future__ import annotations

import re
from typing import Any, Dict, ForwardRef

import stix2
from pydantic import BaseModel, BaseSettings, Field, validator

__all__ = [
    "RootConfig",
    "ShodanConfig",
]


class RootConfig(BaseModel):
    """Root config"""

    shodan: ShodanConfig = Field(default_factory=lambda: ShodanConfig())


class ShodanConfig(BaseSettings):
    """Shodan config"""

    max_tlp: stix2.MarkingDefinition = Field(
        description="Max TLP to allow for lookups",
        env="SHODAN_MAX_TLP",
        default="white",
    )
    ssl_verify: bool = Field(
        description="Verify SSL connections to Shodan",
        env="SHODAN_SSL_VERIFY",
        default=True,
    )

    @validator("ssl_verify", pre=True)
    def _bool_validator(cls, value: str) -> bool:
        """Convert a truthy/falsy value to a bool"""

        if isinstance(value, bool):
            return value

        lowered = value.lower()
        if lowered in ["true", "t", "1"]:
            return True
        elif lowered in ["false", "f", "0"]:
            return False
        else:
            raise ValueError(f"Invalid bool: {value}")

    @validator("max_tlp", pre=True)
    def _tlp_validator(cls, value: str) -> stix2.MarkingDefinition:
        """Convert a marking name to an object"""
        if isinstance(value, stix2.MarkingDefinition):
            return value

        if not isinstance(value, str):
            value = str(value)

        # Chop off any "TLP:" type prefixes
        value = re.split("[^a-zA-Z]", value)[-1]
        value = f"TLP_{value}".upper()

        # Fetch TLP_<VALUE> from the stix2 root
        tlp_value = getattr(stix2, value, None)

        if not isinstance(tlp_value, stix2.MarkingDefinition):
            raise ValueError(f"Invalid marking: {value}")

        return tlp_value


def _update_forward_refs(locals_: Dict[str, Any]) -> None:
    """Update any models that have forward refs"""
    for obj in list(locals_.values()):
        fields = getattr(obj, "__fields__", {}).values()
        for field in fields:
            if isinstance(field.type_, ForwardRef):
                obj.update_forward_refs()


_update_forward_refs(locals())
