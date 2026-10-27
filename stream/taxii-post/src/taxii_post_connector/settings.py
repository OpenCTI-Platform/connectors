from typing import Annotated, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import (
    BeforeValidator,
    Field,
    HttpUrl,
    SecretStr,
    WithJsonSchema,
    model_validator,
)


def parse_identity_id_mapping(value: str | dict[str, str]) -> dict[str, str]:
    """
    Converts a comma separated list of original_id:replacement_id into a dictionary
    """
    # if parsed from config.yml it is already a dictionary and can be returned
    if not isinstance(value, str):
        return value

    mapping = {}
    for pair in value.split(","):
        # for an unset value of "", such that we will return the empty dictionary
        if not pair.strip():
            continue

        if pair.count(":") != 1:
            raise ValueError(
                f"Invalid identity ID mapping pair {pair!r}, expected original_id:replacement_id"
            )

        original_id, replacement_id = pair.split(":")
        mapping[original_id.strip()] = replacement_id.strip()
    return mapping


# A type for the identity_id_mapping config variable, which is a string of the form original_id:replacement_id,original_id:replacement_id
# which this will parse into a dictionary
IdentityIdMapping = Annotated[
    # the final value for identity_id_mapping becomes a dictionary: {original_id: replacement_id}
    dict[str, str],
    # converts the env string into said dictionary
    BeforeValidator(parse_identity_id_mapping),
    # enforces the generated schema to describe identity_id_mapping as a string instead of a dictionary
    # because what is entered is indeed a string, it is just converted afterwards
    WithJsonSchema({"type": "string"}),
]


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="27a0802c-2a6d-4ecc-ac22-151e74d5cd18",
    )
    name: str = Field(
        description="The name of the connector.",
        default="TAXII POST",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["taxii"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )


class TaxiiConfig(BaseConfigModel):
    """Config fields specific to the TAXII POST connector (`TAXII_*` env vars)."""

    url: HttpUrl = Field(
        description="The URL of the TAXII server.",
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL certificates.",
        default=True,
    )
    api_root: str = Field(
        description="The TAXII API root path segment.",
        default="root",
    )
    collection_id: str = Field(
        description="The target TAXII collection ID.",
    )
    token: SecretStr | None = Field(
        description="Bearer token for authentication. Takes precedence over basic auth.",
        default=None,
    )
    login: str | None = Field(
        description="Username for basic auth.",
        default=None,
    )
    password: SecretStr | None = Field(
        description="Password for basic auth.",
        default=None,
    )
    version: str = Field(
        description="TAXII protocol version.",
        default="2.1",
    )
    stix_version: str = Field(
        description="STIX output version.",
        default="2.1",
    )
    delete_created_by_ref: bool = Field(
        description="Strip created_by_ref from objects before posting.",
        default=True,
    )
    delete_marking_definition: bool = Field(
        description="Strip object_marking_refs from objects before posting.",
        default=True,
    )
    identity_id_mapping: IdentityIdMapping = Field(
        description=(
            "The IDs of Identity objects to be replaced before posting, including the identity's own id and every reference to it. Written as comma separated original_id:replacement_id pairs (e.g. identity--<uuid>:identity--<uuid>). This change does not propogate back to the OpenCTI instance, it only alters the bundles being delivered to the TAXII server."
        ),
        default="",
    )

    @model_validator(mode="after")
    def _check_auth(self) -> "TaxiiConfig":
        if not self.token and not (self.login and self.password):
            raise ValueError(
                "Either `token` or both `login` and `password` must be set."
            )
        return self


class ConnectorSettings(BaseConnectorSettings):
    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    taxii: TaxiiConfig = Field(default_factory=TaxiiConfig)
