"""Optional detached opencti-ng connection configuration.

When `url` + `jwt` are set (config.yml `opencti_ng:` section or `OPENCTI_NG_*`
env vars), the connector ingests directly into opencti-ng over a JWT instead of
the classic OpenCTI worker/queue. The write tenant and connector id are read
from the JWT, and run state lives server-side.
"""

from typing import Annotated, Optional

from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic import Field, HttpUrl, PlainSerializer
from pydantic_settings import SettingsConfigDict

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


class OctiNgConfig(BaseConfig):
    """Configuration for the detached opencti-ng platform (optional)."""

    # Hyphenated to match the established `opencti-ng:` convention (also used by
    # the MITRE connector). Env still uses the OPENCTI_NG_ prefix below.
    yaml_section = "opencti-ng"

    model_config = SettingsConfigDict(env_prefix="opencti_ng_")

    url: Optional[HttpUrlToString] = Field(
        default=None,
        description="The base URL of the opencti-ng platform (detached mode).",
        examples=["http://localhost:4100"],
    )
    jwt: Optional[str] = Field(
        default=None,
        description="Long-lived connector JWT for opencti-ng (detached mode).",
    )

    @property
    def enabled(self) -> bool:
        """Whether detached opencti-ng mode is fully configured."""
        return self.url is not None and self.jwt is not None
