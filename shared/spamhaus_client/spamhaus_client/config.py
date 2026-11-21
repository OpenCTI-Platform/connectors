"""Authentication settings shared by the abuse.ch connectors.

abuse.ch data is served in two ways: by abuse.ch itself, with an ``Auth-Key``
header (community mode), and by Spamhaus, with a JWT obtained from a username and
a password (commercial mode).
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)


class AbuseChAuthConfigMixin(BaseModel):
    """Mixin for the settings section of an abuse.ch connector.

    Add it to the section model, before the base config model::

        class ThreatFoxConfig(AbuseChAuthConfigMixin, BaseConfigModel):
            auth_env_prefix: ClassVar[str] = "THREATFOX"

    At least one mode must be configured. When both are, the commercial mode wins
    (``use_commercial``) and the community key is kept as a fallback.

    Validation errors of this section never echo the raw input (``hide_input_in_errors``).
    The settings model that contains the section must set the same option, otherwise
    its own error would show the input again.

    Attributes:
        auth_env_prefix: Prefix of the environment variables (e.g. ``THREATFOX``), used
            in the validation message.
        auth_key: abuse.ch Auth-Key (community mode).
        spamhaus_username: Spamhaus abuse.ch API account username (commercial mode).
        spamhaus_password: Spamhaus abuse.ch API account password (commercial mode).
    """

    # A validation error echoes the raw input by default, which here holds the
    # password in clear text. The outer settings model that embeds this section must
    # set the same option: pydantic decides on the model that raises the error.
    model_config = ConfigDict(hide_input_in_errors=True)

    auth_env_prefix: ClassVar[str] = ""

    auth_key: SecretStr | None = Field(
        default=None,
        description="abuse.ch Auth-Key (community mode), available at "
        "https://auth.abuse.ch. Optional when Spamhaus credentials are set.",
    )
    spamhaus_username: SecretStr | None = Field(
        default=None,
        description="Username of the Spamhaus abuse.ch API account (commercial "
        "mode), from the Spamhaus Customer Portal. Needs `spamhaus_password`.",
    )
    spamhaus_password: SecretStr | None = Field(
        default=None,
        description="Password of the Spamhaus abuse.ch API account (commercial "
        "mode). Needs `spamhaus_username`.",
    )

    @field_validator(
        "auth_key", "spamhaus_username", "spamhaus_password", mode="before"
    )
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        """Treat a blank value as unset (empty variables are common in compose files)."""
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        if isinstance(raw, str) and not raw.strip():
            return None
        return value

    @classmethod
    def _env_name(cls, field: str) -> str:
        """Return the environment variable of a field, e.g. ``THREATFOX_AUTH_KEY``."""
        prefix = f"{cls.auth_env_prefix}_" if cls.auth_env_prefix else ""
        return f"{prefix}{field}".upper()

    @model_validator(mode="after")
    def _check_auth_modes(self) -> AbuseChAuthConfigMixin:
        """Require a complete mode: an Auth-Key, or a username with a password."""
        username = self._env_name("spamhaus_username")
        password = self._env_name("spamhaus_password")
        if self.spamhaus_username is not None and self.spamhaus_password is None:
            raise ValueError(f"{username} is set but {password} is missing.")
        if self.spamhaus_password is not None and self.spamhaus_username is None:
            raise ValueError(f"{password} is set but {username} is missing.")
        if not self.community_configured and not self.commercial_configured:
            raise ValueError(
                "No authentication configured: set either "
                f"{self._env_name('auth_key')} (abuse.ch Auth-Key, community mode, "
                "get one at https://auth.abuse.ch) or "
                f"{username} and {password} (Spamhaus commercial mode)."
            )
        return self

    @property
    def community_configured(self) -> bool:
        """Whether the community mode is usable (an abuse.ch Auth-Key is set).

        A connector may override it when another setting also gives access to the
        community API (e.g. an export URL that holds the key).
        """
        return self.auth_key is not None

    @property
    def commercial_configured(self) -> bool:
        """Whether Spamhaus credentials (username and password) are set."""
        return self.spamhaus_username is not None and self.spamhaus_password is not None

    @property
    def use_commercial(self) -> bool:
        """Whether to use the commercial mode: it wins when both modes are set."""
        return self.commercial_configured
