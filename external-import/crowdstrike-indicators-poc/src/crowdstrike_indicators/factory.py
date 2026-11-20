"""Build the CrowdStrike indicator components from one validated configuration."""

from collections.abc import Callable
from typing import Any, Protocol

from crowdstrike_indicators.extract.actors import ActorsClient, CrowdStrikeActorEnricher
from crowdstrike_indicators.extract.extractor import (
    CrowdStrikeIndicatorExtractor,
    IndicatorsClient,
)
from crowdstrike_indicators.transform.add_attack_patterns import (
    AttackPatternCatalog,
    CrowdStrikeAddAttackPatterns,
)
from crowdstrike_indicators.transform.add_identity import CrowdStrikeAddIdentity
from crowdstrike_indicators.transform.add_malware import CrowdStrikeAddMalware
from crowdstrike_indicators.transform.create_indicator import CreateCrowdStrikeIndicator
from crowdstrike_indicators.transform.make_bundle import MakeStixBundle
from pydantic import Field, FilePath, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from shared.factory import AbstractConnectorFactory, ConnectorConfigurationError
from shared.transformer import AbstractTransformer

DEFAULT_BASE_URL = "https://api.crowdstrike.com"
ATTACK_DATA_VARIABLE = "CROWDSTRIKE_ATTACK_DATA"


class CrowdStrikeSettings(BaseSettings):
    """The configuration of the CrowdStrike indicators source.

    Read from ``CROWDSTRIKE_*`` variables. Keys that are not settings are
    ignored, and so are empty values: an empty credential is reported missing,
    an empty ``CROWDSTRIKE_ATTACK_DATA`` means no dataset.
    """

    model_config = SettingsConfigDict(
        env_prefix="CROWDSTRIKE_", extra="ignore", env_ignore_empty=True
    )

    client_id: SecretStr = Field(min_length=1)
    client_secret: SecretStr = Field(min_length=1)
    base_url: str = Field(default=DEFAULT_BASE_URL, min_length=1)
    attack_data: FilePath | None = None


class IntelClient(IndicatorsClient, ActorsClient, Protocol):
    """The FalconPy ``Intel`` operations the components use: indicators and actors."""


class _LazyIntelClient:
    """Build the API client on the first API call, then forward every call to it.

    FalconPy's ``Intel`` authenticates when it is built: deferring it keeps
    the creation of the components free of any request to CrowdStrike.
    """

    def __init__(self, create: Callable[[], IntelClient]) -> None:
        self._create = create
        self._client: IntelClient | None = None

    def _get(self) -> IntelClient:
        if self._client is None:
            self._client = self._create()
        return self._client

    def query_indicator_entities(self, **kwargs: Any) -> dict[str, Any]:
        return self._get().query_indicator_entities(**kwargs)

    def query_actor_entities(self, **kwargs: Any) -> dict[str, Any]:
        return self._get().query_actor_entities(**kwargs)


class CrowdStrikeConnectorFactory(AbstractConnectorFactory[CrowdStrikeSettings]):
    """Build the CrowdStrike indicator extractor and its chain of transformers.

    Construction validates the settings and, when ``attack_data`` is set,
    reads the MITRE ATT&CK dataset once. One API client per factory is shared
    by every extractor and enricher it creates; it is built, and authenticates,
    on the first API call only.
    """

    def __init__(self, **kwargs: Any) -> None:
        """Load and validate the settings, then read the ATT&CK dataset, if any.

        Takes the arguments of :class:`AbstractConnectorFactory`.

        :raises ConnectorConfigurationError: if a parameter is missing or
            invalid, or if the dataset is not a STIX bundle.
        """
        super().__init__(**kwargs)
        self._catalog = self._load_catalog()
        self._client = _LazyIntelClient(self._create_client)

    def _load_catalog(self) -> AttackPatternCatalog | None:
        path = self.settings.attack_data
        if path is None:
            return None
        try:
            return AttackPatternCatalog.from_file(path)
        except (ValueError, OSError) as error:
            raise ConnectorConfigurationError(
                [(ATTACK_DATA_VARIABLE, str(error))]
            ) from None

    def _create_client(self) -> IntelClient:
        """Build the FalconPy ``Intel`` client; it authenticates when built."""
        from falconpy import Intel

        return Intel(
            client_id=self.settings.client_id.get_secret_value(),
            client_secret=self.settings.client_secret.get_secret_value(),
            base_url=self.settings.base_url,
        )

    @property
    def attack_pattern_catalog(self) -> AttackPatternCatalog | None:
        """The ATT&CK dataset read at construction, or ``None`` without one."""
        return self._catalog

    def create_extractor(self) -> CrowdStrikeIndicatorExtractor:
        """Return a new extractor, with a new actor enricher (and cache),
        both using the factory's API client. Sends no request."""
        return CrowdStrikeIndicatorExtractor(
            self._client, CrowdStrikeActorEnricher(self._client)
        )

    def create_transformers(self) -> list[AbstractTransformer[Any, Any]]:
        """Return new transformers: the STIX indicator, its Malware, its
        AttackPatterns when a dataset is set, the STIX bundle, then its author
        identity."""
        attack_steps: list[AbstractTransformer[Any, Any]] = (
            []
            if self._catalog is None
            else [CrowdStrikeAddAttackPatterns(self._catalog)]
        )
        return [
            CreateCrowdStrikeIndicator(),
            CrowdStrikeAddMalware(),
            *attack_steps,
            MakeStixBundle(),
            CrowdStrikeAddIdentity(),
        ]
