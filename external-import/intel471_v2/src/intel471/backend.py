from dataclasses import dataclass
from enum import StrEnum
from types import ModuleType
from typing import Literal, Union

import titan_client
import verity471
from titan_client import titan_stix
from urllib3 import make_headers
from urllib3.util import parse_url
from verity471 import verity_stix
from verity471.verity_stix.exceptions import EmptyBundle

from .exceptions import UnknownBackendError
from .streams import titan as titan_streams
from .streams import verity471 as verity471_streams
from .streams.core.base import Intel471Stream


class BackendName(StrEnum):
    TITAN = "titan"
    VERITY471 = "verity471"


BackendNameLiteral = Literal["titan", "verity471"]


@dataclass(frozen=True)
class ClientWrapper:
    backend_name: BackendNameLiteral
    module: ModuleType
    config: titan_client.Configuration | verity471.Configuration
    stix_mapper_settings_class: (
        type[titan_stix.STIXMapperSettings] | type[verity_stix.STIXMapperSettings]
    )
    empty_bundle_exception: type[Exception]
    streams: tuple[type[Intel471Stream], ...]


def get_client(
    backend_name: BackendNameLiteral,
    api_username: str,
    api_key: str,
    proxy_url: Union[str, None] = None,
) -> ClientWrapper:
    config_kwargs = {"username": api_username, "password": api_key}
    if proxy_url:
        config_kwargs["proxy"] = proxy_url
        if proxy_auth := parse_url(proxy_url).auth:
            config_kwargs["proxy_headers"] = make_headers(proxy_basic_auth=proxy_auth)

    if backend_name == BackendName.TITAN:
        return ClientWrapper(
            backend_name,
            titan_client,
            titan_client.Configuration(**config_kwargs),
            titan_stix.STIXMapperSettings,
            titan_stix.exceptions.EmptyBundle,
            (
                titan_streams.Intel471IndicatorsStream,
                titan_streams.Intel471YARAStream,
                titan_streams.Intel471CVEsStream,
                titan_streams.Intel471ReportsStream,
                titan_streams.Intel471BreachAlertsStream,
                titan_streams.Intel471MalwareReportsStream,
                titan_streams.Intel471SpotReportsStream,
            ),
        )
    if backend_name == BackendName.VERITY471:
        return ClientWrapper(
            backend_name,
            verity471,
            verity471.Configuration(**config_kwargs),
            verity_stix.STIXMapperSettings,
            EmptyBundle,
            (
                verity471_streams.Verity471IndicatorsStream,
                verity471_streams.Verity471CVEsStream,
                verity471_streams.Verity471FintelStream,
                verity471_streams.Verity471BreachAlertsStream,
                verity471_streams.Verity471GeopolReportsStream,
                verity471_streams.Verity471InfoReportsStream,
                verity471_streams.Verity471MalwareReportsStream,
                verity471_streams.Verity471SpotReportsStream,
            ),
        )
    raise UnknownBackendError(f"Unknown backend: {backend_name}")
