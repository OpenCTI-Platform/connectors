
from dataclasses import dataclass
from types import ModuleType
from typing import Union
from urllib3 import make_headers
from urllib3.util import parse_url

import titan_client
from titan_client import titan_stix
import verity471
from verity471 import verity_stix
from verity471.verity_stix.exceptions import EmptyBundle


from intel471.streams import titan as titan_streams
from intel471.streams import verity471 as verity471_streams


@dataclass
class ClientWrapper:
    backend_name: str
    module: ModuleType
    config: object   # TODO: better type
    stix_mapper_settings_class: object  # TODO: better type
    empty_bundle_exception: object


def get_streams(backend):
    if backend == "titan":
        return (titan_streams.Intel471CVEsStream, )
    if backend == "verity471":
        return (
            verity471_streams.Verity471IndicatorsStream,
            verity471_streams.Verity471CVEsStream, 
            verity471_streams.Verity471FintelStream, 
            verity471_streams.Verity471BreachAlertsStream,
            verity471_streams.Verity471GeopolReportsStream,
            verity471_streams.Verity471InfoReportsStream,
            verity471_streams.Verity471MalwareReportsStream,
            verity471_streams.Verity471SpotReportsStream,
            )
    raise Exception("No such backend")  # TODO better handling, #TODO backend names as consts


def get_client(backend_name: str, api_username: str, api_key: str, proxy_url: Union[str, None] = None) -> ClientWrapper:
    config_kwargs = {
        "username": api_username,
        "password": api_key
    }
    if proxy_url:
        config_kwargs["proxy"] = proxy_url
        if proxy_auth := parse_url(proxy_url).auth:
            config_kwargs["proxy_headers"] = make_headers(
                proxy_basic_auth=proxy_auth
            )

    if backend_name == "titan":
        return ClientWrapper(
            backend_name,
            titan_client,
            titan_client.Configuration(**config_kwargs),
            titan_stix.STIXMapperSettings,
            titan_stix.exceptions.EmptyBundle
            )
    if backend_name == "verity471":
        return ClientWrapper(
            backend_name,
            verity471,
            verity471.Configuration(**config_kwargs),
            verity_stix.STIXMapperSettings,
            EmptyBundle
            )
    raise Exception("No such backend")  # TODO better handling, #TODO backend names as consts
