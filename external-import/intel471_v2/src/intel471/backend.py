
from dataclasses import dataclass
from types import ModuleType
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
    stix_mapper_settings_class: object  # TODO: better type
    empty_bundle_exception: object


def get_streams(backend):
    if backend == "titan":
        return (titan_streams.Intel471CVEsStream, )
    if backend == "verity471":
        return (
            verity471_streams.Verity471CVEsStream, 
            verity471_streams.Verity471FintelStream, 
            )
    raise Exception("No such backend")  # TODO better handling, #TODO backend names as consts


def get_client(backend):
    if backend == "titan":
        return ClientWrapper(
            backend,
            titan_client,
            titan_stix.STIXMapperSettings,
            titan_stix.exceptions.EmptyBundle
            )
    if backend == "verity471":
        return ClientWrapper(
            backend,
            verity471,
            verity_stix.STIXMapperSettings,
            EmptyBundle
            )
    raise Exception("No such backend")  # TODO better handling, #TODO backend names as consts

