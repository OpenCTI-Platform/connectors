import abc
import datetime
import logging
import uuid
from abc import ABC
from collections import Callable, namedtuple
from typing import Union

import titan_client
from stix2 import Relationship, EmailAddress, File, ThreatActor, IPv4Address, URL, Location, DomainName, Bundle, \
    Identity
from stix2.base import _DomainObject, _Observable
from stix2.canonicalization.Canonicalize import canonicalize

from .exceptions import EmptyBundle, StixMapperNotFound

NAMESPACE_OASIS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

log = logging.getLogger(__name__)


MappingConfig = namedtuple("MappingConfig", ["patterning_mapper", "observable_mapper", "kwargs_extractor"])


def generate_id(stix_class: Union[_DomainObject, Relationship, _Observable], **id_contributing_properties: str):
    if id_contributing_properties:
        name = canonicalize(id_contributing_properties, utf8=False)
        return f"{stix_class._type}--{uuid.uuid5(NAMESPACE_OASIS, name)}"
    return f"{stix_class._type}--{uuid.uuid4()}"


author_name = "Intel 471 Inc."
author_identity = Identity(
    id=generate_id(Identity, name=author_name.lower(), identity_class="organization"),
    name=author_name,
    identity_class="organization",
    created=datetime.datetime(2022, 1, 1),
    modified=datetime.datetime(2022, 1, 1)
)


class StixMapper:

    def __init__(self, api_config: titan_client.Configuration):
        self.api_config = api_config

    mappers = {}

    @classmethod
    def register(cls, name: str, condition) -> Callable:
        """
        Decorator used for registering mapper classes. Decorate any class derived from BaseMapper like this:

        @StixMapper.register("actors", lambda x: "actorTotalCount" in x)
        class ActorsMapper(BaseMapper):
            def map(self, source: dict) -> Bundle:
                ... my implementation ...

        @param name: unique name under which the mapper will be registered
        @param condition: callable that will be called against the source dict
                          to determine if given mapper should be used or not

        """
        def inner_wrapper(wrapped_class: Callable) -> Callable:
            if name in cls.mappers:
                log.info(f"Mapper for {name} already exists. Will replace it")
            cls.mappers[name] = (condition, wrapped_class)
            return wrapped_class
        return inner_wrapper

    def map(self, source: dict, stix_version: str = "2.1", girs_names: dict = None) -> Bundle:
        log.info(f"Initializing converter. STIX version {stix_version}.")
        for name, (condition, mapper_class) in self.mappers.items():
            if condition(source):
                log.info(f"Mapping Titan payload for {name}.")
                mapper = mapper_class(self.api_config)
                bundle = mapper.map(source, girs_names)
                if bundle:
                    return bundle
                else:
                    raise EmptyBundle("STIX Mapper produced an empty bundle.")
        raise StixMapperNotFound(f"STIX Mapper for this payload is not available (keys: {', '.join(source.keys())}).")


class BaseMapper(ABC):

    def __init__(self, api_config: titan_client.Configuration):
        self.now = datetime.datetime.utcnow()
        self.api_config = api_config

    @abc.abstractmethod
    def map(self, source: dict) -> Bundle:
        raise NotImplementedError

    def map_entity(self, type_: str, value: str):
        entity2stix = {
            "EmailAddress": [EmailAddress, {"value": value}],
            "SHA256": [File, {"hashes": {"SHA256": value}}],
            "Handle": [ThreatActor, {"name": value}],
            "IPAddress": [IPv4Address, {"value": value}],
            "MaliciousURL": [URL, {"value": value}],
            "MaliciousDomain": [DomainName, {"value": value}],
        }
        try:
            klass, kwargs = entity2stix[type_]
        except KeyError:
            log.warning(f"Cannot map entity. Unknown type `{type_}`")
            return None
        else:
            return klass(**kwargs)

    def map_location(self, region: str = None, country: str = None):
        region_kwargs = {}
        if region:
            # TODO: map to region-ov.
            region_kwargs["region"] = region
        if country:
            region_kwargs["country"] = country
        if region_kwargs:
            return Location(id=generate_id(Location, **region_kwargs), **region_kwargs)
        return None

    def map_confidence(self, confidence: str):
        return {"low": 15, "medium": 50, "high": 85}.get(confidence, 0)

    def map_tactic(self, tactic: str):
        if tactic and len(tactic) > 0:
            return tactic.replace("_", "-").replace(" ", "-").lower()

    @staticmethod
    def shorten(text: str, limit: int) -> str:
        if len(text) > limit:
            text = text[:limit]
            while text[-1] != " ":
                text = text[:-1]
        return text.strip()
