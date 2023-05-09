"""Urlscan connector"""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Iterator, NamedTuple
from urllib.parse import urlparse

import stix2
import validators
import yaml
from pycti import Indicator, StixCoreRelationship
from pycti.connector.opencti_connector_helper import (
    OpenCTIConnectorHelper,
    get_config_variable,
)
from stix2.v21 import _Observable as Observable  # noqa

from .client import UrlscanClient
from .loop import ConnectorLoop
from .patterns import (
    IndicatorPattern,
    create_indicator_pattern_domain_name,
    create_indicator_pattern_url,
)

__all__ = [
    "UrlscanConnector",
]

log = logging.getLogger(__name__)


class UrlscanConnector:
    """Urlscan.io connector"""

    def __init__(self):
        """Initialization."""
        config_path = Path(__file__).parent.parent.joinpath("config.yml")
        config = (
            yaml.load(config_path.open(), Loader=yaml.SafeLoader)
            if config_path.is_file()
            else {}
        )

        self._helper = OpenCTIConnectorHelper(config)

        urlscan_url = get_config_variable(
            "URLSCAN_URL",
            ["urlscan", "url"],
            config,
        )

        urlscan_api_key = get_config_variable(
            "URLSCAN_API_KEY",
            ["urlscan", "api_key"],
            config,
        )

        self._create_indicators = get_config_variable(
            "URLSCAN_CREATE_INDICATORS",
            ["urlscan", "create_indicators"],
            config,
            default=True,
        )  # type: bool

        self._update_existing_data = get_config_variable(
            "URLSCAN_UPDATE_EXISTING_DATA",
            ["urlscan", "update_existing_data"],
            config,
            default=True,
        )  # type: bool

        default_tlp = get_config_variable(
            "URLSCAN_DEFAULT_TLP",
            ["urlscan", "default_tlp"],
            config,
            default="white",
        )  # type: str

        self._default_tlp = getattr(stix2, f"TLP_{default_tlp}".upper(), None)
        if not isinstance(self._default_tlp, stix2.MarkingDefinition):
            raise ValueError(f"Invalid tlp: {default_tlp}")

        self._identity = self._helper.api.identity.create(
            type="Organization",
            name="Urlscan",
            description="Phishing indicators from Urlscan.io",
        )

        self._default_labels = ["Phishing", "phishfeed"]
        self._client = UrlscanClient(urlscan_url, urlscan_api_key)
        self._loop = ConnectorLoop(self._helper, 86_400, 60, self._process_feed, False)

    def start(self) -> None:
        """Start the connector
        :return: None
        """
        self._loop.start()
        self._loop.join()

    def _process_feed(self, work_id: str) -> None:
        """Process the external connector feed
        :param work_id: Work ID
        :return: None
        """
        bundle_objects = []

        results = self._client.query()
        for url in results:
            obs1 = self._create_url_observable(url, "Urlscan.io URL")
            bundle_objects.extend(filter(None, [*obs1]))

            # This could potentially check for just "blob:"
            if url.startswith("blob:http"):
                url = url[5:]

            hostname = urlparse(url).hostname
            if hostname is None:
                log.warning("Could not parse url: %s", hostname)
                continue

            if validators.domain(hostname):
                obs2 = self._create_domain_observable(hostname, "Urlscan.io Domain")
                bundle_objects.extend(filter(None, [*obs2]))

                rels = self._create_observation_relationships(
                    obs1, obs2, "Urlscan.io URL/Domain"
                )
                bundle_objects.extend(rels)

            elif validators.ipv4(hostname):
                log.debug("Skipping IPv4 observable: %s", hostname)
                continue
            elif validators.ipv6(hostname):
                log.debug("Skipping IPv6 observable: %s", hostname)
                continue
            else:
                log.warning("Could not determine hostname: %s", url)
                continue

        if len(bundle_objects) == 0:
            log.info("No objects to bundle")
            return

        log.info(f"Bundling {len(bundle_objects)} objects")

        breakdown = Counter(type(obj).__name__ for obj in bundle_objects)
        log.info("Bundle breakdown: %s", dict(breakdown))

        self._helper.send_stix2_bundle(
            bundle=stix2.Bundle(
                objects=bundle_objects,
                allow_custom=True,
            ).serialize(),
            update=self._update_existing_data,
            work_id=work_id,
        )

    def _create_url_observable(
        self,
        value: str,
        description: str,
    ) -> Observation:
        """Create an observation based on a URL
        :param value: URL value
        :param description: Description
        :return: An observation
        """
        sco = stix2.URL(
            value=value,
            object_marking_refs=[self._default_tlp],
            custom_properties=dict(
                x_opencti_created_by_ref=self._identity["standard_id"],
                x_opencti_description=description,
                x_opencti_labels=self._default_labels,
                x_opencti_score=self._helper.connect_confidence_level,
            ),
        )

        sdo = None
        sro = None
        if self._create_indicators:
            pattern = create_indicator_pattern_url(value)
            sdo = self._create_indicator(
                value=value,
                pattern=pattern,
                description=description,
            )

            sro = self._create_relationship(
                rel_type="based-on",
                source_id=sdo.id,
                target_id=sco.id,
                description=description,
            )

        return Observation(sco, sdo, sro)

    def _create_domain_observable(
        self,
        value: str,
        description: str,
    ) -> Observation:
        """Create an observation based on a domain name
        :param value: Domain name
        :param description: Description
        :return: An observation
        """
        sco = stix2.DomainName(
            value=value,
            object_marking_refs=[self._default_tlp],
            custom_properties=dict(
                x_opencti_created_by_ref=self._identity["standard_id"],
                x_opencti_description=description,
                x_opencti_labels=self._default_labels,
                x_opencti_score=self._helper.connect_confidence_level,
            ),
        )

        sdo = None
        sro = None
        if self._create_indicators:
            pattern = create_indicator_pattern_domain_name(value)
            sdo = self._create_indicator(
                value=value,
                pattern=pattern,
                description=description,
            )

            sro = self._create_relationship(
                rel_type="based-on",
                source_id=sdo.id,
                target_id=sco.id,
                description=description,
            )

        return Observation(sco, sdo, sro)

    def _create_observation_relationships(
        self,
        target: Observation,
        source: Observation,
        description: str,
    ) -> Iterator[stix2.Relationship]:
        """
        Create relationships between two observations
        :param target: The target observation
        :param source: The source Observation
        :param description: Description of the relationship
        :return: Any relationships created
        """
        if source.observable and target.observable:
            yield self._create_relationship(
                rel_type="related-to",
                source_id=source.observable.id,
                target_id=target.observable.id,
                description=description,
            )

        if source.indicator and target.indicator:
            yield self._create_relationship(
                rel_type="related-to",
                source_id=source.indicator.id,
                target_id=target.indicator.id,
                description=description,
            )

    def _create_indicator(
        self,
        value: str,
        pattern: IndicatorPattern,
        description: str,
    ) -> stix2.Indicator:
        """Create an indicator
        :param value: Observable value
        :param pattern: Indicator pattern
        :param description: Description
        :return: An indicator
        """
        return stix2.Indicator(
            id=Indicator.generate_id(pattern.pattern),
            pattern_type="stix",
            pattern=pattern.pattern,
            name=value,
            description=description,
            labels=self._default_labels,
            confidence=self._helper.connect_confidence_level,
            object_marking_refs=[self._default_tlp],
            custom_properties=dict(
                x_opencti_score=self._helper.connect_confidence_level,
                x_opencti_main_observable_type=pattern.main_observable_type,
            ),
            allow_custom=True,
        )

    def _create_relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        description: str,
    ) -> stix2.Relationship:
        """Create a relationship
        :param rel_type: Relationship type
        :param source_id: Source ID
        :param target_id: Target ID
        :param description: Description
        :return: A relationship
        """
        confidence = self._helper.connect_confidence_level
        created_by_ref = self._identity["standard_id"]

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            source_ref=source_id,
            relationship_type=rel_type,
            target_ref=target_id,
            created_by_ref=created_by_ref,
            confidence=confidence,
            description=description,
            labels=self._default_labels,
            object_marking_refs=[self._default_tlp],
            allow_custom=True,
        )


class Observation(NamedTuple):
    """Result from making an observable"""

    observable: Observable
    indicator: stix2.Indicator = None
    relationship: stix2.Relationship = None
