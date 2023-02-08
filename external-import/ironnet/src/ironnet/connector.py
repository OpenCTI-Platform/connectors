"""ThreatAPI connector"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import date
from pathlib import Path
from typing import NamedTuple, Optional

import pycti
import stix2
import yaml
from pycti import Indicator
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2.v21 import _Observable as Observable  # noqa

from .client import IronNetClient, IronNetItem
from .config import RootConfig
from .loop import ConnectorLoop

__all__ = [
    "IronNetConnector",
]

log = logging.getLogger(__name__)


class IronNetConnector:
    """ThreatAPI connector"""

    def __init__(self):
        """Constructor"""

        config_path = Path(__file__).parent.parent.joinpath("config.yml")
        config = (
            yaml.load(config_path.open(), Loader=yaml.SafeLoader)
            if config_path.is_file()
            else {}
        )

        self._config = RootConfig.parse_obj(config)
        self._helper = OpenCTIConnectorHelper(config)

        self._identity = self._helper.api.identity.create(
            type="Organization",
            name="IronNet",
            description="IronNet Cybersecurity",
        )
        self._identity_id = self._identity["standard_id"]

        self._client = IronNetClient(
            self._config.ironnet.api_url,
            self._config.ironnet.api_key,
            self._config.ironnet.verify,
        )
        self._loop = ConnectorLoop(
            self._helper,
            self._config.connector.interval,
            self._config.connector.loop_interval,
            self._process_feed,
            True,
        )

    def start(self) -> None:
        """Start the connector"""

        self._loop.start()
        self._loop.join()

    def _process_feed(self, work_id: str) -> None:
        """
        Process the external connector feed.

        :param work_id: Work ID
        :return: None
        """
        bundle_objects = []

        results = self._client.query()
        for result in results:
            obs = self._create_observable(result)

            if obs:
                bundle_objects.extend(filter(None, [*obs]))

        if len(bundle_objects) == 0:
            log.info("No objects to bundle")
            return

        log.info("Bundling %d objects", len(bundle_objects))

        breakdown = Counter(type(obj).__name__ for obj in bundle_objects)
        log.info("Bundle breakdown: %s", dict(breakdown))

        self._helper.send_stix2_bundle(
            bundle=stix2.Bundle(
                objects=bundle_objects,
                allow_custom=True,
            ).serialize(),
            update=self._config.connector.update_existing_data,
            work_id=work_id,
        )

    def _create_observable(self, result: IronNetItem) -> Optional[Observation]:
        """
        Create an observable.

        :param result: API result item
        :return: An observation
        """

        value = result.indicator
        is_ip_indicator = False

        # TLP marking
        marking_ref = {
            "WHITE": stix2.TLP_WHITE,
            "CLEAR": stix2.TLP_WHITE,
            "GREEN": stix2.TLP_GREEN,
            "AMBER": stix2.TLP_AMBER,
            "AMBER+STRICT": stix2.TLP_AMBER,
            "RED": stix2.TLP_RED,
        }.get(result.tlp)
        if marking_ref is None:
            raise ValueError(f"Invalid marking type: {result.tlp}")
        marking_refs = [marking_ref.id]

        # Score/confidence mapping
        score = {
            "Low": 20,
            "Medium": 60,
            "High": 100,
        }.get(result.confidence)
        if score is None:
            raise ValueError(f"Invalid confidence/score: {result.confidence}")

        if result.type == "domain-name":
            stix_type = stix2.DomainName
            pattern = f"[domain-name:value = '{value}']"
            main_observable_type = "Domain-Name"

        elif result.type == "ipv4-addr":
            stix_type = stix2.IPv4Address
            pattern = f"[ipv4-addr:value = '{value}']"
            main_observable_type = "IPv4-Addr"
            is_ip_indicator = True

        elif result.type == "ipv6-addr":
            stix_type = stix2.IPv6Address
            pattern = f"[ipv6-addr:value = '{value}']"
            main_observable_type = "IPv6-Addr"
            is_ip_indicator = True

        else:
            log.warning("Could not determine hostname: %s", value)
            return None

        description = f"Indicator associated with {result.threat}"
        labels = [result.threat, result.threat_type]

        log.debug("Creating observable: %s", value)
        sco = stix_type(
            value=value,
            object_marking_refs=marking_refs,
            custom_properties=dict(
                x_opencti_created_by_ref=self._identity_id,
                x_opencti_description=description,
                x_opencti_labels=labels,
                x_opencti_score=score,
            ),
        )

        create_indicator = self._config.ironnet.create_indicators
        if is_ip_indicator:
            create_indicator &= self._config.ironnet.create_ip_indicators

        sdo = sro = None
        if create_indicator:
            valid_until = (
                (date.today() + self._config.ironnet.ip_indicator_valid_until)
                if is_ip_indicator
                else None
            )

            log.debug("Creating indicator: %s", pattern)
            sdo = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                pattern_type="stix",
                pattern=pattern,
                name=value,
                description=description,
                labels=labels,
                valid_until=valid_until,
                created_by_ref=self._identity_id,
                confidence=self._helper.connect_confidence_level,
                object_marking_refs=marking_refs,
                custom_properties=dict(
                    x_opencti_score=score,
                    x_opencti_main_observable_type=main_observable_type,
                ),
            )

            rel_type = "based-on"
            sro = stix2.Relationship(
                id=pycti.StixCoreRelationship.generate_id(rel_type, sdo.id, sco.id),
                source_ref=sdo.id,
                relationship_type=rel_type,
                target_ref=sco.id,
                created_by_ref=self._identity_id,
                confidence=self._helper.connect_confidence_level,
                description=description,
                labels=labels,
                object_marking_refs=marking_refs,
            )

        return Observation(sco, sdo, sro)


class Observation(NamedTuple):
    """Result from making an observable"""

    sco: Observable
    sdo: stix2.Indicator = None
    sro: stix2.Relationship = None
