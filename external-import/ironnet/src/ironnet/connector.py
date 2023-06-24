"""ThreatAPI connector"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

import pycti
import stix2
import yaml
from pycti import Indicator
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper

from .client import IronNetClient, IronNetItem
from .config import RootConfig
from .loop import ConnectorLoop

__all__ = [
    "IronNetConnector",
]

log = logging.getLogger(__name__)
ObservableType = Union[stix2.DomainName, stix2.IPv4Address, stix2.IPv6Address]


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
        aggregated: Dict[str, List[IronNetItem]] = defaultdict(list)

        # Aggregate under the ioc value so we can merge objects together
        for result in results:
            aggregated[result.indicator].append(result)

        for agg in aggregated.values():
            stix_objects = self._create_stix(agg)
            bundle_objects.extend(stix_objects)

        if len(bundle_objects) == 0:
            log.info("No objects to bundle")
            return

        # Dedup the bundle (mainly malware objects), keep the first seen
        bundle_objects = {obj.id: obj for obj in reversed(bundle_objects)}
        bundle_objects = list(bundle_objects.values())

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

    def _create_stix(
        self, results: List[IronNetItem]
    ) -> Iterable[
        Union[
            ObservableType,
            stix2.Indicator,
            stix2.Malware,
            stix2.Relationship,
        ]
    ]:
        """
        Create an observable.

        :param result: API result item
        :return: An observation
        """

        observable = self._create_observable(results)
        if observable:
            yield observable
        else:
            return

        indicator = self._create_indicator(observable)
        if indicator:
            yield indicator

        malwares = list(self._create_malwares(results, observable))
        yield from malwares

        yield from self._create_relationships(results, observable, indicator, malwares)

    def _create_observable(
        self,
        results: List[IronNetItem],
    ) -> Optional[ObservableType]:
        """Create an observable"""

        result = results[0]
        value = result.indicator
        marking_refs = [resolve_tlp(result.tlp)]
        score = resolve_confidence(result.confidence)

        threats = {result.threat for result in results}
        threat_types = {result.threat_type for result in results}
        labels = list(threats.union(threat_types))

        threat_ports = defaultdict(set)
        for result in results:
            threat_ports[result.threat].add(result.port)

        description = "Observable associated with: "
        for threat_name, threat_ports in threat_ports.items():
            threat_ports = ",".join(map(str, sorted(threat_ports)))
            description += f"\n- `{threat_name}` on port(s) `{threat_ports}`"

        if result.type == "domain-name":
            stix_type = stix2.DomainName
        elif result.type == "ipv4-addr":
            stix_type = stix2.IPv4Address
        elif result.type == "ipv6-addr":
            stix_type = stix2.IPv6Address
        else:
            log.warning(
                "Could not determine observable type: %s (%s)",
                result.indicator,
                result.type,
            )
            return None

        log.debug("Creating observable: %s", value)
        return stix_type(
            value=value,
            object_marking_refs=marking_refs,
            custom_properties=dict(
                x_opencti_created_by_ref=self._identity_id,
                x_opencti_description=description,
                x_opencti_labels=labels,
                x_opencti_score=score,
            ),
        )

    def _create_malwares(
        self,
        results: List[IronNetItem],
        observable: ObservableType,
    ) -> Iterable[stix2.Malware]:
        """Create a simple malware object"""

        threats = {result.threat for result in results}
        for name in threats:
            yield stix2.Malware(
                id=pycti.Malware.generate_id(name),
                name=name,
                is_family=True,
                created_by_ref=self._identity_id,
                confidence=self._helper.connect_confidence_level,
                object_marking_refs=observable.object_marking_refs,
            )

    def _create_indicator(
        self,
        observable: ObservableType,
    ) -> Optional[stix2.Indicator]:
        """Create an indicator"""

        value = observable.value

        if observable.type == "domain-name":
            pattern = f"[domain-name:value = '{value}']"
            main_observable_type = "Domain-Name"
            is_ip_indicator = False
        elif observable.type == "ipv4-addr":
            pattern = f"[ipv4-addr:value = '{value}']"
            main_observable_type = "IPv4-Addr"
            is_ip_indicator = True
        elif observable.type == "ipv6-addr":
            pattern = f"[ipv6-addr:value = '{value}']"
            main_observable_type = "IPv6-Addr"
            is_ip_indicator = True
        else:
            log.warning("Could not determine observable type: %s", value)
            return None

        create_indicator = self._config.ironnet.create_indicators
        if is_ip_indicator:
            create_indicator &= self._config.ironnet.create_ip_indicators

        if not create_indicator:
            return None

        valid_until = (
            (date.today() + self._config.ironnet.ip_indicator_valid_until)
            if is_ip_indicator
            else None
        )

        description = observable.x_opencti_description.replace(
            "Observable", "Indicator", 1
        )

        log.debug("Creating indicator: %s", pattern)
        return stix2.Indicator(
            id=Indicator.generate_id(pattern),
            pattern_type="stix",
            pattern=pattern,
            name=value,
            description=description,
            labels=observable.x_opencti_labels,
            valid_until=valid_until,
            created_by_ref=self._identity_id,
            confidence=self._helper.connect_confidence_level,
            object_marking_refs=observable.object_marking_refs,
            custom_properties=dict(
                x_opencti_score=observable.x_opencti_score,
                x_opencti_main_observable_type=main_observable_type,
            ),
        )

    def _create_relationships(
        self,
        results: List[IronNetItem],
        observable: ObservableType,
        indicator: Optional[stix2.Indicator],
        malwares: List[stix2.Malware],
    ) -> List[stix2.Relationship]:
        """Create relationships between all available objects"""

        if indicator:
            rel_type = "based-on"
            yield stix2.Relationship(
                id=pycti.StixCoreRelationship.generate_id(
                    rel_type, indicator.id, observable.id
                ),
                source_ref=indicator.id,
                relationship_type=rel_type,
                target_ref=observable.id,
                created_by_ref=self._identity_id,
                confidence=self._helper.connect_confidence_level,
                object_marking_refs=observable.object_marking_refs,
            )

        threat_ports = defaultdict(set)
        for result in results:
            threat_ports[result.threat].add(result.port)

        for malware in malwares:
            malware_ports = threat_ports[malware.name]
            malware_ports = ",".join(map(str, sorted(malware_ports)))
            obs_desc = f"Observable discovered on port(s) `{malware_ports}`"

            rel_type = "communicates-with"
            yield stix2.Relationship(
                id=pycti.StixCoreRelationship.generate_id(
                    rel_type, malware.id, observable.id
                ),
                source_ref=malware.id,
                relationship_type=rel_type,
                target_ref=observable.id,
                description=obs_desc,
                created_by_ref=self._identity_id,
                confidence=self._helper.connect_confidence_level,
                object_marking_refs=observable.object_marking_refs,
            )

            if indicator:
                ind_desc = obs_desc.replace("Observable", "Indicator", 1)
                rel_type = "indicates"
                yield stix2.Relationship(
                    id=pycti.StixCoreRelationship.generate_id(
                        rel_type, indicator.id, malware.id
                    ),
                    source_ref=indicator.id,
                    relationship_type=rel_type,
                    target_ref=malware.id,
                    description=ind_desc,
                    created_by_ref=self._identity_id,
                    confidence=self._helper.connect_confidence_level,
                    object_marking_refs=indicator.object_marking_refs,
                )


def resolve_tlp(tlp: str) -> stix2.MarkingDefinition:
    """Resolve the marking definition to a stix object"""

    marking_ref = {
        "WHITE": stix2.TLP_WHITE.id,
        "CLEAR": stix2.TLP_WHITE.id,  # confirmed same UUID
        "GREEN": stix2.TLP_GREEN.id,
        "AMBER": stix2.TLP_AMBER.id,
        "AMBER+STRICT": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
        "RED": stix2.TLP_RED.id,
    }.get(tlp)

    if marking_ref is None:
        raise ValueError(f"Invalid marking type: {tlp}")

    return marking_ref


def resolve_confidence(confidence: str) -> int:
    """Resolve the score from the result confidence"""

    score = {
        "Low": 20,
        "Medium": 60,
        "High": 100,
    }.get(confidence)

    if score is None:
        raise ValueError(f"Invalid confidence/score: {confidence}")

    return score
