"""OpenCTI Cybersixgill indicator builder module."""

import logging
from datetime import datetime
from typing import List, Mapping, NamedTuple, Optional

import stix2
from cybersixgill.utils import (
    OBSERVATION_FACTORY_DOMAIN_NAME,
    OBSERVATION_FACTORY_FILE_MD5,
    OBSERVATION_FACTORY_FILE_SHA1,
    OBSERVATION_FACTORY_FILE_SHA256,
    OBSERVATION_FACTORY_HOSTNAME,
    OBSERVATION_FACTORY_IPV4_ADDRESS,
    OBSERVATION_FACTORY_IPV6_ADDRESS,
    OBSERVATION_FACTORY_URL,
    ObservableProperties,
    ObservationFactory,
    create_based_on_relationships,
    create_external_reference,
    create_indicator,
    create_organization,
)
from stix2.v21 import _DomainObject, _Observable  # type: ignore

log = logging.getLogger(__name__)


class Observation(NamedTuple):
    """Observation."""

    observable: Optional[_Observable]
    indicator: Optional[stix2.Indicator]
    relationship: Optional[stix2.Relationship]


class IndicatorBundleBuilderConfig(NamedTuple):
    """Cybersixgill Indicator bundle builder configuration."""

    indicator: dict
    provider: stix2.Identity
    source_name: str
    create_observables: bool
    create_indicators: bool
    confidence_level: int
    enable_relationships: bool


class IndicatorBundleBuilder:
    """Indicator bundle builder."""

    _INDICATOR_TYPE_TO_OBSERVATION_FACTORY: Mapping[str, ObservationFactory] = {
        "IPv4": OBSERVATION_FACTORY_IPV4_ADDRESS,
        "IPv6": OBSERVATION_FACTORY_IPV6_ADDRESS,
        "domain": OBSERVATION_FACTORY_DOMAIN_NAME,
        "hostname": OBSERVATION_FACTORY_HOSTNAME,
        "URL": OBSERVATION_FACTORY_URL,
        "URI": OBSERVATION_FACTORY_URL,
        "FileHash-MD5": OBSERVATION_FACTORY_FILE_MD5,
        "FileHash-SHA1": OBSERVATION_FACTORY_FILE_SHA1,
        "FileHash-SHA256": OBSERVATION_FACTORY_FILE_SHA256,
    }

    # STIX2 indicator pattern types.
    _INDICATOR_PATTERN_TYPE_STIX = "stix"

    def __init__(
        self,
        config: IndicatorBundleBuilderConfig,
    ) -> None:
        """Initialize indicator bundle builder."""
        self.indicator = config.indicator
        self.provider = config.provider
        self.indicator_author = self._determine_indicator_author(
            self.indicator, self.provider
        )
        self.source_name = config.source_name
        self.confidence_level = config.confidence_level
        self.create_observables = config.create_observables
        self.create_indicators = config.create_indicators
        self.enable_relationships = config.enable_relationships

    @staticmethod
    def _determine_indicator_author(
        indicator: dict, provider: stix2.Identity
    ) -> stix2.Identity:
        indicator_author = indicator.get("author_name")
        if not indicator_author:
            return provider
        if indicator_author == provider.name:
            return provider
        return create_organization(indicator_author, created_by=provider)

    def _create_authors(self) -> List[stix2.Identity]:
        authors = []
        if self.indicator_author is not self.provider:
            authors.append(self.provider)
        authors.append(self.indicator_author)
        return authors

    def _create_observations(
        self,
    ) -> List[Observation]:
        if not (self.create_observables or self.create_indicators):
            return []

        labels = self.indicator.get("labels")

        observations = []

        for indicator in self.indicator.get("indicators", []):
            indicator_type = indicator.get("Type")
            indicator_value = indicator.get("Value")

            factory = self._INDICATOR_TYPE_TO_OBSERVATION_FACTORY.get(indicator_type)
            if factory is None:
                log.warning(
                    "Unsupported indicator type: %s",
                    indicator_type,
                )
                continue

            # Create an observable.
            observable = None

            if self.create_observables:
                observable_properties = self._create_observable_properties(
                    indicator_value, labels
                )

                observable = factory.create_observable(observable_properties)

            # Create an indicator.
            indicator = None
            indicator_based_on_observable = None

            if self.create_indicators:
                indicator_pattern = factory.create_indicator_pattern(indicator_value)

                pattern_type = self._INDICATOR_PATTERN_TYPE_STIX

                indicator = self._create_indicator(
                    indicator_value,
                    self._create_indicator_description(self.indicator),
                    indicator_pattern.pattern,
                    pattern_type,
                    self.indicator.get("created"),
                    self.indicator.get("modified"),
                    self.indicator.get("valid_from"),
                    labels,
                    self.indicator.get("sixgill_confidence"),
                    main_observable_type=indicator_pattern.main_observable_type,
                    revoked=self.indicator.get("revoked", False),
                )
                if observable is not None:
                    based_on_relationship = self._create_based_on_relationships(
                        [indicator], [observable]
                    )
                    indicator_based_on_observable = based_on_relationship[0]

            observation = Observation(
                observable, indicator, indicator_based_on_observable
            )
            observations.append(observation)

        return observations

    def _create_observable_properties(
        self, value: str, labels: List[str]
    ) -> ObservableProperties:
        return ObservableProperties(value, self.indicator_author, labels, [])

    def _create_indicator(
        self,
        name: str,
        description: str,
        pattern: str,
        pattern_type: str,
        created,
        modified,
        valid_from: datetime,
        labels: List[str],
        confidence,
        main_observable_type: Optional[str] = None,
        revoked: Optional[bool] = False,
    ) -> stix2.Indicator:
        external_references = [self._create_indicator_external_references()]

        return create_indicator(
            pattern,
            pattern_type,
            created_by=self.indicator_author,
            name=name,
            description=description,
            created=created,
            modified=modified,
            valid_from=valid_from,
            labels=labels,
            confidence=confidence,
            external_references=external_references,
            x_opencti_main_observable_type=main_observable_type,
            revoked=revoked,
        )

    @staticmethod
    def _create_indicator_description(indicator) -> str:
        indicator_description = indicator.get("description")

        final_description = (
            f"{indicator_description}\n\n\nCybersixgill Actor: {indicator.get('sixgill_actor')}\n\n\n"
            f"Cybersixgill Feed Id: {indicator.get('sixgill_feedid')}\n\n\nCybersixgill Feed Name: "
            f"{indicator.get('sixgill_feedname')}\n\n\nCybersixgill Source: "
            f"{indicator.get('sixgill_source')}\n\n\nCybersixgill Severity: "
            f"{indicator.get('sixgill_severity')}\n\n\nCybersixgill Modified: "
            f"{indicator.get('modified')}\n\n\nCybersixgill Post Title:{indicator.get('sixgill_posttitle')}"
        )

        return final_description

    def _create_based_on_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[stix2.Relationship]:
        return create_based_on_relationships(
            self.indicator_author, sources, targets, self.confidence_level, []
        )

    def _create_indicator_external_references(self) -> stix2.ExternalReference:
        external_id = self.indicator.get("sixgill_postid")
        indicator_url = self.indicator.get("postid_link")
        source_name = "Cybersixgill Investigation Portal"
        description = self.indicator.get("sixgill_posttitle")
        return self._create_external_reference(
            indicator_url, source_name, description, external_id=external_id
        )

    @staticmethod
    def _create_external_reference(
        url: str, source_name: str, description: str, external_id: Optional[str] = None
    ) -> stix2.ExternalReference:
        return create_external_reference(
            source_name, url, description, external_id=external_id
        )

    def build(self) -> stix2.Bundle:
        """Build pulse bundle."""
        # Prepare STIX2 bundle.
        bundle_objects = []

        # Create author(s) and add to bundle.
        authors = self._create_authors()
        bundle_objects.extend(authors)

        # Create observations.
        observations = self._create_observations()

        # Get observables and add to bundle.
        observables = [o.observable for o in observations if o.observable is not None]
        bundle_objects.extend(observables)

        # Get indicators, create YARA indicators and to bundle.
        indicators = [o.indicator for o in observations if o.indicator is not None]
        # indicators.extend(self._create_yara_indicators())
        bundle_objects.extend(indicators)

        # Get observation relationships and add to bundle.
        indicators_based_on_observables = [
            o.relationship for o in observations if o.relationship is not None
        ]
        bundle_objects.extend(indicators_based_on_observables)

        # XXX: Without allow_custom=True the observable with the custom property
        # will cause an unexpected property (x_opencti_score) error.
        log.info(f"Bundling {len(bundle_objects)} objects")
        return stix2.Bundle(objects=bundle_objects, allow_custom=True)
