"""
VMRay STIX Builder.

Provides the VMRaySTIXBuilder class to convert VMRay data into STIX 2.1 objects
for ingestion into OpenCTI, including indicators, malware, locations, and relationships.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union

from pycti import Indicator as PyctiIndicator
from pycti import Location as PyctiLocation
from pycti import Malware as PyctiMalware
from pycti import StixCoreRelationship
from stix2 import (
    URL,
    DomainName,
    EmailAddress,
    EmailMessage,
    File,
    Indicator,
    IPv4Address,
    IPv6Address,
    Location,
    Malware,
    Mutex,
    Process,
    Relationship,
    WindowsRegistryKey,
)

from .vmray_observable_transform import VMRayObservableTransform

STIXObservable = Union[
    URL,
    DomainName,
    EmailAddress,
    EmailMessage,
    File,
    IPv4Address,
    IPv6Address,
    WindowsRegistryKey,
    Mutex,
    Process,
]

THREAT_NAMES_REGEX = r"^[a-zA-Z0-9\s]+$"


class VMRaySTIXBuilder:
    """
    Unified builder for creating STIX 2.1 objects from VMRay.
    Handles Indicators, Malware, Locations, and Relationships.
    """

    def __init__(
        self,
        identity: str,
        default_markings: List[str],
        helper,
        threat_names_color: str,
        classifications_color: str,
        vti_color: str,
        mitre_color: str,
    ):
        self.identity = identity
        self.default_markings = default_markings
        self.helper = helper

        self.threat_names_color = threat_names_color
        self.classifications_color = classifications_color
        self.vti_color = vti_color
        self.mitre_color = mitre_color

    def create_indicator_from_observable(
        self,
        observable: STIXObservable,
        labels: Optional[List[str]] = None,
        created_by_ref: Optional[str] = None,
        kill_chain_phases: Optional[List[Dict[str, str]]] = None,
        confidence: Optional[int] = None,
        description: Optional[str] = None,
        score: Optional[int] = None,
    ) -> Tuple[Indicator, Relationship]:
        """
        Create a STIX 2.1 Indicator object from a STIX Observable.

        Args:
            observable (Observable): The observable object.
            labels (Optional[List[str]]): List of labels to attach.
            created_by_ref (Optional[str]): Reference ID for the creator.
            kill_chain_phases (Optional[List[Dict[str, str]]]):
                                            Kill-chain phase objects.
            confidence (Optional[int]): Confidence value (0–100).
            description (Optional[str]): Description for the indicator.
            score (Optional[int]): Score of the indicator.

        Returns:
            Tuple[Indicator, Relationship]: Indicator and its relationship to the observable.
        """
        pattern = self._generate_pattern(observable)
        name = self._get_observable_name(observable)
        OPENCTI_MAIN_TYPE_MAP = {
            "ipv4-addr": "IPv4-Addr",
            "ipv6-addr": "IPv6-Addr",
            "domain-name": "Domain-Name",
            "url": "Url",
            "file": "File",
            "windows-registry-key": "Windows-Registry-Key",
            "process": "Process",
            "mutex": "Mutex",
            "email-addr": "Email-Addr",
        }
        indicator = Indicator(
            id=PyctiIndicator.generate_id(pattern),
            name=name,
            description=description,
            pattern_type="stix",
            pattern=pattern,
            created_by_ref=created_by_ref or self.identity,
            labels=labels,
            valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            kill_chain_phases=kill_chain_phases,
            confidence=confidence,
            object_marking_refs=self.default_markings,
            x_opencti_score=score,
            x_opencti_main_observable_type=OPENCTI_MAIN_TYPE_MAP.get(
                getattr(observable, "type")
            ),
            allow_custom=True,
        )
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on", indicator.id, observable.id
            ),
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=observable.id,
            created_by_ref=created_by_ref or self.identity,
            object_marking_refs=self.default_markings,
            allow_custom=True,
        )
        return indicator, relationship

    def create_malware_objects_for_threat_names(
        self,
        threat_names: List[str],
        classifications: List[str],
        indicator: Indicator,
        obs: STIXObservable,
        labels: Optional[List[str]] = None,
    ) -> List[Union[Malware, Relationship]]:
        """
        Create malware objects for given threat names
        and relate them to an indicator.

        Args:
            threat_names (List[str]): List of threat names.
            classifications (List[str]): Malware classifications.
            indicator (Indicator): The associated indicator.
            obs (STIXObservable): The originating observable.
            labels (Optional[List[str]]): Labels for the malware objects.

        Returns:
            List[Union[Malware, Relationship]]: List of malware objects and relationships.
        """
        observables = []
        labels = labels or []
        for name in threat_names:
            malware_obj = Malware(
                id=PyctiMalware.generate_id(name),
                name=name,
                description="Malware created from VMRay IOC",
                malware_types=classifications,
                is_family=True,
                created_by_ref=self.identity,
                labels=labels,
                object_marking_refs=self.default_markings,
                allow_custom=True,
            )
            observables.append(malware_obj)
            rel = obs.create_relationship(
                src_id=indicator.id,
                tgt_id=malware_obj.id,
                markings=self.default_markings,
                rel_type="indicates",
                description="Indicator is related to target malware",
            )
            observables.append(rel)
        return observables

    def create_location_objects(
        self,
        indicator: Indicator,
        obs: STIXObservable,
        countries: List[str],
        country_codes: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
    ) -> List[Union[Location, Relationship]]:
        """
        Create Location objects from country information.

        Args:
            indicator(Indicator): Parent Indicator object.
            obs(STIXObservable): Primary Observable object.
            countries (List[str]): List of country names.
            country_codes (Optional[List[str]]):
                                Optional list of ISO country codes.
            labels (Optional[List[str]]): Optional labels.

        Returns:
            List[Union[Location, Relationship]]: List of location objects and relationships.
        """
        observables = []
        labels = labels or []
        country_codes = country_codes or []
        for i, country in enumerate(countries):
            code = country_codes[i] if i < len(country_codes) else country
            loc_obj = Location(
                id=PyctiLocation.generate_id(country, "country"),
                name=country,
                description="Country created from VMRay IOC",
                country=code,
                created_by_ref=self.identity,
                labels=labels,
                object_marking_refs=self.default_markings,
                allow_custom=True,
            )
            observables.append(loc_obj)
            rel = obs.create_relationship(
                src_id=indicator.id,
                tgt_id=loc_obj.id,
                markings=self.default_markings,
                rel_type="related-to",
            )
            observables.append(rel)
        return observables

    def create_related_obs_for_domain_url_originals(
        self,
        indicator: Indicator,
        obs: STIXObservable,
        originals: List[str],
        obs_type: str,
        labels: List[str],
        score: int,
        rel_type: str = "based-on",
    ) -> List[Union[STIXObservable, Relationship]]:
        """
        Create related observables for original domains or URLs
        and relate them to the indicator.

        Args:
            indicator (Indicator): The primary indicator.
            obs (STIXObservable): The originating observable.
            originals (List[str]): List of original domains or URLs.
            obs_type (str): Type of the observable (domain/url).
            labels (List[str]): Labels to attach.
            rel_type (str): Relationship type.

        Returns:
          List[Union[STIXObservable, Relationship]]:
                        List of created observables and relationships.
        """
        observables = []
        for original in originals:
            orig_obs = VMRayObservableTransform(
                observable_type=obs_type,
                observable_value=original,
                labels=labels,
                description=f"{obs_type.capitalize()} IOC from VMRay",
                created_by_ref=self.identity,
                score=score,
                markings=self.default_markings,
            )
            orig_obj = orig_obs.stix_observable
            if orig_obj:
                observables.append(orig_obj)
                rel = orig_obs.create_relationship(
                    src_id=indicator.id,
                    tgt_id=orig_obj.id,
                    markings=self.default_markings,
                    rel_type=rel_type,
                )
                observables.append(rel)
        return observables

    def _generate_pattern(self, observable: STIXObservable) -> str:
        """Generate STIX pattern for observable."""

        # Helper functions return safe values only
        def safe_registry_key(obs):
            return (
                "".join(c for c in getattr(obs, "key", "") if c.isprintable())
                .replace("\\", "\\\\")
                .replace("'", "\\'")
            )

        def safe_process_cmd(obs):
            return (
                getattr(obs, "command_line", "")
                .replace("\\", "\\\\")
                .replace("'", "\\'")
            )

        type_map = {
            "ipv4-addr": lambda obs: f"[ipv4-addr:value = '{obs.value}']",
            "ipv6-addr": lambda obs: f"[ipv6-addr:value = '{obs.value}']",
            "domain-name": lambda obs: f"[domain-name:value = '{obs.value}']",
            "url": lambda obs: f"[url:value = '{obs.value}']",
            "file": lambda obs: " OR ".join(
                f"[file:hashes.'{k}' = '{v}']"
                for k, v in getattr(obs, "hashes", {}).items()
            ),
            "process": lambda obs: f"[process:command_line = '{safe_process_cmd(obs)}']",
            "mutex": lambda obs: f"[mutex:name = '{getattr(obs, 'name', '')}']",
            "windows-registry-key": lambda obs: f"[windows-registry-key:key = '{safe_registry_key(obs)}']",
            "email-addr": lambda obs: f"[email-addr:value = '{getattr(obs, 'value', '')}']",
        }

        obs_type = getattr(observable, "type", None)
        if obs_type not in type_map:
            raise ValueError(f"Unsupported observable type: {obs_type}")

        return type_map[obs_type](observable)

    def _get_observable_name(self, obs: STIXObservable) -> str:
        """Return human-readable name of observable."""
        if obs.type == "file":
            for algo in ["SHA-256", "SHA1", "MD5"]:
                if hasattr(obs, "hashes") and algo in obs.hashes:
                    return obs.hashes[algo]
            if hasattr(obs, "name") and obs.name:
                return obs.name
            return "file"
        for attr in ["value", "name", "key", "command_line"]:
            if hasattr(obs, attr):
                return getattr(obs, attr)
        return obs.type
