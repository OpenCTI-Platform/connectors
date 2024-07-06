"""
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Recorded Future makes no       #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Recorded Future shall not be liable for, and you assume all risk of          #
# using the foregoing.                                                         #
################################################################################
"""

import ipaddress
import json
from datetime import datetime

import pycti  # type: ignore
import stix2

TLP_MAP = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}


class ConversionError(Exception):
    """Generic exception for stix2 conversion issues"""

    pass


class RFStixEntity:
    """Parent class"""

    def __init__(self, name, _type, author=None, tlp="white"):
        self.name = name
        self.type = _type
        self.author = author or self._create_author()
        self.tlp = TLP_MAP.get(tlp, None)
        self.stix_obj = None

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        if not self.stix_obj:
            self.create_stix_objects()
        return [self.stix_obj]

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        pass

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        return stix2.Bundle(objects=self.to_stix_objects(), allow_custom=True)

    def to_json_bundle(self):
        """Returns STIX Bundle as JSON"""
        return self.to_stix_bundle().serialize()

    def _create_author(self):
        """Creates Recorded Future Author"""
        return stix2.Identity(
            id=pycti.Identity.generate_id("Recorded Future", "organization"),
            name="Recorded Future",
            identity_class="organization",
        )


class Indicator(RFStixEntity):
    """Base class for Indicators of Compromise (IP, Hash, URL, Domain)"""

    def __init__(self, name, _type, author, tlp):
        super().__init__(name, _type, author, tlp)
        self.stix_indicator = None
        self.stix_observable = None
        self.stix_relationship = None
        self.risk_score = None
        self.related_entities = []
        self.objects = []
        self.tlp = TLP_MAP.get(tlp, None)
        self.description = None

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        if not (
            self.stix_indicator and self.stix_observable and self.stix_relationship
        ):
            self.create_stix_objects()
        return [self.stix_indicator, self.stix_observable, self.stix_relationship]

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_indicator = self._create_indicator()
        self.stix_observable = (
            self._create_obs()
        )  # pylint: disable=assignment-from-no-return
        self.stix_relationship = self._create_rel("based-on", self.stix_observable.id)

    def _create_indicator(self):
        """Creates and returns STIX2 indicator object"""
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(self._create_pattern()),
            name=self.name,
            description=self.description,
            pattern_type="stix",
            valid_from=datetime.now(),
            pattern=self._create_pattern(),
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_main_observable_type": self._add_main_observable_type_to_indicators(),
            },
        )
        pass

    def add_description(self, description):
        self.description = description

    def _add_main_observable_type_to_indicators(self):
        """Handle x_opencti_main_observable_type for filtering"""
        stix_main_observable_mapping = {
            "domain-name:value": "Domain-Name",
            "file:hashes": "StixFile",
            "ipv4-addr:value": "IPv4-Addr",
            "ipv6-addr:value": "IPv6-Addr",
            "url:value": "Url",
        }

        pattern = self._create_pattern()
        pattern_splited = pattern.split("=")
        observable_type = pattern_splited[0].strip("[").strip()

        if observable_type.startswith("file:hashes"):
            observable_type = "file:hashes"

        if observable_type in stix_main_observable_mapping:
            return stix_main_observable_mapping[observable_type]
        else:
            return "Unknown"

    def _create_pattern(self):
        """Creates STIX2 pattern for indicator"""
        pass

    def _create_obs(self):
        """Creates and returns STIX2 Observable"""
        pass

    def _create_rel(self, relationship_type, target_id):
        """Creates Relationship object linking indicator and observable"""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type, self.stix_indicator.id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=self.stix_indicator.id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        return stix2.Bundle(
            objects=self.objects if self.objects else self.to_stix_objects(),
            allow_custom=True,
        )

    def map_data(self, rf_indicator, tlp, risklist_related_entities):
        handled_related_entities_types = risklist_related_entities
        try:
            self.risk_score = int(rf_indicator["Risk"])
        except ValueError:
            self.risk_score = 0
        related_entities_hits = json.loads(rf_indicator["Links"])["hits"]
        if (
            related_entities_hits and len(related_entities_hits[0]["sections"]) > 0
        ):  # Sometimes, hits is not empty but sections is
            rf_related_entities = []
            rf_related_entities_sections = related_entities_hits[0]["sections"]

            for section in rf_related_entities_sections:
                # Handle indicators and TTP & Tools
                if "Indicators" or "TTP" in section["section_id"]["name"]:
                    rf_related_entities += section["lists"]

                for element in rf_related_entities:
                    if element["type"]["name"] in handled_related_entities_types:
                        for rf_related_element in element["entities"]:
                            type_ = rf_related_element["type"]
                            name_ = rf_related_element["name"]
                            related_element = ENTITY_TYPE_MAPPER[type_](
                                name_, type_, self.author, tlp
                            )
                            stix_objs = related_element.to_stix_objects()
                            self.related_entities.extend(stix_objs)

    def build_bundle(self, stix_name):
        """
        Adds self and all related entities (indicators, observables, malware, threat-actors, relationships) to objects
        """
        # Put the indicator and its observable and relationship first
        self.objects.extend(stix_name.to_stix_objects())
        # Then related entities
        self.objects.extend(self.related_entities)
        relationships = []
        # Then add 'related-to' relationship with all related entities
        for entity in self.related_entities:
            if entity["type"] in ["indicator"]:
                relationships.append(self._create_rel("related-to", entity.id))
            if entity["type"] in ["attack-pattern", "malware", "threat-actor"]:
                relationships.append(self._create_rel("indicates", entity.id))
        self.objects.extend(relationships)


class IPAddress(Indicator):
    def __init__(self, name, _type, author=None, tlp=None):
        super().__init__(name, _type, author, tlp)

    """Converts IP address to IP indicator and observable"""

    def is_ipv6(self):
        """Determine whether the provided IP string is IPv6."""
        try:
            ipaddress.IPv6Address(self.name)
            return True
        except ipaddress.AddressValueError:
            return False

    def is_ipv4(self):
        """Determine whether the provided IP string is IPv4."""
        try:
            ipaddress.IPv4Address(self.name)
            return True
        except ipaddress.AddressValueError:
            return False

    def _create_pattern(self):
        if self.is_ipv6() is True:
            return f"[ipv6-addr:value = '{self.name}']"
        elif self.is_ipv4() is True:
            return f"[ipv4-addr:value = '{self.name}']"
        else:
            raise ValueError(
                f"'This pattern value {self.name}' is not a valid IPv4 or IPv6 address."
            )

    def _create_obs(self):
        if self.is_ipv6() is True:
            return stix2.IPv6Address(
                value=self.name,
                object_marking_refs=self.tlp,
            )
        elif self.is_ipv4() is True:
            return stix2.IPv4Address(
                value=self.name,
                object_marking_refs=self.tlp,
            )
        else:
            raise ValueError(
                f"This observable value '{self.name}' is not a valid IPv4 or IPv6 address."
            )

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        return stix2.Bundle(objects=self.objects, allow_custom=True)


class Domain(Indicator):
    """Converts Domain to Domain indicator and observable"""

    def __init__(self, name, _type, author=None, tlp=None):
        super().__init__(name, _type, author, tlp)

    def _create_pattern(self):
        return f"[domain-name:value = '{self.name}']"

    def _create_obs(self):
        return stix2.DomainName(value=self.name, object_marking_refs=self.tlp)


class URL(Indicator):
    """Converts URL to URL indicator and observable"""

    def __init__(self, name, _type, author=None, tlp=None):
        super().__init__(name, _type, author, tlp)

    def _create_pattern(self):
        ioc = self.name.replace("\\", "\\\\")
        ioc = ioc.replace("'", "\\'")
        return f"[url:value = '{ioc}']"

    def _create_obs(self):
        return stix2.URL(value=self.name, object_marking_refs=self.tlp)


class FileHash(Indicator):
    """Converts Hash to File indicator and observable"""

    def __init__(self, name, _type, author=None, tlp=None):
        super().__init__(name, _type, author, tlp)
        self.algorithm = self._determine_algorithm()

    def _determine_algorithm(self):
        """Determine file hash algorithm from length"""
        if len(self.name) == 64:
            return "SHA-256"
        elif len(self.name) == 40:
            return "SHA-1"
        elif len(self.name) == 32:
            return "MD5"
        msg = (
            f"[ANALYST NOTES] Could not determine hash type for {self.name}. Only MD5, SHA1"
            " and SHA256 hashes are supported"
        )
        raise ConversionError(msg)

    def _create_pattern(self):
        return f"[file:hashes.'{self.algorithm}' = '{self.name}']"

    def _create_obs(self):
        return stix2.File(
            hashes={self.algorithm: self.name}, object_marking_refs=self.tlp
        )


class TTP(RFStixEntity):
    """Converts MITRE T codes to AttackPattern"""

    def __init__(self, name, _type, author=None, tlp=None, display_name=None):
        super().__init__(name, _type, author, tlp)
        self.display_name = display_name

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(self.name, self.name),
            name=self.display_name or self.name,
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
            custom_properties={"x_mitre_id": self.name},
        )


class Identity(RFStixEntity):
    """Converts various RF entity types to a STIX2 Identity"""

    type_to_class = {
        "Company": "organization",
        "Organization": "organization",
        "Person": "individual",
        "Industry": "class",
    }

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.Identity(
            id=pycti.Identity.generate_id(self.name, self.create_id_class()),
            name=self.name,
            identity_class=self.create_id_class(),
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )

    def create_id_class(self):
        """Creates a STIX2 identity class"""
        return self.type_to_class[self.type]


class ThreatActor(RFStixEntity):
    """Converts various RF Threat Actor Organization to a STIX2 Threat Actor"""

    type_to_class = {
        "Company": "organization",
        "Organization": "organization",
        "Person": "individual",
    }

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        ta_args = {
            "id": pycti.ThreatActor.generate_id(self.name),
            "name": self.name,
            "created_by_ref": self.author.id,
            "object_marking_refs": self.tlp,
        }

        if self.type == "Person":
            ta_args["resource_level"] = "individual"

        self.stix_obj = stix2.ThreatActor(**ta_args)

    def create_id_class(self):
        """Creates a STIX2 identity class"""
        return self.type_to_class[self.type]


class IntrusionSet(RFStixEntity):
    """Converts Threat Actor to Intrusion Set SDO"""

    def __init__(self, name, _type, author=None, tlp=None):
        super().__init__(name, _type, author, tlp)
        self.related_entities = []
        self.objects = []

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(self.name),
            name=self.name,
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        return stix2.Bundle(
            objects=self.objects if self.objects else self.to_stix_objects(),
            allow_custom=True,
        )

    def _create_rel(self, source_id, relationship_type, target_id):
        """Creates Relationship object linking indicator and observable"""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )

    def map_data(self, actor, tlp):
        # Get related entities
        related_entities_links = actor["links"]

        # If there are related entities
        if related_entities_links and len(related_entities_links) > 0:
            handled_related_entities_types = [
                "MitreAttackIdentifier",
                "Malware",
                "CyberVulnerability",
                "IpAddress",
                "InternetDomainName",
                "Hash",
                "URL",
            ]

            for related_entity in related_entities_links:
                _type = related_entity["type"].replace("type:", "")
                _name = related_entity["name"]
                _risk_attributes = related_entity["attributes"]
                RISK_SCORE_MIN = 60

                if _type in handled_related_entities_types:
                    """
                    If related entity is in indicator mapper, return add entity if risk score > 60
                    """
                    if _type in INDICATOR_TYPE_URL_MAPPER:
                        for risk_attribute in _risk_attributes:
                            if (
                                risk_attribute["id"] == "risk_score"
                                and risk_attribute["value"] > RISK_SCORE_MIN
                            ):
                                related_element = ENTITY_TYPE_MAPPER[_type](
                                    _name, _type, self.author, tlp
                                )

                                related_element.risk_score = risk_attribute["value"]
                                stix_objs = related_element.to_stix_objects()
                                self.related_entities.extend(stix_objs)
                        continue
                    elif _type in ["MitreAttackIdentifier"]:
                        for risk_attribute in _risk_attributes:
                            if risk_attribute["id"] == "display_name":
                                """
                                Format of display name is 'TXXXX (Name of method)'
                                We need to have TXXXX for name and 'Name of method' as display name
                                """
                                # initializing substrings
                                sub1 = "("
                                sub2 = ")"
                                display_name = risk_attribute["value"]
                                idx1 = display_name.index(sub1)
                                idx2 = display_name.index(sub2)
                                # length of substring 1 is added to
                                # get string from next character
                                display_name = display_name[idx1 + len(sub1) : idx2]

                                related_element = TTP(
                                    _name, _type, self.author, tlp, display_name
                                )

                                stix_objs = related_element.to_stix_objects()
                                self.related_entities.extend(stix_objs)
                        continue
                    else:
                        related_element = ENTITY_TYPE_MAPPER[_type](
                            _name, _type, self.author, tlp
                        )
                        stix_objs = related_element.to_stix_objects()
                        self.related_entities.extend(stix_objs)

    def build_bundle(self, ta_object):
        """
        Adds self and all related entities to objects
        """
        self.objects.extend(ta_object.to_stix_objects())
        # Related entities
        self.objects.extend(self.related_entities)

        # Create SRO
        relationships = []
        for entity in self.related_entities:
            if entity["type"] in ["malware"]:
                relationships.append(
                    self._create_rel(self.stix_obj.id, "uses", entity.id)
                )
            if entity["type"] in ["indicator"]:
                relationships.append(
                    self._create_rel(entity.id, "indicates", self.stix_obj.id)
                )
            if entity["type"] in ["attack-pattern"]:
                relationships.append(
                    self._create_rel(self.stix_obj.id, "uses", entity.id)
                )
            if entity["type"] in ["vulnerability"]:
                relationships.append(
                    self._create_rel(self.stix_obj.id, "targets", entity.id)
                )
        # Add relationships to stix objects
        self.objects.extend(relationships)


class Malware(RFStixEntity):
    """Converts Malware to a Malware SDO"""

    def __init__(self, name, _type, author=None, tlp=None):
        super().__init__(name, _type, author, tlp)
        self.related_entities = []
        self.objects = []

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.Malware(
            id=pycti.Malware.generate_id(self.name),
            name=self.name,
            is_family=False,
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        return stix2.Bundle(
            objects=self.objects if self.objects else self.to_stix_objects(),
            allow_custom=True,
        )

    def _create_rel(self, source_id, relationship_type, target_id):
        """Creates Relationship object linking indicator and observable"""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )

    def map_data(self, malware, tlp):
        # Get related entities
        related_entities_links = malware["links"]

        # If there are related entities
        if related_entities_links and len(related_entities_links) > 0:
            handled_related_entities_types = [
                "MitreAttackIdentifier",
                "Malware",
                "CyberVulnerability",
                "IpAddress",
                "InternetDomainName",
                "Hash",
                "URL",
                "Organization",
                "Person",
            ]

            for related_entity in related_entities_links:
                _type = related_entity["type"].replace("type:", "")
                _name = related_entity["name"]
                _risk_attributes = related_entity["attributes"]
                RISK_SCORE_MIN = 60

                if _type in handled_related_entities_types:
                    """
                    If related entity is in indicator mapper, return add entity if risk score > 60
                    """
                    if _type in INDICATOR_TYPE_URL_MAPPER:
                        for risk_attribute in _risk_attributes:
                            if (
                                risk_attribute["id"] == "risk_score"
                                and risk_attribute["value"] > RISK_SCORE_MIN
                            ):
                                related_element = ENTITY_TYPE_MAPPER[_type](
                                    _name, _type, self.author, tlp
                                )

                                related_element.risk_score = risk_attribute["value"]
                                stix_objs = related_element.to_stix_objects()
                                self.related_entities.extend(stix_objs)

                    elif _type in ["Person", "Organization"]:
                        """
                        If the related entities is a Person or an Organization
                        and if it is defined by RF as a Threat Actor, then create an Intrusion Set
                        """
                        for risk_attribute in _risk_attributes:
                            if (
                                risk_attribute["id"] == "threat_actor"
                                and risk_attribute["value"] is True
                            ):
                                related_element = IntrusionSet(
                                    _name, _type, self.author, tlp
                                )
                                stix_objs = related_element.to_stix_objects()
                                self.related_entities.extend(stix_objs)
                            elif (
                                risk_attribute["id"] == "threat_actor"
                                and risk_attribute["value"] is False
                            ):
                                related_element = ENTITY_TYPE_MAPPER[_type](
                                    _name, _type, self.author, tlp
                                )
                                stix_objs = related_element.to_stix_objects()
                                self.related_entities.extend(stix_objs)
                                break
                        continue
                    elif _type in ["MitreAttackIdentifier"]:
                        for risk_attribute in _risk_attributes:
                            if risk_attribute["id"] == "display_name":
                                """
                                Format of display name is => 'TXXXX (Name of method)'
                                We need to have TXXXX for name and 'Name of method' as display name
                                """
                                # initializing substrings
                                sub1 = "("
                                sub2 = ")"
                                display_name = risk_attribute["value"]
                                idx1 = display_name.index(sub1)
                                idx2 = display_name.index(sub2)
                                # length of substring 1 is added to
                                # get string from next character
                                display_name = display_name[idx1 + len(sub1) : idx2]

                                related_element = TTP(
                                    _name, _type, self.author, tlp, display_name
                                )

                                stix_objs = related_element.to_stix_objects()
                                self.related_entities.extend(stix_objs)
                        continue
                    else:
                        related_element = ENTITY_TYPE_MAPPER[_type](
                            _name, _type, self.author, tlp
                        )
                        stix_objs = related_element.to_stix_objects()
                        self.related_entities.extend(stix_objs)

    def build_bundle(self, ta_object):
        """
        Adds self and all related entities to objects
        """
        self.objects.extend(ta_object.to_stix_objects())
        # Related entities
        self.objects.extend(self.related_entities)

        # Create SRO
        relationships = []
        for entity in self.related_entities:
            if entity["type"] in ["malware"]:
                relationships.append(
                    self._create_rel(self.stix_obj.id, "related-to", entity.id)
                )
            if entity["type"] in ["indicator"]:
                relationships.append(
                    self._create_rel(entity.id, "indicates", self.stix_obj.id)
                )
            if entity["type"] in ["attack-pattern"]:
                relationships.append(
                    self._create_rel(self.stix_obj.id, "uses", entity.id)
                )
            if entity["type"] in ["vulnerability"]:
                relationships.append(
                    self._create_rel(self.stix_obj.id, "exploits", entity.id)
                )
            if entity["type"] in ["identity"]:
                relationships.append(
                    self._create_rel(self.stix_obj.id, "targets", entity.id)
                )
            if entity["type"] in ["intrusion-set"]:
                relationships.append(
                    self._create_rel(entity.id, "uses", self.stix_obj.id)
                )
        # Add relationships to stix objects
        self.objects.extend(relationships)


class Vulnerability(RFStixEntity):
    """Converts a CyberVulnerability to a Vulnerability SDO"""

    # TODO: add vuln descriptions
    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.Vulnerability(
            id=pycti.Vulnerability.generate_id(self.name),
            name=self.name,
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )


class DetectionRule(RFStixEntity):
    """Represents a Yara, Sigma or SNORT rule"""

    def __init__(self, name, _type, content, author, tlp=None):
        super().__init__(name, _type, author, tlp)
        # TODO: possibly need to accomodate multi-rule. Right now just shoving everything in one

        self.name = name.split(".")[0]
        self.type = _type
        self.content = content
        self.stix_obj = None
        self.author = author

        if self.type not in ("yara", "snort", "sigma"):
            msg = f"[ANALYST NOTES] Detection rule of type {self.type} is not supported"
            raise ConversionError(msg)

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.Indicator(
            id=pycti.Indicator.generate_id(self.content),
            name=self.name,
            pattern_type=self.type,
            pattern=self.content,
            valid_from=datetime.now(),
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )


class Software(RFStixEntity):
    def __init__(self, name, _type, author, tlp):
        super().__init__(name, _type, author, tlp)
        self.software_object = None

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        if not self.software_object:
            self.create_stix_objects()
        return [self.software_object]

    def create_stix_objects(self):
        self.software_object = stix2.Software(
            name=self.name,
            object_marking_refs=self.tlp,
        )


class Location(RFStixEntity):
    rf_type_to_stix = {
        "Country": "Country",
        "City": "City",
        "ProvinceOrState": "Administrative-Area",
    }

    rf_type_to_stix = {
        "Country": "Country",
        "City": "City",
        "ProvinceOrState": "Administrative-Area",
    }

    def __init__(self, name, _type, author, tlp):
        super().__init__(name, _type, author, tlp)
        self.type = self.rf_type_to_stix[_type]
        self.location_object = None

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        if not self.location_object:
            self.create_stix_objects()
        return [self.location_object]

    def create_stix_objects(self):
        self.location_object = stix2.Location(
            id=pycti.Location.generate_id(self.name, self.type),
            name=self.name,
            country=self.name,
            custom_properties={"x_opencti_location_type": self.type},
            object_marking_refs=self.tlp,
        )


class Campaign(RFStixEntity):
    def __init__(self, name, _type, author, tlp):
        super().__init__(name, _type, author, tlp)
        self.campaign_object = None

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        if not self.campaign_object:
            self.create_stix_objects()
        return [self.campaign_object]

    def create_stix_objects(self):
        self.campaign_object = stix2.Campaign(
            id=pycti.Campaign.generate_id(self.name),
            name=self.name,
            object_marking_refs=self.tlp,
        )


# maps RF types to the corresponding python object
ENTITY_TYPE_MAPPER = {
    "IpAddress": IPAddress,
    "InternetDomainName": Domain,
    "URL": URL,
    "Hash": FileHash,
    "MitreAttackIdentifier": TTP,
    "Company": Identity,
    "Person": Identity,
    "Organization": Identity,
    "Malware": Malware,
    "CyberVulnerability": Vulnerability,
    "Product": Software,
    "Country": Location,
    "City": Location,
    "ProvinceOrState": Location,
    "Industry": Identity,
    "Operation": Campaign,
    "Threat Actor": ThreatActor,
}

# maps RF types to the corresponding url to get the risk score
INDICATOR_TYPE_URL_MAPPER = {
    "IpAddress": "ip",
    "InternetDomainName": "domain",
    "URL": "url",
    "Hash": "hash",
}
RELATIONSHIPS_MAPPER = [
    {
        "from": "threat-actor",
        "to": [
            {"entity": "malware", "relation": "uses"},
            {"entity": "vulnerability", "relation": "targets"},
            {"entity": "attack-pattern", "relation": "uses"},
            {"entity": "location", "relation": "targets"},
            {"entity": "identity", "relation": "targets"},
        ],
    },
    {
        "from": "intrusion-set",
        "to": [
            {"entity": "malware", "relation": "uses"},
            {"entity": "vulnerability", "relation": "targets"},
            {"entity": "attack-pattern", "relation": "uses"},
            {"entity": "location", "relation": "targets"},
            {"entity": "identity", "relation": "targets"},
        ],
    },
    {
        "from": "indicator",
        "to": [
            {"entity": "malware", "relation": "indicates"},
            {"entity": "threat-actor", "relation": "indicates"},
            {"entity": "intrusion-set", "relation": "indicates"},
        ],
    },
    {
        "from": "malware",
        "to": [
            {"entity": "attack-pattern", "relation": "uses"},
            {"entity": "location", "relation": "targets"},
            {"entity": "identity", "relation": "targets"},
        ],
    },
]


class StixNote:
    """Represents Analyst Note"""

    report_type_mapper = {
        "Actor Profile": "Threat-Actor",
        "Analyst On-Demand Report": "Threat-Report",
        "Cyber Threat Analysis": "Threat-Report",
        "Executive Insights": "Threat-Report",
        "Flash Report": "Threat-Report",
        "Geopolitical Flash Event": "Threat-Report",
        "Geopolitical Intelligence Summary": "Threat-Report",
        "Geopolitical Profile": "Threat-Actor",
        "Geopolitical Threat Forecast": "Threat-Actor",
        "Geopolitical Validated Event": "Observed-Data",
        "Hunting Package": "Attack-Pattern",
        "Indicator": "Indicator",
        "Informational": "Threat-Report",
        "Insikt Research Lead": "Intrusion-Set",
        "Malware/Tool Profile": "Malware",
        "Regular Vendor Vulnerability Disclosures": "Vulnerability",
        "Sigma Rule": "Attack-Pattern",
        "SNORT Rule": "Indicator",
        "Source Profile": "Observed-Data",
        "The Record by Recorded Future": "Threat-Report",
        "Threat Lead": "Threat-Actor",
        "TTP Instance": "Attack-Pattern",
        "Validated Intelligence Event": "Observed-Data",
        "Weekly Threat Landscape": "Threat-Report",
        "YARA Rule": "Indicator",
    }

    def __init__(
        self,
        opencti_helper,
        tas,
        rfapi,
        tlp="white",
        person_to_ta=False,
        ta_to_intrusion_set=False,
        risk_as_score=False,
        risk_threshold=None,
    ):
        self.author = self._create_author()
        self.name = None
        self.text = None
        self.published = datetime.now()
        self.labels = None
        self.report_types = None
        self.external_references = []
        self.objects = []
        self.helper = opencti_helper
        self.tas = tas
        self.person_to_ta = person_to_ta
        self.ta_to_intrusion_set = ta_to_intrusion_set
        self.risk_as_score = risk_as_score
        self.risk_threshold = risk_threshold
        self.tlp = TLP_MAP.get(tlp.lower(), None)
        self.rfapi = rfapi

    def _create_author(self):
        """Creates Recorded Future Author"""
        return stix2.Identity(
            id=pycti.Identity.generate_id("Recorded Future", "organization"),
            name="Recorded Future",
            identity_class="organization",
        )

    def _generate_external_references(self, urls):
        """Generate External references from validation urls"""
        refs = []
        for url in urls:
            external_url = url["name"]
            source_name = external_url.split("/")[2].split(".")[-2]
            refs.append({"source_name": source_name, "url": external_url})
        return refs

    def from_json(self, note, tlp):
        """Converts to STIX Bundle from JSON objects"""
        # TODO: catch errors in for loop here
        attr = note["attributes"]
        self.name = attr["title"]
        self.text = attr["text"]
        self.published = attr["published"]
        self.external_references = self._generate_external_references(
            attr.get("validation_urls", [])
        )
        self.report_types = self._create_report_types(attr.get("topic", []))
        self.labels = [topic["name"] for topic in attr.get("topic", [])]
        for entity in attr.get("note_entities", []):
            type_ = entity["type"]
            name = entity["name"]
            if self.person_to_ta and type_ == "Person":
                stix_objs = ThreatActor(name, type_, self.author, tlp).to_stix_objects()
            elif entity["id"] in self.tas:
                if self.ta_to_intrusion_set and type_ != "Person":
                    stix_objs = IntrusionSet(
                        name, type_, self.author, tlp
                    ).to_stix_objects()
                else:
                    stix_objs = ThreatActor(
                        name, type_, self.author, tlp
                    ).to_stix_objects()
            elif type_ == "Source":
                external_reference = {"source_name": name, "url": name}
                self.external_references.append(external_reference)
                continue
            elif type_ not in ENTITY_TYPE_MAPPER:
                msg = f"[ANALYST NOTES] Cannot convert entity {name} to STIX2 because it is of type {type_}"
                self.helper.log_warning(msg)
                continue
            else:
                rf_object = ENTITY_TYPE_MAPPER[type_](name, type_, self.author, tlp)
                if type_ in [
                    "IpAddress",
                    "InternetDomainName",
                    "URL",
                    "Hash",
                ]:
                    risk_score = None
                    if self.risk_threshold:
                        # If a min threshold was defined, we ignore the indicator if the score is lower than the defined threshold
                        risk_score = self.rfapi.get_risk_score(
                            INDICATOR_TYPE_URL_MAPPER[type_], name
                        )
                        if risk_score < self.risk_threshold:
                            self.helper.log_info(
                                f"[ANALYST NOTES] Ignoring entity {name} as its risk score is lower than the defined risk threshold"
                            )
                            continue
                    if self.risk_as_score:
                        # We get the risk_score if it was already set. Otherwise, we get it from the API
                        rf_object.risk_score = (
                            risk_score
                            if risk_score
                            else self.rfapi.get_risk_score(
                                INDICATOR_TYPE_URL_MAPPER[type_], name
                            )
                        )
                stix_objs = rf_object.to_stix_objects()
            self.objects.extend(stix_objs)
        if "attachment_content" in attr:
            rule = DetectionRule(
                attr["attachment"],
                attr["attachment_type"],
                attr["attachment_content"],
                self.author,
            )
            self.objects.extend(rule.to_stix_objects())

    def _create_rel(self, from_id, to_id, relation):
        """Creates Relationship object"""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(relation, from_id, to_id),
            relationship_type=relation,
            source_ref=from_id,
            target_ref=to_id,
            created_by_ref=self.author.id,
            object_marking_refs=self.tlp,
        )

    def create_relations(self):
        relationships = []
        for source_entity in self.objects:
            entity_possible_relationships = list(
                filter(
                    lambda obj: obj["from"] == source_entity["type"],
                    RELATIONSHIPS_MAPPER,
                )
            )
            if len(entity_possible_relationships) != 0:
                for to_entity in entity_possible_relationships[0]["to"]:
                    target_entities = list(
                        filter(
                            lambda obj: obj["type"] == to_entity["entity"], self.objects
                        )
                    )
                    for target_entity in target_entities:
                        if (
                            to_entity["entity"] != "identity"
                            or target_entity["identity_class"] == "class"
                        ):
                            relationships.append(
                                self._create_rel(
                                    source_entity["id"],
                                    target_entity["id"],
                                    to_entity["relation"],
                                )
                            )
        self.objects.extend(relationships)

    def _create_report_types(self, topics):
        """Converts Insikt Topics to STIX2 Report types"""
        ret = set()
        for topic in topics:
            name = topic["name"]
            if name not in self.report_type_mapper:
                self.helper.log_warning(
                    "[ANALYST NOTES] Could not map a report type for type {}".format(
                        name
                    )
                )
                continue
            ret.add(self.report_type_mapper[name])
        return list(ret)

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        report = stix2.Report(
            id=pycti.Report.generate_id(self.name, self.published),
            name=self.name,
            description=self.text,
            published=self.published,
            created_by_ref=self.author.id,
            labels=self.labels,
            report_types=self.report_types,
            object_refs=[obj.id for obj in self.objects],
            external_references=self.external_references,
            object_marking_refs=self.tlp,
        )
        return self.objects + [report, self.author, self.tlp]

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        return stix2.Bundle(objects=self.to_stix_objects(), allow_custom=True)

    def to_json_bundle(self):
        """Returns STIX Bundle as JSON"""
        return self.to_stix_bundle().serialize()
