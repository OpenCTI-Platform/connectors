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

from datetime import datetime

import pycti
import stix2

from .rf_utils import validate_ip_or_cidr, validate_mitre_attack_pattern

SUPPORTED_RF_TYPES = ("IpAddress", "InternetDomainName", "Hash", "URL")
INDICATES_RELATIONSHIP = [
    stix2.AttackPattern,
    stix2.Campaign,
    stix2.Infrastructure,
    stix2.IntrusionSet,
    stix2.Malware,
    stix2.ThreatActor,
    stix2.Tool,
]


class ConversionError(Exception):
    """Generic exception for stix2 conversion issues"""

    pass


class RFStixEntity:
    """Parent class"""

    def __init__(self, name, author, opencti_helper, type_=None):
        self.name = name
        self.type = type_
        self.author = author
        self.stix_obj = None
        self.helper = opencti_helper

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


class Indicator(RFStixEntity):
    """Base class for Indicators of Compromise (IP, Hash, URL, Domain)"""

    def __init__(
        self, name, author, opencti_helper, risk_score=None, obs_id=None, **kwargs
    ):
        """
        Name (str): Indicator value
        author (stix2.Identity): Author of bundle
        risk_score (int): Risk score of indicator
        obs_id (str): OpenCTI STIX2 ID of observable that's being enriched
        """
        self.helper = opencti_helper
        self.helper.log_debug("Init Indicator.")
        self.name = name
        self.author = author
        self.obs_id = obs_id
        self.stix_indicator = None
        self.stix_observable = None
        self.stix_relationship = None
        self.risk_score = risk_score

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        self.helper.log_debug("Transform to Stix Object.")
        if not (self.stix_indicator and self.stix_relationship):
            self.create_stix_objects()
        objs = [self.stix_indicator, self.stix_relationship]
        if not self.obs_id and self.stix_observable:
            objs.append(self.stix_observable)
        return objs

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.helper.log_debug("Create Stix Objects.")
        if not self.obs_id:
            self.stix_observable = (
                self._create_obs()
            )  # pylint: disable=assignment-from-no-return
        self.stix_indicator = self._create_indicator()
        self.stix_relationship = self._create_rel()

    def _create_indicator(self):
        """Creates and returns STIX2 indicator object"""
        self.helper.log_debug("Create Indicator.")
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(self._create_pattern()),
            name=self.name,
            pattern_type="stix",
            valid_from=datetime.now(),
            pattern=self._create_pattern(),
            created_by_ref=self.author.id,
            custom_properties={"x_opencti_score": self.risk_score or None},
        )

    def _create_pattern(self):
        """Creates STIX2 pattern for indicator"""
        pass

    def _create_obs(self):
        """Creates and returns STIX2 Observable"""
        pass

    def _create_rel(self):
        self.helper.log_debug("Create Relationship.")
        """Creates Relationship object linking indicator and observable"""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                "based-on",
                self.stix_indicator.id,
                self.obs_id or self.stix_observable.id,
            ),
            relationship_type="based-on",
            source_ref=self.stix_indicator.id,
            target_ref=self.obs_id or self.stix_observable.id,
            start_time=datetime.now(),
            created_by_ref=self.author.id,
        )


class IPAddress(Indicator):
    """Converts IP address to IP indicator and observable"""

    def __init__(
        self, name, author, opencti_helper, risk_score=None, obs_id=None, **kwargs
    ):
        super().__init__(
            name=name,
            author=author,
            opencti_helper=opencti_helper,
            risk_score=risk_score,
            obs_id=obs_id,
        )
        self.ipaddress_type = validate_ip_or_cidr(name)
        if self.ipaddress_type == "Invalid":
            self.helper.log_error(f"Not a valid IP Format ({name})")

    def _create_pattern(self):
        if self.ipaddress_type.startswith("IPv4"):
            return f"[ipv4-addr:value = '{self.name}']"
        elif self.ipaddress_type.startswith("IPv6"):
            return f"[ipv6-addr:value = '{self.name}']"
        else:
            return None

    def _create_obs(self):
        if self.ipaddress_type.startswith("IPv4"):
            return stix2.IPv4Address(
                value=self.name,
            )
        elif self.ipaddress_type.startswith("IPv6"):
            return stix2.IPv6Address(
                value=self.name,
            )
        else:
            return None


class Domain(Indicator):
    """Converts Domain to Domain indicator and observable"""

    def _create_pattern(self):
        return f"[domain-name:value = '{self.name}']"

    def _create_obs(self):
        return stix2.DomainName(
            value=self.name,
        )


class URL(Indicator):
    """Converts URL to URL indicator and observable"""

    def _create_pattern(self):
        ioc = self.name.replace("\\", "\\\\")
        ioc = ioc.replace("'", "\\'")
        return f"[url:value = '{ioc}']"

    def _create_obs(self):
        return stix2.URL(
            value=self.name,
        )


class FileHash(Indicator):
    """Converts Hash to File indicator and observable"""

    def __init__(self, name, author, opencti_helper, risk_score=None, **kwargs):
        super().__init__(name, author, opencti_helper=opencti_helper)
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
            f"Could not determine hash type for {self.name}. Only MD5, SHA1"
            " and SHA256 hashes are supported"
        )
        self.helper.log_error(msg)
        raise ConversionError(msg)

    def _create_pattern(self):
        return f"[file:hashes.'{self.algorithm}' = '{self.name}']"

    def _create_obs(self):
        return stix2.File(
            hashes={self.algorithm: self.name},
        )


# # TODO: Delete? This code looks unused?
# class TLPMarking(RFStixEntity):
#     """Creates TLP marking for report"""

#     def create_stix_objects(self):
#         """Creates STIX objects from object attributes"""
#         self.stix_obj = stix2.AttackPattern(
#             id=pycti.AttackPattern.generate_id(self.name, self.name),
#             name=self.name,
#             created_by_ref=self.author.id,
#             custom_properties={"x_mitre_id": self.name},
#         )


class TTP(RFStixEntity):
    """Converts MITRE T codes to AttackPattern"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.helper.log_debug(f"Add Attack Pattern: {self.name}")
        if validate_mitre_attack_pattern(self.name):
            attack_pattern = self.name.upper()
            attack_pattern_filter = {
                "mode": "and",
                "filters": [{"key": "x_mitre_id", "values": [f"{attack_pattern}"]}],
                "filterGroups": [],
            }
            opencti_attack_pattern = self.helper.api.attack_pattern.read(
                filters=attack_pattern_filter
            )
            if opencti_attack_pattern and "id" in opencti_attack_pattern:
                opencti_stix_object = (
                    self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                        entity_type="Attack-Pattern",
                        entity_id=opencti_attack_pattern.get("id"),
                        mode="simple",
                        only_entity=True,
                    )
                )
                keys_list = ["id", "name", "x_mitre_id"]
                if (
                    opencti_stix_object
                    and isinstance(opencti_stix_object, dict)
                    and all(key in opencti_stix_object for key in keys_list)
                ):
                    self.helper.log_info(
                        f"Appending Attack Pattern: {opencti_stix_object}"
                    )
                    self.stix_obj = stix2.AttackPattern(
                        id=opencti_stix_object.get("id"),
                        name=opencti_stix_object.get("name"),
                        created_by_ref=self.author.id,
                        custom_properties={
                            "x_mitre_id": opencti_stix_object.get("x_mitre_id")
                        },
                    )


class Identity(RFStixEntity):
    """Converts various RF entity types to a STIX2 Identity"""

    type_to_class = {
        "Company": "organization",
        "Organization": "organization",
        "Person": "individual",
    }

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.helper.log_debug("Add Identity.")
        self.stix_obj = stix2.Identity(
            id=pycti.Identity.generate_id(self.name, self.create_id_class()),
            name=self.name,
            identity_class=self.create_id_class(),
            created_by_ref=self.author.id,
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
        self.helper.log_debug("Add Threat Actor.")
        self.stix_obj = stix2.ThreatActor(
            id=pycti.ThreatActor.generate_id(self.name),
            name=self.name,
            created_by_ref=self.author.id,
        )

    def create_id_class(self):
        """Creates a STIX2 identity class"""
        return self.type_to_class[self.type]


class IntrusionSet(RFStixEntity):
    """Converts Threat Actor to Intrusion Set SDO"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.helper.log_debug("Add Intrusion Set.")
        self.stix_obj = stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(self.name),
            name=self.name,
            created_by_ref=self.author.id,
        )


class Malware(RFStixEntity):
    """Converts Malware to a Malware SDO"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.helper.log_debug("Add Malware.")
        self.stix_obj = stix2.Malware(
            id=pycti.Malware.generate_id(self.name),
            name=self.name,
            is_family=False,
            created_by_ref=self.author.id,
        )


class Vulnerability(RFStixEntity):
    """Converts a CyberVulnerability to a Vulnerability SDO"""

    # TODO: add vuln descriptions
    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.helper.log_debug("Add Vulnerability.")
        self.stix_obj = stix2.Vulnerability(
            id=pycti.Vulnerability.generate_id(self.name),
            name=self.name,
            created_by_ref=self.author.id,
        )


class DetectionRule(RFStixEntity):
    """Represents a Yara or SNORT rule"""

    def __init__(self, name, opencti_helper, type_, content):
        # TODO: possibly need to accomodate multi-rule. Right now just shoving everything in one
        super().__init__(
            name=name.split(".")[0], type=type_, opencti_helper=opencti_helper
        )
        self.content = content

        if self.type not in ("yara", "snort"):
            msg = f"Detection rule of type {self.type} is not supported"
            self.helper.log_error(msg)
            raise ConversionError(msg)

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.helper.log_debug("Add Indicator.")
        self.stix_obj = stix2.Indicator(
            id=pycti.Indicator.generate_id(self.content),
            name=self.name,
            pattern_type=self.type,
            pattern=self.content,
            valid_from=datetime.now(),
            created_by_ref=self.author.id,
        )


class EnrichedIndicator:
    """Class for converting Indicator + risk score + links to OpenCTI bundle"""

    entity_mapper = {
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
    }

    def __init__(self, type_, observable_id, opencti_helper, create_indicator=True):
        """
        type_ (str): Recorded Future
        observable_id (str): OpenCTI STIX2 ID of obsrevable being enriched
        opencti_helper (pycti.OpenCTIConnectorHelper): OpenCTI helper class
        create_indicator (bool): Should we create indicator out of enriched observable
        """
        if type_ not in SUPPORTED_RF_TYPES:
            msg = f"Enriched Indicator must be of a supported type. {type_} is not supported."
            self.helper.log_error(msg)
            raise ConversionError(msg)
        self.type = type_
        self.helper = opencti_helper
        self.author = self._create_author()
        self.create_indicator = create_indicator
        self.obs_id = observable_id
        self.linked_sdos = []
        self.chained_objects = (
            []
        )  # STIX objects that are part of the bundle, but not directly linked to indicator
        self.notes = []
        self.indicator = None

    def _create_author(self):
        """Creates Recorded Future Author"""
        self.helper.log_debug("Add Identity Author.")
        return stix2.Identity(
            id=pycti.Identity.generate_id("Recorded Future", "organization"),
            name="Recorded Future",
            identity_class="organization",
        )

    def from_json(self, name, risk, evidenceDetails, links):
        """Creates STIX objects from enriched entity json"""
        object_refs = [self.obs_id]
        if self.create_indicator:
            indicator = self.entity_mapper[self.type](
                name,
                self.author,
                risk_score=risk,
                obs_id=self.obs_id,
                opencti_helper=self.helper,
            )
            indicator.create_stix_objects()
            self.indicator = indicator.stix_indicator
            if self.indicator:
                object_refs.append(self.indicator.id)
            if indicator.stix_relationship:
                self.chained_objects.append(indicator.stix_relationship)

        if risk:
            self.notes.append(
                stix2.Note(
                    abstract="Recorded Future Risk Score",
                    content="{}/99".format(risk),
                    created_by_ref=self.author.id,
                    object_refs=object_refs,
                )
            )
        for rule in evidenceDetails:
            if rule.get("rule"):
                self.notes.append(
                    stix2.Note(
                        abstract=f"{rule['rule']}",
                        content=f"{rule['evidenceString']}",
                        created_by_ref=self.author.id,
                        object_refs=object_refs,
                    )
                )
            # TODO: is a rule ever an Attack Pattern?
            # self.helper.log_debug(f"Rule Content: {rule}")
            # self.helper.log_debug(f"Append SDOs: Rule: {rule.get('rule', 'Not provided')}, Criticality: {rule.get('criticality', 'Not provided')}, Label: {rule.get('name', 'criticalityLabel')}")
            # if validate_mitre_attack_pattern(rule.get('rule')):
            #     attack_pattern = rule.get('rule')
            #     self.linked_sdos.append(
            #         stix2.AttackPattern(
            #             id=pycti.AttackPattern.generate_id(attack_pattern, attack_pattern),
            #             name=attack_pattern,
            #             created_by_ref=self.author.id,
            #             custom_properties={
            #                 "x_rf_criticality": rule["criticality"],
            #                 "x_rf_critcality_label": rule["criticalityLabel"],
            #                 "x_mitre_id": attack_pattern,
            #             },
            #         )
            #     )

        if isinstance(links, list):
            for link in links:
                try:
                    self.helper.log_debug(f"Iterate through links: {link}.")
                    type_ = link["type"].split("type:")[1]

                    if type_ not in self.entity_mapper:
                        msg = "Cannot convert entity {} to STIX2 because it is of type {}".format(
                            link["name"], type_
                        )
                        self.helper.log_warning(msg)
                        continue
                    if any(
                        attr.get("id") == "threat_actor" for attr in link["attributes"]
                    ):
                        link_object = ThreatActor(
                            link["name"],
                            self.author,
                            type_=type_,
                            opencti_helper=self.helper,
                        )

                    else:
                        link_object = self.entity_mapper[type_](
                            link["name"],
                            self.author,
                            type_=type_,
                            opencti_helper=self.helper,
                        )
                    link_object.create_stix_objects()
                    if isinstance(link_object, Indicator):
                        if link_object.stix_indicator:
                            self.linked_sdos.append(link_object.stix_indicator)
                        if link_object.stix_observable:
                            self.chained_objects.append(link_object.stix_observable)
                        if link_object.stix_relationship:
                            self.chained_objects.append(link_object.stix_relationship)
                    else:
                        stix_objects = link_object.to_stix_objects()
                        if stix_objects:
                            self.linked_sdos.extend(stix_objects)
                except Exception as err:
                    self.helper.log_error(err)
                    continue

    def _create_relationships(self, sdo):
        """Creates relationships between the indicators and riskrules + links"""
        ret_val = []
        rel_type = "related-to"
        if any(isinstance(sdo, stixtype) for stixtype in INDICATES_RELATIONSHIP):
            rel_type = "indicates"
        try:
            if self.create_indicator and self.indicator:
                self.helper.log_debug("Append Relationship with Indicator.")
                ret_val.append(
                    stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            rel_type, self.indicator.id, sdo.id
                        ),
                        relationship_type=rel_type,
                        source_ref=self.indicator.id,
                        target_ref=sdo.id,
                        created_by_ref=self.author.id,
                    )
                )
            if self.obs_id and sdo:
                self.helper.log_debug("Append Relationship.")
                ret_val.append(
                    stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            "related-to", self.obs_id, sdo.id
                        ),
                        relationship_type="related-to",
                        source_ref=self.obs_id,
                        target_ref=sdo.id,
                        created_by_ref=self.author.id,
                    )
                )
            return ret_val
        except Exception as err:
            if sdo:
                self.helper.log_error(
                    f"Could not create relationship when source is {self.indicator} and target_ref is {sdo.id}, Error: {err}."
                )
            else:
                self.helper.log_error(
                    f"Could not create relationship when source is {self.indicator}, Error: {err}."
                )

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        self.helper.log_info("Return Stix Object(s).")
        objects = [self.author]
        # self.helper.log_debug("linked_sdos: {}".format(str(self.linked_sdos)))
        for sdo in self.linked_sdos:
            self.helper.log_debug("Creating relationship for {}".format(sdo))
            if sdo:
                objects.extend(self._create_relationships(sdo))
        if self.linked_sdos:
            objects.extend(self.linked_sdos)
        if self.notes:
            objects.extend(self.notes)
        if self.chained_objects:
            objects.extend(self.chained_objects)
        if self.create_indicator:
            objects.append(self.indicator)
        return objects

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        self.helper.log_info("Return STIX objects as a Bundle.")
        stix_objects = self.to_stix_objects()
        if isinstance(stix_objects, list) and len(stix_objects) > 0:
            # Remove all None type from the list.
            # Check for None and remove them, log a warning if None exists
            filtered_list = []
            none_found = False
            for item in stix_objects:
                if item is None:
                    none_found = True
                else:
                    filtered_list.append(item)
            if none_found:
                self.helper.log_warning(
                    "NoneType values found in the list and removed."
                )

            # If filtered list contains objects return a bundle.
            if filtered_list:
                return stix2.Bundle(objects=filtered_list, allow_custom=True)
        self.helper.log_warn("No Object(s) Returned.")
        return None

    def to_json_bundle(self):
        """Returns STIX Bundle as JSON"""
        stix_bundle = self.to_stix_bundle()
        self.helper.log_info("Convert to Stix Bundle and Serialize.")
        if stix_bundle and isinstance(stix_bundle, stix2.Bundle):
            return self.to_stix_bundle().serialize()
        else:
            self.helper.log_warn("No Bundle(s) Returned.")
            return None
