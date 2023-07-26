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
import stix2
import pycti


SUPPORTED_RF_TYPES = ('IpAddress', 'InternetDomainName', 'Hash', 'URL')
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

    def __init__(self, name, author, type_=None):
        self.name = name
        self.type = type_
        self.author = author
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


class Indicator(RFStixEntity):
    """Base class for Indicators of Compromise (IP, Hash, URL, Domain)"""

    def __init__(self, name, author, risk_score=None, obs_id=None, **kwargs):
        """
        Name (str): Indicator value
        author (stix2.Identity): Author of bundle
        risk_score (int): Risk score of indicator
        obs_id (str): OpenCTI STIX2 ID of observable that's being enriched
        """
        self.name = name
        self.author = author
        self.obs_id = obs_id
        self.stix_indicator = None
        self.stix_observable = None
        self.stix_relationship = None
        self.risk_score = risk_score

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        if not (self.stix_indicator and self.stix_relationship):
            self.create_stix_objects()
        objs = [self.stix_indicator, self.stix_relationship]
        if not self.obs_id:
            objs.append(self.stix_observable)
        return objs

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        if not self.obs_id:
            self.stix_observable = self._create_obs()  # pylint: disable=assignment-from-no-return
        self.stix_indicator = self._create_indicator()
        self.stix_relationship = self._create_rel()

    def _create_indicator(self):
        """Creates and returns STIX2 indicator object"""
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(self._create_pattern()),
            name=self.name,
            pattern_type='stix',
            confidence=self.risk_score,
            valid_from=datetime.now(),
            pattern=self._create_pattern(),
            created_by_ref=self.author.id,
        )
        pass

    def _create_pattern(self):
        """Creates STIX2 pattern for indicator"""
        pass

    def _create_obs(self):
        """Creates and returns STIX2 Observable"""
        pass

    def _create_rel(self):
        """Creates Relationship object linking indicator and observable"""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                "based-on", self.stix_indicator.id, self.obs_id or self.stix_observable.id
            ),
            relationship_type='based-on',
            source_ref=self.stix_indicator.id,
            target_ref=self.obs_id or self.stix_observable.id,
            start_time=datetime.now(),
            created_by_ref=self.author.id,
        )


class IPAddress(Indicator):
    """Converts IP address to IP indicator and observable"""

    # TODO: add ipv6 compatibility
    def _create_pattern(self):
        return f"[ipv4-addr:value = '{self.name}']"

    def _create_obs(self):
        return stix2.IPv4Address(value=self.name)


class Domain(Indicator):
    """Converts Domain to Domain indicator and observable"""

    def _create_pattern(self):
        return f"[domain-name:value = '{self.name}']"

    def _create_obs(self):
        return stix2.DomainName(value=self.name)


class URL(Indicator):
    """Converts URL to URL indicator and observable"""

    def _create_pattern(self):
        ioc = self.name.replace('\\', '\\\\')
        ioc = ioc.replace("'", "\\'")
        return f"[url:value = '{ioc}']"

    def _create_obs(self):
        return stix2.URL(value=self.name)


class FileHash(Indicator):
    """Converts Hash to File indicator and observable"""

    def __init__(self, name, author, risk_score=None, **kwargs):
        super().__init__(name, author)
        self.algorithm = self._determine_algorithm()

    def _determine_algorithm(self):
        """Determine file hash algorithm from length"""
        if len(self.name) == 64:
            return 'SHA-256'
        elif len(self.name) == 40:
            return 'SHA-1'
        elif len(self.name) == 32:
            return 'MD5'
        msg = (
            f'Could not determine hash type for {self.name}. Only MD5, SHA1'
            ' and SHA256 hashes are supported'
        )
        raise ConversionError(msg)

    def _create_pattern(self):
        return f"[file:hashes.'{self.algorithm}' = '{self.name}']"

    def _create_obs(self):
        return stix2.File(hashes={self.algorithm: self.name})


class TLPMarking(RFStixEntity):
    """Creates TLP marking for report"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(self.name, self.name),
            name=self.name,
            created_by_ref=self.author.id,
            custom_properties={'x_mitre_id': self.name},
        )


class TTP(RFStixEntity):
    """Converts MITRE T codes to AttackPattern"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(self.name, self.name),
            name=self.name,
            created_by_ref=self.author.id,
            custom_properties={'x_mitre_id': self.name},
        )


class Identity(RFStixEntity):
    """Converts various RF entity types to a STIX2 Identity"""

    type_to_class = {
        'Company': 'organization',
        'Organization': 'organization',
        'Person': 'individual',
    }

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.Identity(
            name=self.name, identity_class=self.create_id_class(), created_by_ref=self.author.id
        )

    def create_id_class(self):
        """Creates a STIX2 identity class"""
        return self.type_to_class[self.type]


class ThreatActor(RFStixEntity):
    """Converts various RF Threat Actor Organization to a STIX2 Threat Actor"""

    type_to_class = {
        'Company': 'organization',
        'Organization': 'organization',
        'Person': 'individual',
    }

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.ThreatActor(name=self.name, created_by_ref=self.author.id)

    def create_id_class(self):
        """Creates a STIX2 identity class"""
        return self.type_to_class[self.type]


class IntrusionSet(RFStixEntity):
    """Converts Threat Actor to Intrusion Set SDO"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.IntrusionSet(name=self.name, created_by_ref=self.author.id)


class Malware(RFStixEntity):
    """Converts Malware to a Malware SDO"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.Malware(
            name=self.name, is_family=False, created_by_ref=self.author.id
        )


class Vulnerability(RFStixEntity):
    """Converts a CyberVulnerability to a Vulnerability SDO"""

    # TODO: add vuln descriptions
    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.Vulnerability(name=self.name, created_by_ref=self.author.id)


class DetectionRule(RFStixEntity):
    """Represents a Yara or SNORT rule"""

    def __init__(self, name, type_, content):
        # TODO: possibly need to accomodate multi-rule. Right now just shoving everything in one

        self.name = name.split('.')[0]
        self.type = type_
        self.content = content
        self.stix_obj = None

        if self.type not in ('yara', 'snort'):
            msg = f'Detection rule of type {self.type} is not supported'
            raise ConversionError(msg)

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.Indicator(
            id=pycti.Indicator.generate_id(self.content()),
            name=self.name,
            pattern_type=self.type,
            pattern=self.content,
            valid_from=datetime.now(),
            created_by_ref=self.author.id,
        )


class EnrichedIndicator:
    """Class for converting Indicator + risk score + links to OpenCTI bundle"""

    entity_mapper = {
        'IpAddress': IPAddress,
        'InternetDomainName': Domain,
        'URL': URL,
        'Hash': FileHash,
        'MitreAttackIdentifier': TTP,
        'Company': Identity,
        'Person': Identity,
        'Organization': Identity,
        'Malware': Malware,
        'CyberVulnerability': Vulnerability,
    }

    def __init__(self, type_, observable_id, opencti_helper, create_indicator=True):
        """
        type_ (str): Recorded Future
        observable_id (str): OpenCTI STIX2 ID of obsrevable being enriched
        opencti_helper (pycti.OpenCTIConnectorHelper): OpenCTI helper class
        create_indicator (bool): Should we create indicator out of enriched observable
        """
        if type_ not in SUPPORTED_RF_TYPES:
            raise ConversionError(
                'Enriched Indicator must be of a supported type. {} is not supported'.format(type_)
            )
        self.type = type_
        self.author = self._create_author()
        self.helper = opencti_helper
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
        return stix2.Identity(name='Recorded Future', identity_class='organization')

    def from_json(self, name, risk, evidenceDetails, links):
        """Creates STIX objects from enriched entity json"""
        object_refs = [self.obs_id]
        if self.create_indicator:
            indicator = self.entity_mapper[self.type](
                name, self.author, risk_score=risk, obs_id=self.obs_id
            )
            indicator.create_stix_objects()
            self.indicator = indicator.stix_indicator
            object_refs.append(self.indicator.id)
            self.chained_objects.append(indicator.stix_relationship)

        self.notes.append(
            stix2.Note(
                abstract='Recorded Future Risk Score',
                content='{}/99'.format(risk),
                created_by_ref=self.author.id,
                object_refs=object_refs,
            )
        )
        for rule in evidenceDetails:
            self.notes.append(
                stix2.Note(
                    abstract=f"{rule['rule']}",
                    content=f"{rule['evidenceString']}",
                    created_by_ref=self.author.id,
                    object_refs=object_refs,
                )
            )
            self.linked_sdos.append(
                stix2.AttackPattern(
                    id=pycti.AttackPattern.generate_id(rule['rule'], rule['rule']),
                    name=rule['rule'],
                    created_by_ref=self.author.id,
                    custom_properties={
                        'x_rf_criticality': rule['criticality'],
                        'x_rf_critcality_label': rule['criticalityLabel'],
                        'x_mitre_id': rule['rule'],
                    },
                )
            )
        for link in links:
            try:
                type_ = link['type'].split('type:')[1]

                if type_ not in self.entity_mapper:
                    msg = 'Cannot convert entity {} to STIX2 because it is of type {}'.format(
                        link['name'], type_
                    )
                    self.helper.log_warning(msg)
                    continue
                if any(attr.get("id") == "threat_actor" for attr in link['attributes']):
                    link_object = ThreatActor(link['name'], self.author, type_=type_)

                else:
                    link_object = self.entity_mapper[type_](link['name'], self.author, type_=type_)
                link_object.create_stix_objects()
                if isinstance(link_object, Indicator):
                    self.linked_sdos.append(link_object.stix_indicator)
                    self.chained_objects.append(link_object.stix_observable)
                    self.chained_objects.append(link_object.stix_relationship)
                else:
                    self.linked_sdos.extend(link_object.to_stix_objects())
            except Exception as err:
                self.helper.log_error(err)
                continue

    def _create_relationships(self, sdo):
        """Creates relationships between the indicators and riskrules + links"""
        ret_val = []
        rel_type = 'related-to'
        if any(isinstance(sdo, stixtype) for stixtype in INDICATES_RELATIONSHIP):
            rel_type = 'indicates'
        try:
            if self.create_indicator:
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
            ret_val.append(
                stix2.Relationship(
                    id=pycti.StixCoreRelationship.generate_id('related-to', self.obs_id, sdo.id),
                    relationship_type='related-to',
                    source_ref=self.obs_id,
                    target_ref=sdo.id,
                    created_by_ref=self.author.id,
                )
            )
            return ret_val
        except Exception as err:
            self.helper.log_error(
                'Could not create relationship when source is {} and target_ref is {}'.format(
                    str(self.indicator), sdo.id
                )
            )
            raise err

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        objects = [self.author]
        # self.helper.log_debug("linked_sdos: {}".format(str(self.linked_sdos)))
        for sdo in self.linked_sdos:
            self.helper.log_debug("Creating relationship for {}".format(sdo))
            objects.extend(self._create_relationships(sdo))
        objects.extend(self.linked_sdos)
        objects.extend(self.notes)
        objects.extend(self.chained_objects)
        if self.create_indicator:
            objects.append(self.indicator)
        return objects

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        return stix2.Bundle(objects=self.to_stix_objects(), allow_custom=True)

    def to_json_bundle(self):
        """Returns STIX Bundle as JSON"""
        return self.to_stix_bundle().serialize()


# maps RF types to the corresponding python object
ENTITY_TYPE_MAPPER = {
    # TODO: add more supported types, starting with location
    'IpAddress': IPAddress,
    'InternetDomainName': Domain,
    'URL': URL,
    'Hash': FileHash,
    'MitreAttackIdentifier': TTP,
    'Company': Identity,
    'Person': Identity,
    'Organization': Identity,
    'Malware': Malware,
    'CyberVulnerability': Vulnerability,
}
