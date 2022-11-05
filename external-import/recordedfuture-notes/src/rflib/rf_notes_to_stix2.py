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
import stix2.v21


class ConversionError(Exception):
    """Generic exception for stix2 conversion issues"""

    pass


class RFStixEntity:
    """Parent class"""

    def __init__(self, name, type_, author):
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
        return stix2.v21.Bundle(objects=self.to_stix_objects(), allow_custom=True)

    def to_json_bundle(self):
        """Returns STIX Bundle as JSON"""
        return self.to_stix_bundle().serialize()


class Indicator(RFStixEntity):
    """Base class for Indicators of Compromise (IP, Hash, URL, Domain)"""

    def __init__(self, name, type_, author):
        self.name = name
        self.author = author
        self.stix_indicator = None
        self.stix_observable = None
        self.stix_relationship = None

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        if not (self.stix_indicator and self.stix_observable and self.stix_relationship):
            self.create_stix_objects()
        return [self.stix_indicator, self.stix_observable, self.stix_relationship]

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_indicator = self._create_indicator()
        self.stix_observable = self._create_obs()  # pylint: disable=assignment-from-no-return
        self.stix_relationship = self._create_rel()

    def _create_indicator(self):
        """Creates and returns STIX2 indicator object"""
        return stix2.v21.Indicator(
            name=self.name,
            pattern_type='stix',
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
        return stix2.v21.Relationship(
            relationship_type='based_on',
            source_ref=self.stix_indicator.id,
            target_ref=self.stix_observable.id,
            start_time=datetime.now(),
            created_by_ref=self.author.id,
        )


class IPAddress(Indicator):
    """Converts IP address to IP indicator and observable"""

    # TODO: add ipv6 compatibility
    def _create_pattern(self):
        return f"[ipv4-addr:value = '{self.name}']"

    def _create_obs(self):
        return stix2.v21.IPv4Address(value=self.name)


class Domain(Indicator):
    """Converts Domain to Domain indicator and observable"""

    def _create_pattern(self):
        return f"[domain-name:value = '{self.name}']"

    def _create_obs(self):
        return stix2.v21.DomainName(value=self.name)


class URL(Indicator):
    """Converts URL to URL indicator and observable"""

    def _create_pattern(self):
        ioc = self.name.replace('\\', '\\\\')
        ioc = ioc.replace("'", "\\'")
        return f"[url:value = '{ioc}']"

    def _create_obs(self):
        return stix2.v21.URL(value=self.name)


class FileHash(Indicator):
    """Converts Hash to File indicator and observable"""

    def __init__(self, name, type_, author):
        super().__init__(name, type_, author)
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
        return stix2.v21.File(hashes={self.algorithm: self.name})


class TTP(RFStixEntity):
    """Converts MITRE T codes to AttackPattern"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.v21.AttackPattern(
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
        self.stix_obj = stix2.v21.Identity(
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
        self.stix_obj = stix2.v21.ThreatActor(name=self.name, created_by_ref=self.author.id)

    def create_id_class(self):
        """Creates a STIX2 identity class"""
        return self.type_to_class[self.type]


class Malware(RFStixEntity):
    """Converts Malware to a Malware SDO"""

    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.v21.Malware(
            name=self.name, is_family=False, created_by_ref=self.author.id
        )


class Vulnerability(RFStixEntity):
    """Converts a CyberVulnerability to a Vulnerability SDO"""

    # TODO: add vuln descriptions
    def create_stix_objects(self):
        """Creates STIX objects from object attributes"""
        self.stix_obj = stix2.v21.Vulnerability(name=self.name, created_by_ref=self.author.id)


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
        self.stix_obj = stix2.v21.Indicator(
            name=self.name,
            pattern_type=self.type,
            pattern=self.content,
            valid_from=datetime.now(),
            created_by_ref=self.author.id,
        )


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


class StixNote:
    """Represents Analyst Note"""

    report_type_mapper = {
        'Actor Profile': 'Threat-Actor',
        'Analyst On-Demand Report': 'Threat-Report',
        'Cyber Threat Analysis': 'Threat-Report',
        'Flash Report': 'Threat-Report',
        'Geopolitical Flash Event': 'Threat-Report',
        'Geopolitical Intelligence Summary': 'Threat-Report',
        'Geopolitical Profile': 'Threat-Actor',
        'Geopolitical Threat Forecast': 'Threat-Actor',
        'Geopolitical Validated Event': 'Observed-Data',
        'Hunting Package': 'Attack-Pattern',
        'Indicator': 'Indicator',
        'Informational': 'Threat-Report',
        'Insikt Research Lead': 'Intrusion-Set',
        'Malware/Tool Profile': 'Malware',
        'Regular Vendor Vulnerability Disclosures': 'Vulnerability',
        'Sigma Rule': 'Attack-Pattern',
        'SNORT Rule': 'Indicator',
        'Source Profile': 'Observed-Data',
        'The Record by Recorded Future': 'Threat-Report',
        'Threat Lead': 'Threat-Actor',
        'TTP Instance': 'Attack-Pattern',
        'Validated Intelligence Event': 'Observed-Data',
        'Weekly Threat Landscape': 'Threat-Report',
        'YARA Rule': 'Indicator',
    }

    def __init__(self, opencti_helper, tas):
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

    def _create_author(self):
        """Creates Recorded Future Author"""
        return stix2.v21.Identity(name='Recorded Future', identity_class='organization')

    def _generate_external_references(self, urls):
        """Generate External references from validation urls"""
        refs = []
        for url in urls:
            external_url = url['name']
            source_name = external_url.split('/')[2].split('.')[-2]
            refs.append({'source_name': source_name, 'url': external_url})
        return refs

    def from_json(self, note):
        """Converts to STIX Bundle from JSON objects"""
        # TODO: catch errors in for loop here
        attr = note['attributes']
        self.name = attr['title']
        self.text = attr['text']
        self.published = attr['published']
        self.external_references = self._generate_external_references(
            attr.get('validation_urls', [])
        )
        self.report_types = self._create_report_types(attr.get('topic', []))
        self.labels = [topic['name'] for topic in attr.get('topic', [])]
        for entity in attr.get('note_entities', []):
            type_ = entity['type']
            name = entity['name']
            if entity['id'] in self.tas:
                stix_objs = ThreatActor(name, type_, self.author).to_stix_objects()
            elif type_ not in ENTITY_TYPE_MAPPER:
                msg = f'Cannot convert entity {name} to STIX2 because it is of type {type_}'
                self.helper.log_warning(msg)
                continue
            else:
                stix_objs = ENTITY_TYPE_MAPPER[type_](name, type_, self.author).to_stix_objects()
            self.objects.extend(stix_objs)
        if 'attachment_content' in attr:
            rule = DetectionRule(
                attr['attachment'], attr['attachment_type'], attr['attachment_content']
            )
            self.objects.extend(rule.to_stix_objects())

    def _create_report_types(self, topics):
        """Converts Insikt Topics to STIX2 Report types"""
        ret = set()
        for topic in topics:
            name = topic['name']
            if name not in self.report_type_mapper:
                self.helper.log_warning('Could not map a report type for type {}'.format(name))
                continue
            ret.add(self.report_type_mapper[name])
        return list(ret)

    def to_stix_objects(self):
        """Returns a list of STIX objects"""
        report = stix2.v21.Report(
            name=self.name,
            description=self.text,
            published=self.published,
            created_by_ref=self.author.id,
            labels=self.labels,
            report_types=self.report_types,
            object_refs=[obj.id for obj in self.objects] + [self.author.id],
            external_references=self.external_references,
        )
        return self.objects + [report, self.author]

    def to_stix_bundle(self):
        """Returns STIX objects as a Bundle"""
        return stix2.v21.Bundle(objects=self.to_stix_objects(), allow_custom=True)

    def to_json_bundle(self):
        """Returns STIX Bundle as JSON"""
        return self.to_stix_bundle().serialize()
