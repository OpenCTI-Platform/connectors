from dateutil.parser import parse
from pymisp import MISPEvent, MISPAttribute, MISPObject
from src.connector.errors import (
    ConnectorError,
    ConnectorWarning,
)
from src.models.configs.config_loader import ConfigLoader

SUPPORTED_OBSERVABLE_TYPES = [
    "Domain-Name",
    "IPv4-Addr",
    "IPv6-Addr",
    "Url",
    "StixFile",
    "Hostname"
]

class Converter:
    """
    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        self.misp_event = MISPEvent()

    def convert_to_misp_event(self, entity, contains_entities) -> MISPEvent:
        self.misp_event.distribution = 0
        self.misp_event.threat_level_id = 1
        self.misp_event.analysis = 0
        self.misp_event.date = parse(entity.get("published"))

        # model name
        self.misp_event.info = entity.get("name")

        # model labels as tags
        for label in entity.get("labels", []):
            self.misp_event.add_tag(label)

        # model report types as tags
        for report_type in entity.get("report_types", []):
            tag = 'opencti:report-type="'+report_type+'"'
            self.misp_event.add_tag(tag)

        # model description as comment Other attribute
        if entity.get("description", ""):
            attribute = MISPAttribute()
            attribute.type = "comment"
            attribute.category = "Other"
            attribute.value = entity.get("description")
            self.misp_event.add_attribute(**attribute)

        # TODO: process external attached files

        # model external references
        if entity.get("external_references", []):
            self.convert_external_reference(entity)

        # process related entities
        for entity in contains_entities:
            if entity.get("entity_type") == "Attack-Pattern":
                self.convert_attack_pattern(entity)
            elif entity.get("entity_type") == "Vulnerability":
                self.convert_vulnerability(entity)
            elif entity.get("entity_type") == "Country":
                self.convert_country(entity)
            #if entity.get("entity_type") == "Region":
            #    self.convert_country(entity)
            elif entity.get("entity_type") == "Sector":
                self.convert_sector(entity)
            elif entity.get("entity_type") == "Tool":
                self.convert_tool(entity)
            elif entity.get("entity_type") == "Malware":
                self.convert_malware(entity)
            elif entity.get("entity_type") in SUPPORTED_OBSERVABLE_TYPES:
                self.convert_observable(entity)
            else:
                print("UNSUPPORTED ENTITY TYPE: " + entity.get("entity_type"))

        return self.misp_event

    def convert_external_reference(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        for external_ref in stix_entity.get("external_references", []):
            if external_ref.get("source_name", None) != "MISP Stream Export":
                attribute = MISPAttribute()
                attribute.type = "link"
                attribute.category = "External analysis"
                attribute.value = external_ref.get("url")
                self.misp_event.add_attribute(**attribute)


    def convert_observable(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        if stix_entity.get("entity_type") == "Domain-Name":
            attribute = MISPAttribute()
            attribute.type = "domain"
            attribute.category = "Network activity"
            attribute.value = stix_entity.get("value")
            attribute.comment = stix_entity.get("description", "")
            self.misp_event.add_attribute(**attribute)
        if stix_entity.get("entity_type") == "IPv4-Addr" or stix_entity.get("entity_type") == "IPv6-Addr":
            attribute = MISPAttribute()
            attribute.type = "ip-dst"
            attribute.category = "Network activity"
            attribute.value = stix_entity.get("value")
            attribute.comment = stix_entity.get("description", "")
            self.misp_event.add_attribute(**attribute)
        if stix_entity.get("entity_type") == "Url":
            attribute = MISPAttribute()
            attribute.type = "url"
            attribute.category = "Network activity"
            attribute.value = stix_entity.get("value")
            attribute.comment = stix_entity.get("description", "")
            self.misp_event.add_attribute(**attribute)
        if stix_entity.get("entity_type") == "Hostname":
            attribute = MISPAttribute()
            attribute.type = "hostname"
            attribute.category = "Network activity"
            attribute.value = stix_entity.get("value")
            attribute.comment = stix_entity.get("description", "")
            self.misp_event.add_attribute(**attribute)
        if stix_entity.get("entity_type") == "StixFile":
            print(stix_entity)
            for hash_def in stix_entity.get("hashes"):
                if hash_def.get("algorithm").lower() == "sha-1":
                    attribute = MISPAttribute()
                    attribute.type = "sha1"
                    attribute.category = "Payload delivery"
                    attribute.value = hash_def.get("hash")
                    attribute.comment = stix_entity.get("description", "")
                    self.misp_event.add_attribute(**attribute)
                if hash_def.get("algorithm").lower() == "sha-256":
                    attribute = MISPAttribute()
                    attribute.type = "sha256"
                    attribute.category = "Payload delivery"
                    attribute.value = hash_def.get("hash")
                    attribute.comment = stix_entity.get("description", "")
                    self.misp_event.add_attribute(**attribute)
                if hash_def.get("algorithm").lower() == "md5":
                    attribute = MISPAttribute()
                    attribute.type = "md5"
                    attribute.category = "Payload delivery"
                    attribute.value = hash_def.get("hash")
                    attribute.comment = stix_entity.get("description", "")
                    self.misp_event.add_attribute(**attribute)

    def convert_tool(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        tag = 'misp-galaxy:tool="'+stix_entity.get("name")+'"'
        self.misp_event.add_tag(tag)

    def convert_sector(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        tag = 'misp-galaxy:sector="'+stix_entity.get("name")+'"'
        self.misp_event.add_tag(tag)

    def convert_country(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        tag = 'misp-galaxy:country="'+stix_entity.get("name")+'"'
        self.misp_event.add_tag(tag)

    def convert_attack_pattern(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        tag = 'misp-galaxy:mitre-attack-pattern="'+stix_entity.get("name")+' - '+stix_entity.get("x_mitre_id")+'"'
        self.misp_event.add_tag(tag)

    def convert_vulnerability(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        attribute = MISPAttribute()
        attribute.type = "vulnerability"
        attribute.category = "External analysis"
        attribute.value = stix_entity.get("name")
        attribute.comment = stix_entity.get("description", "")
        self.misp_event.add_attribute(**attribute)

    def convert_malware(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        tag = 'misp-galaxy:malware="'+stix_entity.get("name")+'"'
        self.misp_event.add_tag(tag)

    def convert_intrusion_set(self, stix_entity):
        """
        :param stix_entity:
        :return:
        """
        tag = 'misp-galaxy:threat-actor="'+stix_entity.get("name")+'"'
        self.misp_event.add_tag(tag)
