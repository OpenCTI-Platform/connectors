"""Connector to enrich IOCs with Recorded Future data"""
import os
import urllib
from datetime import datetime

import requests
import stix2
import yaml
from pycti import (
    AttackPattern,
    Identity,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


def map_stix2_type_to_rf(entity_type):
    """
    Translates a STIX2 indicator type to its RF equivalent

    Args:
        entity_type (str): A STIX2 observable type

    Returns a Recorded Future IOC type as string
    """

    if entity_type in ("IPv4-Addr", "IPv6-Addr"):
        return "ip"
    elif entity_type == "Domain-Name":
        return "domain"
    elif entity_type == "Url":
        return "url"
    if entity_type == "StixFile":
        return "hash"
    return None


class RFEnrichmentConnector:
    """Enrichment connector class"""

    def __init__(self):
        """Instantiate the connector with config variables"""
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.token = get_config_variable(
            "RECORDEDFUTURE_ENRICHMENT_TOKEN",
            ["recordedfuture-enrichment", "token"],
            config,
        )
        self.max_tlp = get_config_variable(
            "RECORDEDFUTURE_ENRICHMENT_INFO_MAX_TLP",
            ["recordedfuture-enrichment", "max_tlp"],
            config,
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        # In a crisis, smash glass and uncomment this line of code
        # self.helper.config['uri'] = self.helper.config['uri'].replace('rabbitmq', '172.19.0.10')

    @staticmethod
    def _generate_fields():
        """
        Generates the fields returned in the Recorded Future API Query
        In the Future more fields will be supported
        """
        fields = ["entity", "risk", "hashAlgorithm"]
        return ",".join(fields)

    def generate_stix_bundle(self, response, ioc, obs_id, data_type):
        """
        Generates a STIX2 bundle from the RF API response

        Args:
            response (dict): A JSON object of data from the RF API
            ioc (str): the Indicator being enriched
            data_type (str): the OpenCTI data type of the indicator

        Returns a STIX2 bundle object
        """
        now = datetime.now()
        pattern = self.generate_pattern(
            ioc, data_type, algorithm=response.get("hashAlgorithm")
        )

        rf_identity = stix2.Identity(
            id=Identity.generate_id("Recorded Future", "organization"),
            name="Recorded Future",
            identity_class="organization",
        )

        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=ioc,
            confidence=int(response["risk"]["score"]),
            pattern_type="stix",
            valid_from=now,
            pattern=pattern,
            external_references=[
                {
                    "source_name": "RecordedFuture",
                    "url": f"https://app.recordedfuture.com/live/sc/entity/{map_stix2_type_to_rf(data_type)}%3A{ioc}",
                }
            ],
        )
        rel = stix2.Relationship(
            id=StixCoreRelationship.generate_id("based-on", indicator.id, obs_id),
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=obs_id,
            created_by_ref=rf_identity.id,
        )
        score_note = stix2.Note(
            abstract="Recorded Future Risk Score",
            content=f"{response['risk']['score']}/99",
            created_by_ref=rf_identity.id,
            object_refs=[indicator.id],
        )
        objects = [indicator, score_note, rf_identity, rel]
        for rule in response["risk"]["evidenceDetails"]:
            note = stix2.Note(
                abstract=f"{rule['rule']}",
                content=f"{rule['evidenceString']}",
                created_by_ref=rf_identity.id,
                object_refs=[indicator.id],
            )
            ttp = stix2.AttackPattern(
                id=AttackPattern.generate_id(rule["rule"], rule["rule"]),
                name=rule["rule"],
                created_by_ref=rf_identity.id,
                custom_properties={
                    "x_rf_criticality": rule["criticality"],
                    "x_rf_critcality_label": rule["criticalityLabel"],
                    "x_mitre_id": rule["rule"],
                },
            )
            rel = stix2.Relationship(
                id=StixCoreRelationship.generate_id("indicates", indicator.id, ttp.id),
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=ttp.id,
                created_by_ref=rf_identity.id,
            )
            objects.append(note)
            objects.append(ttp)
            objects.append(rel)

        return stix2.Bundle(objects=objects, allow_custom=True).serialize()

    @staticmethod
    def generate_pattern(ioc, data_type, algorithm=None):
        """
        Generates the appropiate STIX2 pattern for an IOC

        Args:
            ioc (str): the indicator being enriched
            data_type (str): the OpenCTI data type of the indicator
            algorithm (str): The hash algorithm, if data_type is hash

        Returns the STIX2 pattern as a string
        """

        if data_type == "StixFile":
            return f"[file:hashes.'{algorithm.lower()}' = '{ioc}']"
        return f"[{data_type.lower()}:value = '{ioc}']"

    def _process_message(self, data):
        """
        Listener that is triggered when someone enriches an Observable
        in the OpenCTI platform
        """

        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        self.helper.log_info("OBS IS")
        self.helper.log_info(observable)
        # Extract IOC from entity data
        observable_value = observable["observable_value"]
        entity_type = observable["entity_type"]

        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        # Convert to RF types
        rf_type = map_stix2_type_to_rf(entity_type)
        if rf_type is None:
            message = f"Recorded Future enrichment does not support type {entity_type}"
            self.helper.log_error(message)
            return [message]

        self.helper.log_info(f"enriching observable {observable_value}")
        fields = self._generate_fields()

        # Fetch risk data from RF API
        api_url = f'https://api.recordedfuture.com/v2/{rf_type}/{urllib.parse.quote(observable_value, safe="")}'
        response = requests.get(
            api_url,
            headers={"X-RFToken": self.token, "User-Agent": "OpenCTI-enrichment/V4.0"},
            params={"fields": fields},
        )
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            self.helper.log_error(
                f"Error trying to enrich indicator {observable_value}"
            )
            self.helper.log_error(err)
            return f"Error trying to enrich indicator {observable_value}"

        response = response.json()["data"]
        self.helper.log_info(response)

        bundle = self.generate_stix_bundle(
            response, observable_value, observable["standard_id"], entity_type
        )
        self.helper.log_info("ABOUT TO SEND BUNDLE")
        bundles_sent = self.helper.send_stix2_bundle(
            bundle, update=self.update_existing_data
        )
        return "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"

    def start(self):
        """Start the main loop"""
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    RF = RFEnrichmentConnector()
    RF.start()
