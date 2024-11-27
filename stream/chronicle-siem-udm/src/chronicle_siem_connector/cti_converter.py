from datetime import datetime

from stix_shifter.stix_translation import stix_translation

PRODUCT_NAME = "OPENCTI"
VENDOR_NAME = "FILIGRAN"


def now():
    # Get the current time
    current_time = datetime.utcnow()

    # Format the current time
    formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    return formatted_time


class CTIConverter:

    def __init__(self, helper, config):
        """
        Init CTI Converter.
        Convert OpenCTI entities into Chronicle UDM entities.
        :param config: Connector's config
        """
        self.config = config
        self.helper = helper

    def create_udm_entity(self, data):
        """
        Create a UDM chronicle entity based on an openCTI stream indicator.
        :param data: OpenCTI Indicator
        :return:
        """
        events = []
        # Use the new method to get parsed observables from STIX pattern
        parsed_observables = self.helper.get_attribute_in_extension("observable_values", data)

        if parsed_observables:
            for observable in parsed_observables:
                print(f"going to parse observable: {observable}")

                metadata = {
                    "vendor_name": VENDOR_NAME,
                    "product_name": PRODUCT_NAME,
                    "collected_timestamp": str(now()),
                    "product_entity_id": data["id"],
                    "interval": {
                        "start_time": data["valid_from"],
                        "end_time": data["valid_until"],
                    },
                    "threat": {
                        #"confidence_details": str(data["confidence"]),
                        "confidence_score": data.get("confidence"),
                        "risk_score": int(self.helper.get_attribute_in_extension("score", data))
                        #"url_back_to_product": ""
                    }
                }

                if data.get("description", None):
                    metadata["description"] = data.get("description")

                if data.get("labels"):
                    metadata["threat"]["category_details"] = ", ".join(data.get("labels"))

                entity = {}
                match observable.get("type").lower():
                    case "domain-name":
                        entity['hostname'] = observable.get("value")
                        metadata['entity_type'] = 'DOMAIN_NAME'
                    case "hostname":
                        entity['hostname'] = observable.get("value")
                        metadata['entity_type'] = 'DOMAIN_NAME'
                    case "ipv4-addr":
                        entity['ip'] = observable.get("value")
                        metadata['entity_type'] = 'IP_ADDRESS'
                    case "ipv6-addr":
                        entity['ip'] = observable.get("value")
                        metadata['entity_type'] = 'IP_ADDRESS'
                    case "url":
                        # remove the http or https protocol from URL if your log source doesn't record this
                        # sanitized_url = fix_url(indicator['value'],"^http(s)?://")
                        # entity['url'] = sanitized_url
                        entity['url'] = observable.get("value")
                        metadata['entity_type'] = 'URL'
                    case "stixfile":
                        file = {}
                        metadata['entity_type'] = 'FILE'
                        for key, value in observable.get("hashes").items():
                            if key.lower() == "md5":
                                file['md5'] = value
                                entity['file'] = file
                            if key.lower() == "sha-1":
                                file['sha1'] = value
                                entity['file'] = file
                            if key.lower() == "sha-256":
                                file['sha256'] = value
                                entity['file'] = file
                            if key.lower() == "sha-512":
                                file['sha512'] = value
                                entity['file'] = file
                    case _:
                        self.helper.connector_logger.info(f"Unable to map observable type: {observable.get('type')} "
                                                          f"to Chronicle entity type, skipping indicator")
                        pass
                # create the final UDM event
                event = {}
                event['metadata'] = metadata
                event['entity'] = entity
                event['additional'] = {}
                events.append(event)
        else:
            self.helper.connector_logger.info(
                "Indicator doesn't contains 'observable_values' key, unable to parse observables",
                {"indicator_id": data["id"]})
        print(events)
        return events

