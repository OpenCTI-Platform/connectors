from datetime import datetime, timezone

from .utils import ENTITY_TYPE_MAPPER, HASH_TYPES_MAPPER

PRODUCT_NAME = "OPENCTI"
VENDOR_NAME = "FILIGRAN"


class CTIConverter:

    def __init__(self, helper, config):
        """
        Init CTI Converter.
        Convert OpenCTI entities into Chronicle UDM entities.
        :param config: Connector's config
        """
        self.config = config
        self.helper = helper

    @staticmethod
    def current_date() -> str:
        # Get the current time
        current_time = datetime.now(timezone.utc)

        # Format the current time
        formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        return formatted_time

    def extract_octi_ioc_url(self, data: dict) -> str | None:
        """
        Extract the OpenCTI URL for an IOC from the data.
        :param data: Data of OpenCTI Indicator in dict
        :return: OpenCTI URL for the IOC
        """
        x_opencti_ioc_id = self.helper.get_attribute_in_extension("id", data)

        if x_opencti_ioc_id is None:
            return None

        ioc_opencti_url = (
            self.helper.opencti_url
            + "/dashboard/observations/indicators/"
            + x_opencti_ioc_id
        )

        return ioc_opencti_url

    def generate_entity_metadata(self, data: dict) -> dict:
        """
        Generate metadata for Chronicle entity UDM format
        :param data: Data of OpenCTI Indicator in dict
        :return: Entity metadata in dict
        """
        ioc_stix_id = data["id"]
        ioc_start_time = data["valid_from"]
        ioc_end_time = data["valid_until"]
        ioc_confidence_level = data.get("confidence")
        ioc_description = data.get("description")
        ioc_score = int(self.helper.get_attribute_in_extension("score", data))
        ioc_threat_labels = data.get("labels")
        x_opencti_ioc_url = self.extract_octi_ioc_url(data)

        metadata = {
            "vendor_name": VENDOR_NAME,
            "product_name": PRODUCT_NAME,
            "collected_timestamp": self.current_date(),
            "product_entity_id": ioc_stix_id,
            "description": ioc_description,
            "interval": {
                "start_time": ioc_start_time,
                "end_time": ioc_end_time,
            },
            "threat": {
                "confidence_details": (
                    str(ioc_confidence_level) if ioc_confidence_level else None
                ),
                "confidence_score": ioc_confidence_level,
                "risk_score": ioc_score,
                "category_details": ioc_threat_labels,
                "url_back_to_product": x_opencti_ioc_url,
            },
        }

        return metadata

    @staticmethod
    def generate_entity_details(observable: dict, entity_metadata: dict) -> dict:
        """
        Generate entity details for Chronicle entity UDM format and complete entity metadata with correct entity type.
        :param observable:
        :param entity_metadata:
        :return:
        """
        x_opencti_observable_type = observable.get("type").lower()

        entity = {}

        observable_type = ENTITY_TYPE_MAPPER.get(x_opencti_observable_type)

        chronicle_entity_field = observable_type["chronicle_entity_field"]
        chronicle_entity_type = observable_type["chronicle_entity_type"]

        if x_opencti_observable_type == "stixfile":
            file = {}
            for key, value in observable.get("hashes", {}).items():
                hash_type = HASH_TYPES_MAPPER.get(key.lower())

                if hash_type is not None:
                    file[hash_type] = value
            if file:
                entity["file"] = file
                entity_metadata["entity_type"] = chronicle_entity_type
        else:
            entity[chronicle_entity_field] = observable.get("value")
            entity_metadata["entity_type"] = chronicle_entity_type

        return entity

    def create_udm_entities_from_indicator(self, indicator: dict) -> list:
        """
        Create a UDM chronicle entity based on an openCTI stream indicator.
        :param indicator: Data of OpenCTI Indicator in dict
        :return List of UDM entities in dict as Events
        """
        self.helper.connector_logger.info(
            "Creating UDM entities from OpenCTI Indicator for Chronicle to be ingested..."
        )

        udm_entities = []

        # Use the new method to get parsed observables from STIX pattern introduced in >= 6.4
        parsed_observables = self.helper.get_attribute_in_extension(
            "observable_values", indicator
        )

        if parsed_observables:

            # Iterate over the parsed observables
            for observable in parsed_observables:

                entity_metadata = self.generate_entity_metadata(indicator)
                entity_details = self.generate_entity_details(
                    observable, entity_metadata
                )

                if not entity_metadata or not entity_details:
                    self.helper.connector_logger.info(
                        "Skipping indicator as it is not supported",
                        {"observable_details": observable},
                    )
                    continue
                else:
                    # create the final UDM event
                    udm_entity = {"metadata": entity_metadata, "entity": entity_details}
                    udm_entities.append(udm_entity)
        else:
            self.helper.connector_logger.info(
                "Indicator doesn't contains 'observable_values' key, unable to parse observables",
                {"indicator_id": indicator["id"]},
            )

        return udm_entities
