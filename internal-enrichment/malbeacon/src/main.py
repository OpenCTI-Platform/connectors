from malbeacon_client import MalbeaconClient
from malbeacon_config_variables import ConfigMalbeacon
from malbeacon_converter import MalbeaconConverter
from malbeacon_endpoints import C2_PATH
from models.c2_model import C2Beacon
from pycti import OpenCTIConnectorHelper


class MalBeaconConnector:
    """
    Malbeacon connector class
    """

    def __init__(self):
        """
        Initialize the Malbeacon Connector with necessary configurations
        """
        self.config = ConfigMalbeacon()
        self.helper = OpenCTIConnectorHelper(self.config.load, True)
        self.client = MalbeaconClient(self.helper)
        self.converter = MalbeaconConverter()

        # Define variables
        self.author = None
        self.tlp = None
        self.external_references = None
        self.stix_object_list = []

    def extract_and_check_markings(self, opencti_entity: dict) -> bool:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: Boolean
        """
        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    self.tlp = marking_definition["definition"]

        is_valid_max_tlp = self.helper.check_max_tlp(self.tlp, self.config.max_tlp)

        return is_valid_max_tlp

    def _process_observable(self, data: dict) -> str:
        """
        Get the observable created in OpenCTI and check which type
        Send for process c2
        :param data_from_enrichment: dict of observable properties
        :return: Info message in string
        """
        opencti_entity = data["enrichment_entity"]
        is_valid_tlp = self.extract_and_check_markings(opencti_entity)
        if not is_valid_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

        self.stix_object_list = data["stix_objects"]
        observable = data["stix_entity"]

        # Extract IPv4, IPv6, and Domain from entity data
        obs_standard_id = observable["id"]
        obs_value = observable["value"]
        obs_type = observable["type"]

        info_msg = "[CONNECTOR] Processing observable for the following entity type: "
        self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

        # TODO: add "Email-Address" in scope
        connector_scope = (
            self.config.connector_scope.lower().replace(" ", "").split(",")
        )
        if obs_type in connector_scope:
            stix_objects = self.process_c2(
                obs_value, obs_standard_id, opencti_entity["entity_type"]
            )

            if stix_objects is not None and len(stix_objects) is not None:
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

                info_msg = (
                    "[API] Observable value found on Malbeacon API and knowledge added for type: "
                    + obs_type
                    + ", sending "
                    + str(len(bundles_sent))
                    + " stix bundle(s) for worker import"
                )
                return info_msg
            else:
                info_msg = "[API] No information found on Malbeacon"
                return info_msg
        else:
            return self.helper.connector_logger.info(
                "[CONNECTOR] Skip the following entity as it does not concern "
                "the initial scope found in the config connector: ",
                {"entity_id": opencti_entity["entity_id"]},
            )

    def _process_message(self, data: dict) -> str:
        """
        Get observable newly created from OpenCTI and process enrichment
        :param data: Dictionary of data
        :return: A string from process observable
        """
        return self._process_observable(data)

    def start(self) -> None:
        """
        Start main execution loop procedure for Malbeacon connector
        """
        self.helper.listen(message_callback=self._process_message)

    """
    ==============================================================
    Main C2 process
    Convert Malbeacon data imported into STIX2 standard object
    ==============================================================
    """

    def process_c2(
        self, obs_value: str, obs_standard_id: str, obs_type: str
    ) -> list | None:
        """
        Process C2 if data found in Malbeacon
        :param obs_value: Observable value in string
        :param obs_standard_id: Standard observable id in string
        :param obs_type: Observable type in string
        :return: STIX2 object in dict
        """
        try:
            already_processed = []

            data = self.client.request_data(
                self.config.api_base_url + C2_PATH + obs_value
            )

            """
            =========================================================
            If the API returns a JSON document with a message,
            there probably has been an error or no information
            could be retrieved from the Malbeacon database
            =========================================================
            """
            if data is None or "message" in data:
                error_msg = "No data found for this following observable: "
                self.helper.connector_logger.info(
                    error_msg, {"observable_value": obs_value}
                )

            else:
                """
                ========================================================================
                Complete observable added
                Add author, external references and indicator based on this observable
                ========================================================================
                """

                self.author = self.converter.create_author()
                stix_external_ref_on_base_obs = self.converter.create_obs(
                    obs_value, obs_standard_id
                )
                stix_indicator_based_on_obs = self.converter.create_indicator(
                    obs_type, obs_value
                )
                base_stix_relationship = self.converter.create_relationship(
                    stix_indicator_based_on_obs["id"],
                    "based-on",
                    stix_external_ref_on_base_obs["id"],
                )

                self.stix_object_list.extend(
                    [
                        self.author,
                        stix_external_ref_on_base_obs,
                        stix_indicator_based_on_obs,
                        base_stix_relationship,
                    ]
                )

                """
                =================================================================================
                Main C2 process, convert Malbeacon observables related to the base observable
                into STIX2 standard object, create indicator based on them and add relationships
                =================================================================================
                """
                for entry in data:
                    # Parse object from C2Beacon Models
                    c2_beacon = C2Beacon.parse_obj(entry)

                    info_msg = "Processing C2 from Malbeacon for: "
                    self.helper.connector_logger.info(
                        info_msg,
                        {
                            "date": {c2_beacon.cti_date},
                            "actor_ip": {c2_beacon.actorip},
                            "actor_hostname": {c2_beacon.actorhostname},
                        },
                    )

                    """
                    ======================================================
                    Process knowledge about the actors infrastructure
                    ======================================================
                    """

                    if (
                        c2_beacon.actorip != "NA"
                        and c2_beacon.actorip not in already_processed
                    ):
                        c2_value = c2_beacon.actorip
                        c2_type = self.converter.main_observable_type(c2_value)
                        c2_description = (
                            "Malbeacon Actor IP Address for C2 " + obs_value
                        )

                        c2_stix_observable = self.converter.create_obs(c2_value)
                        c2_stix_indicator = self.converter.create_indicator(
                            c2_type, c2_value, c2_description
                        )
                        c2_stix_relationship = self.converter.create_relationship(
                            c2_stix_indicator["id"],
                            "based-on",
                            c2_stix_observable["id"],
                        )
                        base_relationship = self.converter.create_relationship(
                            obs_standard_id,
                            "related-to",
                            c2_stix_observable["id"],
                        )

                        self.stix_object_list.extend(
                            [
                                c2_stix_observable,
                                c2_stix_indicator,
                                c2_stix_relationship,
                                base_relationship,
                            ]
                        )

                        if c2_beacon.actorhostname != "NA":
                            c2_value = c2_beacon.actorhostname
                            c2_type = self.converter.main_observable_type(c2_value)
                            c2_description = (
                                "Malbeacon Actor DomainName for C2 " + obs_value
                            )

                            c2_stix_observable = self.converter.create_obs(c2_value)
                            c2_stix_indicator = self.converter.create_indicator(
                                c2_type, c2_value, c2_description
                            )
                            c2_stix_relationship = self.converter.create_relationship(
                                c2_stix_indicator["id"],
                                "based-on",
                                c2_stix_observable["id"],
                            )
                            base_relationship = self.converter.create_relationship(
                                obs_standard_id,
                                "related-to",
                                c2_stix_observable["id"],
                            )

                            self.stix_object_list.extend(
                                [
                                    c2_stix_observable,
                                    c2_stix_indicator,
                                    c2_stix_relationship,
                                    base_relationship,
                                ]
                            )

                        # Make sure we only process this specific IP once
                        already_processed.append(c2_beacon.actorip)

                return self.stix_object_list

        except Exception as err:
            error_msg = "[CONNECTOR] Error while processing C2 beacons: "
            self.helper.connector_logger.error(error_msg, {"error": {str(err)}})
            return None


if __name__ == "__main__":
    MalBeaconInstance = MalBeaconConnector()
    MalBeaconInstance.start()
