# import os
import sys
import time

# WARN: python-dotenv is used for integration manual run
import dotenv
from adapter import DataToSTIXAdapter
from lib.external_import import ExternalImportConnector

dotenv.load_dotenv()


class CustomConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector

        Note that additional attributes for the connector can be set after the super() call.

        Standardized way to grab attributes from environment variables is as follows:

        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")

        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.

        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization.
        """
        super().__init__()

    def _collect_intelligence(self, collection, event, mitre_mapper) -> []:
        """Collects intelligence from channels

        Add your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )

        # ===========================
        # === Add your code below ===
        # ===========================

        self.helper.log_debug("Collecting data")

        stix_objects = list()

        # ++
        if collection in ["apt/threat", "hi/threat"]:

            json_threat_report_obj = event.get("threat_report", {})
            json_file_obj = event.get("file", {})
            json_network_obj = event.get("network", {})
            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug(json_threat_actor_obj.get("name"))

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                )
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[stix_threat_actor],
                    domain_is_ioc=False,
                    url_is_ioc=False,
                    ip_is_ioc=True,
                )
            )
            stix_file_list = report_adapter.generate_stix_file(
                obj=json_file_obj, related_objects=[stix_threat_actor], is_ioc=True
            )

            # report_related_objects_ids = [
            #     # Files
            #     *[sf.stix_main_object.id for sf in stix_file_list],
            #     *[ind.id for sf in stix_file_list for ind in sf.stix_indicator],
            #     *[rel.id for rel_list in [sf.stix_relationships for sf in stix_file_list] for rel in rel_list],
            #     # Domains
            #     *[sf.stix_main_object.id for sf in stix_domain_list],
            #     *[rel.id for rel_list in [sf.stix_relationships for sf in stix_domain_list] for rel in rel_list],
            #     # URLs
            #     *[sf.stix_main_object.id for sf in stix_url_list],
            #     *[rel.id for rel_list in [sf.stix_relationships for sf in stix_url_list] for rel in rel_list],
            #     # IPs
            #     *[sf.stix_main_object.id for sf in stix_ip_list],
            #     *[sf.stix_indicator.id for sf in stix_ip_list],
            #     *[rel.id for rel_list in [sf.stix_relationships for sf in stix_ip_list] for rel in rel_list],
            #     # Malware
            #     *[sf.stix_main_object.id for sf in stix_malware_list],
            #     *[rel.id for rel_list in [sf.stix_relationships for sf in stix_malware_list] for rel in rel_list],
            #     # Vulnerability
            #     *[sf.stix_main_object.id for sf in stix_vulnerability_list],
            #     *[rel.id for rel_list in [sf.stix_relationships for sf in stix_vulnerability_list] for rel in rel_list],
            #     # MITRE
            #     *[sf.stix_main_object.id for sf in stix_attack_pattern_list],
            #     *[rel.id for rel_list in [sf.stix_relationships for sf in stix_attack_pattern_list] for rel in rel_list],
            #     # Threat Actor
            #     stix_threat_actor.stix_main_object.id,
            #     *[rel.id for rel in stix_threat_actor.stix_relationships],
            #     # Locations
            #     * [sf.stix_main_object.id for sf in stix_threat_actor_location_list]
            # ]

            x = list()
            if stix_file_list:
                [x.extend(ob.stix_objects) for ob in stix_file_list]
            if stix_domain_list:
                [x.extend(ob.stix_objects) for ob in stix_domain_list]
            if stix_url_list:
                [x.extend(ob.stix_objects) for ob in stix_url_list]
            if stix_ip_list:
                [x.extend(ob.stix_objects) for ob in stix_ip_list]
            if stix_attack_pattern_list:
                [x.extend(ob.stix_objects) for ob in stix_attack_pattern_list]
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]

            # TODO:
            #   - dates parser should be added to objects (report)          ++
            #   - add types/labels to mapping.json:                         ++
            #       - "data_label": "threat_actor"                          ++
            #       - "data_type": "nation-state"                           ++
            #   - add "targets" countries for TA along with "located-at"    ++
            #   - add URL, Domain stix objects                              ++
            #   - remove URL as IP or domains as IP                         ++
            #   - check COUNTRIES                                           --
            #   - extend suspicious_ip collections with attributed data     --
            #   - add phishing, deface collections                          --
            #   - finalize README.md                                        ++
            #   - bug with relationship "uses" for TA vulnerability         --
            #   - add valid_from, valid_until to Indicator (file, network)  --
            #   - add apply_hunting_rules=1 and tailored tag                --
            #   - hash error                                                ++
            #     388996fdb916fcOef12677531d8f2e0a
            #     "Invalid value for Indicator 'pattern': FAIL: '388996fdb916fcOef12677531d8f2e0a' is not a valid MD5 hash", "exc_info": "Traceback (most recent call last):\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/src/lib/external_import.py\", line 169, in run\n    bundle_objects = self._collect_intelligence(collection, parsed_portion, MITRE_MAPPER)\n                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/src/main.py\", line 110, in _collect_intelligence\n    stix_file_list = report_adapter.generate_stix_file(\n                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/src/adapter.py\", line 288, in generate_stix_file\n    file.generate_stix_objects()\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/src/data_to_stix2.py\", line 225, in generate_stix_objects\n    self.stix_indicator = self._generate_indicator()\n                          ^^^^^^^^^^^^^^^^^^^^^^^^^^\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/src/data_to_stix2.py\", line 333, in _generate_indicator\n    return [\n           ^\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/src/data_to_stix2.py\", line 334, in <listcomp>\n    stix2.Indicator(\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/venv/lib/python3.11/site-packages/stix2/v21/sdo.py\", line 250, in __init__\n    super(Indicator, self).__init__(*args, **kwargs)\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/venv/lib/python3.11/site-packages/stix2/base.py\", line 232, in __init__\n    self._check_object_constraints()\n  File \"/home/hack/PycharmProjects/Integrations/OpenCTI/connectors/external-import/group-ib/venv/lib/python3.11/site-packages/stix2/v21/sdo.py\", line 270, in _check_object_constraints\n    raise InvalidValueError(self.__class__, 'pattern', str(errors[0]))\nstix2.exceptions.InvalidValueError: Invalid value for Indicator 'pattern': FAIL: 'p' is not a valid MD5 hash"}

            stix_report = report_adapter.generate_stix_report(
                obj=json_threat_report_obj,
                json_date_obj=json_date_obj,
                report_related_objects_ids=[_.id for _ in x],
                json_malware_report_obj=json_malware_report_obj,
                json_threat_actor_obj=json_threat_actor_obj,
            )

            self.helper.log_debug("Pack objects")

            if stix_report:
                x += stix_report.stix_objects
                x += [stix_report.author]
                x += [stix_report.tlp]

            stix_objects += x

        # ++
        if collection in ["apt/threat_actor", "hi/threat_actor"]:

            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                    json_date_obj=json_date_obj,
                )
            )

            x = list()
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]

            stix_objects += x

        # ++
        if collection in ["attacks/ddos"]:

            json_network_obj = event.get("network", {})
            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                )
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[],
                    domain_is_ioc=False,
                    url_is_ioc=False,
                    ip_is_ioc=False,
                )
            )

            x = list()
            if stix_domain_list:
                [x.extend(ob.stix_objects) for ob in stix_domain_list]
            if stix_url_list:
                [x.extend(ob.stix_objects) for ob in stix_url_list]
            if stix_ip_list:
                [x.extend(ob.stix_objects) for ob in stix_ip_list]
            if stix_attack_pattern_list:
                [x.extend(ob.stix_objects) for ob in stix_attack_pattern_list]
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]

            stix_objects += x

        # ++
        if collection in ["attacks/deface"]:

            json_network_obj = event.get("network", {})
            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                )
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[],
                    domain_is_ioc=False,
                    url_is_ioc=False,
                    ip_is_ioc=False,
                )
            )

            x = list()
            if stix_domain_list:
                [x.extend(ob.stix_objects) for ob in stix_domain_list]
            if stix_url_list:
                [x.extend(ob.stix_objects) for ob in stix_url_list]
            if stix_ip_list:
                [x.extend(ob.stix_objects) for ob in stix_ip_list]
            if stix_attack_pattern_list:
                [x.extend(ob.stix_objects) for ob in stix_attack_pattern_list]
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]

            stix_objects += x

        # ++
        if collection in ["attacks/phishing_group"]:

            json_network_obj = event.get("network", {})
            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                )
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[],
                    domain_is_ioc=False,
                    url_is_ioc=False,
                    ip_is_ioc=False,
                )
            )

            x = list()
            if stix_domain_list:
                [x.extend(ob.stix_objects) for ob in stix_domain_list]
            if stix_url_list:
                [x.extend(ob.stix_objects) for ob in stix_url_list]
            if stix_ip_list:
                [x.extend(ob.stix_objects) for ob in stix_ip_list]
            if stix_attack_pattern_list:
                [x.extend(ob.stix_objects) for ob in stix_attack_pattern_list]
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]

            stix_objects += x

        # ++
        if collection in ["attacks/phishing_kit"]:

            json_file_obj = event.get("file", {})
            json_network_obj = event.get("network", {})
            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                )
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[],
                    domain_is_ioc=False,
                    url_is_ioc=False,
                    ip_is_ioc=False,
                )
            )
            stix_file_list = report_adapter.generate_stix_file(
                obj=json_file_obj, related_objects=[stix_threat_actor], is_ioc=False
            )

            x = list()
            if stix_file_list:
                [x.extend(ob.stix_objects) for ob in stix_file_list]
            if stix_domain_list:
                [x.extend(ob.stix_objects) for ob in stix_domain_list]
            if stix_url_list:
                [x.extend(ob.stix_objects) for ob in stix_url_list]
            if stix_ip_list:
                [x.extend(ob.stix_objects) for ob in stix_ip_list]
            if stix_attack_pattern_list:
                [x.extend(ob.stix_objects) for ob in stix_attack_pattern_list]
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]

            stix_objects += x

        # ++
        if collection in ["malware/malware"]:

            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj, json_date_obj=json_date_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                    json_date_obj=json_date_obj,
                )
            )

            x = list()
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]

            stix_objects += x

        # ++
        if collection in ["malware/signature"]:

            json_yara_obj = event.get("yara_report", {})
            json_suricata_obj = event.get("suricata_report", {})
            json_network_obj = event.get("network", {})
            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                )
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[],
                    domain_is_ioc=False,
                    url_is_ioc=False,
                    ip_is_ioc=False,
                )
            )
            stix_yara = report_adapter.generate_stix_yara(
                obj=json_yara_obj, json_date_obj=json_date_obj, is_ioc=True
            )
            stix_suricata = report_adapter.generate_stix_suricata(
                obj=json_suricata_obj, json_date_obj=json_date_obj, is_ioc=True
            )

            x = list()
            if stix_domain_list:
                [x.extend(ob.stix_objects) for ob in stix_domain_list]
            if stix_url_list:
                [x.extend(ob.stix_objects) for ob in stix_url_list]
            if stix_ip_list:
                [x.extend(ob.stix_objects) for ob in stix_ip_list]
            if stix_attack_pattern_list:
                [x.extend(ob.stix_objects) for ob in stix_attack_pattern_list]
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]
            if stix_yara:
                x += stix_yara.stix_objects
            if stix_suricata:
                x += stix_suricata.stix_objects

            stix_objects += x

        # ++
        if collection in ["malware/yara"]:

            json_yara_obj = event.get("yara_report", {})
            json_suricata_obj = event.get("suricata_report", {})
            json_network_obj = event.get("network", {})
            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                )
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[],
                    domain_is_ioc=False,
                    url_is_ioc=False,
                    ip_is_ioc=False,
                )
            )
            stix_yara = report_adapter.generate_stix_yara(
                obj=json_yara_obj,
                related_objects=[stix_malware_list],
                json_date_obj=json_date_obj,
                is_ioc=True,
            )
            stix_suricata = report_adapter.generate_stix_suricata(
                obj=json_suricata_obj,
                related_objects=[stix_malware_list],
                json_date_obj=json_date_obj,
                is_ioc=True,
            )

            x = list()
            if stix_domain_list:
                [x.extend(ob.stix_objects) for ob in stix_domain_list]
            if stix_url_list:
                [x.extend(ob.stix_objects) for ob in stix_url_list]
            if stix_ip_list:
                [x.extend(ob.stix_objects) for ob in stix_ip_list]
            if stix_attack_pattern_list:
                [x.extend(ob.stix_objects) for ob in stix_attack_pattern_list]
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]
            if stix_yara:
                x += stix_yara.stix_objects
            if stix_suricata:
                x += stix_suricata.stix_objects

            stix_objects += x

        # ++
        if collection in ["osi/vulnerability"]:

            json_malware_report_obj = event.get("malware_report", {})
            json_threat_actor_obj = event.get("threat_actor", {})
            json_vulnerability_obj = event.get("vulnerability", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_mitre_matrix_obj = event.get("mitre_matrix", {})
            json_cvss_obj = event.get("cvssv3", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_malware_list = report_adapter.generate_stix_malware(
                obj=json_malware_report_obj, json_date_obj=json_date_obj
            )
            stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
                obj=json_mitre_matrix_obj
            )
            stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
                obj=json_vulnerability_obj,
                related_objects=[
                    # stix_threat_actor
                ],
                json_date_obj=json_date_obj,
                json_cvss_obj=json_cvss_obj,
            )
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                    json_date_obj=json_date_obj,
                )
            )

            x = list()
            if stix_malware_list:
                [x.extend(ob.stix_objects) for ob in stix_malware_list]
            if stix_vulnerability_list:
                [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
            if stix_threat_actor:
                x += stix_threat_actor.stix_objects
            if stix_threat_actor_location_list:
                [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]

            stix_objects += x

        # ++
        if collection in [
            "suspicious_ip/open_proxy",
            "suspicious_ip/scanner",
            "suspicious_ip/socks_proxy",
            "suspicious_ip/tor_node",
            "suspicious_ip/vpn",
        ]:

            json_network_obj = event.get("network", {})
            json_evaluation_obj = event.get("evaluation", {})
            json_date_obj = event.get("date", {})

            self.helper.log_debug("Initializing adapter")

            report_adapter = DataToSTIXAdapter(
                mitre_mapper=mitre_mapper,
                collection=collection,
                tlp_color=json_evaluation_obj.get("tlp", "white"),
                helper=self.helper,
                is_ioc=True,
            )

            self.helper.log_debug("Generating STIX objects")

            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[],
                    domain_is_ioc=False,
                    url_is_ioc=False,
                    ip_is_ioc=False,
                )
            )

            x = list()
            if stix_domain_list:
                [x.extend(ob.stix_objects) for ob in stix_domain_list]
            if stix_url_list:
                [x.extend(ob.stix_objects) for ob in stix_url_list]
            if stix_ip_list:
                [x.extend(ob.stix_objects) for ob in stix_ip_list]

            stix_objects += x

        # ===========================
        # === Add your code above ===
        # ===========================

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
