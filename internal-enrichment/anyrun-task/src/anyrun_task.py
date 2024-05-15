import json
import os
import time

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class AnyRunTask:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.token = get_config_variable("ANYRUN_TOKEN", ["anyrun", "token"], config)
        self.anyrun_url = get_config_variable(
            "ANYRUN_API_URL",
            ["anyrun", "url"],
            config,
            default="https://api.any.run",
        )
        self.organization = self.helper.api.identity.create(
            type="Organization",
            name="ANY.RUN",
            description="Interactive Online Malware Sandbox",
            contact_information="https://any.run/",
        )
        self.task_timer = int(
            get_config_variable(
                "ANYRUN_TASK_TIMER", ["anyrun", "timer"], config, default=60
            )
        )
        self.task_os = get_config_variable(
            "ANYRUN_OS", ["anyrun", "os"], config, default="windows"
        )
        self.task_os_bitness = get_config_variable(
            "ANYRUN_OS_BITNESS", ["anyrun", "bitness"], config, default="64"
        )
        self.task_os_version = get_config_variable(
            "ANYRUN_OS_VERSION", ["anyrun", "version"], config, default="10"
        )
        self.task_os_locale = get_config_variable(
            "ANYRUN_OS_LOCALE", ["anyrun", "locale"], config, default="en-US"
        )
        self.task_os_browser = get_config_variable(
            "ANYRUN_OS_BROWSER", ["anyrun", "browser"], config, default="Google Chrome"
        )
        self.task_privacy = get_config_variable(
            "ANYRUN_PRIVACY", ["anyrun", "privacy"], config, default="bylink"
        )
        self.automated_interactivity = get_config_variable(
            "ANYRUN_AUTOMATED_INTERACTIVITY",
            ["anyrun", "automated_interactivity"],
            config,
            default=False,
        )
        self.enable_ioc = get_config_variable(
            "ANYRUN_IOC", ["anyrun", "ioc"], config, default=True
        )
        self.enable_mitre = get_config_variable(
            "ANYRUN_MITRE", ["anyrun", "mitre"], config, default=False
        )
        self.enable_processes = get_config_variable(
            "ANYRUN_PROCESSES", ["anyrun", "processes"], config, default=False
        )
        self.iocs_types_mapping = {
            "domain": "Domain-Name",
            "url": "Url",
            "ip": "IPv4-Addr",
        }

    def call_anyrun_api(self, method, uri, data=None, file=None):
        if data is None:
            data = {}
        url = "{}/{}".format(self.anyrun_url, uri)
        if method == "POST":
            response = requests.post(
                url,
                data=data,
                headers={"Authorization": "API-Key {}".format(self.token)},
                files={"file": file},
            )
        elif method == "GET":
            response = requests.get(
                url, headers={"Authorization": "API-Key {}".format(self.token)}
            )
        # if response.status_code != 200:
        #     raise ValueError("Any.RUN api code {}. text: {}".format(response.status_code,
        #                                                             response.text))
        return response

    def run_task(self, type, data, file=None):
        """

        :param file: bytes file content
        :param data: dict
        :param type: str: 'url' or 'file'
        :return: int: task id
        """
        rdata = {
            "env_os": self.task_os,
            "env_bitness": self.task_os_bitness,
            "env_locale": self.task_os_locale,
            "env_version": self.task_os_version,
            "obj_url": data.get("value"),
            "obj_type": type,
            "opt_network_connect": "true",
            "obj_ext_browser": self.task_os_browser,
            "opt_timeout": self.task_timer,
            "opt_automated_interactivity": self.automated_interactivity,
            "opt_privacy_type": self.task_privacy,
        }

        response = self.call_anyrun_api("POST", "v1/analysis", rdata, file)
        # self.helper.log_error(str(response.text))
        json_data = json.loads(response.text)
        return json_data

    def wait_for_task(self, task_id, timer=300):
        num = 0
        self.helper.log_info(
            "ANY.RUN Waiting {} seconds for task {}".format(timer, task_id)
        )
        while True:
            time.sleep(1)
            num += 1
            response = self.call_anyrun_api("GET", "v1/analysis/{}".format(task_id))
            try:
                result = json.loads(response.text)
                if result["data"]["status"] == "done":
                    self.helper.log_info("ANY.RUN task {} completed".format(task_id))
                    return result
            except:
                continue
            finally:
                if num == timer:
                    raise ValueError("ANY.RUN task waiting timeout")

    def _process_message(self, data):
        self.helper.log_debug(str(data))
        opencti_entity = self.helper.api.stix_cyber_observable.read(
            id=data["entity_id"], withFiles=True
        )
        if opencti_entity is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, check the group of the connector user)"
            )

        self.helper.log_debug(str(opencti_entity))

        if opencti_entity["entity_type"] == "Artifact":
            artifact_url = f'{self.helper.opencti_url}/storage/get/{opencti_entity["importFiles"][0]["id"]}'
            try:
                artifact = self.helper.api.fetch_opencti_file(artifact_url, binary=True)
            except Exception as err:
                raise ValueError("Error fetching artifact from OpenCTI") from err

            task = self.run_task("file", data={}, file=artifact)

        elif opencti_entity["entity_type"] == "Url":
            task = self.run_task("url", {"value": opencti_entity["value"]})
        else:
            raise ValueError(
                'Wrong scope! supported only "Artifact" and "Url" observables types'
            )

        if task.get("error", False):
            error_message = task.get("message", "Unknown error")
            raise ValueError(error_message)
        else:
            self.helper.log_info(
                "ANY.RUN task started url: https://app.any.run/tasks/{}".format(
                    task["data"]["taskid"]
                )
            )
            # Create external reference to ANY.RUN task
            external_reference_task = self.helper.api.external_reference.create(
                source_name="ANY.RUN task {}".format(task["data"]["taskid"]),
                url="https://app.any.run/tasks/{}".format(task["data"]["taskid"]),
            )
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=opencti_entity["id"],
                external_reference_id=external_reference_task["id"],
            )

            result = self.wait_for_task(
                task["data"]["taskid"], timer=self.task_timer + 20
            )
            # self.helper.log_info(result)

            # Add labels from ANY.RUN task result
            for tag in result["data"]["analysis"]["tags"]:
                label = self.helper.api.label.create(
                    value=tag["tag"],
                    # color="#ffa500",
                )
                self.helper.api.stix_cyber_observable.add_label(
                    id=opencti_entity["id"], label_id=label["id"]
                )
            # Add score
            anyrun_score = result["data"]["analysis"]["scores"]["verdict"]["score"]
            opencti_score = opencti_entity.get("x_opencti_score", anyrun_score)
            if opencti_score is None:
                opencti_score = 0
            if anyrun_score < opencti_score:
                note = self.helper.api.note.create(
                    authors=[self.organization["id"]],
                    content="ANY.RUN score: {}".format(str(anyrun_score)),
                )
                self.helper.api.note.add_stix_object_or_stix_relationship(
                    id=note["id"], stixObjectOrStixRelationshipId=opencti_entity["id"]
                )
            else:
                self.helper.api.stix_cyber_observable.update_field(
                    id=opencti_entity["id"],
                    input={"key": "x_opencti_score", "value": str(anyrun_score)},
                )

            # Add mitre relationship
            if self.enable_mitre:
                for pattern_anyrun in result["data"]["mitre"]:
                    patterns_opencti = self.helper.api.attack_pattern.list(
                        search=pattern_anyrun["id"]
                    )
                    for pattern_opencti in patterns_opencti:
                        if pattern_opencti["x_mitre_id"] == pattern_anyrun["id"]:
                            self.helper.api.stix_core_relationship.create(
                                toId=pattern_opencti["id"],
                                fromId=opencti_entity["id"],
                                confidence=90,
                                createdBy=self.organization["id"],
                                relationship_type="related-to",
                                description="Attack pattern",
                            )

            # add malicious iocs
            if self.enable_ioc:
                response = self.call_anyrun_api(
                    "GET", "report/{}/ioc/json".format(task["data"]["taskid"])
                )
                iocs = json.loads(response.text)
                for ioc in iocs:
                    if self.iocs_types_mapping.get(ioc["type"]) is None:
                        self.helper.log_warning(
                            "Indicator type {} is not supported. value ({})".format(
                                ioc["type"], str(ioc)
                            )
                        )
                        continue
                    if ioc["reputation"] == 2:
                        new_observable = self.helper.api.stix_cyber_observable.create(
                            observableData={
                                "type": self.iocs_types_mapping.get(ioc["type"]),
                                "value": ioc["ioc"],
                            },
                            createIndicator=True,
                            createdBy=self.organization["id"],
                            update=True,
                        )
                        if new_observable["id"] != opencti_entity["id"]:
                            self.helper.api.stix_core_relationship.create(
                                toId=new_observable["id"],
                                fromId=opencti_entity["id"],
                                confidence=90,
                                createdBy=self.organization["id"],
                                relationship_type="related-to",
                                description=ioc["category"],
                            )
                        indicator = self.helper.api.indicator.create(
                            name=ioc["ioc"],
                            description=ioc["category"],
                            pattern_type="stix",
                            pattern="[{}:value = '{}']".format(
                                self.iocs_types_mapping[ioc["type"]].lower(), ioc["ioc"]
                            ),
                            x_opencti_main_observable_type=self.iocs_types_mapping[
                                ioc["type"]
                            ],
                            x_opencti_score=opencti_score,
                            update=True,
                            x_mitre_platforms=[
                                get_config_variable(
                                    "ANYRUN_OS", ["anyrun", "os"], {}, default="windows"
                                )
                            ],
                            createdBy=self.organization["id"],
                        )

                        if new_observable["id"] != opencti_entity["id"]:
                            self.helper.api.indicator.add_stix_cyber_observable(
                                id=indicator["id"],
                                # indicator=indicator,
                                stix_cyber_observable_id=opencti_entity["id"],
                            )
                        else:
                            self.helper.api.indicator.add_stix_cyber_observable(
                                id=indicator["id"],
                                # indicator=indicator,
                                stix_cyber_observable_id=new_observable["id"],
                            )

            # add malicious processes
            if self.enable_processes:
                procs_links = []
                for proc in result["data"]["processes"]:
                    if (
                        proc["scores"]["verdict"]["score"] > 0
                        and proc["important"] is True
                    ):
                        # self.helper.log_error(str(proc))
                        process = self.helper.api.stix_cyber_observable.create(
                            observableData={
                                "type": "Process",
                                "x_opencti_description": proc["scores"]["verdict"][
                                    "threatLevelText"
                                ],
                                "cwd": proc["fileName"],
                                "pid": proc["pid"],
                                "command_line": proc["commandLine"],
                                "x_opencti_score": proc["scores"]["verdict"]["score"],
                                "value": proc["commandLine"],
                            },
                            createdBy=self.organization["id"],
                            update=True,
                        )
                        if proc.get("threatName") is not None:
                            label = self.helper.api.label.create(
                                value=proc["threatName"],
                                # color="#ffa500",
                            )
                            self.helper.api.stix_cyber_observable.add_label(
                                id=process["id"], label_id=label["id"]
                            )
                        self.helper.api.stix_core_relationship.create(
                            toId=opencti_entity["id"],
                            fromId=process["id"],
                            confidence=90,
                            createdBy=self.organization["id"],
                            relationship_type="related-to",
                            description="Relation between the Main object and Process objects",
                        )

                        procs_links.append(
                            {
                                "pid": proc["pid"],
                                "ppid": proc["ppid"],
                                "observable_id": process["id"],
                            }
                        )

                for proc_main in procs_links:
                    for proc_child in procs_links:
                        if proc_child["ppid"] == proc_main["pid"]:
                            self.helper.api.stix_core_relationship.create(
                                toId=proc_main["observable_id"],
                                fromId=proc_child["observable_id"],
                                confidence=90,
                                createdBy=self.organization["id"],
                                relationship_type="related-to",
                                description="Relation between child and parent process",
                            )

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    anyruntask = AnyRunTask()
    anyruntask.start()
