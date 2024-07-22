import os
import sys
import time
import traceback
from datetime import datetime, timedelta
from typing import List

import stix2
import yaml
from pycti import (
    Identity,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from rstcloud import (
    FeedDownloader,
    FeedType,
    ThreatTypes,
    feed_converter,
    read_state,
    write_state,
)


class RSTThreatFeed:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.safe_load(open(config_file_path))
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.interval = self.get_config("interval", config, 86400)
        self._downloader_config = {
            "baseurl": self.get_config(
                "baseurl", config, "https://api.rstcloud.net/v1/"
            ),
            "apikey": self.get_config("apikey", config, None),
            "contimeout": int(self.get_config("contimeout", config, 30)),
            "readtimeout": int(self.get_config("readtimeout", config, 60)),
            "retry": int(self.get_config("retry", config, 5)),
            "delete_gz": True,
            "feeds": {"filetype": "json"},
            "dirs": {"tmp": self.get_config("dirs_tmp", config, "/tmp")},
        }
        self._state_dir = self.get_config("dirs_tmp", config, "/tmp")
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self._min_score_import = int(self.get_config("min_score_import", config, 20))
        self._min_score_detection = {
            "IPv4-Addr": self.get_config(
                "min_score_detection_ip",
                config,
                50,
            ),
            "Domain-Name": self.get_config(
                "min_score_detection_domain",
                config,
                45,
            ),
            "Url": self.get_config(
                "min_score_detection_url",
                config,
                30,
            ),
            "StixFile": self.get_config(
                "min_score_detection_hash",
                config,
                25,
            ),
        }
        self._only_new = bool(self.get_config("only_new", config, True))
        self._only_attributed = bool(self.get_config("only_attributed", config, True))

    @staticmethod
    def get_config(name: str, config, default=None):
        env_name = "RST_THREAT_FEED_{}".format(name.upper())
        result = get_config_variable(env_name, ["rst-threat-feed", name], config)
        if result is not None:
            return result
        else:
            return default

    def get_interval(self) -> int:
        return int(self.interval)

    def run(self):
        self.helper.log_info("Starting RST Threat Feed connector")

        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    last_run_str = datetime.utcfromtimestamp(last_run).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    self.helper.log_info(
                        "Connector's last run: {}".format(last_run_str)
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector's first run")

                if last_run is None or ((timestamp - last_run) > self.get_interval()):
                    self._process_feed(FeedType.IP)
                    self._process_feed(FeedType.DOMAIN)
                    self._process_feed(FeedType.URL)
                    self._process_feed(FeedType.HASH)
                    self.helper.set_state({"last_run": timestamp})
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run. Next run in: {} seconds.".format(
                            round(new_interval, 2)
                        )
                    )
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stopped")
                sys.exit(0)
            except Exception as ex:
                self.helper.log_error(str(ex))
                raise ex

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stopped")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)

    def _process_feed(self, feed_type):
        state = read_state(self._state_dir, feed_type)
        downloader = FeedDownloader(self._downloader_config, state, feed_type)
        downloader.set_current_day()
        downloader.init_connection()
        new_state = downloader.download_feed()

        if downloader.already_processed:
            return

        stix_bundle = self._create_stix_bundle(new_state, feed_type)
        self._batch_send(stix_bundle, feed_type)

        write_state(self._state_dir, feed_type, new_state)

    def _create_stix_bundle(self, new_state, feed_type):
        self.helper.log_info("Parsing IOCs from Feed. State {}".format(new_state))

        iocs, threats, mapping = feed_converter(
            self._downloader_config["dirs"]["tmp"],
            new_state,
            feed_type,
            self._min_score_import,
            self._only_new,
            self._only_attributed,
        )

        self.helper.log_info(
            "Parsed IOCs: {}, Threats: {}, Mappings: {}".format(
                len(iocs), len(threats), len(mapping)
            )
        )

        stix_bundle = list()
        organization = stix2.v21.Identity(
            id=Identity.generate_id("RST Cloud", "organization"),
            name="RST Cloud",
            identity_class="organization",
            description="Threat Intelligence Company https://www.rstcloud.com",
        )
        stix_bundle.append(organization)

        self.helper.log_info("Converting {} IOCs to STIX objects".format(len(iocs)))
        for ioc_id, ioc in iocs.items():
            external_references = list()
            for i in ioc["src"]:
                external_references.append(
                    stix2.v21.ExternalReference(source_name=i["name"], url=i["url"])
                )
            x_opencti_detection = False
            try:
                if int(ioc["score"]) > int(
                    self._min_score_detection[ioc["observable_type"]]
                ):
                    x_opencti_detection = True
            except:
                self.helper.log_info(
                    "Error while checking x_opencti_detection for {} IOCs to STIX objects".format(
                        ioc["name"]
                    )
                )
            # indicator
            indicator = stix2.v21.Indicator(
                id=ioc_id,
                name=ioc["name"],
                description=ioc["descr"],
                labels=ioc["tags"] + ioc["threats"],
                pattern_type="stix",
                pattern=ioc["pattern"],
                valid_from=ioc["lseen"],
                created=ioc["fseen"],
                modified=ioc["collect"],
                created_by_ref=organization.id,
                object_marking_refs=[stix2.TLP_WHITE],
                confidence=int(ioc["score"]),
                external_references=external_references,
                custom_properties={
                    "x_opencti_score": ioc["score"],
                    "x_opencti_main_observable_type": ioc["observable_type"],
                    "x_opencti_detection": x_opencti_detection,
                },
            )
            stix_bundle.append(indicator)

        self.helper.log_info(
            "Converting {} Threats to STIX objects".format(len(threats))
        )
        for threat_key, threat in threats.items():
            external_references = list()
            for source_name, source_url in threat["src"].items():
                external_references.append(
                    stix2.v21.ExternalReference(source_name=source_name, url=source_url)
                )

            malicious_object = None
            isfamily = True if "/" not in threat["name"] else False
            if threat["type"] == ThreatTypes.MALWARE:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    description="{} malware".format(threat["name"]),
                    created_by_ref=organization.id,
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.RANSOMWARE:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    description="{} ransomware".format(threat["name"]),
                    created_by_ref=organization.id,
                    malware_types=["ransomware"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.BACKDOOR:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    description="{} backdoor".format(threat["name"]),
                    created_by_ref=organization.id,
                    malware_types=["backdoor"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.RAT:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    description="{} remote access trojan".format(threat["name"]),
                    created_by_ref=organization.id,
                    malware_types=["remote-access-trojan"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.EXPLOIT:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    description="{} exploit".format(threat["name"]),
                    created_by_ref=organization.id,
                    malware_types=["exploit-kit"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.CRYPTOMINER:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    description="{} cryptominer".format(threat["name"]),
                    created_by_ref=organization.id,
                    malware_types=["resource-exploitation"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.GROUP:
                malicious_object = stix2.v21.IntrusionSet(
                    id=threat_key,
                    name=threat["name"],
                    description="{} group".format(threat["name"]),
                    created_by_ref=organization.id,
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.CAMPAIGN:
                malicious_object = stix2.v21.Campaign(
                    id=threat_key,
                    name=threat["name"],
                    description="{} campaign".format(threat["name"]),
                    created_by_ref=organization.id,
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.TOOL:
                malicious_object = stix2.v21.Tool(
                    id=threat_key,
                    name=threat["name"],
                    description="{} tool".format(threat["name"]),
                    created_by_ref=organization.id,
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.VULNERABILITY:
                malicious_object = stix2.v21.Vulnerability(
                    id=threat_key,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    external_references=[
                        stix2.v21.ExternalReference(
                            source_name=threat["name"],
                            url="https://www.cve.org/CVERecord?id=" + threat["name"],
                        )
                    ],
                )
            if malicious_object:
                stix_bundle.append(malicious_object)

        self.helper.log_info(
            "Converting {} Relations to STIX objects".format(len(mapping))
        )
        for m in mapping:
            indicator_id = m[0]
            threat_id = m[1]
            fseen = m[2]
            collect = m[3]
            refs = m[4]

            external_references = list()
            for i in refs:
                external_references.append(
                    stix2.v21.ExternalReference(source_name=i["name"], url=i["url"])
                )
            relationshipType = "indicates"
            if threats[threat_id]["type"] == "sector":
                relationshipType = "related-to"
            if fseen > collect + timedelta(0, 3):
                self.helper.log_error(
                    f"stop_time {collect} must be later than start_time {fseen}. Fixing"
                )
                fseen = collect
            relation = stix2.v21.Relationship(
                id=StixCoreRelationship.generate_id(
                    relationshipType, indicator_id, threat_id, collect, collect
                ),
                source_ref=indicator_id,
                target_ref=threat_id,
                relationship_type=relationshipType,
                start_time=fseen,
                stop_time=collect + timedelta(0, 3),
                description="IOC associated with: {}".format(
                    threats[threat_id]["name"]
                ),
                created_by_ref=organization.id,
                object_marking_refs=[stix2.TLP_WHITE],
                created=collect,
                modified=collect,
                external_references=external_references,
                allow_custom=True,
            )

            stix_bundle.append(relation)

        return stix_bundle

    def _batch_send(self, stix_bundle: List, feed_type: str):
        timestamp = int(time.time())
        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = "Run for {} @ {}".format(
            feed_type, now.strftime("%Y-%m-%d %H:%M:%S")
        )

        self.helper.log_debug(
            "Start uploading of the objects: {}".format(len(stix_bundle))
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        bundle = stix2.v21.Bundle(objects=stix_bundle, allow_custom=True)
        self.helper.send_stix2_bundle(
            bundle=bundle.serialize(),
            update=self.update_existing_data,
            work_id=work_id,
        )
        # Finish the work
        self.helper.log_info(
            f"Connector ran successfully, saving last_run as {str(timestamp)}"
        )
        message = f"Last_run stored, next run in: {str(self.get_interval())} seconds"
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_debug("End of the batch upload")


if __name__ == "__main__":
    try:
        connector = RSTThreatFeed()
        connector.run()
    except Exception as ex:
        print(str(ex))
        traceback.print_tb(ex.__traceback__)
        time.sleep(10)
        sys.exit(0)
