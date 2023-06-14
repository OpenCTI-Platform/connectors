import os
import random
import re
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Optional

import requests
import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

__version__ = "0.0.1"
BANNER = f"""

▄▄▄█████▓ █     █░▓█████ ▓█████▄▄▄█████▓  █████▒▓█████ ▓█████ ▓█████▄ 
▓  ██▒ ▓▒▓█░ █ ░█░▓█   ▀ ▓█   ▀▓  ██▒ ▓▒▓██   ▒ ▓█   ▀ ▓█   ▀ ▒██▀ ██▌
▒ ▓██░ ▒░▒█░ █ ░█ ▒███   ▒███  ▒ ▓██░ ▒░▒████ ░ ▒███   ▒███   ░██   █▌
░ ▓██▓ ░ ░█░ █ ░█ ▒▓█  ▄ ▒▓█  ▄░ ▓██▓ ░ ░▓█▒  ░ ▒▓█  ▄ ▒▓█  ▄ ░▓█▄   ▌
  ▒██▒ ░ ░░██▒██▓ ░▒████▒░▒████▒ ▒██▒ ░ ░▒█░    ░▒████▒░▒████▒░▒████▓ 
  ▒ ░░   ░ ▓░▒ ▒  ░░ ▒░ ░░░ ▒░ ░ ▒ ░░    ▒ ░    ░░ ▒░ ░░░ ▒░ ░ ▒▒▓  ▒ 
    ░      ▒ ░ ░   ░ ░  ░ ░ ░  ░   ░     ░       ░ ░  ░ ░ ░  ░ ░ ▒  ▒ 
  ░        ░   ░     ░      ░    ░       ░ ░       ░      ░    ░ ░  ░ 
             ░       ░  ░   ░  ░                   ░  ░   ░  ░   ░    
                                                               ░       
\n
\n
                              TWEETFeed importer, version {__version__}
"""

# create a class for the IOC
class TweetFeed:
    @staticmethod
    def _validate_ipv4(ipv4):
        ipv4validator = re.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        return ipv4validator.match(ipv4)

    @staticmethod
    def _validate_domain(domain):
        domainvalidator = re.compile(
            "^((?!-))(xn\-\-)?[a-z0-9][a-z0-9\-_]{0,61}[a-z0-9]{0,1}(\.(xn\-\-)?([a-z0-9\-]{1,61}|[a-z0-9\-]{1,30}\.[a-z]{2,}))+$"
        )
        return domainvalidator.match(domain)

    @staticmethod
    def _validate_urls(domain):
        urlvalidator = re.compile(
            "^((http|https):\/\/)[a-zA-Z0-9@:%._\+\-~#?&=\(\)]{1,256}\.[a-z]{2,6}(\/([a-zA-Z0-9@:%._\-\\+~#?&//=\(\)]*))?$"
        )
        return urlvalidator.match(domain)

    @staticmethod
    def _validate_sha256(domain):
        sha256validator = re.compile("^[a-fA-F0-9]{64}$")
        return sha256validator.match(domain)

    @staticmethod
    def _validate_md5(domain):
        md5validator = re.compile("^[a-fA-F0-9]{32}$")
        return md5validator.match(domain)

    @staticmethod
    def _generate_path(date):
        dateyear = date[0:4]
        datemonth = date[4:6]
        dateday = date[6:8]
        now = datetime.now()
        string_path = "{}{}/{}{}{}.csv".format(
            dateyear, datemonth, dateyear, datemonth, dateday
        )
        current_date = now.strftime("%Y%m%d")
        if current_date == string_path:
            return "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv"
        else:
            return "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/{}".format(
                string_path
            )

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def __init__(self):
        print(BANNER)
        self.session = requests.session()
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.tweetfeed_interval = get_config_variable(
            "TWEETFEED_INTERVAL", ["tweetfeed", "interval"], config, True
        )
        self.create_indicators = get_config_variable(
            "TWEETFEED_CREATE_INDICATORS",
            ["tweetfeed", "create_indicators"],
            config,
            False,
            True,
        )
        self.create_observables = get_config_variable(
            "TWEETFEED_CREATE_OBSERVABLES",
            ["tweetfeed", "create_observables"],
            config,
            False,
            True,
        )
        self.update = get_config_variable(
            "TWEETFEED_UPDATE",
            ["tweetfeed", "update_existing_data"],
            config,
            False,
            True,
        )
        self.org_name = get_config_variable(
            "TWEETFEED_ORG_NAME", ["tweetfeed", "org_name"], config, False, False
        )
        self.org_desc = get_config_variable(
            "TWEETFEED_ORG_NAME", ["tweetfeed", "org_description"], config, False, False
        )
        external_reference_org = self.helper.api.external_reference.create(
            source_name="TWEETFEEED",
            url="https://tweetfeed.live/",
        )
        self.organization = self.helper.api.identity.create(
            type="Organization",
            name=self.org_name,
            description=self.org_desc,
            externalReferences=[external_reference_org["id"]],
            contact_information="'TWITTER: https://twitter.com/0xDanielLopez'",
            update=True,
        )
        self.update_existing_data = get_config_variable(
            "TWEETFEED_UPDATE_EXISTING_DATA",
            ["tweetfeed", "update_existing_data"],
            config,
            False,
            True,
        )
        self.score = get_config_variable(
            "TWEETFEED_CONFIDENCE_LEVEL",
            ["tweetfeed", "confidence_level"],
            config,
            True,
            25,
        )
        self.data = {}

    def create_label(self, label_name):
        color = "%06x" % random.randint(0, 0xFFFFFF)
        self.helper.api.label.create(value=label_name, color=color)

    def load_state(self) -> Dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    def is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.info("Connector first run")
            return True
        time_diff = current_time - last_run
        return time_diff >= self.get_interval()

    def info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def get_interval(self):
        return int(self.tweetfeed_interval) * 60 * 60 * 24

    def retrieve_data(self):
        self.helper.log_info("Fetching data...")
        while True:

            try:

                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "TWEETFEED run @ " + now.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                )
                self.workid = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    last_run_datetime = datetime.utcfromtimestamp(last_run)
                    self.helper.log_info(
                        "Connector last run: "
                        + last_run_datetime.strftime("%Y-%m-%d %H:%M:%S")
                    )
                else:
                    last_run = None
                    last_run_datetime = datetime.today()
                    self.helper.log_info("Connector has never run")
                last_run_datetime = last_run_datetime + timedelta(days=-1)

                if last_run is None or (
                    (timestamp - last_run)
                    > ((int(self.tweetfeed_interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    datetimex = datetime.utcfromtimestamp(timestamp).strftime(
                        "%Y-%m-%dT%H:%M:%S.000Z"
                    )
                    self.data = {
                        "Date": datetimex,
                    }
                    self.process_ioc_per_date(last_run_datetime)
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                sys.exit(0)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)
            time.sleep(60)

    def download_ioc_file(self, url):
        # download the file
        result = ""
        try:
            r = self.session.get(url)
            result = r.content
        except Exception:
            pass
        return result

    def process_line(self, network):

        _observable = None
        _indicator = None
        _network = {
            "author": network[1],
            "type": network[2],
            "value": network[3],
            "tags": network[4],
            "url": network[5],
        }
        external_reference = self.helper.api.external_reference.create(
            source_name="TWEETFEED: Twitter",
            url=_network["url"],
        )

        tags = []
        if self.create_observables:
            _observable = self.create_observables_i(_network, external_reference)
            tags = self.process_tags(_observable, _network["tags"])
        if self.create_indicators:
            _indicator = self.create_indicators_i(_network, external_reference, tags)

        if _observable and _indicator:
            self.helper.api.stix_core_relationship.create(
                fromId=_indicator["id"],
                toId=_observable["id"],
                relationship_type="based-on",
                createdBy=self.organization["id"],
                external_references=[external_reference["id"]],
            )

    def create_observables_i(self, observable, external_reference):
        _observable = None
        type_observable = ""
        if observable["type"] == "domain":
            type_observable = "Domain-Name.value"
        elif observable["type"] == "ip":
            type_observable = "IPv4-Addr.value"
        elif observable["type"] == "url":
            type_observable = "Url.value"
        elif observable["type"] == "sha256":
            type_observable = "file.hashes.sha-256"
        elif observable["type"] == "md5":
            type_observable = "file.hashes.md5"

        if self.create_observables:
            _observable = self.helper.api.stix_cyber_observable.create(
                simple_observable_key=f"{type_observable}",
                simple_observable_value=observable["value"],
                simple_observable_description="TWEETFEED IOC " + observable["value"],
                objectMarking=[stix2.TLP_GREEN["id"]],
                externalReferences=[external_reference["id"]],
                createdBy=self.organization["id"],
                update=self.update,
                x_opencti_score=self.score,
            )
        return _observable

    def create_indicators_i(self, ioc, external_reference, tags):

        indicator = None
        type_ioc = ""
        if ioc["type"] == "domain":
            type_ioc = "Domain-Name:value"
        elif ioc["type"] == "ip":
            type_ioc = "IPv4-Addr:value"
        elif ioc["type"] == "url":
            type_ioc = "Url:value"
        elif ioc["type"] == "sha256":
            type_ioc = "File:hashes.'SHA-256'"
        elif ioc["type"] == "md5":
            type_ioc = "File:hashes.'MD5'"

        if self.create_indicators:
            if ioc["tags"][0] and ioc["tags"][0] != "":
                indicator = self.helper.api.indicator.create(
                    name=ioc["value"],
                    description="TWEETFEED IOC " + ioc["value"],
                    pattern_type="stix2",
                    pattern=f"[{type_ioc.lower()} = '" + ioc["value"] + "']",
                    x_opencti_main_observable_type=type_ioc.split(":")[0],
                    objectMarking=[stix2.TLP_GREEN["id"]],
                    objectLabel=tags,
                    value=ioc["value"],
                    valid_from=self.data["Date"],
                    createdBy=self.organization["id"],
                    externalReferences=[external_reference["id"]],
                    update=self.update,
                    indicator_types=["malicious-activity"],
                    x_opencti_score=self.score,
                )
            else:
                indicator = self.helper.api.indicator.create(
                    name=ioc["value"],
                    description="TWEETFEED IOC " + ioc["value"],
                    pattern_type="stix2",
                    pattern=f"[{type_ioc.lower()} = '" + ioc["value"] + "']",
                    x_opencti_main_observable_type=type_ioc.split(":")[0],
                    objectMarking=[stix2.TLP_GREEN["id"]],
                    value=ioc["value"],
                    valid_from=self.data["Date"],
                    createdBy=self.organization["id"],
                    externalReferences=[external_reference["id"]],
                    update=self.update,
                    indicator_types=["malicious-activity"],
                    x_opencti_score=self.score,
                )
        return indicator

    def process_tags(self, observable, tags):
        taggs = []
        for taglabel in tags:
            if taglabel is not None and taglabel != "":
                if taglabel[0].isupper():

                    malwsearc = self.helper.api.malware.read(
                        filters={"key": "name", "values": [taglabel.lower().strip()]}
                    )
                    if malwsearc:
                        if (
                            malwsearc["name"].lower().strip()
                            == taglabel.lower().strip().replace(" ", "")
                            or malwsearc["name"].lower().strip() == taglabel.lower()
                        ):
                            ### create relation and continue indicates
                            self.helper.api.stix_core_relationship.create(
                                fromId=observable["id"],
                                toId=malwsearc["id"],
                                relationship_type="related-to",
                                created_by_ref=self.organization["standard_id"],
                            )

                    ## second search for intrusion set like APT
                    intrusion = self.helper.api.intrusion_set.read(
                        filters={"key": "name", "values": [taglabel.lower().strip()]}
                    )
                    if intrusion:
                        if intrusion[
                            "name"
                        ].lower().strip() == taglabel.lower().strip() or intrusion[
                            "name"
                        ].lower().strip() == taglabel.lower().strip().replace(
                            " ", ""
                        ):
                            self.helper.api.stix_core_relationship.create(
                                fromId=observable["id"],
                                toId=intrusion["id"],
                                relationship_type="related-to",
                                created_by_ref=self.organization["standard_id"],
                            )
                else:
                    color = "%06x" % random.randint(0, 0xFFFFFF)
                    labl = self.helper.api.label.create(
                        value=taglabel, color=color, update=False
                    )
                    taggs.append(taglabel)
                    if observable:
                        self.helper.api.stix_cyber_observable.add_label(
                            id=observable["id"], label_id=labl["id"]
                        )
        return taggs

    def parse_ioc_csv(self, ioc_txt):
        for line in ioc_txt.splitlines():
            if line:
                current_line = line.decode("utf-8").strip().split(",")
                current_line[4] = current_line[4].replace("#", "").split(" ")
                if current_line[2] == "ip":
                    if TweetFeed._validate_ipv4(current_line[3]):
                        self.process_line(current_line)

                elif current_line[2] == "domain":
                    if TweetFeed._validate_domain(current_line[3]):
                        self.process_line(current_line)

                elif current_line[2] == "url":
                    if TweetFeed._validate_urls(current_line[3]):
                        self.process_line(current_line)

                elif current_line[2] == "sha256":
                    if TweetFeed._validate_sha256(current_line[3]):
                        self.process_line(current_line)

                elif current_line[2] == "md5":
                    if TweetFeed._validate_md5(current_line[3]):
                        self.process_line(current_line)

    def process_ioc_per_date(self, last_update):
        delta = datetime.today() - last_update
        for day in reversed(range(0, delta.days + 1)):
            ## get the date
            date = datetime.today() - timedelta(days=day)
            ## get the url
            url = self._generate_path(date.strftime("%Y%m%d"))
            text = self.download_ioc_file(url)
            self.parse_ioc_csv(text)

    def run(self):
        self.helper.log_info(" SATAYO IOC reader, Fetching IOC data...")
        self.retrieve_data()
        exit(0)


if __name__ == "__main__":
    try:
        satayo_connector = TweetFeed()
        satayo_connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
