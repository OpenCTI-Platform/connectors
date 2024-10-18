from dateutil.parser import parse
from ..utils import (
    is_ipv4,
    is_ipv6,
    is_md5,
    is_sha1,
    is_sha256,
    is_sha512,
)  # TODO: relaplace relative import


class Agent:
    """
    Represent an agent from a Harfanglab alert.
    """

    def __init__(self, data: dict):
        self.hostname = data["hostname"]
        self.agent_id = data["agentid"]
        self.os_type = data["ostype"]
        self.os_product_type = data["osproducttype"]


class Alert:
    """
    Represent an Alert from Harfanglab API.
    """

    def __init__(self, data: dict):
        self.id = data.get("alert_unique_id", None)
        self.status = data.get("status", None)
        self.message = data.get("msg", None)
        self.rule_name = data.get("rule_name", None)
        self.type = data.get("alert_type", None)
        self.log_type = data.get("log_type", None)
        self.level = data.get("level", None)
        self.maturity = data.get("maturity", None)
        self.process = Process(data["process"])
        self.agent = Agent(data["agent"])
        self.url_id = data["id"]
        self.created_at = parse(data["alert_time"]) if "alert_time" in data else None
        self.updated_at = parse(data["last_update"]) if "last_update" in data else None

        self.name = f"{self.message} on {self.agent.hostname}"

    def get_ioc_rule(self):
        ioc_rule = None
        split_message = self.message.split("=") or self.message.split(":")
        if len(split_message) == 2:
            ioc_rule = split_message[1]
        return ioc_rule

    def get_sigma_rule(self):
        return self.rule_name

    def get_yara_file(self):
        yara_file = None
        split_rule_name = self.rule_name.split(":").replace(" ", "")
        if len(split_rule_name) == 2:
            yara_file = split_rule_name[1]
        return yara_file

    def update_with_indicator_info(self, indicator):
        if indicator.type.startswith("file:hashes."):
            self.name = f"{indicator.value} on {self.agent.hostname}"
        elif indicator.type == "file:name":
            self.name = f"{self.process.hashes['sha256']} on {self.agent.hostname}"


class Indicator:
    def __init__(self, data: dict):
        data_type = data.get("type", None)
        data_value = data.get("value", None)

        self.pattern_type = "stix"
        self.value = data_value
        self.name = data_value
        self.description = data.get("description", None)
        self.rule_name = data.get("rule_name", None)
        self.created_at = (
            parse(data["creation_date"]) if "creation_date" in data else None
        )
        self.updated_at = parse(data["last_update"]) if "last_update" in data else None

        self.type = Indicator._convert_type(data_type, data_value)
        self.pattern = f"[{self.type} = '{self.value}']"
        self.hashes = None  # placeholder for update_with_alert_info()

    def update_with_alert_info(self, alert):
        if self.type.startswith("file:"):
            self.name = alert.process.name
        if self.type.startswith("file:hashes."):
            self.hashes = alert.process.hashes
            self.pattern = (
                f"[file:hashes.'SHA-256' = '{alert.process.hashes['SHA-256']}' AND "
                f"file:hashes.'MD5' = '{alert.process.hashes['MD5']}' AND "
                f"file:hashes.'SHA-1' = '{alert.process.hashes['SHA-1']}']"
            )

    @staticmethod
    def _convert_type(original_type: str, original_value: str) -> str:
        indicator_types = {
            "domain-name": "domain-name:value",
            "filename": "file:name",
            "filepath": "file:name",
            "ip": {"ipv4": "ipv4-addr:value", "ipv6": "ipv6-addr:value"},
            "url": "url:value",
            "hash": {
                "sha-512": "file:hashes.'SHA-512'",
                "sha-256": "file:hashes.'SHA-256'",
                "sha-1": "file:hashes.'SHA-1'",
                "md5": "file:hashes.'MD5'",
            },
        }

        indicator_type = None
        if original_type in ["ip_src", "ip_dst", "ip_both"]:
            if is_ipv4(original_value):
                indicator_type = indicator_types["ip"]["ipv4"]
            if is_ipv6(original_value):
                indicator_type = indicator_types["ip"]["ipv6"]
        elif original_type == "hash":
            hash_algorithm = None
            match original_value:
                case _ if is_md5(original_value):
                    hash_algorithm = "md5"
                case _ if is_sha1(original_value):
                    hash_algorithm = "sha-1"
                case _ if is_sha256(original_value):
                    hash_algorithm = "sha-256"
                case _ if is_sha256(original_value):
                    hash_algorithm = "sha-512"
            indicator_type = indicator_types["hash"][hash_algorithm]
        else:
            indicator_type = indicator_types[original_type]
        return indicator_type


class Process:
    """
    Represent a process from a Harfanglab alert.
    """

    def __init__(self, data: dict):
        self.username = data["username"]
        self.user_sid = data["usersid"]
        self.current_directory = data["current_directory"]
        self.name = data["process_name"]
        self.hashes = {
            # "SHA-512": data["hashes"]["sha512"],
            "SHA-256": data["hashes"]["sha256"],
            "SHA-1": data["hashes"]["sha1"],
            "MD5": data["hashes"]["md5"],
        }


class SigmaIndicator:
    def __init__(self, data: dict):
        self.pattern_type = "sigma"
        self.rule_names = data.get("rule_names", None)
        self.content = data.get("content", None)
        self.rule_technique_tags = data["rule_technique_tags"]


class Threat:
    """
    Represent a Threat from Harfanglab.
    """

    def __init__(self, data: dict):
        self.id = data.get("threat_unique_id", None)
        self.status = data.get("status", None)
        self.level = data.get("level", None)
        # "process": {
        #     "username": data["process"]["username"],
        #     "user_sid": data["process"]["usersid"],
        #     "process_name": data["process"]["process_name"],
        #     "hashes": data["process"]["hashes"],
        #     "current_directory": data["process"]["current_directory"],
        # },
        # "agent": {
        #     "hostname": data["agent"]["hostname"],
        #     "agent_id": data["agent"]["agentid"],
        #     "os_type": data["agent"]["ostype"],
        #     "os_product_type": data["agent"]["osproducttype"],
        # },
        self.url_id = data["id"]
        self.first_seen = parse(data["first_seen"]) if "first_seen" in data else None
        self.last_seen = parse(data["last_seen"]) if "last_seen" in data else None


class YaraIndicator:
    def __init__(self, data: dict):
        self.pattern_type = "yara"
        self.rule_names = data.get("rule_names", None)
        self.content = data.get("content", None)
        self.rule_technique_tags = data["rule_technique_tags"]
