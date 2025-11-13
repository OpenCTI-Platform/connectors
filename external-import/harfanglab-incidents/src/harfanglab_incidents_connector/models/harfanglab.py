from dateutil.parser import parse


class Agent:
    """
    Represent an agent from Harfanglab API (nested either under an alert or a threat).
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data: dict):
        # data is coming from alert["agent"] or threat["top_agents"][index]
        self.id = data.get("agentid") or data.get("agent_id") or None
        self.hostname = data.get("hostname") or data.get("agent_hostname") or None
        self.os_type = data.get("ostype") or data.get("agent_ostype") or None
        self.os_product_type = (
            data.get("osproducttype") or data.get("agent_osproducttype") or None
        )


class Alert:
    """
    Represent an alert from Harfanglab API.
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data: dict):
        self.id = data.get("id") or None
        self.unique_id = data.get("alert_unique_id") or None
        self.status = data.get("status") or None
        self.message = data.get("msg") or None
        self.rule_name = data.get("rule_name") or None
        self.type = data.get("alert_type") or None
        self.log_type = data.get("log_type") or None
        self.level = data.get("level") or None
        self.maturity = data.get("maturity") or None
        self.process = Process(data["process"]) if "process" in data else None
        self.agent = Agent(data["agent"]) if "agent" in data else None
        self.created_at = parse(data["alert_time"]) if "alert_time" in data else None
        self.updated_at = parse(data["last_update"]) if "last_update" in data else None

        self.name = f"{self.message} on {self.agent.hostname}"


class IocRule:
    """
    Represent an IOC rule from Harfanglab API.
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data: dict):
        self.type = data.get("type") or None
        self.value = data.get("value") or None
        self.pattern = f"[{self.type} = '{self.value}']"
        self.created_at = (
            parse(data["creation_date"]) if "creation_date" in data else None
        )
        self.updated_at = parse(data["last_update"]) if "last_update" in data else None


class Process:
    """
    Represent a process from Harfanglab API (nested in an alert).
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data: dict):
        self.user_sid = data.get("usersid") or None
        self.username = data.get("username") or None
        self.current_directory = data.get("current_directory") or None
        self.name = data.get("process_name") or None
        self.hashes = {
            # "SHA-512": data.get("hashes"][")ha512"],
            "SHA-256": data.get("hashes")["sha256"],
            "SHA-1": data.get("hashes")["sha1"],
            "MD5": data.get("hashes")["md5"],
        }


class SigmaRule:
    """
    Represent a Sigma rule from Harfanglab API.
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data: dict):
        self.name = data.get("name") or None
        self.content = data.get("content") or None
        self.rule_name = data.get("rule_name") or None
        self.created_at = (
            parse(data["creation_date"]) if "creation_date" in data else None
        )
        self.updated_at = parse(data["last_update"]) if "last_update" in data else None


class Threat:
    """
    Represent a threat from Harfanglab.
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data: dict):
        self.id = data.get("id") or None
        self.slug = data.get("slug") or None
        self.status = data.get("status") or None
        self.level = data.get("level") or None
        self.top_agents = (
            [Agent(top_agent) for top_agent in data["top_agents"]]
            if "top_agents" in data
            else None
        )
        self.top_impacted_users = (
            [
                User(top_impacted_user)
                for top_impacted_user in data["top_impacted_users"]
            ]
            if "top_impacted_users" in data
            else None
        )
        self.first_seen = parse(data["first_seen"]) if "first_seen" in data else None
        self.last_seen = parse(data["last_seen"]) if "last_seen" in data else None
        self.created_at = (
            parse(data["creation_date"]) if "creation_date" in data else None
        )


class ThreatNote:
    """
    Represent a threat's note from Harfanglab API.
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data):
        self.title = data.get("title") or None
        self.content = data.get("content") or None
        self.created_at = (
            parse(data["creation_date"]) if data["creation_date"] else None
        )
        self.updated_at = parse(data["last_update"]) if data["last_update"] else None


class User:
    """
    Represent an impacted user from Harfanglab API (nested in a Threat).
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data):
        self.user_sid = data.get("user_sid") or None
        self.username = data.get("user_name") or None


class YaraSignature:
    """
    Represent a YARA signature from Harfanglab API.
    Non-existing or empty fields are set to None.
    All other fields sent by Harfanglab API are discarded.
    """

    def __init__(self, data: dict):
        self.name = data.get("name") or None
        self.content = data.get("content") or None
        self.rule_names = data.get("rule_names") or None
        self.rule_technique_tags = data.get("rule_technique_tags") or None
        self.created_at = (
            parse(data["creation_date"]) if "creation_date" in data else None
        )
        self.updated_at = parse(data["last_update"]) if "last_update" in data else None
