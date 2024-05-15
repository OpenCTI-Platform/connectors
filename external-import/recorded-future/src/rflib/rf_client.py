"""Client for Recorded Future API
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Recorded Future makes no       #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Recorded Future shall not be liable for, and you assume all risk of          #
# using the foregoing.                                                         #
################################################################################
"""

import io
import json
import string
from urllib import parse

import requests
import requests.exceptions

API_BASE = "https://api.recordedfuture.com"
CONNECT_BASE = API_BASE + "/v2"
DETECTION_SEARCH = API_BASE + "/detection-rule/search"
CONNECT_IP_SEARCH = CONNECT_BASE + "/ip/search"
CONNECT_DOMAIN_SEARCH = CONNECT_BASE + "/domain/search"
CONNECT_URL_SEARCH = CONNECT_BASE + "/url/search"
NOTES_BASE = CONNECT_BASE + "/analystnote"
NOTES_SEARCH = NOTES_BASE + "/search"
FUSION_FILE_BASE = CONNECT_BASE + "/fusion/files"
THREAT_ACTOR_PATH = "/public/opencti/threat_actors.json"
INSIKT_SOURCE = "VKz42X"
THREAT_MAPS_PATH = API_BASE + "/threat/maps"
LINKS_PATH = API_BASE + "/links/search"


class RFClient:
    """class for talking to the RF API, specifically pulling analyst notes"""

    def __init__(self, token, helper, header="PS_Custom_Script/0.0"):
        """Inits function"""
        self.token = token
        self.headers = {"X-RFToken": token, "User-Agent": header}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.helper = helper

    def get_notes(
        self,
        published: int,
        pull_signatures: bool = False,
        insikt_only: bool = True,
        topic: str = None,
        limit: int = 10000,
    ):
        """Pulls Insikt Notes from API
        Args:
            * published: in hours, how far back to fetch notes
            * pull_signatures - boolean value whether to fetch hunting package
            * insikt_only - pull only notes from Insikt group or also client written notes
            * topic - filter for a specific set of notes

        Returns:
            a list of dicts of notes
        #TODO: add pagination for notes
        """
        note_params = {"published": f"-{published}h", "limit": limit}
        if insikt_only:
            note_params["source"] = INSIKT_SOURCE
        if topic:
            note_params["topic"] = topic
        res = self.session.get(NOTES_SEARCH, params=note_params)
        res.raise_for_status()
        notes = []
        for note in res.json()["data"]["results"]:
            attributes = note["attributes"]
            msg = f'[ANALYST NOTES] Processing note "{attributes["title"]}"'
            self.helper.log_info(msg)
            if pull_signatures and "attachment" in attributes:
                try:
                    result = self.get_attachment(note["id"])
                    attributes["attachment_content"] = result["rules"][0]["content"]
                    attributes["attachment_type"] = result["type"]
                except requests.exceptions.HTTPError as err:
                    if "403" in str(err):
                        msg = "[ANALYST NOTES] Your API token does not have permission to pull Detection Rules"
                        self.helper.log_error(msg)
                    else:
                        raise err
                except (KeyError, IndexError):
                    self.helper.log_error(
                        "[ANALYST NOTES] Problem with API response for detection"
                        "rule for note {}. Rule will not be added".format(note["id"])
                    )
            notes.append(note)
        return notes

    def get_risk_ip_addresses(self, limit: int = 1000, risk_threshold=65):
        """

        :param limit:
        :param risk_threshold:
        :return:
        """
        note_params = {
            "fields": "entity,risk,relatedEntities",
            "limit": limit,
            "riskScore": f"[{risk_threshold},)",  # for example [65,) which means riskScore >= 65
        }
        res = self.session.get(CONNECT_IP_SEARCH, params=note_params)
        res.raise_for_status()
        ip_addresses = []
        for ip_address in res.json()["data"]["results"]:
            ip_addresses.append(ip_address)
        return ip_addresses

    def get_attachment(self, doc_id: str) -> str:
        """Pulls a hunting package from the detection rules API
        Args:
            * doc_id: ID of analyst note
        Returns:
            The string of the detection rule
        """
        query = {"filter": {"doc_id": f"doc:{doc_id}"}, "limit": 1}

        res = self.session.post(DETECTION_SEARCH, json=query)
        res.raise_for_status()
        return res.json()["result"][0]

    def get_fusion_file(self, path: str) -> str:
        """Gets a fusion file provided a path
        Args:
            * path: fusion file path
        Returns
            The body of the file as a string
        """
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        res = self.session.get(FUSION_FILE_BASE, params={"path": path})
        res.raise_for_status()
        return res.text

    def get_threat_actors(self) -> set:
        """Gets a list of all threat actors from fusion/file
        Returns:
            The threat actors as a set
        """
        res = self.get_fusion_file(THREAT_ACTOR_PATH)
        ret = set()
        for entity in json.loads(res):
            ret.add(entity["entity"])
        return ret

    def get_risk_list_CSV(self, path: string) -> io.StringIO:
        res = self.get_fusion_file(path)
        buffer = io.StringIO(res)

        return buffer

    def get_risk_score(self, type: str, value: str) -> int:
        """Gets risk score for an indicator
        Args:
            * type: indicator type
            * value: indicator value
        Returns:
            The risk score as an int
        """
        indicator_params = {"fields": "risk"}
        value_indicator = value if type != "url" else parse.quote(value, safe="")
        res = self.session.get(
            CONNECT_BASE + "/" + type + "/" + value_indicator, params=indicator_params
        )
        res.raise_for_status()
        return res.json()["data"]["risk"]["score"]

    def get_threat_maps(self):
        """
        Get threat maps for an organization
        :return: List of threat map for Threat actor and Malware for an organization
        """
        res = self.session.get(THREAT_MAPS_PATH)
        res.raise_for_status()

        threat_maps_list = res.json()["data"]

        return threat_maps_list

    def get_entities_mapped(self, path: string):
        res = self.session.post(API_BASE + path, json={})
        res.raise_for_status()

        threat_map_data = res.json()["data"]["threat_map"]

        return threat_map_data

    def get_entities_links(self, entities_id: list):
        entities_params = {"entities": entities_id}

        res = self.session.post(LINKS_PATH, json=entities_params)
        res.raise_for_status()

        entity_links = res.json()["data"]

        return entity_links
