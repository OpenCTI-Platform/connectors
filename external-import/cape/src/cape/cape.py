from datetime import datetime

import requests
from requests.exceptions import HTTPError

# ------------------------------------------------------------------
# This is a Class to serialize the Cuckoo API /tasks/Summary JSON
# ------------------------------------------------------------------


class cuckooMachine:
    def __init__(self, json):
        self.json = json
        # Get Basic info
        if "label" in self.json:
            self.label = self.json["label"]
        else:
            self.label = ""
        self.manager = self.json["manager"]
        self.name = self.json["name"]
        self.shutdown_on = self.json["shutdown_on"]
        self.started_on = self.json["started_on"]
        self.status = self.json["status"]

    def __str__(self):
        return self.name


class cuckooReportInfo:
    def __init__(self, report_json):
        self.json = report_json["info"]

        # Get Basic info
        self.id = self.json["id"]
        self.started = self.json["started"]
        self.ended = self.json["ended"]
        self.duration = self.json["duration"]
        self.category = self.json["category"]
        self.route = self.json["route"]
        self.package = self.json["package"]
        self.machine = cuckooMachine(self.json["machine"])
        self.version = self.json["version"]
        self.tlp = self.json["tlp"]

    def __str__(self):
        return self.id


class cuckooTarget:
    def __init__(self, report_json, target="file"):
        self.json = report_json["target"][target]

        # Get Basic info

        self.name = self.json["name"]
        self.path = self.json["path"]
        self.type = self.json["type"]
        self.size = self.json["size"]

        self.crc32 = self.json["crc32"]
        self.md5 = self.json["md5"]
        self.sha1 = self.json["sha1"]
        self.sha256 = self.json["sha256"]
        self.sha512 = self.json["sha512"]
        self.ssdeep = self.json["ssdeep"]
        self.tlsh = self.json["tlsh"]
        self.sha3_384 = self.json["sha3_384"]

        self.yara = self.getYara()
        self.cape_yara = self.getCapeYara()
        self.clamav = self.getclamav()
        self.trid = self.json["trid"]

    def getYara(self):
        yara_matches = []
        for match in self.json["yara"]:
            yara_matches.append({"name": match["name"], "meta": match["meta"]})
        return yara_matches

    def getCapeYara(self):
        yara_matches = []
        for match in self.json["cape_yara"]:
            yara_matches.append({"name": match["name"], "meta": match["meta"]})
        return yara_matches

    def getclamav(self):
        clam_matches = []
        for match in self.json["clamav"]:
            if isinstance(match, dict):
                clam_matches.append({"name": match["name"], "meta": match["meta"]})
            else:
                clam_matches.append(match)
        return clam_matches

    def __str__(self):
        return self.name


class cuckooReportTarget:
    def __init__(self, report_json):
        self.category = report_json["target"]["category"]

        if self.category == "url":
            self.url = report_json["target"]["url"]
        elif self.category == "file":
            self.file = cuckooTarget(report_json, "file")

    def __str__(self) -> str:
        if self.category == "url":
            return self.url
        elif self.category == "file":
            return self.file.name


class cuckooReportSignature:
    def __init__(self, signature_json):
        self.json = signature_json

        # Get Basic info
        self.description = self.json["description"]
        self.weight = self.json["weight"]
        self.name = self.json["name"]
        self.confidence = self.json["confidence"]
        self.references = self.json["references"]
        self.data = self.json["data"]
        self.new_data = self.json["new_data"]
        self.alert = self.json["alert"]
        self.severity = self.json["severity"]
        self.families = self.json["families"]

    def __str__(self):
        return self.name


class cuckooReportExtracted:
    def __init__(self, json):
        self.json = json

        self.category = self.json["category"]
        self.pid = self.json["pid"]
        self.info = self.json["info"]
        self.program = self.json["program"]
        self.raw = self.json["raw"]
        self.yara = self.getYara()
        self.first_seen = datetime.fromtimestamp(self.json["first_seen"])

    def getYara(self):
        yara_matches = []
        for match in self.json["yara"]:
            yara_matches.append({"name": match["name"], "meta": match["meta"]})
        return yara_matches

    def __str__(self):
        return f"[{str(self.pid)}][{self.category}] {self.raw.split('/')[-1]}"


class cuckooReportDropped:
    def __init__(self, json):
        self.json = json

        # Get Basic info
        self.crc32 = self.json["crc32"]
        self.md5 = self.json["md5"]
        self.name = self.json["name"]
        self.path = self.json["path"]
        self.filepath = self.json["filepath"]
        self.pids = self.json["pids"]
        self.sha1 = self.json["sha1"]
        self.sha256 = self.json["sha256"]
        self.sha512 = self.json["sha512"]
        self.ssdeep = self.json["ssdeep"]
        self.size = self.json["size"]
        self.type = self.json["type"]
        self.yara = self.getYara()
        self.urls = self.json["urls"]

    def getYara(self):
        yara_matches = []
        for match in self.json["yara"]:
            yara_matches.append({"name": match["name"], "meta": match["meta"]})
        return yara_matches

    def __str__(self):
        return self.name


class cuckooReportBuffer:
    def __init__(self, json):
        self.json = json

        # Get Basic info
        self.crc32 = self.json["crc32"]
        self.md5 = self.json["md5"]
        self.name = self.json["name"]
        self.path = self.json["path"]
        self.sha1 = self.json["sha1"]
        self.sha256 = self.json["sha256"]
        self.sha512 = self.json["sha512"]
        self.ssdeep = self.json["ssdeep"]
        self.size = self.json["size"]
        self.type = self.json["type"]
        self.yara = self.getYara()
        self.urls = self.json["urls"]

    def getYara(self):
        yara_matches = []
        for match in self.json["yara"]:
            yara_matches.append({"name": match["name"], "meta": match["meta"]})
        return yara_matches

    def __str__(self):
        return self.name


class cuckooReportDNSResponse:
    def __init__(self, json):
        self.json = json

        self.data = self.json["data"]
        self.type = self.json["type"]


class cuckooReportDNSRequest:
    def __init__(self, json):
        self.json = json

        self.request = self.json["request"]
        self.type = self.json["type"]
        self.answers = self.getDNSAnswers()

    def getDNSAnswers(self):
        answers = []
        for answer in self.json["answers"]:
            answerObj: cuckooReportDNSResponse = cuckooReportDNSResponse(answer)
            answers.append(answerObj)
        return answers

    def __str__(self):
        return self.request


class cuckooReportHTTPRequest:
    def __init__(self, json):
        self.json = json

        if "body" in self.json:
            self.body = self.json["body"]
        else:
            self.body = None

        if "count" in self.json:
            self.count = self.json["count"]
        else:
            self.count = None

        if "data" in self.json:
            self.data = self.json["data"]
        else:
            self.data = None

        if "host" in self.json:
            self.host = self.json["host"]
        else:
            self.host = None

        if "method" in self.json:
            self.method = self.json["method"]
        else:
            self.method = None

        if "path" in self.json:
            self.path = self.json["path"]
        else:
            self.path = None

        if "port" in self.json:
            self.port = self.json["port"]
        else:
            self.port = None

        if "uri" in self.json:
            self.data = self.json["uri"]
        else:
            self.data = None

        if "user-agent" in self.json:
            self.useragent = self.json["user-agent"]
        else:
            self.useragent = None

        if "version" in self.json:
            self.version = self.json["version"]
        else:
            self.version = None

    def __str__(self):
        return f"[{self.method}] {self.host}"


class cuckooReportHTTPResponse:
    def __init__(self, json):
        self.json = json

        self.dport = self.json["dport"]
        self.dst = self.json["dst"]
        self.host = self.json["host"]
        self.method = self.json["method"]
        self.protocol = self.json["protocol"]
        self.request = self.json["request"]
        self.response = self.json["response"]
        self.sport = self.json["sport"]
        self.src = self.json["src"]
        self.status = self.json["status"]
        self.uri = self.json["uri"]

    def __str__(self):
        return f"[{str(self.status)}][{self.method}] {self.host}"


class cuckooReportICMP:
    def __init__(self, json):
        self.json = json

        self.data = self.json["data"]
        self.dst = self.json["dst"]
        self.src = self.json["src"]
        self.type = self.json["type"]

    def __str__(self):
        return f"{self.dst}"


class cuckooReportTCPUDP:
    def __init__(self, json):
        self.json = json

        self.dport = self.json["dport"]
        self.dst = self.json["dst"]
        self.offset = self.json["offset"]
        self.sport = self.json["sport"]
        self.src = self.json["src"]
        self.time = self.json["time"]

    def __str__(self):
        return f"{self.dst}"


class cuckooReportDomain:
    def __init__(self, json):
        self.json = json

        self.domain = self.json["domain"]
        self.ip = self.json["ip"]

    def __str__(self):
        return f"{self.domain}"


class cuckooReportHost:
    def __init__(self, json):
        self.json = json

        self.ip = self.json["ip"]
        self.country_name = self.json["country_name"]
        self.hostname = self.json["hostname"]
        self.inaddrarpa = self.json["inaddrarpa"]

    def __str__(self):
        return f"{self.ip}"


class cuckooReportNetwork:
    def __init__(self, report_json):
        self.json = report_json["network"]

        # Get Basic info
        self.dead_hosts = self.json["dead_hosts"]
        self.domains = self.getDomains()
        self.hosts = self.getHosts()
        self.dns = self.getDNS()
        self.http = self.getHTTP()
        self.http_ex = self.getHTTPEX()
        self.icmp = self.getICMP()
        self.tcp = self.getpackets("tcp")
        self.udp = self.getpackets("udp")

    def getpackets(self, type="tcp"):
        packets = []
        for reqObj in self.json[type]:
            respObj: cuckooReportTCPUDP = cuckooReportTCPUDP(reqObj)
            packets.append(respObj)

        return packets

    def getICMP(self):
        requests = []
        for reqObj in self.json["icmp"]:
            respObj: cuckooReportICMP = cuckooReportICMP(reqObj)
            requests.append(respObj)

        return requests

    def getHosts(self):
        hosts = []
        for reqObj in self.json["hosts"]:
            respObj: cuckooReportHost = cuckooReportHost(reqObj)
            hosts.append(respObj)

        return hosts

    def getDomains(self):
        domains = []
        for reqObj in self.json["domains"]:
            respObj: cuckooReportDomain = cuckooReportDomain(reqObj)
            domains.append(respObj)

        return domains

    def getDNS(self):
        requests = []
        for reqObj in self.json["dns"]:
            respObj: cuckooReportDNSRequest = cuckooReportDNSRequest(reqObj)
            requests.append(respObj)

        return requests

    def getHTTP(self):
        requests = []
        for reqObj in self.json["http"]:
            respObj: cuckooReportHTTPRequest = cuckooReportHTTPRequest(reqObj)
            requests.append(respObj)

        return requests

    def getHTTPEX(self):
        requests = []
        if "http_ex" not in self.json:
            return []

        for reqObj in self.json["http_ex"]:
            respObj: cuckooReportHTTPResponse = cuckooReportHTTPResponse(reqObj)
            requests.append(respObj)

        return requests

    # def __str__(self):
    #     return self.id


class cuckooReportBehaviorSummary:
    def __init__(self, report_json):
        self.json = report_json["behavior"]["summary"]

        if "files" in self.json:
            self.files = self.json["files"]
        else:
            self.files = []

        if "read_files" in self.json:
            self.read_files = self.json["read_files"]
        else:
            self.read_files = []

        if "write_files" in self.json:
            self.write_files = self.json["write_files"]
        else:
            self.write_files = []

        if "delete_files" in self.json:
            self.delete_files = self.json["delete_files"]
        else:
            self.delete_files = []

        if "keys" in self.json:
            self.keys = self.json["keys"]
        else:
            self.keys = []

        if "read_keys" in self.json:
            self.read_keys = self.json["read_keys"]
        else:
            self.read_keys = []

        if "write_keys" in self.json:
            self.write_keys = self.json["write_keys"]
        else:
            self.write_keys = []

        if "delete_keys" in self.json:
            self.delete_keys = self.json["delete_keys"]
        else:
            self.delete_keys = []

        # Get Basic info
        if "executed_commands" in self.json:
            self.executed_commands = self.json["executed_commands"]
        else:
            self.executed_commands = []

        if "resolved_apis" in self.json:
            self.resolved_apis = self.json["resolved_apis"]
        else:
            self.resolved_apis = []

        if "created_services" in self.json:
            self.created_services = self.json["created_services"]
        else:
            self.created_services = []

        if "started_services" in self.json:
            self.started_services = self.json["started_services"]
        else:
            self.started_services = []

        if "mutexes" in self.json:
            self.mutexes = self.json["mutexes"]
        else:
            self.mutexes = []


class cuckooReportProcessEnviron:
    def __init__(self, environ_json):
        self.json = environ_json

        # Get Basic info
        if "UserName" in self.json:
            self.UserName = self.json["UserName"]
        else:
            self.UserName = ""

        if "ComputerName" in self.json:
            self.ComputerName = self.json["ComputerName"]
        else:
            self.ComputerName = ""

        if "WindowsPath" in self.json:
            self.WindowsPath = self.json["WindowsPath"]
        else:
            self.WindowsPath = ""

        if "TempPath" in self.json:
            self.TempPath = self.json["TempPath"]
        else:
            self.TempPath = ""

        if "CommandLine" in self.json:
            self.command_line = self.json["CommandLine"]
        else:
            self.command_line = ""

        if "RegisteredOwner" in self.json:
            self.RegisteredOwner = self.json["RegisteredOwner"]
        else:
            self.RegisteredOwner = ""

        if "RegisteredOrganization" in self.json:
            self.RegisteredOrganization = self.json["RegisteredOrganization"]
        else:
            self.RegisteredOrganization = ""

        if "ProductName" in self.json:
            self.ProductName = self.json["ProductName"]
        else:
            self.ProductName = ""

        if "SystemVolumeSerialNumber" in self.json:
            self.SystemVolumeSerialNumber = self.json["SystemVolumeSerialNumber"]
        else:
            self.SystemVolumeSerialNumber = ""

        if "SystemVolumeGUID" in self.json:
            self.SystemVolumeGUID = self.json["SystemVolumeGUID"]
        else:
            self.SystemVolumeGUID = ""

        if "MachineGUID" in self.json:
            self.MachineGUID = self.json["MachineGUID"]
        else:
            self.MachineGUID = ""


class cuckooReportProcess:
    def __init__(self, process_json, children=[]):
        self.json = process_json

        # Get Basic info
        if "environ" in self.json:
            self.environ = cuckooReportProcessEnviron(self.json["environ"])
        else:
            self.environ = []

        if "pid" in self.json:
            self.pid = self.json["pid"]
        else:
            self.pid = -1

        if "parent_id" in self.json:
            self.parent_id = self.json["parent_id"]
        else:
            self.parent_id = -1

        if "name" in self.json:
            self.name = self.json["name"]
        else:
            self.name = ""

        if "module_path" in self.json:
            self.module_path = self.json["module_path"]
        else:
            self.module_path = False

        if "threads" in self.json:
            self.threads = self.json["threads"]
        else:
            self.threads = False

        self.children = children


class cuckooReportTTP:
    def __init__(self, ttp_json):
        self.json = ttp_json

        # Get Basic info
        if "ttp" in self.json:
            self.ttp = self.json["ttp"]
        else:
            self.ttp = ""

        if "signature" in self.json:
            self.signature = self.json["signature"]
        else:
            self.signature = ""


class cuckooPayload:
    def __init__(self, report_json):
        self.json = report_json

        # Get Basic info

        self.name = self.json["name"]
        self.path = self.json["path"]
        self.type = self.json["type"]
        self.size = self.json["size"]

        self.crc32 = self.json["crc32"]
        self.md5 = self.json["md5"]
        self.sha1 = self.json["sha1"]
        self.sha256 = self.json["sha256"]
        self.sha512 = self.json["sha512"]
        self.ssdeep = self.json["ssdeep"]
        self.tlsh = self.json["tlsh"]
        self.sha3_384 = self.json["sha3_384"]

        self.yara = self.getYara()
        self.cape_yara = self.getCapeYara()
        self.clamav = self.getclamav()
        self.trid = self.json["trid"]

    def getYara(self):
        yara_matches = []
        for match in self.json["yara"]:
            yara_matches.append({"name": match["name"], "meta": match["meta"]})
        return yara_matches

    def getCapeYara(self):
        yara_matches = []
        for match in self.json["cape_yara"]:
            yara_matches.append({"name": match["name"], "meta": match["meta"]})
        return yara_matches

    def getclamav(self):
        clam_matches = []
        for match in self.json["clamav"]:
            if isinstance(match, dict):
                clam_matches.append({"name": match["name"], "meta": match["meta"]})
            else:
                clam_matches.append(match)
        return clam_matches

    def __str__(self):
        return self.name


class cuckooReport:
    def __init__(self, report_json):
        self.report_json = report_json

        if "malscore" in report_json:
            self.malscore = report_json["malscore"]
        else:
            self.malscore = None

        if "detections" in report_json:
            self.detections = report_json["detections"]
        else:
            self.detections = None

        if "info" in report_json:
            self.info: cuckooReportInfo = cuckooReportInfo(report_json)
        else:
            self.info = None

        if "target" in report_json:
            self.target: cuckooReportTarget = cuckooReportTarget(report_json)
        else:
            self.target = None

        if "network" in report_json:
            self.network: cuckooReportNetwork = cuckooReportNetwork(report_json)
        else:
            self.network = None

        if "behavior" in report_json:
            if "processtree" in report_json["behavior"]:
                self.process = self.getProcesses(report_json["behavior"]["processtree"])
            else:
                self.process = []

            if "summary" in report_json["behavior"]:
                self.behavior: cuckooReportBehaviorSummary = (
                    cuckooReportBehaviorSummary(report_json)
                )
            else:
                self.behavior = None
        else:
            self.behavior = None
            self.process = []

        if "ttps" in report_json:
            self.ttps = self.getReportTTPs()
        else:
            self.ttps = []

        if "payloads" in report_json["CAPE"]:
            self.payloads: cuckooPayload = self.getReportPayloads()
        else:
            self.payloads = []

        if "strings" in report_json:
            self.strings = report_json["strings"]
        else:
            self.strings = []

        self.signatures = self.getReportSignatures()
        # self.payloads = self.getpayloads()

    def hasSignatures(self):
        return len(self.signatures) > 0

    def getpayloads(self):
        return len(self.payloads) > 0

    def getReportTTPs(self):
        TTPs = []
        if "ttps" not in self.report_json:
            return []
        for sig in self.report_json["ttps"]:
            sigObj: cuckooReportTTP = cuckooReportTTP(sig)
            TTPs.append(sigObj)

        return TTPs

    def getReportSignatures(self):
        signatures = []
        if "signatures" not in self.report_json:
            return []
        for sig in self.report_json["signatures"]:
            sigObj: cuckooReportSignature = cuckooReportSignature(sig)
            signatures.append(sigObj)

        return signatures

    def getReportPayloads(self):
        PayloadObjects = []
        for objx in self.report_json["CAPE"]["payloads"]:
            extObj: cuckooPayload = cuckooPayload(objx)
            PayloadObjects.append(extObj)

        return PayloadObjects

    def getProcesses(self, json):
        ProcessObjects = []

        for objx in json:
            ChildProcObjs = []
            ChildProcObjs.extend(self.extractChildren(objx["children"]))
            ProcessObjects.append(cuckooReportProcess(objx, ChildProcObjs))

        return ProcessObjects

    def extractChildren(self, children):
        grand = []
        for Child in children:
            childs = []
            if not len(Child["children"]) > 0:
                grand.append(cuckooReportProcess(Child))
            else:
                childs.extend(self.extractChildren(Child["children"]))
                grand.append(cuckooReportProcess(Child, childs))

        return grand

    def __str__(self) -> str:
        return str(self.target)


class cuckoo:
    def __init__(self, connectorHelper, api_url, Verify=True):
        self.URL = api_url
        self.verify = Verify
        self.connectorHelper = connectorHelper

    def getCuckooTasks(self):
        EP = "tasks/list"
        Method = "GET"
        response = self._make_request(Method, EP)
        return response.json()["data"]

    def getTaskIOCs(self, TaskID):
        EP = f"tasks/get/iocs/{TaskID}"
        Method = "GET"
        response = self._make_request(Method, EP)
        return cuckooReport(response.json())

    def getTaskReport(self, TaskID):
        EP = f"tasks/get/report/{TaskID}"
        Method = "GET"
        response = self._make_request(Method, EP)
        return response.json()

    def _make_request(self, method, EP, data=None, params=None, host=None):
        try:
            if self.URL[-1] == "/":
                URL = f"{self.URL}{EP}"
            else:
                URL = f"{self.URL}/{EP}"

            if params and data:
                resp = requests.request(
                    method, URL, data=data, params=params, verify=self.verify
                )
            elif params:
                resp = requests.request(method, URL, params=params, verify=self.verify)
            elif data:
                resp = requests.request(method, URL, data=data, verify=self.verify)
            else:
                resp = requests.request(method, URL, verify=self.verify)

            if not resp.ok:
                self.connectorHelper.log_error(
                    f"Received response code {resp.status_code} from {URL}"
                )
                retry = 0
                while not resp.ok:
                    if retry >= 5:
                        break
                    retry = retry + 1
                    if params and data:
                        resp = requests.request(
                            method, URL, data=data, params=params, verify=self.verify
                        )
                    elif params:
                        resp = requests.request(
                            method, URL, params=params, verify=self.verify
                        )
                    elif data:
                        resp = requests.request(
                            method, URL, data=data, verify=self.verify
                        )
                    else:
                        resp = requests.request(method, URL, verify=self.verify)

            return resp
        except HTTPError as e:
            self.connectorHelper.log_error(str(e))
            pass
