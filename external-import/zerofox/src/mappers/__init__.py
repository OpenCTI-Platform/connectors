from datetime import datetime
from zerofox.app.endpoints import CTIEndpoint
from typing import Any
from mappers.malwareToMalware import malware_to_malware


def threat_feed_to_stix(feed: Any):
    return {
        CTIEndpoint.Malware: malware_to_malware,


    }.get(feed)