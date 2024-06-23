from typing import List

from collectors.collector import Collector
from collectors.mappers import threat_feed_to_stix
from zerofox.app.endpoints import CTIEndpoint


def build_collectors(client, feeds: str | None = None, logger=None):
    """Builds collectors for the ZeroFox connector.

    Args:
        client: The ZeroFox client.
        feeds: A list of feeds to collect.

    Returns:
        A dictionary of collectors.
    """
    collectors = {}
    parsed_feeds = _parse(feeds) if feeds else CTIEndpoint

    for feed in parsed_feeds:
        collectors[str(feed)] = Collector(feed, threat_feed_to_stix(feed), client)
    if logger:
        logger.debug(f"Collectors to use are {list(collectors.keys())}")
    return collectors


def _parse(feeds_str: str) -> List[CTIEndpoint]:
    """Parses a list of feeds.

    Args:
        feeds: A list of feeds.

    Returns:
        A list of CTIEndpoint objects.
    """
    feeds = list(map(lambda s: s.strip(), feeds_str.split(",")))
    endpoints = []
    for feed in feeds:
        try:
            endpoint = CTIEndpoint(feed)
            endpoints.append(endpoint)
        except ValueError:
            pass
    return endpoints
