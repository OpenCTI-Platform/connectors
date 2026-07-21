from unittest.mock import MagicMock

import stix2
from connector.connector import VisionHeightConnector


def test_collect_intelligence_returns_original_bundle_on_api_failure():
    """API failure on the IP path must preserve the input bundle, not drop it.

    Regression: the API-error path used to ``return []``, which made playbook
    chains lose the bundle for that observable. It must return the original
    ``stix_objects_list`` unchanged.
    """
    connector = VisionHeightConnector.__new__(VisionHeightConnector)
    connector.helper = MagicMock()
    connector.client = MagicMock()
    connector.converter_to_stix = MagicMock()
    connector.client.get_ip.return_value = None

    original_ip = stix2.IPv4Address(value="1.2.3.4")
    original_bundle = [original_ip]
    connector.stix_objects_list = original_bundle

    stix_entity = {"id": original_ip.id, "type": "IPv4-Addr", "value": "1.2.3.4"}
    result = connector._collect_intelligence(stix_entity)

    assert (
        result is original_bundle
    ), "expected the original bundle to be returned unchanged on API failure"
    assert result == [original_ip]
