import json
from unittest.mock import MagicMock, patch

from connector import SpurIPProcessor
from connectors_sdk import InternalEnrichmentConnector
from connectors_sdk.models import IPV4Address
from pycti import OpenCTIConnectorHelper
from spur_client import IPContext, SpurClient

PATCH_HELPER = "connectors_sdk.connectors.internal_enrichment.internal_enrichment_connector.OpenCTIConnectorHelper"


def test_connector_should_send_the_enriched_ip_in_the_original_bundle(settings):
    # Given the SDK connector with the Spur processor
    helper = MagicMock()
    helper.playbook = None
    helper.check_max_tlp.side_effect = OpenCTIConnectorHelper.check_max_tlp
    helper.stix2_create_bundle.side_effect = OpenCTIConnectorHelper.stix2_create_bundle
    processor = SpurIPProcessor()
    connector = InternalEnrichmentConnector(
        settings=settings, enrichment_processors=[processor]
    )
    with patch(PATCH_HELPER, return_value=helper):
        connector._init_dependencies()
    processor.client = MagicMock(spec=SpurClient)
    processor.client.get_ip_context.return_value = IPContext.model_validate(
        {
            "ip": "1.2.3.4",
            "risks": ["CALLBACK_PROXY"],
            "tunnels": [{"type": "VPN", "operator": "PROTON_VPN", "anonymous": True}],
        }
    )
    ip_id = IPV4Address(value="1.2.3.4").id
    entity = {"type": "ipv4-addr", "id": ip_id, "value": "1.2.3.4"}
    data = {
        "event_type": "INTERNAL_ENRICHMENT",
        "entity_id": ip_id,
        "entity_type": "IPv4-Addr",
        "enrichment_entity": {"entity_type": "IPv4-Addr", "objectMarking": []},
        "stix_entity": entity,
        "stix_objects": [dict(entity)],
    }

    # When an IPv4 enrichment message is received
    connector.callback(data)

    # Then one bundle is sent with the original IP replaced by the enriched one
    helper.send_stix2_bundle.assert_called_once()
    objects = json.loads(helper.send_stix2_bundle.call_args.args[0])["objects"]
    ips = [obj for obj in objects if obj["id"] == ip_id]
    assert len(ips) == 1
    assert ips[0]["x_opencti_score"] == 75
    assert "spur-tunnel-type:vpn" in ips[0]["x_opencti_labels"]
    assert {obj["type"] for obj in objects} == {
        "identity",
        "marking-definition",
        "ipv4-addr",
        "infrastructure",
        "relationship",
    }
