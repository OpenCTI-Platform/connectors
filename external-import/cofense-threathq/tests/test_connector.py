import base64
from unittest.mock import AsyncMock, Mock, patch

import stix2
from pycti import OpenCTIApiClient, OpenCTIApiConnector, OpenCTIConnectorHelper
from src.connector import CofenseThreatHQ
from src.connector.services.config_loader import CofenseThreatHQConfig


@patch.dict(
    "os.environ",
    {
        "OPENCTI_URL": "http://localhost",
        "OPENCTI_TOKEN": "CHANGEME",
        "CONNECTOR_ID": "CHANGEME",
        "COFENSE_THREATHQ_TOKEN_USER": "user",
        "COFENSE_THREATHQ_TOKEN_PASSWORD": "password",
        "COFENSE_THREATHQ_API_BASE_URL": "http://fake-api.test",
        "COFENSE_THREATHQ_PROMOTE_OBSERVABLES_AS_INDICATORS": "true",
    },
)
@patch.object(
    OpenCTIApiClient,
    "health_check",
    return_value=True,
)
@patch.object(
    OpenCTIApiConnector,
    "register",
    return_value={
        "id": "CHANGEME",
        "connector_user_id": "1",
        "connector_state": "{}",
        "config": {
            "connection": {
                "host": "rabbitmq",
                "vhost": "/",
                "use_ssl": False,
                "port": 5672,
                "user": "opencti",
                "pass": "changeme",
            }
        },
        "jwks": {},
    },
)
def test_should_promote_observables_to_indicators(_, __):
    config = CofenseThreatHQConfig()
    config_instance = config.load
    config_dict = config_instance.model_dump(exclude_none=True)
    helper = OpenCTIConnectorHelper(config=config_dict)
    helper.api.bundle_send_to_queue = False
    connector = CofenseThreatHQ(config_instance, helper)

    connector.helper.api.work.initiate_work = lambda x, y: {"id": "work_id_123"}
    connector.client.get_reports = AsyncMock(
        return_value={
            "success": True,
            "data": {
                "nextPosition": "9a4b228f-ba32-4151-bca0-33a87f2e1b72",
                "changelog": [
                    {
                        "threatId": 382064,
                        "threatType": "malware",
                        "occurredOn": 1732198136721,
                        "deleted": False,
                    }
                ],
            },
        }
    )
    connector.client.get_report_malware_details = AsyncMock(
        return_value={
            "success": True,
            "data": {
                "id": "threat-382064",
                "label": "Phishing Campaign Alpha - Invoice Theme",
                "threatDetailURL": "https://threathq.cofense.com/threats/382064",
                "executiveSummary": "A phishing campaign delivering AgentTesla malware via malicious attachments disguised as invoices.",
                "firstPublished": 1698397200000,  # Corresponds to a date in Oct 2023
                "lastPublished": 1698397800000,
                "malwareFamilySet": [{"familyName": "AgentTesla"}],
                "deliveryMechanisms": [{"mechanismName": "Email Attachment"}],
                "subjectSet": [{"subject": "Urgent: Invoice INV-2023-987"}],
                "campaignBrandSet": [{"brand": {"text": "Microsoft Office 365"}}],
                "campaignLanguageSet": [{"languageDefinition": {"name": "English"}}],
                "naicsCodes": [{"label": "Manufacturing (31-33)"}],
                "secureEmailGatewaySet": [{"segName": "Proofpoint"}],
                "blockSet": [
                    {
                        "blockType": "URL",
                        "impact": "High",
                        "role": "C2 Server",
                        "data": "http://evil-c2-server.com/callback",
                    },
                    {
                        "blockType": "Domain Name",
                        "impact": "High",
                        "role": "Payload Distribution",
                        "data": "payload-drop.net",
                    },
                ],
                "executableSet": [
                    {
                        "type": "Malicious Executable",
                        "severityLevel": "High",
                        "fileName": "invoice_details.exe",
                        "malwareFamily": [{"familyName": "AgentTesla"}],
                        "deliveryMechanisms": [{"mechanismName": "Email Attachment"}],
                        "md5Hex": "d41d8cd98f00b204e9800998ecf8427e",
                        "hashes": [
                            {
                                "type": "MD5",
                                "value": "d41d8cd98f00b204e9800998ecf8427e",
                            },
                            {
                                "type": "SHA256",
                                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            },
                        ],
                    }
                ],
            },
        }
    )
    connector.client.get_report_pdf = AsyncMock(
        return_value={
            "name": "Report-382064.pdf",
            "mime_type": "application/pdf",
            "data": base64.b64encode(b"%PDF-1.4... (binary content)").decode("utf-8"),
            "no_trigger_import": False,
        }
    )

    are_observables_promoted = True

    def check_if_observables_promoted(intelligence):
        nonlocal are_observables_promoted
        for observable in intelligence:
            if isinstance(
                observable,
                (
                    stix2.URL,
                    stix2.File,
                    stix2.EmailAddress,
                    stix2.EmailMessage,
                    stix2.IPv4Address,
                    stix2.DomainName,
                    stix2.AutonomousSystem,
                ),
            ):
                are_observables_promoted &= observable.x_opencti_create_indicator

    connector._send_intelligence = Mock(side_effect=check_if_observables_promoted)

    connector.process_message()

    assert are_observables_promoted
