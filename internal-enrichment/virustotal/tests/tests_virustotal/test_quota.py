"""VirusTotal quota (HTTP 429) handling unit tests."""

import io
import json
import unittest
from unittest.mock import MagicMock, patch

import requests
import urllib3
from tests_virustotal.test_ip_resolutions import THREE_PAGES, _make_processor
from tests_virustotal.test_virustotal import _make_connector
from virustotal.client import (
    QUOTA_MAX_WAIT,
    VirusTotalClient,
    VirusTotalQuotaExceededError,
)
from virustotal.processors import FileProcessor, IPProcessor, URLProcessor

QUOTA_BODY = {"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}}
OK_BODY = {"data": {"id": "x", "attributes": {}}}


def _response(status: int, body: dict, retry_after: str | None = None):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    if retry_after is not None:
        response.headers["Retry-After"] = retry_after
    return response


def _make_client() -> VirusTotalClient:
    helper = MagicMock()
    helper.connector_id = "test-connector-uuid"
    return VirusTotalClient(helper, "https://www.virustotal.com/api/v3", "fake-api-key")


@patch("virustotal.client.time.sleep")
class TestClientQuota(unittest.TestCase):
    """HTTP 429 handling of VirusTotalClient."""

    def test_daily_quota_raises_without_waiting(self, sleep):
        client = _make_client()
        with patch.object(
            requests.Session,
            "get",
            return_value=_response(429, QUOTA_BODY, retry_after="8746"),
        ) as get:
            with self.assertRaises(VirusTotalQuotaExceededError) as ctx:
                client.get_file_info("abc")
        get.assert_called_once()
        sleep.assert_not_called()
        self.assertIn("QuotaExceededError", str(ctx.exception))
        self.assertIn("8746", str(ctx.exception))

    def test_daily_quota_is_not_retried_by_urllib3(self, sleep):
        # Goes through the mounted HTTPAdapter and its urllib3 Retry: only the
        # connection-level request is faked.
        client = _make_client()
        with (
            patch(
                "urllib3.connectionpool.HTTPConnectionPool._make_request",
                side_effect=lambda *args, **kwargs: urllib3.HTTPResponse(
                    body=io.BytesIO(json.dumps(QUOTA_BODY).encode()),
                    status=429,
                    headers={"Retry-After": "8746"},
                    preload_content=False,
                ),
            ) as make_request,
            patch("urllib3.util.retry.time.sleep") as urllib3_sleep,
        ):
            with self.assertRaises(VirusTotalQuotaExceededError):
                client.get_file_info("abc")
        make_request.assert_called_once()
        urllib3_sleep.assert_not_called()
        sleep.assert_not_called()

    def test_minute_quota_waits_once_and_retries(self, sleep):
        client = _make_client()
        with patch.object(
            requests.Session,
            "get",
            side_effect=[
                _response(429, QUOTA_BODY, retry_after="12"),
                _response(200, OK_BODY),
            ],
        ) as get:
            result = client.get_file_info("abc")
        self.assertEqual(result, OK_BODY)
        self.assertEqual(get.call_count, 2)
        sleep.assert_called_once_with(12)

    def test_second_429_raises(self, sleep):
        client = _make_client()
        with patch.object(
            requests.Session,
            "get",
            return_value=_response(429, QUOTA_BODY, retry_after="12"),
        ) as get:
            with self.assertRaises(VirusTotalQuotaExceededError):
                client.get_file_info("abc")
        self.assertEqual(get.call_count, 2)
        sleep.assert_called_once_with(12)

    def test_missing_retry_after_waits_the_cap(self, sleep):
        client = _make_client()
        with patch.object(
            requests.Session,
            "get",
            side_effect=[_response(429, {}), _response(200, OK_BODY)],
        ):
            self.assertEqual(client.get_file_info("abc"), OK_BODY)
        sleep.assert_called_once_with(QUOTA_MAX_WAIT)

    def test_retry_after_above_cap_raises(self, sleep):
        client = _make_client()
        with patch.object(
            requests.Session,
            "get",
            return_value=_response(
                429, QUOTA_BODY, retry_after=str(QUOTA_MAX_WAIT + 1)
            ),
        ):
            with self.assertRaises(VirusTotalQuotaExceededError):
                client.get_file_info("abc")
        sleep.assert_not_called()

    def test_other_http_errors_still_return_the_error_body(self, sleep):
        client = _make_client()
        not_found = {"error": {"code": "NotFoundError", "message": "not found"}}
        with patch.object(
            requests.Session, "get", return_value=_response(404, not_found)
        ):
            self.assertEqual(client.get_file_info("abc"), not_found)
        sleep.assert_not_called()

    def test_upload_raises_on_quota(self, sleep):
        client = _make_client()
        with patch(
            "virustotal.client.requests.post",
            return_value=_response(429, QUOTA_BODY, retry_after="3600"),
        ):
            with self.assertRaises(VirusTotalQuotaExceededError):
                client.upload_url("http://example.com")

    def test_pagination_keeps_collected_pages_on_quota(self, sleep):
        client = _make_client()
        page_1 = {
            "data": [{"id": "a"}],
            "links": {"next": "https://www.virustotal.com/api/v3/next-page"},
        }
        with patch.object(
            client,
            "_query",
            side_effect=[page_1, VirusTotalQuotaExceededError("quota")],
        ):
            result = client.get_gti_relationship(
                "ip_addresses", "1.2.3.4", "malware_families", 10
            )
        self.assertEqual(result["data"], [{"id": "a"}])


class TestProcessorsQuota(unittest.TestCase):
    """Quota errors fail the primary lookup and skip the optional ones."""

    def test_primary_lookup_quota_fails_the_enrichment(self):
        connector = _make_connector()
        connector.client.get_ip_info.side_effect = VirusTotalQuotaExceededError(
            "VirusTotal quota exceeded"
        )
        entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        processor = IPProcessor(connector, [], {"id": "x"}, entity, False)
        with self.assertRaises(VirusTotalQuotaExceededError):
            processor.process()

    def test_indicator_quota_fails_the_enrichment(self):
        connector = _make_connector()
        connector.client.get_domain_info.side_effect = VirusTotalQuotaExceededError(
            "VirusTotal quota exceeded"
        )
        connector.helper.get_attribute_in_extension.return_value = [
            {"type": "domain-name", "value": "example.com"}
        ]
        data = {
            "stix_objects": [],
            "stix_entity": {"id": "x"},
            "enrichment_entity": {
                "entity_type": "Indicator",
                "name": "example.com",
                "objectMarking": [],
            },
        }
        with self.assertRaises(VirusTotalQuotaExceededError):
            connector._process_message(data)

    def test_gti_relationship_quota_is_skipped(self):
        connector = _make_connector()
        connector.gti_include_malware_families = True
        connector.gti_include_reports = True
        connector.client.get_gti_relationship.side_effect = [
            VirusTotalQuotaExceededError("quota"),
            {"data": [{"id": "r"}]},
        ]
        entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        processor = IPProcessor(connector, [], {"id": "x"}, entity, False)
        builder = MagicMock()
        processor._enrich_gti_relationships(builder)
        builder.create_malware_family.assert_not_called()
        builder.create_report.assert_called_once_with({"id": "r"})

    def test_ip_resolutions_quota_stops_paging(self):
        pages = [THREE_PAGES[0], VirusTotalQuotaExceededError("quota")]
        processor, helper = _make_processor(pages)
        result = processor.process()
        self.assertEqual(processor.client.get_ip_resolutions_page.call_count, 2)
        self.assertTrue(
            result.endswith(
                "resolutions: kept 2 of 2 fetched (1 pages, stopped: error)"
            ),
            result,
        )
        # Main bundle, then the resolutions of the first page.
        self.assertEqual(helper.send_stix2_bundle.call_count, 2)

    def test_url_last_serving_ip_quota_is_skipped(self):
        connector = _make_connector()
        connector.client.get_url_related_objects.side_effect = (
            VirusTotalQuotaExceededError("quota")
        )
        entity = {"entity_type": "Url", "observable_value": "http://example.com"}
        processor = URLProcessor(connector, [], {"id": "x"}, entity, False)
        with patch("virustotal.processors.entity.VirusTotalBuilder") as builder_class:
            processor._make_builder(OK_BODY)
        self.assertEqual(builder_class.call_args.kwargs["url_related_object_data"], {})

    def test_url_upload_quota_is_not_wrapped(self):
        connector = _make_connector()
        connector.url_upload_unseen = True
        connector.client.get_url_info.return_value = {
            "error": {"code": "NotFoundError", "message": "not found"}
        }
        connector.client.upload_url.side_effect = VirusTotalQuotaExceededError(
            "VirusTotal quota exceeded"
        )
        entity = {"entity_type": "Url", "observable_value": "http://example.com"}
        processor = URLProcessor(connector, [], {"id": "x"}, entity, False)
        with self.assertRaises(VirusTotalQuotaExceededError):
            processor.process()

    def test_yara_ruleset_quota_is_skipped(self):
        connector = _make_connector()
        connector.file_create_note_full_report = False
        connector.client.get_yara_ruleset.side_effect = VirusTotalQuotaExceededError(
            "quota"
        )
        entity = {"entity_type": "StixFile", "observable_value": "abc"}
        processor = FileProcessor(connector, [], {"id": "x"}, entity, True)
        builder = MagicMock()
        json_data = {
            "data": {
                "attributes": {
                    "sha256": "abc",
                    "crowdsourced_yara_results": [{"ruleset_id": "r1"}],
                }
            }
        }
        processor._enrich(builder, json_data)
        builder.create_yara.assert_not_called()
        builder.update_labels.assert_called_once()
        self.assertNotIn("r1", connector.yara_cache)
