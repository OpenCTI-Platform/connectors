"""Progress messages on the platform work (issue #7862)."""

import unittest

from tests_virustotal.test_virustotal import _make_connector
from virustotal.processors import URLProcessor

NOT_FOUND = {"error": {"code": "NotFoundError", "message": "not found"}}
FOUND = {"data": {"id": "x", "attributes": {}}}


def _make_url_processor(work_id):
    connector = _make_connector()
    connector.url_upload_unseen = True
    connector.helper.work_id = work_id
    connector.client.get_url_info.side_effect = [NOT_FOUND, FOUND]
    connector.client.upload_url.return_value = "analysis-id"
    entity = {"entity_type": "Url", "observable_value": "http://example.com"}
    return connector, URLProcessor(connector, [], {"id": "x"}, entity, False)


class TestWorkProgress(unittest.TestCase):
    def test_unseen_url_is_uploaded_without_a_work_id(self):
        connector, processor = _make_url_processor(None)

        json_data = processor._fetch_data()

        self.assertEqual(json_data, FOUND)
        connector.helper.api.work.to_received.assert_not_called()
        connector.client.upload_url.assert_called_once_with("http://example.com")
        connector.helper.log_debug.assert_called_once()

    def test_unseen_url_reports_progress_on_the_work(self):
        connector, processor = _make_url_processor("work-1")

        json_data = processor._fetch_data()

        self.assertEqual(json_data, FOUND)
        connector.helper.api.work.to_received.assert_called_once()
        self.assertEqual(
            connector.helper.api.work.to_received.call_args.args[0], "work-1"
        )
        connector.client.upload_url.assert_called_once_with("http://example.com")

    def test_report_progress_without_work_id_only_logs(self):
        connector, processor = _make_url_processor("")

        processor._report_progress("message")

        connector.helper.api.work.to_received.assert_not_called()
        connector.helper.log_debug.assert_called_once_with("message")


if __name__ == "__main__":
    unittest.main()
