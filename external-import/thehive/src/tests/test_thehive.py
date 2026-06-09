import time
import unittest
from unittest.mock import MagicMock, patch, sentinel

import thehive as module


@patch.object(module, "TheHiveApi")
@patch.object(module, "OpenCTIConnectorHelper")
@patch.object(module, "yaml")
@patch.object(module, "os")
class TheHiveTest(unittest.TestCase):

    def test_process_comments_simple(self, m_os, m_yaml, m_helper, m_thehiveapi):
        """testing the calls made to hive API by the process_comments function"""
        _now = int(time.time() * 1000)
        _case = MagicMock()
        _case_values = {
            "_id": sentinel.case_id,
            "title": MagicMock(),
            "_createdAt": _now,
        }
        _case.get.side_effect = _case_values.get

        _stix_case = MagicMock()
        _stix_case.id = sentinel.stix_case_id

        _comment = "this is my comment"
        _case_comment = MagicMock()
        _case_comment_values = {"message": _comment, "_createdAt": _now}
        _case_comment.get.side_effect = _case_comment_values.get
        m_thehiveapi.return_value.case.find_comments.return_value = [_case_comment]

        m_os.path.isfile.return_value = False
        _connector = module.TheHive()

        processed_comments = _connector.process_comments(_case, _stix_case)

        m_thehiveapi.return_value.case.find_comments.assert_called_with(
            case_id=sentinel.case_id,
            sortby=module.Asc("_createdAt"),
            paginate=module.Paginate(start=0, end=10),
        )
        self.assertEqual(len(processed_comments), 1)
        self.assertEqual(processed_comments[0]["type"], "note")
        self.assertEqual(processed_comments[0]["content"], _comment)
        self.assertEqual(processed_comments[0]["object_refs"], [sentinel.stix_case_id])

    def test_process_comments_duplicate(self, m_os, m_yaml, m_helper, m_thehiveapi):
        """testing process_comments proper handling of duplicates"""
        _now = int(time.time() * 1000)
        _case = MagicMock()
        _case_values = {
            "_id": sentinel.case_id,
            "title": MagicMock(),
            "_createdAt": _now,
        }
        _case.get.side_effect = _case_values.get

        _stix_case = MagicMock()
        _stix_case.id = sentinel.stix_case_id

        _comment = "this is my comment"
        _case_comment = MagicMock()
        _case_comment_values = {"message": _comment, "_createdAt": _now}
        _case_comment.get.side_effect = _case_comment_values.get
        m_thehiveapi.return_value.case.find_comments.return_value = [
            _case_comment,
            _case_comment,
        ]

        m_os.path.isfile.return_value = False
        _connector = module.TheHive()

        processed_comments = _connector.process_comments(_case, _stix_case)

        m_thehiveapi.return_value.case.find_comments.assert_called_with(
            case_id=sentinel.case_id,
            sortby=module.Asc("_createdAt"),
            paginate=module.Paginate(start=0, end=10),
        )
        self.assertEqual(len(processed_comments), 2)
        self.assertEqual(processed_comments[0]["type"], "note")
        self.assertEqual(processed_comments[0]["type"], processed_comments[1]["type"])
        self.assertEqual(processed_comments[0]["content"], _comment)
        self.assertEqual(
            processed_comments[0]["content"], processed_comments[1]["content"]
        )
        self.assertEqual(processed_comments[0]["object_refs"], [sentinel.stix_case_id])
        self.assertEqual(
            processed_comments[0]["object_refs"], processed_comments[1]["object_refs"]
        )

        self.assertEqual(processed_comments[0]["id"], processed_comments[1]["id"])

    def test_process_items_respects_tlp_filter(
        self, m_os, m_yaml, m_helper, m_thehiveapi
    ):
        """process_items must skip items whose TLP is not in import_only_tlp and
        send allowed items exactly once, under the work_id."""
        m_os.path.isfile.return_value = False
        _connector = module.TheHive()
        _connector.current_state = {}
        _connector.thehive_import_from_date = 0
        _connector.thehive_import_only_tlp = ["2"]

        _now = int(time.time() * 1000)
        allowed = {"tlp": 2, "title": "allowed", "_updatedAt": _now, "_createdAt": _now}
        blocked = {"tlp": 3, "title": "blocked", "_updatedAt": _now, "_createdAt": _now}

        process_func = MagicMock(return_value=sentinel.bundle)
        work_id = _connector.helper.api.work.initiate_work.return_value

        _connector.process_items(
            type="case",
            items=[allowed, blocked],
            process_func=process_func,
            last_date_key="last_case_date",
        )

        # Only the allowed item is converted and sent, and it carries the work_id.
        process_func.assert_called_once_with(allowed, work_id)
        _connector.helper.send_stix2_bundle.assert_called_once_with(
            sentinel.bundle, work_id=work_id
        )

    def test_generate_case_bundle_does_not_self_send_main_bundle(
        self, m_os, m_yaml, m_helper, m_thehiveapi
    ):
        """The main case bundle must be returned for process_items to send under the
        work_id, not sent from within generate_case_bundle. The previous self-send
        bypassed the TLP filter and ingested every case twice."""
        m_os.path.isfile.return_value = False
        _connector = module.TheHive()
        _connector.thehive_import_attachments = False

        _connector.process_markings = MagicMock(return_value=[])
        _connector.process_observables = MagicMock(return_value=([], []))
        _connector.process_main_case = MagicMock(return_value=MagicMock())
        _connector.process_tasks = MagicMock(return_value=[])
        _connector.process_comments = MagicMock(return_value=[])
        _connector.helper.stix2_create_bundle.return_value = sentinel.bundle

        _now = int(time.time() * 1000)
        case = {"title": "my case", "_createdAt": _now}

        result = _connector.generate_case_bundle(case)

        _connector.helper.send_stix2_bundle.assert_not_called()
        self.assertEqual(result, sentinel.bundle)

    def test_process_observables_and_relations_handles_missing_id(
        self, m_os, m_yaml, m_helper, m_thehiveapi
    ):
        """When the converted observable has no `id`, the function must return
        (observable, None) instead of raising UnboundLocalError."""
        m_os.path.isfile.return_value = False
        _connector = module.TheHive()

        observable_without_id = object()  # truthy, but has no `id` attribute
        _connector.convert_observable = MagicMock(return_value=observable_without_id)

        stix_observable, relation = _connector.process_observables_and_relations(
            observable={}, markings=[], stix_incident=MagicMock()
        )

        self.assertIs(stix_observable, observable_without_id)
        self.assertIsNone(relation)
