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
