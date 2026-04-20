import unittest
from unittest.mock import MagicMock, mock_open, patch, sentinel

import chapsvision as module


@patch.object(module, "base64")
@patch.object(module, "OpenCTIConnectorHelper")
@patch.object(module.Chapsvision, "_generate_id_for_media_content")
@patch.object(module, "os")
class ChapsvisionTest(unittest.TestCase):

    def test_generate_micro_blogging_link_only_single(
        self, m_os, m_gen_id, m_helper, m_base64
    ):
        """testing serialization by generate_micro_blogging for link only data (single)"""
        _link = sentinel.link
        _broadcaster_category = sentinel.broadcaster_category
        _doc = {
            "link": _link,
            "broadcaster": MagicMock(),
            "broadcaster_category": _broadcaster_category,
        }

        m_os.path.isfile.return_value = False
        with patch("builtins.open", mock_open()) as m_open:
            _connector = module.Chapsvision()

        objects = _connector.generate_micro_blogging(_doc)

        m_gen_id.assert_called_once_with(sentinel.link)
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0]["media_category"], sentinel.broadcaster_category)
        self.assertEqual(objects[0]["url"], sentinel.link)

    def test_generate_micro_blogging_link_only_duplicate(
        self, m_os, m_gen_id, m_helper, m_base64
    ):
        """testing serialization by generate_micro_blogging for link only data (duplicate)"""
        _link = sentinel.link
        _broadcaster_category = sentinel.broadcaster_category
        _doc = {
            "link": _link,
            "broadcaster": MagicMock(),
            "broadcaster_category": _broadcaster_category,
        }

        m_os.path.isfile.return_value = False
        with patch("builtins.open", mock_open()) as m_open:
            _connector = module.Chapsvision()

        objects_first_run = _connector.generate_micro_blogging(_doc)
        objects_second_run = _connector.generate_micro_blogging(_doc)

        self.assertEqual(m_gen_id._mock_call_count, 2)
        self.assertEqual(len(objects_first_run), 1)
        self.assertEqual(len(objects_second_run), 1)
        self.assertEqual(
            objects_first_run[0]["media_category"], sentinel.broadcaster_category
        )
        self.assertEqual(
            objects_first_run[0]["media_category"],
            objects_second_run[0]["media_category"],
        )
        self.assertEqual(objects_first_run[0]["url"], sentinel.link)
        self.assertEqual(objects_first_run[0]["url"], objects_second_run[0]["url"])
        self.assertEqual(objects_first_run[0]["id"], objects_second_run[0]["id"])

    def test_generate_website_single(self, m_os, m_gen_id, m_helper, m_base64):
        """testing serialization by generate_website (single)"""
        _link = sentinel.link
        _broadcaster_category = sentinel.broadcaster_category
        _doc = {
            "link": _link,
            "content_provider": MagicMock(),
            "broadcaster_category": _broadcaster_category,
        }

        m_os.path.isfile.return_value = False
        with patch("builtins.open", mock_open()) as m_open:
            _connector = module.Chapsvision()

        objects = _connector.generate_website(_doc)

        m_gen_id.assert_called_once_with(sentinel.link)
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0]["media_category"], sentinel.broadcaster_category)
        self.assertEqual(objects[0]["url"], sentinel.link)

    def test_generate_website_duplicate(self, m_os, m_gen_id, m_helper, m_base64):
        """testing serialization by generate_website (duplicate)"""
        _link = sentinel.link
        _broadcaster_category = sentinel.broadcaster_category
        _doc = {
            "link": _link,
            "content_provider": MagicMock(),
            "broadcaster_category": _broadcaster_category,
        }

        m_os.path.isfile.return_value = False
        with patch("builtins.open", mock_open()) as m_open:
            _connector = module.Chapsvision()

        objects_first_run = _connector.generate_website(_doc)
        objects_second_run = _connector.generate_website(_doc)

        self.assertEqual(m_gen_id._mock_call_count, 2)
        self.assertEqual(len(objects_first_run), 1)
        self.assertEqual(len(objects_second_run), 1)
        self.assertEqual(
            objects_first_run[0]["media_category"], sentinel.broadcaster_category
        )
        self.assertEqual(
            objects_first_run[0]["media_category"],
            objects_second_run[0]["media_category"],
        )
        self.assertEqual(objects_first_run[0]["url"], sentinel.link)
        self.assertEqual(objects_first_run[0]["url"], objects_second_run[0]["url"])
        self.assertEqual(objects_first_run[0]["id"], objects_second_run[0]["id"])

    def test_generate_messaging_link_only_single(
        self, m_os, m_gen_id, m_helper, m_base64
    ):
        """testing serialization by generate_messaging_link for link only data (single)"""
        _link = sentinel.link
        _broadcaster_category = sentinel.broadcaster_category
        _doc = {
            "link": _link,
            "broadcaster": MagicMock(),
            "broadcaster_category": _broadcaster_category,
        }

        m_os.path.isfile.return_value = False
        with patch("builtins.open", mock_open()) as m_open:
            _connector = module.Chapsvision()

        objects = _connector.generate_messaging(_doc)

        m_gen_id.assert_called_once_with(sentinel.link)
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0]["media_category"], sentinel.broadcaster_category)
        self.assertEqual(objects[0]["url"], sentinel.link)

    def test_generate_messaging_link_only_duplicate(
        self, m_os, m_gen_id, m_helper, m_base64
    ):
        """testing serialization by generate_messaging_link for link only data (duplicate)"""
        _link = sentinel.link
        _broadcaster_category = sentinel.broadcaster_category
        _doc = {
            "link": _link,
            "broadcaster": MagicMock(),
            "broadcaster_category": _broadcaster_category,
        }

        m_os.path.isfile.return_value = False
        with patch("builtins.open", mock_open()) as m_open:
            _connector = module.Chapsvision()

        objects_first_run = _connector.generate_messaging(_doc)
        objects_second_run = _connector.generate_messaging(_doc)

        self.assertEqual(m_gen_id._mock_call_count, 2)
        self.assertEqual(len(objects_first_run), 1)
        self.assertEqual(len(objects_second_run), 1)
        self.assertEqual(
            objects_first_run[0]["media_category"], sentinel.broadcaster_category
        )
        self.assertEqual(
            objects_first_run[0]["media_category"],
            objects_second_run[0]["media_category"],
        )
        self.assertEqual(objects_first_run[0]["url"], sentinel.link)
        self.assertEqual(objects_first_run[0]["url"], objects_second_run[0]["url"])
        self.assertEqual(objects_first_run[0]["id"], objects_second_run[0]["id"])
