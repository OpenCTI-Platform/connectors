import unittest
from datetime import timedelta

from connector.settings import ConnectorSettings


def _stub_settings(**thehive_overrides):
    """Build a `ConnectorSettings` instance from a fixed config dict, bypassing
    env/YAML discovery (mirrors the connectors-sdk template testing pattern)."""
    thehive_section = {
        "url": "https://thehive.test",
        "api_key": "api-key",
        "organization_name": "MyOrg",
    }
    thehive_section.update(thehive_overrides)

    class StubSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _data, handler):
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {
                        "id": "connector-id",
                        "name": "TheHive",
                        "scope": "thehive",
                        "log_level": "info",
                    },
                    "thehive": thehive_section,
                }
            )

    return StubSettings()


class SettingsTest(unittest.TestCase):

    def test_required_fields_and_defaults(self):
        settings = _stub_settings()
        thehive = settings.thehive

        # Required values
        self.assertEqual(str(thehive.url), "https://thehive.test/")
        self.assertEqual(thehive.api_key, "api-key")
        self.assertEqual(thehive.organization_name, "MyOrg")

        # Defaults preserved from the legacy connector behaviour
        self.assertTrue(thehive.check_ssl)
        self.assertTrue(thehive.import_alerts)
        self.assertFalse(thehive.import_attachments)
        self.assertIsNone(thehive.import_from_date)
        self.assertEqual(thehive.import_only_tlp, ["0", "1", "2", "3", "4"])
        self.assertEqual(
            thehive.severity_mapping,
            ["1:01 - low", "2:02 - medium", "3:03 - high", "4:04 - critical"],
        )
        self.assertEqual(thehive.case_status_mapping, [])
        self.assertEqual(thehive.task_status_mapping, [])
        self.assertEqual(thehive.alert_status_mapping, [])
        self.assertEqual(thehive.user_mapping, [])
        self.assertEqual(thehive.case_tag_whitelist, [])
        self.assertEqual(thehive.interval, 5)

        # Connector-level defaults
        self.assertEqual(settings.connector.name, "TheHive")
        self.assertEqual(settings.connector.duration_period, timedelta(minutes=5))

    def test_comma_separated_strings_are_parsed_into_lists(self):
        settings = _stub_settings(
            import_only_tlp="1,2",
            case_tag_whitelist="TAG_OK, TAG_GOOD",
            severity_mapping="1:low,2:high",
        )
        self.assertEqual(settings.thehive.import_only_tlp, ["1", "2"])
        self.assertEqual(settings.thehive.case_tag_whitelist, ["TAG_OK", "TAG_GOOD"])
        self.assertEqual(settings.thehive.severity_mapping, ["1:low", "2:high"])

    def test_empty_mapping_string_becomes_empty_list(self):
        settings = _stub_settings(case_status_mapping="")
        self.assertEqual(settings.thehive.case_status_mapping, [])

    def test_to_helper_config_returns_dict(self):
        helper_config = _stub_settings().to_helper_config()
        self.assertIsInstance(helper_config, dict)
        self.assertIn("opencti", helper_config)
        self.assertIn("connector", helper_config)


if __name__ == "__main__":
    unittest.main()
