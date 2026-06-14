"""Tests for software_toolkit batch processor configuration and date extraction function."""

from unittest.mock import MagicMock

from connector.src.custom.configs.software_toolkit.batch_processor_config_software_toolkit import (
    SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG,
    software_toolkit_extract_stix_date,
)

# =====================
# software_toolkit_extract_stix_date tests
# =====================


class TestSoftwareToolkitExtractStixDate:
    """Tests for software_toolkit_extract_stix_date function (line 33 coverage)."""

    def test_given_tool_object_when_extract_date_then_returns_date(self):
        """When stix_object is type 'tool' with modified date, returns date string."""
        from datetime import datetime, timezone

        stix_object = MagicMock()
        stix_object.type = "tool"
        stix_object.modified = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        result = software_toolkit_extract_stix_date(stix_object)

        assert result is not None
        assert "2024" in result

    def test_given_non_tool_object_when_extract_date_then_returns_none(self):
        """When stix_object type is not 'tool', returns None."""
        stix_object = MagicMock()
        stix_object.type = "malware"
        stix_object.modified = "2024-06-15T12:00:00+00:00"

        result = software_toolkit_extract_stix_date(stix_object)

        assert result is None

    def test_given_identity_object_when_extract_date_then_returns_none(self):
        """Identity objects are ignored and None is returned."""
        stix_object = MagicMock()
        stix_object.type = "identity"

        result = software_toolkit_extract_stix_date(stix_object)

        assert result is None

    def test_given_tool_object_without_modified_when_extract_date_then_returns_none(
        self,
    ):
        """When tool object has no modified date, returns None."""
        _ = MagicMock(spec=[])  # no attributes
        # Force type attribute to be "tool" via __getattr__
        type_mock = MagicMock()
        type_mock.__str__ = lambda self: "tool"

        stix_obj = MagicMock()
        stix_obj.type = "tool"
        del stix_obj.modified  # remove the modified attribute
        stix_obj.modified = None

        result = software_toolkit_extract_stix_date(stix_obj)

        assert result is None


# =====================
# SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG tests
# =====================


class TestSoftwareToolkitBatchProcessorConfig:
    """Tests for SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG configuration object."""

    def test_config_has_correct_state_key(self):
        """Config uses the expected state key for software toolkits."""
        assert (
            SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG.state_key
            == "software_toolkit_next_cursor_start_date"
        )

    def test_config_has_correct_entity_type(self):
        """Config targets stix_objects entity type."""
        assert SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG.entity_type == "stix_objects"

    def test_config_has_date_extraction_function(self):
        """Config has a callable date_extraction_function."""
        assert callable(
            SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG.date_extraction_function
        )

    def test_config_date_extraction_function_is_software_toolkit_extractor(self):
        """The date_extraction_function in config is software_toolkit_extract_stix_date."""
        from datetime import datetime, timezone

        stix_object = MagicMock()
        stix_object.type = "tool"
        stix_object.modified = datetime(2024, 1, 1, tzinfo=timezone.utc)

        result = SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG.date_extraction_function(
            stix_object
        )
        assert result is not None
