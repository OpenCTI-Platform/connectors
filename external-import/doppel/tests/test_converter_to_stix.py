from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_helper():
    """Create a fully mocked OpenCTIConnectorHelper."""
    helper = MagicMock()
    # Mocking standard logger methods
    helper.connector_logger = MagicMock()

    # Mock OpenCTI API sub-attributes
    helper.api.stix_cyber_observable = MagicMock()
    helper.api.stix_domain_object = MagicMock()
    helper.api.indicator = MagicMock()
    helper.api.case_rft = MagicMock()

    # Simple bundle creation bypass
    helper.stix2_create_bundle.side_effect = lambda objects: objects
    return helper


@pytest.fixture
def converter(mock_helper):
    """Instantiate the converter with mocked helper and configurations."""
    # Corrected the class name import to match converter_to_stix.py
    from doppel.converter_to_stix import ConverterToStix

    with patch.object(ConverterToStix, "create_author") as mock_author, patch.object(
        ConverterToStix, "_create_tlp_marking"
    ) as mock_tlp:

        # Used properly formatted UUID strings to comply with stix2 validation
        mock_author.return_value.id = "identity--2d1d6d54-f8a4-44cf-9844-311b017b2b2b"
        mock_tlp.return_value.id = (
            "marking-definition--613f2e26-407d-48c7-9ec7-7a84c5f5a897"
        )

        conv = ConverterToStix(
            helper=mock_helper,
            tlp_level="clear",
            enable_grouping_case=False,
            enable_rft_case=False,
        )
        return conv


# -------------------------------------------------------------------------
# Test Cases
# -------------------------------------------------------------------------


def test_convert_alerts_to_stix_telco_product(converter):
    """
    Scenario 1: Test 'telco' product path.
    Covers: _handle_observable_creation (phone branch), _create_observable,
            _handle_indicators_new (phone mapping), and _handle_note_addition.
    """
    # Given an alert with a telco product type in an actioned state
    alert = {
        "id": "alert_telco_123",
        "product": "telco",
        "entity": "+1234567890",
        "queue_state": "actioned",
        "score": 0.9,
        "created_at": "2026-06-11T09:00:00Z",
    }

    # Mocking behaviors: No existing observable or existing indicators
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []

    # When
    result = converter.convert_alerts_to_stix([alert])

    # Then verify bundle structure
    assert len(result) > 2
    types_created = [
        obj["type"] if isinstance(obj, dict) else obj.type for obj in result
    ]

    assert "phone" in types_created or "phone-number" in str(types_created)
    assert "indicator" in types_created
    assert "note" in types_created


def test_convert_alerts_to_stix_domains_product_with_ip(converter):
    """
    Scenario 2: Test heavy 'domains' path including an attached IP address.
    Covers: _handle_observable_creation (domain + IP handling),
            _handle_domain_ip_relationship (resolves-to),
            _handle_indicators_new (domain + IP indicators).
    """
    # Given a domains alert containing nested root_domain IP configuration
    alert = {
        "id": "alert_domain_456",
        "product": "domains",
        "entity": "malicious-domain.com",
        "queue_state": "taken_down",
        "score": 0.95,
        "entity_content": {
            "root_domain": {"domain": "malicious-domain.com", "ip_address": "1.2.3.4"}
        },
        "created_at": "2026-06-11T09:00:00Z",
    }

    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []

    # When
    result = converter.convert_alerts_to_stix([alert])

    # Then verify that the domain and IP both triggered indicators and cross-relationship
    serialized_bundle = str(result)

    assert "domain-name" in serialized_bundle
    assert "ipv4-addr" in serialized_bundle
    assert "resolves-to" in serialized_bundle
    assert "based-on" in serialized_bundle


def test_convert_alerts_to_stix_existing_indicator_reversion(converter):
    """
    Scenario 3: Test reversion state updates against an already existing indicator.
    Covers: _find_indicators_by_alert_id_or_entity_value,
            _handle_indicators_existing, setting revoked=True,
            and managed prefix label cleanups via _handle_labels.
    """
    # Given an alert moving to an un-actioned/reverted state
    alert = {
        "id": "alert_revert_789",
        "product": "domains",
        "entity": "reverted-domain.com",
        "queue_state": "resolved",  # Not a takedown state -> triggers reversion
        "score": 0.4,
        "created_at": "2026-06-11T09:00:00Z",
    }

    # Mocking that the indicator already exists in OpenCTI.
    # Real pycti API responses return "id" as an internal OpenCTI UUID (no "--"),
    # not a STIX identifier — only "standard_id" is the valid STIX id.
    mock_indicator = {
        "id": "e5a6f272-3595-4673-9097-f5be0df2a926",
        "standard_id": "indicator--e5a6f272-3595-4673-9097-f5be0df2a926",
        "objectLabel": [
            {"value": "queue_state:taken_down"},
            {"value": "severity:high"},
        ],
    }
    converter.helper.api.indicator.list.return_value = [mock_indicator]
    converter.helper.api.stix_cyber_observable.read.return_value = {
        "id": "domain-name--b638b9d8-967c-4861-bfdf-d97e2030f065",
        "objectLabel": [],
    }

    # When
    converter.convert_alerts_to_stix([alert])

    # Then verify that the update_field API was called to revoke the indicator
    converter.helper.api.indicator.update_field.assert_called_with(
        id="e5a6f272-3595-4673-9097-f5be0df2a926",
        input={"key": "revoked", "value": True},
    )


def test_convert_alerts_to_stix_with_optional_cases_enabled(converter):
    """
    Scenario 4: Test functional processing flags enabled (Grouping and RFT Cases).
    Covers: _handle_grouping_case_creation, _create_case_rft,
            _handle_rft_case, and all internal structural cross-linking relationships.
    """
    # Explicitly enable the new config switches introduced in the PR
    converter.enable_grouping_case = True
    converter.enable_rft_case = True

    # Given an active takedown alert structure
    alert = {
        "id": "alert_cases_000",
        "product": "domains",
        "entity": "case-handling-domain.com",
        "queue_state": "actioned",
        "score": 0.85,
        "created_at": "2026-06-11T09:00:00Z",
    }

    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.stix_domain_object.read.return_value = (
        None  # Grouping case new
    )
    converter.helper.api.indicator.list.return_value = []
    converter.helper.api.case_rft.list.return_value = []  # RFT Case new

    # When
    result = converter.convert_alerts_to_stix([alert])

    # Then check for Case creations within the final payload stream
    serialized_bundle = str(result)

    assert "grouping" in serialized_bundle
    assert "case-rft" in serialized_bundle
    assert "related-to" in serialized_bundle


def _domains_alert(alert_id="alert_x", queue_state="actioned", **extra):
    alert = {
        "id": alert_id,
        "product": "domains",
        "entity": "example-domain.com",
        "queue_state": queue_state,
        "score": 0.8,
        "created_at": "2026-06-11T09:00:00Z",
    }
    alert.update(extra)
    return alert


def test_other_product_type_creates_domain_observable_and_indicator(converter):
    """Covers the DOPPEL_ALERT_TYPES_EXCEPT_DOMAIN_AND_TELCO branch (observable + indicator)."""
    alert = _domains_alert(alert_id="alert_social_1")
    alert["product"] = "social_media"
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []

    result = converter.convert_alerts_to_stix([alert])

    bundle = str(result)
    assert "domain-name" in bundle
    assert "indicator" in bundle


def test_unsupported_product_type_skips_alert(converter):
    """Covers the unsupported-product warning + 'no observables -> skip' path."""
    alert = _domains_alert(alert_id="alert_unknown_1")
    alert["product"] = "totally_unknown"
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []

    result = converter.convert_alerts_to_stix([alert])

    # Only the author + tlp marking, no observable/indicator for the skipped alert.
    types_created = [
        obj["type"] if isinstance(obj, dict) else obj.type for obj in result
    ]
    assert "domain-name" not in types_created
    assert "indicator" not in types_created


def test_indicator_new_not_takedown_is_skipped(converter):
    """Covers _handle_indicators_new early return when not in takedown state."""
    alert = _domains_alert(alert_id="alert_monitor_1", queue_state="monitoring")
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []

    result = converter.convert_alerts_to_stix([alert])

    types_created = [
        obj["type"] if isinstance(obj, dict) else obj.type for obj in result
    ]
    # Observable is created but no indicator (not in takedown state).
    assert "domain-name" in types_created
    assert "indicator" not in types_created


def test_indicator_found_via_name_search_fallback(converter):
    """Covers the name-search fallback in _find_indicators_by_alert_id_or_entity_value."""
    alert = _domains_alert(alert_id="alert_name_fb", queue_state="actioned")
    matching_indicator = {
        "id": "indicator--e5a6f272-3595-4673-9097-f5be0df2a926",
        "standard_id": "indicator--e5a6f272-3595-4673-9097-f5be0df2a926",
        "objectLabel": [{"value": "queue_state:taken_down"}],
        "externalReferences": [{"external_id": "alert_name_fb"}],
    }
    # First call (workflow_id filter) -> empty; second call (name filter) -> match.
    converter.helper.api.indicator.list.side_effect = [[], [matching_indicator]]
    converter.helper.api.stix_cyber_observable.read.return_value = None

    converter.convert_alerts_to_stix([alert])

    # Existing indicator path updates revoked=False (actioned state).
    converter.helper.api.indicator.update_field.assert_called_with(
        id="indicator--e5a6f272-3595-4673-9097-f5be0df2a926",
        input={"key": "revoked", "value": False},
    )


def test_rft_case_new_creation(converter):
    """Covers _handle_rft_cases_new + RFT/observable relationship."""
    converter.enable_rft_case = True
    alert = _domains_alert(alert_id="alert_rft_new", queue_state="actioned")
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []
    converter.helper.api.case_rft.list.return_value = []

    result = converter.convert_alerts_to_stix([alert])

    bundle = str(result)
    assert "case-rft" in bundle
    assert "related-to" in bundle


def test_rft_case_new_not_takedown_is_skipped(converter):
    """Covers _handle_rft_cases_new early return when not in takedown state."""
    converter.enable_rft_case = True
    alert = _domains_alert(alert_id="alert_rft_skip", queue_state="monitoring")
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []
    converter.helper.api.case_rft.list.return_value = []

    result = converter.convert_alerts_to_stix([alert])

    assert "case-rft" not in str(result)


def test_rft_case_existing_revoked_on_reversion(converter):
    """Covers _handle_rft_cases_existing revoke + note + RFTCase labels."""
    converter.enable_rft_case = True
    alert = _domains_alert(alert_id="alert_rft_exist", queue_state="resolved")
    existing_case = {
        "id": "case-rft--11111111-1111-4111-8111-111111111111",
        "standard_id": "case-rft--11111111-1111-4111-8111-111111111111",
        "objectLabel": [{"value": "queue_state:taken_down"}],
    }
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []
    converter.helper.api.case_rft.list.return_value = [existing_case]

    converter.convert_alerts_to_stix([alert])

    converter.helper.api.stix_domain_object.update_field.assert_called_with(
        id="case-rft--11111111-1111-4111-8111-111111111111",
        input={"key": "revoked", "value": True},
    )


def test_rft_case_found_via_name_search_fallback(converter):
    """Covers the name-search fallback in _find_rft_cases_by_alert_id."""
    converter.enable_rft_case = True
    alert = _domains_alert(alert_id="alert_rft_name", queue_state="actioned")
    matching_case = {
        "id": "case-rft--22222222-2222-4222-8222-222222222222",
        "standard_id": "case-rft--22222222-2222-4222-8222-222222222222",
        "objectLabel": [],
        "externalReferences": [{"external_id": "alert_rft_name"}],
    }
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []
    # First call (workflow_id) -> empty; second (name) -> match.
    converter.helper.api.case_rft.list.side_effect = [[], [matching_case]]

    converter.convert_alerts_to_stix([alert])

    # Existing (actioned) -> revoked=False.
    converter.helper.api.stix_domain_object.update_field.assert_called_with(
        id="case-rft--22222222-2222-4222-8222-222222222222",
        input={"key": "revoked", "value": False},
    )


def test_grouping_case_existing_updates_labels(converter):
    """Covers the grouping-case label update path when the case already exists."""
    converter.enable_grouping_case = True
    alert = _domains_alert(alert_id="alert_group_lbl", queue_state="actioned")
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []
    # Grouping case 'exists' so the label-update branch runs.
    converter.helper.api.stix_domain_object.read.return_value = {
        "id": "grouping--33333333-3333-4333-8333-333333333333",
        "objectLabel": [{"value": "queue_state:old"}],
    }

    result = converter.convert_alerts_to_stix([alert])

    assert "grouping" in str(result)
    converter.helper.api.stix_domain_object.add_label.assert_called()


def test_create_tlp_marking_levels():
    """Direct coverage of the TLP marking mapping (patched out in the converter fixture)."""
    from doppel.converter_to_stix import ConverterToStix

    for level in ["white", "clear", "green", "amber", "red"]:
        marking = ConverterToStix._create_tlp_marking(level)
        assert marking is not None

    # TLP:CLEAR must be its own custom statement marking carrying
    # x_opencti_definition="TLP:CLEAR" (so OpenCTI resolves it to TLP:CLEAR),
    # not the plain STIX TLP:WHITE marking. The canonical marking id is shared
    # with TLP:WHITE by design (CLEAR is the renamed WHITE in STIX 2.1).
    clear = ConverterToStix._create_tlp_marking("clear")
    white = ConverterToStix._create_tlp_marking("white")
    assert clear.definition_type == "statement"
    assert clear.x_opencti_definition == "TLP:CLEAR"
    assert getattr(white, "name", None) == "TLP:WHITE"
    assert getattr(white, "x_opencti_definition", None) != "TLP:CLEAR"

    strict = ConverterToStix._create_tlp_marking("amber+strict")
    assert strict.definition_type == "statement"


def _relationships(result, relationship_type):
    return [
        obj
        for obj in result
        if isinstance(obj, dict)
        and obj.get("type") == "relationship"
        and obj.get("relationship_type") == relationship_type
    ]


def test_existing_indicator_creates_based_on_relationship(converter):
    """An existing indicator still gets a based-on relationship (using its STIX standard_id)."""
    alert = _domains_alert(alert_id="alert_exist_rel", queue_state="actioned")
    existing_indicator = {
        "id": "internal-indicator-id",
        "standard_id": "indicator--e5a6f272-3595-4673-9097-f5be0df2a926",
        "objectLabel": [],
    }
    converter.helper.api.indicator.list.return_value = [existing_indicator]
    converter.helper.api.stix_cyber_observable.read.return_value = None

    result = converter.convert_alerts_to_stix([alert])

    based_on = _relationships(result, "based-on")
    assert based_on, "expected a based-on relationship for the existing indicator"
    assert any(
        rel["source_ref"] == "indicator--e5a6f272-3595-4673-9097-f5be0df2a926"
        for rel in based_on
    )


def test_existing_rft_case_creates_related_to_relationship(converter):
    """An existing RFT case still gets a related-to relationship (using its STIX standard_id)."""
    converter.enable_rft_case = True
    alert = _domains_alert(alert_id="alert_rft_rel", queue_state="actioned")
    existing_case = {
        "id": "internal-case-id",
        "standard_id": "case-rft--11111111-1111-4111-8111-111111111111",
        "objectLabel": [],
    }
    converter.helper.api.case_rft.list.return_value = [existing_case]
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []

    result = converter.convert_alerts_to_stix([alert])

    related_to = _relationships(result, "related-to")
    assert any(
        rel["source_ref"] == "case-rft--11111111-1111-4111-8111-111111111111"
        for rel in related_to
    )


def test_reverted_indicator_gains_revoked_false_positive_label(converter):
    """Reverting (not-takedown) must ADD the revoked-false-positive label."""
    alert = _domains_alert(alert_id="alert_rfp_add", queue_state="resolved")
    existing_indicator = {
        "id": "e5a6f272-3595-4673-9097-f5be0df2a926",
        "standard_id": "indicator--e5a6f272-3595-4673-9097-f5be0df2a926",
        "objectLabel": [],
    }
    converter.helper.api.indicator.list.return_value = [existing_indicator]
    converter.helper.api.stix_cyber_observable.read.return_value = None

    converter.convert_alerts_to_stix([alert])

    add_calls = converter.helper.api.stix_domain_object.add_label.call_args_list
    assert any(
        call.kwargs.get("label_name") == "revoked-false-positive" for call in add_calls
    )


def test_takedown_indicator_removes_revoked_false_positive_label(converter):
    """An actioned/taken-down indicator must REMOVE the revoked-false-positive label."""
    alert = _domains_alert(alert_id="alert_rfp_rm", queue_state="actioned")
    existing_indicator = {
        "id": "e5a6f272-3595-4673-9097-f5be0df2a926",
        "standard_id": "indicator--e5a6f272-3595-4673-9097-f5be0df2a926",
        "objectLabel": [{"value": "revoked-false-positive"}],
    }
    converter.helper.api.indicator.list.return_value = [existing_indicator]
    converter.helper.api.stix_cyber_observable.read.return_value = None

    converter.convert_alerts_to_stix([alert])

    remove_calls = converter.helper.api.stix_domain_object.remove_label.call_args_list
    assert any(
        call.kwargs.get("label_name") == "revoked-false-positive"
        for call in remove_calls
    )


def test_create_case_rft_exposes_workflow_id_top_level(converter):
    """The RFT case dict must carry x_opencti_* at top level (not nested) so it is queryable."""
    converter.enable_rft_case = True
    alert = _domains_alert(alert_id="alert_rft_wf", queue_state="actioned")
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []
    converter.helper.api.case_rft.list.return_value = []

    result = converter.convert_alerts_to_stix([alert])

    cases = [
        obj for obj in result if isinstance(obj, dict) and obj.get("type") == "case-rft"
    ]
    assert cases
    case = cases[0]
    assert case.get("x_opencti_workflow_id") == "alert_rft_wf"
    # The stix2 constructor-only keys must not leak into the raw STIX dict.
    assert "custom_properties" not in case
    assert "allow_custom" not in case


def test_indicator_name_is_raw_value_while_pattern_is_escaped(converter):
    """The indicator name must keep the raw entity value; only the pattern escapes it."""
    alert = _domains_alert(alert_id="alert_quote", queue_state="actioned")
    alert["entity"] = "ex'ample.com"
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []

    result = converter.convert_alerts_to_stix([alert])

    indicators = [
        obj
        for obj in result
        if isinstance(obj, dict) and obj.get("type") == "indicator"
    ]
    assert indicators
    indicator = indicators[0]
    assert indicator["name"] == "ex'ample.com"
    assert "\\'" in indicator["pattern"]


def test_existing_indicator_without_objectlabel_rereads_to_remove_managed_labels(
    converter,
):
    """When .list() omits objectLabel on an existing indicator, _get_labels_to_remove
    must re-read it from the API so managed labels are removed (not accumulated)."""
    alert = _domains_alert(alert_id="alert_ind_reread", queue_state="actioned")
    # Indicator as returned by .list()/search: no objectLabel key.
    existing_indicator = {
        "id": "internal-indicator-id",
        "standard_id": "indicator--e5a6f272-3595-4673-9097-f5be0df2a926",
    }
    converter.helper.api.indicator.list.return_value = [existing_indicator]
    converter.helper.api.stix_cyber_observable.read.return_value = None
    # The API re-read returns the managed labels that must be removed.
    converter.helper.api.stix_domain_object.read.return_value = {
        "id": "internal-indicator-id",
        "objectLabel": [
            {"value": "queue_state:taken_down"},
            {"value": "priority:P2"},
        ],
    }

    converter.convert_alerts_to_stix([alert])

    converter.helper.api.stix_domain_object.read.assert_any_call(
        id="internal-indicator-id"
    )
    removed = {
        call.kwargs.get("label_name")
        for call in converter.helper.api.stix_domain_object.remove_label.call_args_list
    }
    assert "queue_state:taken_down" in removed
    assert "priority:P2" in removed


def test_existing_rft_case_without_objectlabel_rereads_to_remove_managed_labels(
    converter,
):
    """Same re-read fallback for an existing RFT case fetched without objectLabel."""
    converter.enable_rft_case = True
    alert = _domains_alert(alert_id="alert_rft_reread", queue_state="actioned")
    # RFT case as returned by .list()/search: no objectLabel key.
    existing_case = {
        "id": "internal-case-id",
        "standard_id": "case-rft--11111111-1111-4111-8111-111111111111",
    }
    converter.helper.api.case_rft.list.return_value = [existing_case]
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []
    converter.helper.api.stix_domain_object.read.return_value = {
        "id": "internal-case-id",
        "objectLabel": [
            {"value": "severity:high"},
            {"value": "priority:P1"},
        ],
    }

    converter.convert_alerts_to_stix([alert])

    converter.helper.api.stix_domain_object.read.assert_any_call(id="internal-case-id")
    removed = {
        call.kwargs.get("label_name")
        for call in converter.helper.api.stix_domain_object.remove_label.call_args_list
    }
    assert "severity:high" in removed
    assert "priority:P1" in removed


def test_create_case_rft_id_is_deterministic_without_created_at(converter):
    """A missing created_at must still yield a stable (deterministic) case id."""
    converter.enable_rft_case = True
    alert = _domains_alert(alert_id="alert_rft_det", queue_state="actioned")
    alert.pop("created_at", None)
    converter.helper.api.stix_cyber_observable.read.return_value = None
    converter.helper.api.indicator.list.return_value = []
    converter.helper.api.case_rft.list.return_value = []

    def _case_id(result):
        return next(
            obj["id"]
            for obj in result
            if isinstance(obj, dict) and obj.get("type") == "case-rft"
        )

    first = _case_id(converter.convert_alerts_to_stix([alert]))
    second = _case_id(converter.convert_alerts_to_stix([alert]))
    assert first == second
