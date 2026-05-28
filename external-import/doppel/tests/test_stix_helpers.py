from doppel.stix_helpers import (
    build_custom_properties,
    build_description,
    build_external_references,
    build_labels,
)

# --------------------------
# --- Scenario Functions ---
# --------------------------


# Scenario: If custom properties are correctly formatted
def test_build_custom_properties():
    # Given an alert
    alert = _given_an_alert()
    # When we call build_custom_properties function
    result = _when_call_build_custom_properties(alert)
    # Then the custom properties are correctly formatted
    assert result == {
        "x_opencti_created_by_ref": "Identity--9662c90d-96a3-43b9-bb4e-03fae4389baf",
        "x_opencti_score": 35,
        "x_opencti_workflow_id": "Id Test",
        "x_opencti_labels": [
            "queue_state:actioned",
            "entity_state:active",
            "severity:medium",
            "platform:domains",
            "brand:Brand Test",
        ],
        "x_opencti_external_references": [
            {
                "source_name": "Test Upload",
                "url": "https://link-test.com/",
                "external_id": "Id Test",
                "description": "2026-03-26T15:18:01.622404: queue_state - actioned (by Test)\n2026-02-26T15:08:24.442521: alert_create - needs_review (by Test)",
            }
        ],
        "x_opencti_description": "**Brand**: Brand Test\n\n**Product**: domains\n\n**Notes**: Note Test\n\n**Uploaded By**: Test uploader\n\n**Screenshot URL**: https://test.com/\n\n**Message**: Message test\n\n**Source**: Test Upload\n\n**Assignee**: Assignee Test\n\n**Country**: US\n\n**Hosting Provider**: Test Hosting\n\n**Contact Email**: contact@test.com\n\n**MX Records**: test.com. (pref: 10)\n\n**Nameservers**: NS.TEST.COM\n",
    }


# Scenario: If external references are correctly formatted
def test_build_external_references():
    # Given an alert
    alert = _given_an_alert()
    # When we call build_external_references function
    result = _when_call_build_external_references(alert)
    # Then the external references are correctly formatted
    assert result == [
        {
            "description": "2026-03-26T15:18:01.622404: queue_state - actioned (by Test)\n"
            "2026-02-26T15:08:24.442521: alert_create - needs_review (by Test)",
            "external_id": "Id Test",
            "source_name": "Test Upload",
            "url": "https://link-test.com/",
        },
    ]


# Scenario: If description is correctly formatted
def test_build_description():
    # Given an alert
    alert = _given_an_alert()
    # When we call build_description function
    result = _when_call_build_description(alert)
    # Then the description is correctly formatted
    assert (
        result
        == "**Brand**: Brand Test\n\n**Product**: domains\n\n**Notes**: Note Test\n\n**Uploaded By**: Test uploader\n\n**Screenshot URL**: https://test.com/\n\n**Message**: Message test\n\n**Source**: Test Upload\n\n**Assignee**: Assignee Test\n\n**Country**: US\n\n**Hosting Provider**: Test Hosting\n\n**Contact Email**: contact@test.com\n\n**MX Records**: test.com. (pref: 10)\n\n**Nameservers**: NS.TEST.COM\n"
    )


# Scenario: If labels are correctly formatted
def test_build_labels():
    # Given an alert
    alert = _given_an_alert()
    # When we call build_labels function
    result = _when_call_build_labels(alert)
    # Then the labels are correctly formatted
    assert result == [
        "queue_state:actioned",
        "entity_state:active",
        "severity:medium",
        "platform:domains",
        "brand:Brand Test",
    ]


# ---------------------------------------------------------
# --- Helper Functions (implementing the Gherkin steps) ---
# ---------------------------------------------------------


# Given an alert
def _given_an_alert():
    return {
        "id": "Id Test",
        "brand": "Brand Test",
        "queue_state": "actioned",
        "entity_state": "active",
        "severity": "medium",
        "product": "domains",
        "platform": "domains",
        "source": "Test Upload",
        "notes": "Note Test",
        "screenshot_url": "https://test.com/",
        "score": "0.35",
        "message": "Message test",
        "assignee": "Assignee Test",
        "doppel_link": "https://link-test.com/",
        "uploaded_by": "Test uploader",
        "entity_content": {
            "root_domain": {
                "domain": "domain-test.com",
                "ip_address": "123.45.6.789",
                "country_code": "US",
                "hosting_provider": "Test Hosting",
                "contact_email": "contact@test.com",
                "mx_records": [
                    {"exchange": "test.com.", "preference": 10},
                ],
                "nameservers": ["NS.TEST.COM"],
            }
        },
        "audit_logs": [
            {
                "timestamp": "2026-03-26T15:18:01.622404",
                "type": "queue_state",
                "value": "actioned",
                "changed_by": "Test",
                "metadata": {},
            },
            {
                "timestamp": "2026-02-26T15:08:24.442521",
                "type": "alert_create",
                "value": "needs_review",
                "changed_by": "Test",
                "metadata": {},
            },
        ],
        "tags": [],
    }


# When we call _build_custom_properties function
def _when_call_build_custom_properties(alert):
    return build_custom_properties(
        alert=alert,
        author_id="Identity--9662c90d-96a3-43b9-bb4e-03fae4389baf",
    )


# When we call _build_external_references function
def _when_call_build_external_references(alert):
    return build_external_references(alert=alert)


# When we call _build_description function
def _when_call_build_description(alert):
    return build_description(alert=alert)


# When we call _build_custom_properties function
def _when_call_build_labels(alert):
    return build_labels(alert=alert)
