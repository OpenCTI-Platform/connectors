from unittest.mock import MagicMock

from connector.converter_to_stix import ConverterToStix


def _converter():
    return ConverterToStix(helper=MagicMock(), tlp_level="amber+strict")


def test_clear_tlp_marking_is_distinct_from_white():
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    # "clear" must produce a distinct TLP:CLEAR marking, not an alias of
    # TLP:WHITE.
    assert converter.tlp_marking["x_opencti_definition"] == "TLP:CLEAR"


def _types(stix_objects):
    return [obj["type"] for obj in stix_objects]


def _incident(stix_objects):
    return next(obj for obj in stix_objects if obj["type"] == "incident")


def test_create_incident_typosquatting():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n1",
            "created_date": "2026-05-01T00:00:00Z",
            "item_type": "typosquatting_domain",
            "rule_name": "Brand Rule",
            "rule_priority": "high",
            "typosquatting": {
                "unicode_format": "exemple.com",
                "punycode_format": "xn--exemple.com",
            },
        }
    }

    objects = converter.create_incident(notification_detail=detail)
    types = _types(objects)

    assert types.count("domain-name") == 2
    assert "incident" in types
    assert types.count("relationship") == 2

    incident = _incident(objects)
    assert incident["name"] == "Brand Rule : exemple.com"
    # incident_type is derived from the notification item_type
    assert incident["incident_type"] == "typosquatting_domain"
    assert incident["severity"] == "high"


def test_create_incident_typosquatting_missing_punycode_is_skipped():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n1b",
            "created_date": "2026-05-01T00:00:00Z",
            "item_type": "typosquatting_domain",
            "rule_name": "Brand Rule",
            "typosquatting": {"unicode_format": "exemple.com"},
        }
    }

    objects = converter.create_incident(notification_detail=detail)

    # Only the unicode domain is created; the missing punycode value is skipped
    # instead of building a DomainName with value=None.
    assert _types(objects).count("domain-name") == 1


def test_create_incident_exposed_data_builds_observables():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n2",
            "created_date": "2026-05-02T00:00:00Z",
            "item_type": "exposed_data",
            "rule_name": "Breach Rule",
            "rule_priority": "medium",
            "breach_summary": {"name": "BigBreach"},
        },
        "breach_details": {
            "items": [
                {
                    "email": "alice@example.com",
                    "login_id": "alice",
                    "credentials_url": "https://example.com/login",
                    "credentials_domain": "example.com",
                    "malware_family": "redline",
                }
            ]
        },
    }

    objects = converter.create_incident(notification_detail=detail)
    types = _types(objects)

    for expected in ("malware", "email-addr", "user-account", "url", "domain-name"):
        assert expected in types
    assert _incident(objects)["name"] == "Breach Rule : BigBreach"


def test_generate_exposed_data_content_with_files_and_items():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n",
            "created_date": "2026-05-02T00:00:00Z",
            "breach_summary": {
                "name": "B",
                "files": [
                    {
                        "name": "leak.txt",
                        "size": 1234,
                        "complete_data_set": True,
                        "download_urls": ["http://x/leak"],
                    },
                    {},
                ],
            },
        },
        "breach_details": {"items": [{"email": "a@b.com", "login_id": "l"}]},
    }

    content = converter.generate_exposed_data_content(detail)

    assert "### Files" in content
    assert "leak.txt" in content
    assert "### Breach Details" in content


def test_create_incident_post_with_highlights_truncates_title():
    converter = _converter()
    long_highlight = "x" * 80
    detail = {
        "notification": {
            "id": "n3",
            "created_date": "2026-05-03T00:00:00Z",
            "item_type": "post",
            "rule_name": "Dark Web Rule",
            "highlights": [long_highlight],
        },
        "details": {"content": "leaked"},
    }

    objects = converter.create_incident(notification_detail=detail)
    incident = _incident(objects)

    assert incident["name"] == "Dark Web Rule : " + "x" * 50 + "..."


def test_create_incident_content_in_description():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n4",
            "created_date": "2026-05-04T00:00:00Z",
            "item_type": "post",
            "rule_name": "Rule",
            "highlights": ["short"],
        },
        "details": {"content": "leaked"},
    }

    incident = _incident(converter.create_incident(notification_detail=detail))
    assert "Alert Metadata" in incident["description"]


def test_create_incident_missing_highlights_does_not_crash():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n5",
            "created_date": "2026-05-05T00:00:00Z",
            "item_type": "reply",
            "rule_name": "Rule",
            # no "highlights" key at all
        },
        "details": {},
    }

    incident = _incident(converter.create_incident(notification_detail=detail))
    assert incident["name"] == "Rule : --"


def test_create_incident_missing_rule_name_uses_default():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n6",
            "created_date": "2026-05-06T00:00:00Z",
            "item_type": "post",
            "highlights": ["topic"],
        },
        "details": {},
    }

    incident = _incident(converter.create_incident(notification_detail=detail))
    assert incident["name"] == "CrowdStrike Recon : topic"


def test_create_incident_missing_created_date_returns_empty():
    converter = _converter()
    detail = {"notification": {"id": "n7", "item_type": "post"}}

    assert converter.create_incident(notification_detail=detail) == []


def test_create_incident_unparseable_created_date_returns_empty():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n9",
            "created_date": "not-a-real-date",
            "item_type": "post",
            "highlights": ["x"],
        },
        "details": {},
    }

    assert converter.create_incident(notification_detail=detail) == []


def test_create_incident_unsupported_type_returns_empty():
    converter = _converter()
    detail = {
        "notification": {
            "id": "n8",
            "created_date": "2026-05-08T00:00:00Z",
            "item_type": "something_new",
        }
    }

    assert converter.create_incident(notification_detail=detail) == []
