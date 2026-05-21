"""Internal payload handling library - Data Protection Configuration.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""

from typing import Dict, List, Union


# pylint: disable=R0912
def data_protection_classification_payload(
        passed_keywords: dict
        ) -> Dict[str, List[Dict[str, Union[str, int, bool, list, dict]]]]:
    """Create classifications.

    {
        "resources": [
            {
            "classification_properties": {
                "content_patterns": [
                "string"
                ],
                "evidence_duplication_enabled": true,
                "file_types": [
                "string"
                ],
                "protection_mode": "monitor",
                "rules": [
                {
                    "ad_groups": [
                    "string"
                    ],
                    "ad_users": [
                    "string"
                    ],
                    "created_time_stamp": "string",
                    "description": "string",
                    "detection_severity": "informational",
                    "enable_printer_egress": true,
                    "enable_usb_devices": true,
                    "enable_web_locations": true,
                    "id": "string",
                    "modified_time_stamp": "string",
                    "notify_end_user": true,
                    "response_action": "allow",
                    "trigger_detection": true,
                    "user_scope": "all",
                    "web_locations": [
                    "string"
                    ],
                    "web_locations_scope": "all"
                }
                ],
                "sensitivity_labels": [
                "string"
                ],
                "web_sources": [
                "string"
                ]
            },
            "name": "string"
            }
        ]
    }
    """
    returned_payload = {}
    resources = []
    resource = {}
    keys = ["name", "classification_properties"]
    for key in keys:
        if passed_keywords.get(key, None):
            provided = passed_keywords.get(key, None)
            resource[key] = provided
    resources.append(resource)
    returned_payload['resources'] = resources

    return returned_payload


def data_protection_cloud_app_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int, bool, list, dict]]]]:
    """Persist the given cloud application for the provided entity instance.

    {
        "description": "string",
        "name": "string",
        "urls": [
            {
            "fqdn": "string",
            "path": "string"
            }
        ]
    }
    """
    returned_payload = {}
    keys = ["description", "name", "urls"]
    for key in keys:
        if passed_keywords.get(key, None):
            provided = passed_keywords.get(key, None)
            if provided == "urls" and isinstance(provided, dict):
                provided = [provided]
            returned_payload[key] = provided

    return returned_payload


def data_protection_content_pattern_payload(
        passed_keywords: dict
        ) -> Dict[str, List[Dict[str, Union[str, int, bool, list, dict]]]]:
    """Persist the given content pattern for the provided entity instance.

    {
        "category": "string",
        "description": "string",
        "example": "string",
        "min_match_threshold": 0,
        "name": "string",
        "regexes": [
            "string"
        ],
        "region": "string"
    }
    """
    returned_payload = {}
    keys = ["category", "description", "example", "min_match_threshold", "name", "regexes", "region"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


def data_protection_enterprise_account_payload(
        passed_keywords: dict
        ) -> Dict[str, List[Dict[str, Union[str, int, bool, list, dict]]]]:
    """Persist the given content pattern for the provided entity instance.

    {
        "application_group_id": "string",
        "domains": [
            "string"
        ],
        "name": "string",
        "plugin_config_id": "string"
    }
    """
    returned_payload = {}
    keys = ["application_group_id", "domains", "name", "plugin_config_id"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


def data_protection_sensitivity_label_payload(
        passed_keywords: dict
        ) -> Dict[str, List[Dict[str, Union[str, int, bool, list, dict]]]]:
    """Create new sensitivity label (V2).

    {
        "co_authoring": true,
        "display_name": "string",
        "external_id": "string",
        "label_provider": "string",
        "name": "string",
        "plugins_configuration_id": "string",
        "synced": true
    }
    """
    returned_payload = {}
    keys = ["co_authoring", "display_name",
            "external_id", "label_provider",
            "name", "plugins_configuration_id",
            "synced"
            ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


# pylint: disable=R0912
def data_protection_policy_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int, bool, list, dict]]]]:
    """Create data protection policies.

    {
        "resources": [
            {
            "description": "string",
            "name": "string",
            "policy_properties": {
                "allow_notifications": "default",
                "be_exclude_domains": "string",
                "be_paste_clipboard_max_size": 0,
                "be_paste_clipboard_max_size_unit": "Bytes",
                "be_paste_clipboard_min_size": 0,
                "be_paste_clipboard_min_size_unit": "Bytes",
                "be_paste_clipboard_over_size_behaviour_block": true,
                "be_paste_timeout_duration_milliseconds": 0,
                "be_paste_timeout_response": "block",
                "be_splash_custom_message": "string",
                "be_splash_enabled": true,
                "be_splash_message_source": "default",
                "be_upload_timeout_duration_seconds": 0,
                "be_upload_timeout_response": "block",
                "block_all_data_access": true,
                "block_notifications": "default",
                "browsers_without_active_extension": "allow",
                "classifications": [
                "string"
                ],
                "custom_allow_notification": "string",
                "custom_block_notification": "string",
                "enable_clipboard_inspection": true,
                "enable_content_inspection": true,
                "enable_context_inspection": true,
                "enable_end_user_notifications_unsupported_browser": true,
                "enable_network_inspection": true,
                "euj_dialog_box_logo": "string",
                "euj_dialog_timeout": 0,
                "euj_dropdown_options": {
                "justifications": [
                    {
                    "default": true,
                    "id": "string",
                    "justification": "string",
                    "selected": true
                    }
                ]
                },
                "euj_header_text": {
                    "headers": [
                        {
                        "default": true,
                        "header": "string",
                        "selected": true
                        }
                    ]
                },
                "euj_require_additional_details": true,
                "euj_response_cache_timeout": 0,
                "evidence_download_enabled": true,
                "evidence_duplication_enabled_default": true,
                "evidence_encrypted_enabled": true,
                "evidence_storage_free_disk_perc": 0,
                "evidence_storage_max_size": 0,
                "inspection_depth": "balanced",
                "max_file_size_to_inspect": 0,
                "max_file_size_to_inspect_unit": "Bytes",
                "min_confidence_level": "low",
                "network_inspection_files_exceeding_size_limit": "block",
                "similarity_detection": true,
                "similarity_threshold": "10",
                "unsupported_browsers_action": "allow"
            },
            "precedence": 0
            }
        ]
    }
    """
    returned_payload = {}

    if passed_keywords.get("resources", None) is not None:
        returned_payload["resources"] = passed_keywords.get("resources", None)
        return returned_payload

    resources = []
    resource = {}

    resource_fields = ["description", "name", "precedence", "policy_properties"]
    for field in resource_fields:
        if passed_keywords.get(field, None) is not None:
            resource[field] = passed_keywords.get(field, None)
    resources.append(resource)
    returned_payload['resources'] = resources

    return returned_payload


def data_protection_web_locations_payload(
        passed_keywords: dict
        ) -> Dict[str, List[Dict[str, Union[str, int, bool, list, dict]]]]:
    """Persist the given web-locations.

    {
        "web_locations": [
            {
                "application_id": "string",
                "deleted": true,
                "enterprise_account_id": "string",
                "location_type": "string",
                "name": "string",
                "provider_location_id": "string",
                "provider_location_name": "string",
                "type": "string"
            }
        ]
    }
    """
    returned_payload = {}
    web_locations = []
    web_location = {}
    keys = ["application_id", "deleted",
            "enterprise_account_id", "location_type",
            "name", "provider_location_id",
            "provider_location_name", "type"
            ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            web_location[key] = passed_keywords.get(key, None)
    web_locations.append(web_location)
    returned_payload["web_locations"] = web_locations

    return returned_payload
