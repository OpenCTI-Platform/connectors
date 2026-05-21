"""Internal payload handling library - Device Control Policy Payloads.

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


def device_policy_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int, bool]]]]:
    """Create a properly formatted device control policy payload.

    Supports create and update operations. Single policy only.
    {
        "resources": [
            {
                "description": "string",
                "id": "string",
                "clone_id": "string",
                "name": "string",
                "settings": {
                    "classes": [
                        {
                            "action": "FULL_ACCESS",
                            "exceptions": [
                            {
                                "action": "string",
                                "combined_id": "string",
                                "description": "string",
                                "expiration_time": "2023-06-08T06:10:39.965Z",
                                "id": "string",
                                "product_id": "string",
                                "product_id_decimal": "string",
                                "product_name": "string",
                                "serial_number": "string",
                                "use_wildcard": true,
                                "vendor_id": "string",
                                "vendor_id_decimal": "string",
                                "vendor_name": "string"
                            }
                            ],
                            "id": "string"
                        }
                    ],
                    "custom_notifications": {
                        "blocked_notification": {
                            "custom_message": "string",
                            "use_custom": true
                        },
                        "restricted_notification": {
                            "custom_message": "string",
                            "use_custom": true
                        }
                    },
                    "delete_exceptions": [
                        "string"
                    ],
                    "end_user_notification": "SILENT",
                    "enforcement_mode": "MONITOR_ONLY",
                    "enhanced_file_metadata": true
                }
            }
        ]
    }
    """
    returned_payload = {}
    resources = []
    item = {}
    keys = ["clone_id", "description", "name", "platform_name", "id"]
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)

    # Settings classes not currently abstracted
    if passed_keywords.get("settings", None):
        item["settings"] = passed_keywords.get("settings", None)

    resources.append(item)
    returned_payload["resources"] = resources

    return returned_payload


def default_device_policy_config_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int, bool]]]]:
    """Create a properly formatted device control policy default configuration payload.

    {
        "custom_notifications": {
            "blocked_notification": {
                "custom_message": "string",
                "use_custom": boolean
            },
            "restricted_notification": {
                "custom_message": "string",
                "use_custom": boolean
            }
        }
    }
    """
    returned_payload = {}
    custom_notifications = {}
    blocked_notification = {}
    restricted_notification = {}

    # Blocked notifications
    if passed_keywords.get("blocked_custom_message", None):
        blocked_notification["custom_message"] = passed_keywords.get("blocked_custom_message", None)
        blocked_notification["use_custom"] = True
        custom_notifications["blocked_notification"] = blocked_notification

    # Restricted notifications
    if passed_keywords.get("restricted_custom_message", None):
        restricted_notification["custom_message"] = passed_keywords.get("restricted_custom_message", None)
        restricted_notification["use_custom"] = True
        custom_notifications["restricted_notification"] = restricted_notification

    # Passing the entire dictionary for either type will override other provided keywords
    keys = ["blocked_notification", "restricted_notification"]
    for key in keys:
        if passed_keywords.get(key, None):
            custom_notifications[key] = passed_keywords.get(key, None)

    if custom_notifications:
        returned_payload["custom_notifications"] = custom_notifications

    return returned_payload


def device_classes_policy_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int, bool]]]]:
    """Craft a properly formatted device classes policy payload that supports bluetooth and USB.

    {
        "policies": [
            {
                "bluetooth_classes": {
                    "classes": [
                        {
                            "action": "string",
                            "class": "string",
                            "minor_classes": [
                                {
                                    "action": "string",
                                    "minor_class": "string"
                                }
                            ]
                        }
                    ],
                    "delete_exceptions": [
                        "string"
                    ],
                    "upsert_exceptions": [
                        {
                            "action": "string",
                            "class": "string",
                            "description": "string",
                            "expiration_time": "UTC date string",
                            "id": "string",
                            "minor_classes": [
                                "string"
                            ],
                            "product_id": "string",
                            "product_name": "string",
                            "vendor_id": "string",
                            "vendor_id_source": "string",
                            "vendor_name": "string"
                        }
                    ]
                },
                "id": "string",
                "usb_classes": {
                    "classes": [
                        {
                            "action": "string",
                            "class": "string"
                        }
                    ],
                    "delete_exceptions": [
                        "string"
                    ],
                    "upsert_exceptions": [
                        {
                            "action": "string",
                            "class": "string",
                            "combined_id": "string",
                            "description": "string",
                            "expiration_time": "UTC date string",
                            "id": "string",
                            "product_id": "string",
                            "product_name": "string",
                            "serial_number": "string",
                            "use_wildcard": boolean,
                            "vendor_id": "string",
                            "vendor_name": "string"
                        }
                    ]
                }
            }
        ]
    }
    """
    returned = {}
    returned["policies"] = []
    item = {}
    keys = ["bluetooth_classes", "id", "usb_classes"]
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)
    returned["policies"].append(item)

    return returned


def device_policy_bluetooth_config_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int, bool]]]]:
    """Craft a properly formatted device control configuration payload that supports bluetooth and USB.

    {
        "bluetooth_custom_notifications": {
            "blocked_notification": {
                "custom_message": "string",
                "use_custom": boolean
            }
        },
        "usb_custom_notifications": {
            "blocked_notification": {
                "custom_message": "string",
                "use_custom": boolean
            },
            "restricted_notification": {
                "custom_message": "string",
                "use_custom": boolean
            }
        },
        "usb_exceptions": [
            {
                "delete_exceptions": [
                    "string"
                ],
                "platform_name": "string",
                "upsert_exceptions": [
                    {
                        "action": "string",
                        "class": "string",
                        "combined_id": "string",
                        "description": "string",
                        "id": "string",
                        "product_id": "string",
                        "product_name": "string",
                        "serial_number": "string",
                        "vendor_id": "string",
                        "vendor_name": "string"
                    }
                ]
            }
        ]
    }
    """
    returned = {}
    keys = ["bluetooth_custom_notifications", "usb_custom_notifications", "usb_exceptions"]
    for key in keys:
        if passed_keywords.get(key, None):
            provided = passed_keywords.get(key, None)
            if key == "usb_exceptions" and isinstance(provided, dict):
                provided = [provided]
            returned[key] = provided

    return returned


def device_control_policy_payload_v2(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int, bool]]]]:
    """Craft a properly formatted device control policy v2 payload.

    {
        "policies": [
            {
                "bluetooth_settings": {
                    "custom_end_user_notifications": {
                        "blocked_notification": {
                            "custom_message": "string",
                            "use_custom": boolean
                        }
                    },
                    "end_user_notification": "string",
                    "enforcement_mode": "string"
                },
                "clone_id": "string",
                "id": "string",
                "description": "string",
                "name": "string",
                "platform_name": "string",
                "usb_settings": {
                    "custom_notifications": {
                        "blocked_notification": {
                            "custom_message": "string",
                            "use_custom": boolean
                        },
                        "restricted_notification": {
                            "custom_message": "string",
                            "use_custom": boolean
                        }
                    },
                    "end_user_notification": "string",
                    "enforcement_mode": "string",
                    "enhanced_file_metadata": boolean,
                    "whitelist_mode": "string"
                }
            }
        ]
    }
    """
    returned = {}
    returned["policies"] = []
    item = {}
    keys = ["bluetooth_settings", "clone_id", "id", "description",
            "name", "platform_name", "usb_settings"
            ]
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)
    returned["policies"].append(item)

    return returned
