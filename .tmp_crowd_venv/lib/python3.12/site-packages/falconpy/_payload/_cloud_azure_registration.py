"""Internal payload handling library - Cloud Azure Registration.

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


def cloud_azure_registration_create_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Craft a properly formatted payload to create an Azure tenant registration.

    {
        "resource": {
            "account_type": "string",
            "additional_features": [
                {
                    "feature": "string",
                    "product": "string",
                    "subscription_ids": [
                        "string"
                    ]
                }
            ],
            "additional_properties": {},
            "api_client_key_id": "string",
            "api_client_key_type": "string",
            "cs_infra_region": "string",
            "cs_infra_subscription_id": "string",
            "deployment_method": "string",
            "deployment_stack_host_id": "string",
            "deployment_stack_name": "string",
            "dspm_regions": [
                "string"
            ],
            "environment": "string",
            "event_hub_settings": [
                {
                    "cid": "string",
                    "consumer_group": "string",
                    "event_hub_id": "string",
                    "purpose": "string",
                    "tenant_id": "string"
                }
            ],
            "management_group_ids": [
                "string"
            ],
            "microsoft_graph_permission_ids": [
                "string"
            ],
            "microsoft_graph_permission_ids_readonly": true,
            "products": [
                {
                    "features": [
                        "string"
                    ],
                    "product": "string"
                }
            ],
            "resource_name_prefix": "string",
            "resource_name_suffix": "string",
            "status": "string",
            "subscription_ids": [
                "string"
            ],
            "tags": {
                "additionalProp1": "string",
                "additionalProp2": "string",
                "additionalProp3": "string"
            },
            "template_version": "string",
            "tenant_id": "string"
        }
    }
    """
    returned_payload = {}
    returned_payload["resource"] = {}
    keys = ["account_type", "additional_features", "additional_properties", "api_client_key_id",
            "api_client_key_type", "cs_infra_region", "cs_infra_subscription_id", "deployment_method",
            "deployment_stack_host_id", "deployment_stack_name", "dspm_regions", "environment",
            "event_hub_settings", "management_group_ids", "microsoft_graph_permission_ids",
            "microsoft_graph_permissions_ids_readonly", "products", "resource_name_prefix",
            "resource_name_suffix", "status", "subscription_ids", "tags", "template_version", "tenant_id"
            ]
    simple_list_keys = ["dspm_regions", "management_group_ids", "microsoft_graph_permission_ids",
                        "subscription_ids"
                        ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            value = passed_keywords.get(key, None)
            if isinstance(value, str) and key in simple_list_keys:
                value = value.split(",")
            returned_payload["resource"][key] = value

    return returned_payload


def cloud_azure_registration_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Create a properly formatted payload for Azure registration script download.

    {
        "resources": [
            {
                "tenantId": "string"
            }
        ]
    }
    """
    returned = {
        "resources": []
    }
    item = {}
    if passed_keywords.get("tenant_id", None):
        item["tenantId"] = passed_keywords.get("tenant_id", None)

    returned["resources"].append(item)

    return returned


def cloud_azure_registration_legacy_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Delete existing legacy Azure subscriptions.

    {
        "resources": [
            {
                "retain_client": true,
                "subscription_id": "string",
                "tenant_id": "string"
            }
        ]
    }
    """
    returned = {
        "resources": []
    }
    keys = ["retain_client", "subscription_id", "tenant_id"]
    item = {}
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)

    returned["resources"].append(item)

    return returned
