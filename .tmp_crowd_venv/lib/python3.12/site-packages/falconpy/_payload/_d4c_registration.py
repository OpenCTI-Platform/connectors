"""Internal payload handling library - D4C Registration Payloads.

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
from typing import Dict, List, Union, Any


def aws_d4c_registration_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, bool]]]]:
    """Create a properly formatted AWS registration payload.

    {
        "resources": [
            {
                "account_id": "string",
                "account_type": "string",
                "cloudtrail_region": "string",
                "iam_role_arn": "string",
                "is_master": true,
                "organization_id": "string"
            }
        ]
    }
    """
    returned_payload: Dict[str, List[Dict[str, Union[str, bool]]]] = {}
    returned_payload["resources"] = []
    keys = ["account_id", "account_type", "cloudtrail_region", "iam_role_arn", "organization_id"]
    item: Dict[str, Any] = {}

    for key in keys:
        if isinstance(passed_keywords.get(key, None), str):
            item[key] = passed_keywords.get(key)
    if isinstance(passed_keywords.get("is_master", None), bool):
        item["is_master"] = passed_keywords.get("is_master")

    if item:
        returned_payload["resources"].append(item)

    return returned_payload


def azure_registration_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, str]]]:
    """Create a properly formatted Azure registration payload.

    {
        "resources": [
            {
                "account_type": "string",
                "client_id": "string",
                "default_subscription": true,
                "subscription_id": "string",
                "tenant_id": "string",
                "years_valid": integer
            }
        ]
    }
    """
    returned_payload = {}
    returned_payload["resources"] = []
    keys = ["account_type", "client_id", "subscription_id", "tenant_id"]
    item = {}
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)

    if passed_keywords.get("default_subscription", None) is not None:
        item["default_subscription"] = passed_keywords.get("default_subscription", None)

    if passed_keywords.get("years_valid", -1) >= 0:
        item["years_valid"] = passed_keywords.get("years_valid", -1)

    returned_payload["resources"].append(item)

    return returned_payload


def gcp_registration_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted Azure registration payload.

    {
        "resources": [
            {
                "client_email": "string",
                "client_id": "string",
                "parent_id": "string",
                "parent_type": "string",
                "private_key": "string",
                "private_key_id": "string",
                "project_id": "string",
                "service_account_id": 0
            }
        ]
    }
    """
    returned_payload: Dict[str, List[Dict[str, str]]] = {}
    returned_payload["resources"] = []
    keys = ["client_email", "client_id", "parent_id", "parent_type",
            "private_key", "private_key_id", "project_id", "service_account_id"
            ]
    item = {}
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)

    returned_payload["resources"].append(item)

    return returned_payload
