"""Internal payload handling library - Cloud OCI Registration.

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


def cloud_oci_refresh_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Create a properly formatted payload for OCI key rotation or script download.

    {
        "resources": [
            {
                "deployment_method": "string",
                "is_download": boolean,
                "tenancy_ocid": "string"
            }
        ]
    }
    """
    returned = {
        "resources": []
    }
    item = {}
    keys = ["deployment_method", "is_download", "tenancy_ocid"]
    for key in keys:
        provided = passed_keywords.get(key, None)
        if provided is not None:
            item[key] = passed_keywords.get(key, None)

    returned["resources"].append(item)

    return returned


def cloud_oci_validate_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Craft a properly formatted OCI tenancy validation payload.

    {
        "resources": [
            {
                "products": [
                    {
                        "features": [
                            "string"
                        ],
                        "product": "string"
                    }
                ],
                "tenancy_ocid": "string"
            }
        ]
    }
    """
    returned = {
        "resources": []
    }
    item = {}
    keys = ["products", "tenancy_ocid"]
    for key in keys:
        provided = passed_keywords.get(key, None)
        if provided is not None:
            if key == "products" and isinstance(provided, dict):
                # products is a list of dictionaries
                provided = [provided]
            item[key] = provided

    returned["resources"].append(item)

    return returned


def cloud_oci_create_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Craft a properly formatted OCI account creation (or update) payload.

    {
        "resources": [
            {
                "group_name": "string",
                "home_region": "string",
                "policy_name": "string",
                "products": [
                    {
                        "features": [
                            {
                                "deployment_method": "string",
                                "feature": "string",
                                "is_enabled": true,
                                "persona": "string",
                                "registration_detailed_status": "string"
                            }
                        ],
                        "product": "string"
                    }
                ],
                "stack_ocid": "string",
                "tenancy_ocid": "string",
                "user_email": "string",
                "user_name": "string",
                "user_ocid": "string"
            }
        ]
    }
    """
    returned = {
        "resources": []
    }
    item = {}
    keys = ["group_name", "home_region", "policy_name", "products", "tenancy_ocid", "user_email",
            "user_name", "stack_ocid", "user_ocid"
            ]
    for key in keys:
        provided = passed_keywords.get(key, None)
        if provided is not None:
            if key == "products" and isinstance(provided, dict):
                # products is a list of dictionaries
                provided = [provided]
            item[key] = provided

    returned["resources"].append(item)

    return returned
