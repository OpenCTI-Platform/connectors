"""Internal payload handling library - Certificate Based Exclusions.

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


def certificate_based_exclusions_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Create a properly formatted payload for exclusion creation.

    {
        "exclusions": [
            {
                "applied_globally": true,
                "certificate": {
                    "issuer": "string",
                    "serial": "string",
                    "subject": "string",
                    "thumbprint": "string",
                    "valid_from": "2024-07-17T16:55:01.502Z",
                    "valid_to": "2024-07-17T16:55:01.502Z"
                },
                "children_cids": [
                    "string"
                ],
                "comment": "string",
                "created_by": "string",
                "created_on": "2024-07-17T16:55:01.502Z",
                "description": "string",
                "host_groups": [
                    "string"
                ],
                "modified_by": "string",
                "modified_on": "2024-07-17T16:55:01.502Z",
                "name": "string",
                "status": "string"
            }
        ]
    }
    """
    returned = {
        "exclusions": []
    }
    item = {}
    keys = [
            "applied_globally", "certificate", "comment", "created_by", "created_on",
            "description", "modified_by", "modified_on", "name", "status",
            ]
    certificate_keys = [
        "issuer", "serial", "subject", "thumbprint", "valid_from", "valid_to"
    ]
    list_keys = ["children_cids", "host_groups"]
    certkey = {}
    for key in certificate_keys:
        # Certificate keywords overridden if certificate keyword is passed
        if passed_keywords.get(key, None):
            certkey[key] = passed_keywords.get(key, None)
    if certkey:
        item["certificate"] = certkey
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)
    for key in list_keys:
        if passed_keywords.get(key, None):
            provided = passed_keywords.get(key, None)
            if isinstance(provided, str):
                provided = provided.split(",")
            item[key] = provided

    returned["exclusions"].append(item)

    return returned
