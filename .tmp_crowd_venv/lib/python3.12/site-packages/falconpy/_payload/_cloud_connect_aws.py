"""Internal payload handling library - Discover for AWS.

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


def aws_registration_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Create a properly formatted payload for RTR command.

    {
        "resources": [
            {
                "cloudtrail_bucket_owner_id": "string",
                "cloudtrail_bucket_region": "string",
                "external_id": "string",
                "iam_role_arn": "string",
                "id": "string",
                "rate_limit_reqs": integer,
                "rate_limit_time": integer,
                "static_external_id": "string"
            }
        ]
    }
    """
    returned_payload: Dict[str, List[Dict[str, Union[str, int]]]] = {}
    returned_payload["resources"] = []
    item = {}
    if passed_keywords.get("cloudtrail_bucket_owner_id", None):
        item["cloudtrail_bucket_owner_id"] = passed_keywords.get("cloudtrail_bucket_owner_id", None)
    if passed_keywords.get("cloudtrail_bucket_region", None):
        item["cloudtrail_bucket_region"] = passed_keywords.get("cloudtrail_bucket_region", None)
    if passed_keywords.get("external_id", None):
        item["external_id"] = passed_keywords.get("external_id", None)
    if passed_keywords.get("iam_role_arn", None):
        item["iam_role_arn"] = passed_keywords.get("iam_role_arn", None)
    if passed_keywords.get("id", None):
        item["id"] = passed_keywords.get("id", None)
    if passed_keywords.get("rate_limit_reqs", -1) >= 0:
        item["rate_limit_reqs"] = passed_keywords.get("rate_limit_reqs", None)
    if passed_keywords.get("rate_limit_time", -1) >= 0:
        item["rate_limit_time"] = passed_keywords.get("rate_limit_time", None)
    if passed_keywords.get("static_external_id", None):
        item["static_external_id"] = passed_keywords.get("static_external_id", None)

    returned_payload["resources"].append(item)

    return returned_payload
