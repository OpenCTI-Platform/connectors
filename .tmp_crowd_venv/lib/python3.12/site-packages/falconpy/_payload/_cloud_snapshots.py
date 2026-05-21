"""Internal payload handling library - Cloud Snapshots Payloads.

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


def snapshot_registration_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted Cloud Snapshot registration payload.

    {
        "aws_accounts": [
            {
                "account_number": "string",
                "batch_regions": [
                    {
                        "job_definition_name": "string",
                        "job_queue": "string",
                        "region": "string"
                    }
                ],
                "iam_external_id": "string",
                "iam_role_arn": "string",
                "kms_alias": "string",
                "processing_account": "string"
            }
        ]
    }
    """
    returned_payload = {}
    if passed_keywords.get("aws_accounts", None):
        returned_payload["aws_accounts"] = passed_keywords.get("aws_accounts", None)
    else:
        returned_payload["aws_accounts"] = []
        returned = {}
        keys = ["account_number", "batch_regions", "iam_external_id",
                "iam_role_arn", "kms_alias", "processing_account"
                ]
        for key in keys:
            if passed_keywords.get(key, None):
                returned[key] = passed_keywords.get(key)
        returned_payload["aws_accounts"].append(returned)

    return returned_payload


def snapshot_launch_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted snapshot scan launch payload.

    {
        "resources": [
            {
                "account_id": "string",
                "asset_identifier": "string",
                "cloud_provider": "string",
                "region": "string"
            }
        ]
    }
    """
    returned_payload = {}
    returned_payload["resources"] = []
    keys = ["account_id", "asset_identifier", "cloud_provider", "region"]
    item = {}
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)
    returned_payload["resources"].append(item)

    return returned_payload
