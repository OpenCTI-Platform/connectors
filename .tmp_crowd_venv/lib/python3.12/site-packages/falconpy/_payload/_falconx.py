"""Internal payload handling library - Falcon X Sandbox.

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


def falconx_payload(passed_keywords: dict) -> dict:
    """Create a properly formatting submit payload.

    {
        "sandbox": [
            {
                "action_script": "string",
                "command_line": "string",
                "document_password": "string",
                "enable_tor": true,
                "environment_id": 0,
                "network_settings": "string",
                "sha256": "string",
                "submit_name": "string",
                "system_date": "string",
                "system_time": "string",
                "url": "string"
            }
        ],
        "send_email_notification": true,
        "user_tags": [
            "string"
        ]
    }
    """
    returned_payload = {}
    sandbox = []
    sandbox_item = {}
    keys = [
        "action_script", "command_line", "document_password", "network_settings", "sha256",
        "submit_name", "system_date", "system_time", "url"
        ]
    for key in keys:
        if passed_keywords.get(key, None):
            sandbox_item[key] = passed_keywords.get(key, None)
    if passed_keywords.get("enable_tor", None) is not None:
        sandbox_item["enable_tor"] = passed_keywords.get("enable_tor", None)
    if passed_keywords.get("environment_id", 0) > 0:
        sandbox_item["environment_id"] = passed_keywords.get("environment_id", None)
    if sandbox_item:
        sandbox.append(sandbox_item)

    if passed_keywords.get("send_email_notifications", None) is not None:
        email_notify = passed_keywords.get("send_email_notifications", None)
        returned_payload["send_email_notifications"] = email_notify

    passed_tags = passed_keywords.get("user_tags", None)
    if passed_tags:
        if isinstance(passed_tags, str):
            passed_tags = passed_tags.split(",")
        returned_payload["user_tags"] = passed_tags

    if sandbox:
        returned_payload["sandbox"] = sandbox

    return returned_payload
