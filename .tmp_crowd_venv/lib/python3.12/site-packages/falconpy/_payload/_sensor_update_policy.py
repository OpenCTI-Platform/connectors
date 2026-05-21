"""Internal payload handling library - Sensor Update Policy Payloads.

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


def sensor_policy_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted prevention policy payload.

    Supports create and update operations. Single policy only.
    {
        "resources": [
            {
                "description": "string",
                "name": "string",
                "platform_name": "Windows",
                "settings": {
                    "build": "string",
                    "scheduler": {
                        "enabled": true,
                        "schedules": [
                            {
                                "days": [
                                    0
                                ],
                                "end": "string",
                                "start": "string"
                            }
                        ],
                        "timezone": "string"
                    },
                    "show_early_adopter_builds": true,
                    "uninstall_protection": "ENABLED",
                    "variants": [
                        {
                            "build": "string",
                            "platform": "string"
                        }
                    ]
                }
            }
        ]
    }
    """
    returned_payload = {}
    resources = []
    item = {}
    if passed_keywords.get("id", None):
        item["id"] = passed_keywords.get("id", None)
    if passed_keywords.get("description", None):
        item["description"] = passed_keywords.get("description", None)
    if passed_keywords.get("name", None):
        item["name"] = passed_keywords.get("name", None)
    if passed_keywords.get("platform_name", None):
        item["platform_name"] = passed_keywords.get("platform_name", None)
    settings = {}
    if passed_keywords.get("build", None):
        settings["build"] = passed_keywords.get("build", None)
    if passed_keywords.get("scheduler", None):
        settings["scheduler"] = passed_keywords.get("scheduler", None)
    if passed_keywords.get("show_early_adopter_builds", None):
        settings["show_early_adopter_builds"] = passed_keywords.get("show_early_adopter_builds", None)
    if passed_keywords.get("uninstall_protection", None):
        settings["uninstall_protection"] = passed_keywords.get("uninstall_protection", "DISABLED")
    if passed_keywords.get("variants", None):
        settings["variants"] = passed_keywords.get("variants", None)
    if settings:
        item["settings"] = settings
    # Passing settings overrides the passed build / uninstall_protection values
    if passed_keywords.get("settings", None):
        item["settings"] = passed_keywords.get("settings", None)

    resources.append(item)
    returned_payload["resources"] = resources

    return returned_payload
