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


def scheduled_scan_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted scheduled scan creation payload.

    {
        "cloud_ml_level_detection": 0,
        "cloud_ml_level_prevention": 0,
        "cpu_priority": 0,
        "description": "string",
        "endpoint_notification": true,
        "file_paths": [
            "string"
        ],
        "host_groups": [
            "string"
        ],
        "hosts": [
            "string"
        ]
        "initiated_from": "string",
        "max_duration": 0,
        "max_file_size": 0,
        "pause_duration": 0,
        "quarantine": true,
        "scan_exclusions": [
            "string"
        ],
        "scan_inclusions": [
            "string"
        ],
        "schedule": {
            "ignored_by_channelfile": true,
            "interval": 0,
            "start_timestamp": "string"
        },
        "sensor_ml_level_detection": 0,
        "sensor_ml_level_prevention": 0
    }
    """
    returned_payload = {}
    keys = ["cloud_ml_level_detection", "cloud_ml_level_prevention", "cpu_priority", "description",
            "endpoint_notification", "file_paths", "host_groups", "initiated_from", "max_duration",
            "max_file_size", "pause_duration", "quarantine", "scan_exclusions", "schedule",
            "sensor_ml_level_detection", "sensor_ml_level_prevention", "hosts", "scan_inclusions"
            ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key)

    schedule_keys = ["ignored_by_channelfile", "interval", "start_timestamp"]
    if "schedule" not in returned_payload:
        returned_payload["schedule"] = {}
    for key in schedule_keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload["schedule"][key] = passed_keywords.get(key)

    return returned_payload


# This operation is no longer supported
# def scans_report_payload(passed_keywords: dict) -> dict:
#     """Craft a properly formatted scans report creation payload.

#     {
#         "is_schedule": true,
#         "report_format": "string",
#         "search": {
#             "filter": "string",
#             "sort": "string"
#         }
#     }
#     """
#     returned_payload = {}
#     keys = ["is_schedule", "report_format", "search"]
#     for key in keys:
#         if passed_keywords.get(key, None) is not None:
#             returned_payload[key] = passed_keywords.get(key)

#     if "search" not in returned_payload:
#         returned_payload["search"] = {}
#     search_keys = ["filter", "sort"]
#     for key in search_keys:
#         if passed_keywords.get(key, None):
#             returned_payload["search"][key] = passed_keywords.get(key)

#     return returned_payload
