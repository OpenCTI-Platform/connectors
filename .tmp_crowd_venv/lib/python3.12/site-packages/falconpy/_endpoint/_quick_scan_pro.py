"""Internal API endpoint constant library.

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

_quick_scan_pro_endpoints = [
  [
    "UploadFileQuickScanPro",
    "POST",
    "/quickscanpro/entities/files/v1",
    "Uploads a file to be further analyzed with QuickScan Pro. Supports both multipart/form-data and "
    "application/octet-stream uploads. The samples expire according to the Retention Policies set. See parameter "
    "descriptions for usage per content type.",
    "quick_scan_pro",
    [
      {
        "type": "file",
        "description": "Binary file to be uploaded. Max file size: 256 MB. Use --data-binary @$FILE_PATH for "
        "octet-stream/cURL uploads",
        "name": "file",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "OCTET-STREAM ONLY - Name of the file (required for octet-stream uploads).",
        "name": "file_name",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "If true, after upload, it starts scanning immediately. Default scan mode is 'false'",
        "name": "scan",
        "in": "formData"
      }
    ]
  ],
  [
    "UploadFileMixin0Mixin94",
    "POST",
    "/quickscanpro/entities/files/v1",
    "Uploads a file to be further analyzed with QuickScan Pro. The samples expire after 90 days.",
    "quick_scan_pro",
    [
      {
        "type": "file",
        "description": "Binary file to be uploaded. Max file size: 256 MB.",
        "name": "file",
        "in": "formData",
        "required": True
      },
      {
        "type": "boolean",
        "default": False,
        "description": "If true, after upload, it starts scanning immediately. Default scan mode is 'false'",
        "name": "scan",
        "in": "formData"
      }
    ]
  ],
  [
    "DeleteFile",
    "DELETE",
    "/quickscanpro/entities/files/v1",
    "Deletes file by its sha256 identifier.",
    "quick_scan_pro",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "File's SHA256",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetScanResult",
    "GET",
    "/quickscanpro/entities/scans/v1",
    "Gets the result of an QuickScan Pro scan.",
    "quick_scan_pro",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Scan job IDs previously created by LaunchScan",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "LaunchScan",
    "POST",
    "/quickscanpro/entities/scans/v1",
    "Starts scanning a file uploaded through '/quickscanpro/entities/files/v1'.",
    "quick_scan_pro",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteScanResult",
    "DELETE",
    "/quickscanpro/entities/scans/v1",
    "Deletes the result of an QuickScan Pro scan.",
    "quick_scan_pro",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Scan job IDs previously created by LaunchScan",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "QueryScanResults",
    "GET",
    "/quickscanpro/queries/scans/v1",
    "FQL query specifying the filter parameters",
    "quick_scan_pro",
    [
      {
        "type": "string",
        "description": "Empty value means to not filter on anything\nAvailable filter fields that supports "
        "match (~): _all, mitre_attacks.description\nAvailable filter fields that supports exact match: cid,sha256,id,s "
        "tatus,type,entity,executor,verdict,verdict_reason,verdict_source,artifacts.file_artifacts.sha256,artifacts.fil "
        "e_artifacts.filename,artifacts.file_artifacts.verdict,artifacts.file_artifacts.verdict_reasons,artifacts.url_a "
        "rtifacts.url,artifacts.url_artifacts.verdict,artifacts.url_artifacts.verdict_reasons,mitre_attacks.attack_id,m "
        "itre_attacks.attack_id_wiki,mitre_attacks.tactic,mitre_attacks.technique,mitre_attacks.capec_id,mitre_attacks. "
        "parent.attack_id,mitre_attacks.parent.attack_id_wiki,mitre_attacks.parent.technique\nAvailable filter fields "
        "that supports wildcard (*): mitre_attacks.description\nAvailable filter fields that supports range comparisons "
        " (>, <, >=, <=): created_timestamp, updated_timestamp\nAll filter fields and operations supports negation "
        "(!).\n_all field is used to search between all fields.",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving ids from.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 50,
        "description": "Maximum number of IDs to return. Max: 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort order: asc or desc. Sort supported fields created_timestamp",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
