"""Internal API endpoint constant library (deprecated operations).

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

_real_time_response_admin_endpoints = [
  [
    "RTR-CheckAdminCommandStatus",
    "GET",
    "/real-time-response/entities/admin-command/v1",
    "Get status of an executed RTR administrator command on a single host.",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "Cloud Request ID of the executed command to query",
        "name": "cloud_request_id",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Sequence ID that we want to retrieve. Command responses are chunked across sequences",
        "name": "sequence_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-ExecuteAdminCommand",
    "POST",
    "/real-time-response/entities/admin-command/v1",
    "Execute a RTR administrator command on a single host.",
    "real_time_response_admin",
    [
      {
        "description": "Use this endpoint to run these [real time response "
        "commands](https://falcon.crowdstrike.com/documentation/page/b8c1738c/real-time-response-and-network-"
        "containment#k893b7c0):  cat  cd  clear  cp  encrypt  env  eventlog  filehash  get  getsid  help  history  "
        "ipconfig  kill  ls  map  memdump  mkdir  mount  mv  netstat  ps  put  reg query  reg set  reg delete  reg load "
        "  reg unload  restart  rm  run  runscript  shutdown  unmap  update history  update install  update list  "
        "update query  xmemdump  zip\n\nRequired values.  The rest of the fields are unused.\n**base_command** Active-"
        "Responder command type we are going to execute, for example: get or cp.  Refer to the RTR documentation for "
        "the full list of commands.\n**command_string** Full command string for the command. For example  get "
        "some_file.txt\n**session_id** RTR session ID to run the command on",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "RTR-GetFalconScripts",
    "GET",
    "/real-time-response/entities/falcon-scripts/v1",
    "Get Falcon scripts with metadata and content of script",
    "real_time_response_admin",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of the Falcon scripts you want to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-GetPutFileContents",
    "GET",
    "/real-time-response/entities/put-file-contents/v1",
    "Get RTR put file contents for a given file ID",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "put file ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-GetPut-Files",
    "GET",
    "/real-time-response/entities/put-files/v1",
    "Get put-files based on the ID's given. These are used for the RTR `put` command.",
    "real_time_response_admin",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "File IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-CreatePut-Files",
    "POST",
    "/real-time-response/entities/put-files/v1",
    "Upload a new put-file to use for the RTR `put` command.",
    "real_time_response_admin",
    [
      {
        "type": "file",
        "description": "put-file to upload",
        "name": "file",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "File description",
        "name": "description",
        "in": "formData",
        "required": True
      },
      {
        "maxLength": 32766,
        "type": "string",
        "description": "File name (if different than actual file name)",
        "name": "name",
        "in": "formData"
      },
      {
        "maxLength": 4096,
        "type": "string",
        "description": "The audit log comment",
        "name": "comments_for_audit_log",
        "in": "formData"
      }
    ]
  ],
  [
    "RTR-DeletePut-Files",
    "DELETE",
    "/real-time-response/entities/put-files/v1",
    "Delete a put-file based on the ID given.  Can only delete one file at a time.",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "File id",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-GetPut-FilesV2",
    "GET",
    "/real-time-response/entities/put-files/v2",
    "Get put-files based on the ID's given. These are used for the RTR `put` command.",
    "real_time_response_admin",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "File IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-CreatePut-FilesV2",
    "POST",
    "/real-time-response/entities/put-files/v2",
    "Upload a new put-file to use for the RTR `put` command.",
    "real_time_response_admin",
    [
      {
        "type": "file",
        "description": "put-file to upload",
        "name": "file",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "File description",
        "name": "description",
        "in": "formData",
        "required": True
      },
      {
        "maxLength": 32766,
        "type": "string",
        "description": "File name (if different than actual file name)",
        "name": "name",
        "in": "formData"
      },
      {
        "maxLength": 4096,
        "type": "string",
        "description": "The audit log comment",
        "name": "comments_for_audit_log",
        "in": "formData"
      }
    ]
  ],
  [
    "RTR-GetScripts",
    "GET",
    "/real-time-response/entities/scripts/v1",
    "Get custom-scripts based on the ID's given. These are used for the RTR `runscript` command.",
    "real_time_response_admin",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "File IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-CreateScripts",
    "POST",
    "/real-time-response/entities/scripts/v1",
    "Upload a new custom-script to use for the RTR `runscript` command.",
    "real_time_response_admin",
    [
      {
        "type": "file",
        "description": "custom-script file to upload.  These should be powershell scripts.",
        "name": "file",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "File description",
        "name": "description",
        "in": "formData",
        "required": True
      },
      {
        "maxLength": 32766,
        "type": "string",
        "description": "File name (if different than actual file name)",
        "name": "name",
        "in": "formData"
      },
      {
        "maxLength": 4096,
        "type": "string",
        "description": "The audit log comment",
        "name": "comments_for_audit_log",
        "in": "formData"
      },
      {
        "type": "string",
        "default": "none",
        "description": "Permission for the custom-script. Valid permission values: \n - private, usable by "
        "only the user who uploaded it \n - group, usable by all RTR Admins \n - public, usable by all active-"
        "responders and RTR admins",
        "name": "permission_type",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "The script text that you want to use to upload",
        "name": "content",
        "in": "formData"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Platforms for the file. Currently supports: windows, mac, linux, . If no platform is "
        "provided, it will default to 'windows'",
        "name": "platform",
        "in": "formData"
      }
    ]
  ],
  [
    "RTR-UpdateScripts",
    "PATCH",
    "/real-time-response/entities/scripts/v1",
    "Upload a new scripts to replace an existing one.",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "ID to update",
        "name": "id",
        "in": "formData",
        "required": True
      },
      {
        "type": "file",
        "description": "custom-script file to upload.  These should be powershell scripts.",
        "name": "file",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "File description",
        "name": "description",
        "in": "formData"
      },
      {
        "maxLength": 32766,
        "type": "string",
        "description": "File name (if different than actual file name)",
        "name": "name",
        "in": "formData"
      },
      {
        "maxLength": 4096,
        "type": "string",
        "description": "The audit log comment",
        "name": "comments_for_audit_log",
        "in": "formData"
      },
      {
        "type": "string",
        "default": "none",
        "description": "Permission for the custom-script. Valid permission values: \n - private, usable by "
        "only the user who uploaded it \n - group, usable by all RTR Admins \n - public, usable by all active-"
        "responders and RTR admins",
        "name": "permission_type",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "The script text that you want to use to upload",
        "name": "content",
        "in": "formData"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Platforms for the file. Currently supports: windows, mac, linux, ",
        "name": "platform",
        "in": "formData"
      }
    ]
  ],
  [
    "RTR-DeleteScripts",
    "DELETE",
    "/real-time-response/entities/scripts/v1",
    "Delete a custom-script based on the ID given.  Can only delete one script at a time.",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "File id",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-GetScriptsV2",
    "GET",
    "/real-time-response/entities/scripts/v2",
    "Get custom-scripts based on the ID's given. These are used for the RTR `runscript` command.",
    "real_time_response_admin",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "File IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-CreateScriptsV2",
    "POST",
    "/real-time-response/entities/scripts/v2",
    "Upload a new custom-script to use for the RTR `runscript` command.",
    "real_time_response_admin",
    [
      {
        "type": "file",
        "description": "custom-script file to upload.  These should be powershell scripts.",
        "name": "file",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "File description",
        "name": "description",
        "in": "formData",
        "required": True
      },
      {
        "maxLength": 32766,
        "type": "string",
        "description": "File name (if different than actual file name)",
        "name": "name",
        "in": "formData"
      },
      {
        "maxLength": 4096,
        "type": "string",
        "description": "The audit log comment",
        "name": "comments_for_audit_log",
        "in": "formData"
      },
      {
        "type": "string",
        "default": "none",
        "description": "Permission for the custom-script. Valid permission values: \n - private, usable by "
        "only the user who uploaded it \n - group, usable by all RTR Admins \n - public, usable by all active-"
        "responders and RTR admins",
        "name": "permission_type",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "The script text that you want to use to upload",
        "name": "content",
        "in": "formData"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Platforms for the file. Currently supports: windows, mac, linux, . If no platform is "
        "provided, it will default to 'windows'",
        "name": "platform",
        "in": "formData"
      }
    ]
  ],
  [
    "RTR-UpdateScriptsV2",
    "PATCH",
    "/real-time-response/entities/scripts/v2",
    "Upload a new scripts to replace an existing one.",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "ID to update",
        "name": "id",
        "in": "formData",
        "required": True
      },
      {
        "type": "file",
        "description": "custom-script file to upload.  These should be powershell scripts.",
        "name": "file",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "File description",
        "name": "description",
        "in": "formData"
      },
      {
        "maxLength": 32766,
        "type": "string",
        "description": "File name (if different than actual file name)",
        "name": "name",
        "in": "formData"
      },
      {
        "maxLength": 4096,
        "type": "string",
        "description": "The audit log comment",
        "name": "comments_for_audit_log",
        "in": "formData"
      },
      {
        "type": "string",
        "default": "none",
        "description": "Permission for the custom-script. Valid permission values: \n - private, usable by "
        "only the user who uploaded it \n - group, usable by all RTR Admins \n - public, usable by all active-"
        "responders and RTR admins",
        "name": "permission_type",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "The script text that you want to use to upload",
        "name": "content",
        "in": "formData"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Platforms for the file. Currently supports: windows, mac, linux, ",
        "name": "platform",
        "in": "formData"
      }
    ]
  ],
  [
    "RTR-ListFalconScripts",
    "GET",
    "/real-time-response/queries/falcon-scripts/v1",
    "Get a list of Falcon script IDs available to the user to run",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "Optional filter criteria in the form of an FQL query. For more information about FQL "
        "queries, see our [FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-"
        "query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 100,
        "type": "integer",
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "created_timestamp",
          "modified_timestamp",
          "name"
        ],
        "type": "string",
        "description": "Sort by spec. Ex: 'created_at|asc'.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "RTR-ListPut-Files",
    "GET",
    "/real-time-response/queries/put-files/v1",
    "Get a list of put-file ID's that are available to the user for the `put` command.",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "Optional filter criteria in the form of an FQL query. For more information about FQL "
        "queries, see our [FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-"
        "query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort by spec. Ex: 'created_at|asc'.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "RTR-ListScripts",
    "GET",
    "/real-time-response/queries/scripts/v1",
    "Get a list of custom-script ID's that are available to the user for the `runscript` command.",
    "real_time_response_admin",
    [
      {
        "type": "string",
        "description": "Optional filter criteria in the form of an FQL query. For more information about FQL "
        "queries, see our [FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-"
        "query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort by spec. Ex: 'created_at|asc'.",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
