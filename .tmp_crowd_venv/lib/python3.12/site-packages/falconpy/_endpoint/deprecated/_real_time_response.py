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

_real_time_response_endpoints = [
  [
    "RTR-AggregateSessions",
    "POST",
    "/real-time-response/aggregates/sessions/GET/v1",
    "Get aggregates on session data.",
    "real_time_response",
    [
      {
        "description": "Supported aggregations:   term  date_range\n\nSupported aggregation "
        "members:\n\n**date_ranges** If peforming a date range query specify the **from** and **to** date ranges.  "
        "These can be in common date formats like 2019-07-18 or now\n**field** Term you want to aggregate on.  If doing "
        " a date_range query, this is the date field you want to apply the date ranges to\n**filter** Optional filter "
        "criteria in the form of an FQL query. For more information about FQL queries, see our [FQL documentation in "
        "Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-"
        "guide).\n**name** Name of the aggregation\n**size** Size limit to apply to the queries.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "RTR-CheckActiveResponderCommandStatus",
    "GET",
    "/real-time-response/entities/active-responder-command/v1",
    "Get status of an executed active-responder command on a single host.",
    "real_time_response",
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
    "RTR-ExecuteActiveResponderCommand",
    "POST",
    "/real-time-response/entities/active-responder-command/v1",
    "Execute an active responder command on a single host.",
    "real_time_response",
    [
      {
        "description": "Use this endpoint to run these [real time response "
        "commands](https://falcon.crowdstrike.com/documentation/page/b8c1738c/real-time-response-and-network-"
        "containment#k893b7c0):  cat  cd  clear  cp  encrypt  env  eventlog  filehash  get  getsid  help  history  "
        "ipconfig  kill  ls  map  memdump  mkdir  mount  mv  netstat  ps  reg query  reg set  reg delete  reg load  reg "
        " unload  restart  rm  runscript  shutdown  unmap  update history  update install  update list  update query  "
        "xmemdump  zip\n\nRequired values.  The rest of the fields are unused.\n**base_command** Active-Responder "
        "command type we are going to execute, for example: get or cp.  Refer to the RTR documentation for the full "
        "list of commands.\n**command_string** Full command string for the command. For example  get "
        "some_file.txt\n**session_id** RTR session ID to run the command on",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "RTR-CheckCommandStatus",
    "GET",
    "/real-time-response/entities/command/v1",
    "Get status of an executed command on a single host.",
    "real_time_response",
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
    "RTR-ExecuteCommand",
    "POST",
    "/real-time-response/entities/command/v1",
    "Execute a command on a single host.",
    "real_time_response",
    [
      {
        "description": "Use this endpoint to run these [real time response "
        "commands](https://falcon.crowdstrike.com/documentation/page/b8c1738c/real-time-response-and-network-"
        "containment#k893b7c0):  cat  cd  clear  env  eventlog  filehash  getsid  help  history  ipconfig  ls  mount  "
        "netstat  ps  reg query\n\nRequired values.  The rest of the fields are unused.\n**base_command** read-only "
        "command type we are going to execute, for example: ls or cd.  Refer to the RTR documentation for the full list "
        " of commands.\n**command_string** Full command string for the command. For example  cd "
        "C:\\some_directory\n**session_id** RTR session ID to run the command on",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "RTR-GetExtractedFileContents",
    "GET",
    "/real-time-response/entities/extracted-file-contents/v1",
    "Get RTR extracted file contents for specified session and sha256.",
    "real_time_response",
    [
      {
        "type": "string",
        "description": "RTR Session id",
        "name": "session_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Extracted SHA256 (e.g. 'efa256a96af3b556cd3fc9d8b1cf587d72807d7805ced441e8149fc279db422b')",
        "name": "sha256",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Filename to use for the archive name and the file within the archive.",
        "name": "filename",
        "in": "query"
      }
    ]
  ],
  [
    "RTR-ListFiles",
    "GET",
    "/real-time-response/entities/file/v1",
    "Get a list of files for the specified RTR session.",
    "real_time_response",
    [
      {
        "type": "string",
        "description": "RTR Session id",
        "name": "session_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-DeleteFile",
    "DELETE",
    "/real-time-response/entities/file/v1",
    "Delete a RTR session file.",
    "real_time_response",
    [
      {
        "type": "string",
        "description": "RTR Session file id",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "RTR Session id",
        "name": "session_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-ListFilesV2",
    "GET",
    "/real-time-response/entities/file/v2",
    "Get a list of files for the specified RTR session.",
    "real_time_response",
    [
      {
        "type": "string",
        "description": "RTR Session id",
        "name": "session_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-DeleteFileV2",
    "DELETE",
    "/real-time-response/entities/file/v2",
    "Delete a RTR session file.",
    "real_time_response",
    [
      {
        "type": "string",
        "description": "RTR Session file id",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "RTR Session id",
        "name": "session_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-ListQueuedSessions",
    "POST",
    "/real-time-response/entities/queued-sessions/GET/v1",
    "Get queued session metadata by session ID.",
    "real_time_response",
    [
      {
        "description": "**ids** List of RTR sessions to retrieve.  RTR will only return the sessions that were "
        "created by the calling user",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "RTR-DeleteQueuedSession",
    "DELETE",
    "/real-time-response/entities/queued-sessions/command/v1",
    "Delete a queued session command",
    "real_time_response",
    [
      {
        "type": "string",
        "description": "RTR Session id",
        "name": "session_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Cloud Request ID of the executed command to query",
        "name": "cloud_request_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-PulseSession",
    "POST",
    "/real-time-response/entities/refresh-session/v1",
    "Refresh a session timeout on a single host.",
    "real_time_response",
    [
      {
        "description": "**device_id** The host agent ID to refresh the RTR session on.  RTR will retrieve an "
        "existing session for the calling user on this host",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "RTR-ListSessions",
    "POST",
    "/real-time-response/entities/sessions/GET/v1",
    "Get session metadata by session id.",
    "real_time_response",
    [
      {
        "description": "**ids** List of RTR sessions to retrieve.  RTR will only return the sessions that were "
        "created by the calling user",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "RTR-InitSession",
    "POST",
    "/real-time-response/entities/sessions/v1",
    "Initialize a new session with the RTR cloud.",
    "real_time_response",
    [
      {
        "type": "integer",
        "default": 30,
        "description": "Timeout for how long to wait for the request in seconds, default timeout is 30 "
        "seconds. Maximum is 5 minutes.",
        "name": "timeout",
        "in": "query"
      },
      {
        "type": "string",
        "default": "30s",
        "description": "Timeout duration for how long to wait for the request in duration syntax. Example, "
        "10s. Valid units: ns, us, ms, s, m, h. Maximum is 5 minutes.",
        "name": "timeout_duration",
        "in": "query"
      },
      {
        "description": "**device_id** The host agent ID to initialize the RTR session on.  RTR will retrieve "
        "an existing session for the calling user on this host\n**queue_offline** If we should queue this session if "
        "the host is offline.  Any commands run against an offline-queued session will be queued up and executed when "
        "the host comes online.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "RTR-DeleteSession",
    "DELETE",
    "/real-time-response/entities/sessions/v1",
    "Delete a session.",
    "real_time_response",
    [
      {
        "type": "string",
        "description": "RTR Session id",
        "name": "session_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RTR-ListAllSessions",
    "GET",
    "/real-time-response/queries/sessions/v1",
    "Get a list of session_ids.",
    "real_time_response",
    [
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
        "description": "Sort by spec. Ex: 'date_created|asc'.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Optional filter criteria in the form of an FQL query. For more information about FQL "
        "queries, see our [FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-"
        "query-language-feature-guide). “user_id” can accept a special value ‘@me’ which will restrict results to "
        "records with current user’s ID.",
        "name": "filter",
        "in": "query"
      }
    ]
  ]
]
