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

_downloads_endpoints = [
  [
    "FetchFilesDownloadInfo",
    "GET",
    "/csdownloads/combined/files-download/v1",
    "Get files info and pre-signed download URLs",
    "downloads",
    [
      {
        "type": "string",
        "description": "Search files using various filters using query in Falcon Query Language (FQL). "
        "Supported filters: arch,category,file_name,file_version,os",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort records on. Supported columns:   arch  category  file_name  file_version  os",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "FetchFilesDownloadInfoV2",
    "GET",
    "/csdownloads/combined/files-download/v2",
    "Get cloud security tools info and pre-signed download URLs",
    "downloads",
    [
      {
        "type": "string",
        "description": "Search files using various filters. Supported filters: arch,category,file_name,file_version,os",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort records on. Supported columns:   arch  category  file_name  file_version  os",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset from where to begin. Maximum offset = 1000 - limit.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "DownloadFile",
    "GET",
    "/csdownloads/entities/files/download/v1",
    "Gets pre-signed URL for the file",
    "downloads",
    [
      {
        "type": "string",
        "description": "Name of the file to be downloaded",
        "name": "file_name",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Version of the file to be downloaded",
        "name": "file_version",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "EnumerateFile",
    "GET",
    "/csdownloads/entities/files/enumerate/v1",
    "Enumerates a list of files available for CID",
    "downloads",
    [
      {
        "type": "string",
        "description": "Apply filtering on file name",
        "name": "file_name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Apply filtering on file version",
        "name": "file_version",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Apply filtering on file platform",
        "name": "platform",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Apply filtering on operating system",
        "name": "os",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Apply filtering on architecture",
        "name": "arch",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Apply filtering on file category",
        "name": "category",
        "in": "query"
      }
    ]
  ]
]
