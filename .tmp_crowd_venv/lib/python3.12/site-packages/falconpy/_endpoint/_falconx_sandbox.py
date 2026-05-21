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

_falconx_sandbox_endpoints = [
  [
    "GetArtifacts",
    "GET",
    "/falconx/entities/artifacts/v1",
    "Download IOC packs, PCAP files, memory dumps, and other analysis artifacts.",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "ID of an artifact, such as an IOC pack, PCAP file, memory dump, or actor image. Find "
        "an artifact ID in a report or summary.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The name given to your downloaded file.",
        "name": "name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Format used to compress your downloaded file. Currently, you must provide the value "
        "gzip, the only valid format.",
        "name": "Accept-Encoding",
        "in": "header"
      }
    ]
  ],
  [
    "GetMemoryDumpExtractedStrings",
    "GET",
    "/falconx/entities/memory-dump/extracted-strings/v1",
    "Get extracted strings from a memory dump",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "Extracted strings id",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The name given to your downloaded file.",
        "name": "name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Format used to compress your downloaded file. Currently, you must provide the value "
        "gzip, the only valid format.",
        "name": "Accept-Encoding",
        "in": "header"
      }
    ]
  ],
  [
    "GetMemoryDumpHexDump",
    "GET",
    "/falconx/entities/memory-dump/hex-dump/v1",
    "Get hex view of a memory dump",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "Hex dump id",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The name given to your downloaded file.",
        "name": "name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Format used to compress your downloaded file. Currently, you must provide the value "
        "gzip, the only valid format.",
        "name": "Accept-Encoding",
        "in": "header"
      }
    ]
  ],
  [
    "GetMemoryDump",
    "GET",
    "/falconx/entities/memory-dump/v1",
    "Get memory dump content, as binary",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "Memory dump id",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The name given to your downloaded file.",
        "name": "name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Format used to compress your downloaded file. Currently, you must provide the value "
        "gzip, the only valid format.",
        "name": "Accept-Encoding",
        "in": "header"
      }
    ]
  ],
  [
    "GetSummaryReports",
    "GET",
    "/falconx/entities/report-summaries/v1",
    "Get a short summary version of a sandbox report.",
    "falconx_sandbox",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "ID of a summary. Find a summary ID from the response when submitting a malware sample "
        "or search with /falconx/queries/reports/v1.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetReports",
    "GET",
    "/falconx/entities/reports/v1",
    "Get a full sandbox report.",
    "falconx_sandbox",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "ID of a report. Find a report ID from the response when submitting a malware sample or "
        "search with /falconx/queries/reports/v1.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "DeleteReport",
    "DELETE",
    "/falconx/entities/reports/v1",
    "Delete report based on the report ID. Operation can be checked for success by polling for the report ID "
    "on the report-summaries endpoint.",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "ID of a report.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetSubmissions",
    "GET",
    "/falconx/entities/submissions/v1",
    "Check the status of a sandbox analysis. Time required for analysis varies but is usually less than 15 minutes.",
    "falconx_sandbox",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "ID of a submitted malware sample. Find a submission ID from the response when "
        "submitting a malware sample or search with /falconx/queries/submissions/v1.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "Submit",
    "POST",
    "/falconx/entities/submissions/v1",
    "Submit an uploaded file or a URL for sandbox analysis. Time required for analysis varies but is usually "
    "less than 15 minutes.",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "Agent ID",
        "name": "aid",
        "in": "query"
      },
      {
        "description": "Submit either a URL or a sample SHA256 for sandbox analysis. The sample file must have "
        " been previously uploaded through /samples/entities/samples/v2. You must specify a JSON object that includes "
        "the falconx.SubmissionParametersV1 key/value pairs shown below.\n\n**environment_id**: Specifies the sandbox "
        "environment used for analysis. Values:\n  400: MacOS Catalina 10.15  300: Linux Ubuntu 16.04, 64-bit - "
        "deprecated  310: Linux Ubuntu 20, 64-bit  200: Android (static analysis)  160: Windows 10, 64-bit  140: "
        "Windows 11, 64-bit  110: Windows 7, 64-bit  100: Windows 7, 32-bit\n\n**sha256** ID of the sample, which is a "
        "SHA256 hash value. Find a sample ID from the response when uploading a malware sample or search with "
        "/falconx/queries/submissions/v1.The url parameter must be unset if sha256 is used.\n\n**url** A web page or "
        "file URL. It can be HTTP(S) or FTP. The sha256 parameter must be unset if url is used.\n\n**action_script** "
        "(optional): Runtime script for sandbox analysis. Values:\n  default  default_maxantievasion  "
        "default_randomfiles  default_randomtheme  default_openie\n\n**command_line** (optional): Command line script "
        "passed to the submitted file at runtime. Max length: 2048 characters\n\n**document_password** (optional): "
        "Auto-filled for Adobe or Office files that prompt for a password. Max length: 32 characters\n\n**enable_tor** "
        "(optional): Deprecated, please use network_settings instead. If true, sandbox analysis routes network traffic "
        "via TOR. Default: False.\n\n**network_settings** (optional): Specifies the sandbox network_settings used for "
        "analysis. Values:\n  default: Fully operating network  tor: Route network traffic via TOR  simulated: Simulate "
        " network traffic  offline: No network traffic\n\n**submit_name** (optional): Name of the malware sample that's "
        " used for file type detection and analysis\n\n**system_date** (optional): Set a custom date in the format "
        "yyyy-MM-dd for the sandbox environment\n\n**system_time** (optional): Set a custom time in the format HH:mm "
        "for the sandbox environment.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QueryReports",
    "GET",
    "/falconx/queries/reports/v1",
    "Find sandbox reports by providing an FQL filter and paging details. Returns a set of report IDs that "
    "match your criteria.",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "Optional filter and sort criteria in the form of an FQL query. For more information "
        "about FQL queries, see [our FQL documentation in "
        "Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The offset to start retrieving reports from.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Maximum number of report IDs to return. Max: 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort order: asc or desc.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "QuerySubmissions",
    "GET",
    "/falconx/queries/submissions/v1",
    "Find submission IDs for uploaded files by providing an FQL filter and paging details. Returns a set of "
    "submission IDs that match your criteria.",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "Optional filter and sort criteria in the form of an FQL query. For more information "
        "about FQL queries, see [our FQL documentation in "
        "Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The offset to start retrieving submissions from.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Maximum number of submission IDs to return. Max: 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort order: asc or desc.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "GetSampleV2",
    "GET",
    "/samples/entities/samples/v2",
    "Retrieves the file associated with the given ID (SHA256)",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "The file SHA256.",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Flag whether the sample should be zipped and password protected with pass='infected'",
        "name": "password_protected",
        "in": "query"
      }
    ]
  ],
  [
    "UploadSampleV2",
    "POST",
    "/samples/entities/samples/v2",
    "Upload a file for sandbox analysis. After uploading, use `/falconx/entities/submissions/v1` to start "
    "analyzing the file.",
    "falconx_sandbox",
    [
      {
        "type": "file",
        "description": "Content of the uploaded sample in binary format. For example, use --data-binary "
        "@$FILE_PATH when using cURL. Max file size: 256 MB.\n\nAccepted file formats:\n  Portable executables: .exe, "
        ".scr, .pif, .dll, .com, .cpl, etc.  Office documents: .doc, .docx, .ppt, .pps, .pptx, .ppsx, .xls, .xlsx, "
        ".rtf, .pub  PDF  APK  Executable JAR  Windows script component: .sct  Windows shortcut: .lnk  Windows help: "
        ".chm  HTML application: .hta  Windows script file: .wsf  Javascript: .js  Visual Basic: .vbs,  .vbe  Shockwave "
        " Flash: .swf  Perl: .pl  Powershell: .ps1, .psd1, .psm1  Scalable vector graphics: .svg  Python: .py  Linux "
        "ELF executables  Email files: MIME RFC 822 .eml, Outlook .msg.",
        "name": "sample",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "Name of the file.",
        "name": "file_name",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "A descriptive comment to identify the file for other users.",
        "name": "comment",
        "in": "formData"
      },
      {
        "type": "boolean",
        "default": True,
        "description": "Defines visibility of this file in Falcon MalQuery, either via the API or the Falcon "
        "console.\n  true: File is only shown to users within your customer account  false: File can be seen by other "
        "CrowdStrike customers \n\nDefault: True.",
        "name": "is_confidential",
        "in": "formData"
      }
    ]
  ],
  [
    "DeleteSampleV2",
    "DELETE",
    "/samples/entities/samples/v2",
    "Removes a sample, including file, meta and submissions from the collection",
    "falconx_sandbox",
    [
      {
        "type": "string",
        "description": "The file SHA256.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "QuerySampleV1",
    "POST",
    "/samples/queries/samples/GET/v1",
    "Retrieves a list with sha256 of samples that exist and customer has rights to access them, maximum number "
    "of accepted items is 200",
    "falconx_sandbox",
    [
      {
        "description": "Pass a list of sha256s to check if the exist. It will be returned the list of existing hashes.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
