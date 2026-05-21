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

_sample_uploads_endpoints = [
  [
    "ArchiveListV1",
    "GET",
    "/archives/entities/archive-files/v1",
    "Retrieves the archives files in chunks.",
    "sample_uploads",
    [
      {
        "type": "string",
        "description": "The archive SHA256.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "default": 100,
        "description": "Max number of files to retrieve.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Offset from where to get files.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "ArchiveGetV1",
    "GET",
    "/archives/entities/archives/v1",
    "Retrieves the archives upload operation statuses. Status `done` means that archive was processed "
    "successfully. Status `error` means that archive was not processed successfully.",
    "sample_uploads",
    [
      {
        "type": "string",
        "description": "The archive SHA256.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "default": False,
        "description": "If true includes processed archive files in response.",
        "name": "include_files",
        "in": "query"
      }
    ]
  ],
  [
    "ArchiveUploadV1",
    "POST",
    "/archives/entities/archives/v1",
    "Uploads an archive and extracts files list from it. Operation is asynchronous use "
    "`/archives/entities/archives/v1` to check the status. After uploading, use `/archives/entities/extractions/v1` "
    " to copy the file to internal storage making it available for content analysis.\nThis method is deprecated in "
    "favor of `/archives/entities/archives/v2`",
    "sample_uploads",
    [
      {
        "description": "Content of the uploaded archive in binary format. For example, use --data-binary "
        "@$FILE_PATH when using cURL. Max file size: 100 MB.\n\nAccepted file formats:\n  Portable executables: .zip, "
        ".7z.",
        "name": "body",
        "in": "body",
        "required": True
      },
      {
        "type": "string",
        "description": "Name of the archive.",
        "name": "name",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Archive password.",
        "name": "password",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": True,
        "description": "Defines visibility of this file, either via the API or the Falcon console.\n  true: "
        "File is only shown to users within your customer account  false: File can be seen by other CrowdStrike "
        "customers \n\nDefault: True.",
        "name": "is_confidential",
        "in": "query"
      },
      {
        "type": "string",
        "description": "A descriptive comment to identify the file for other users.",
        "name": "comment",
        "in": "query"
      }
    ]
  ],
  [
    "ArchiveDeleteV1",
    "DELETE",
    "/archives/entities/archives/v1",
    "Delete an archive that was uploaded previously",
    "sample_uploads",
    [
      {
        "type": "string",
        "description": "The archive SHA256.",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ArchiveUploadV2",
    "POST",
    "/archives/entities/archives/v2",
    "Uploads an archive and extracts files list from it. Operation is asynchronous use "
    "`/archives/entities/archives/v1` to check the status. After uploading, use `/archives/entities/extractions/v1` "
    "to copy the file to internal storage making it available for content analysis.",
    "sample_uploads",
    [
      {
        "type": "file",
        "description": "Content of the uploaded archive. For example, use --form file=@$FILE_PATH;type= when "
        "using cURL. Supported file types are application/zip and application/x-7z-compressed.",
        "name": "file",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "Archive password. For example, use --form password= when using cURL.",
        "name": "password",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "Name of the archive. For example, use --form name= when using cURL.",
        "name": "name",
        "in": "formData",
        "required": True
      },
      {
        "type": "boolean",
        "default": True,
        "description": "Defines visibility of this file in Falcon MalQuery, either via the API or the Falcon "
        "console. For example, use --form is_confidential= when using cURL.\n  true: File is only shown to users within "
        "your customer account  false: File can be seen by other CrowdStrike customers \n\nDefault: True.",
        "name": "is_confidential",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "A descriptive comment to identify the file for other users. For example, use --form "
        "comment= when using cURL.",
        "name": "comment",
        "in": "formData"
      }
    ]
  ],
  [
    "ExtractionListV1",
    "GET",
    "/archives/entities/extraction-files/v1",
    "Retrieves the files extractions in chunks. Status `done` means that all files were processed "
    "successfully. Status `error` means that at least one of the file could not be processed.",
    "sample_uploads",
    [
      {
        "type": "string",
        "description": "The extraction operation ID.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Max number of file extractions to retrieve.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Offset from where to get file extractions.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "ExtractionGetV1",
    "GET",
    "/archives/entities/extractions/v1",
    "Retrieves the files extraction operation statuses. Status `done` means that all files were processed "
    "successfully. Status `error` means that at least one of the file could not be processed.",
    "sample_uploads",
    [
      {
        "type": "string",
        "description": "The extraction operation ID.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "default": False,
        "description": "If true includes processed archive files in response.",
        "name": "include_files",
        "in": "query"
      }
    ]
  ],
  [
    "ExtractionCreateV1",
    "POST",
    "/archives/entities/extractions/v1",
    "Extracts files from an uploaded archive and copies them to internal storage making it available for content analysis.",
    "sample_uploads",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetSampleV3",
    "GET",
    "/samples/entities/samples/v3",
    "Retrieves the file associated with the given ID (SHA256)",
    "sample_uploads",
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
    "UploadSampleV3",
    "POST",
    "/samples/entities/samples/v3",
    "Upload a file for further cloud analysis. After uploading, call the specific analysis API endpoint.",
    "sample_uploads",
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
    "DeleteSampleV3",
    "DELETE",
    "/samples/entities/samples/v3",
    "Removes a sample, including file, meta and submissions from the collection",
    "sample_uploads",
    [
      {
        "type": "string",
        "description": "The file SHA256.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ]
]
