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

_foundry_logscale_endpoints = [
  [
    "ListReposV1",
    "GET",
    "/loggingapi/combined/repos/v1",
    "Lists available repositories and views",
    "foundry_logscale",
    [
      {
        "type": "boolean",
        "default": False,
        "description": "Include whether test data is present in the application repository",
        "name": "check_test_data",
        "in": "query"
      }
    ]
  ],
  [
    "IngestDataAsyncV1",
    "POST",
    "/loggingapi/entities/data-ingestion/ingest-async/v1",
    "Asynchronously ingest data into the application repository",
    "foundry_logscale",
    [
      {
        "type": "string",
        "description": "JSON data to ingest",
        "name": "data_content",
        "in": "formData"
      },
      {
        "type": "file",
        "description": "Data file to ingest",
        "name": "data_file",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "Repository name if not part of a foundry app",
        "name": "repo",
        "in": "formData"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "description": "Custom tag for ingested data in the form tag:value",
        "name": "tag",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "Tag the data with the specified source",
        "name": "tag_source",
        "in": "formData"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Tag the data with test-ingest",
        "name": "test_data",
        "in": "formData"
      }
    ]
  ],
  [
    "IngestDataV1",
    "POST",
    "/loggingapi/entities/data-ingestion/ingest/v1",
    "Synchronously ingest data into the application repository",
    "foundry_logscale",
    [
      {
        "type": "string",
        "description": "JSON data to ingest",
        "name": "data_content",
        "in": "formData"
      },
      {
        "type": "file",
        "description": "Data file to ingest",
        "name": "data_file",
        "in": "formData"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "description": "Custom tag for ingested data in the form tag:value",
        "name": "tag",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "Tag the data with the specified source",
        "name": "tag_source",
        "in": "formData"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Tag the data with test-ingest",
        "name": "test_data",
        "in": "formData"
      }
    ]
  ],
  [
    "CreateFileV1",
    "POST",
    "/loggingapi/entities/lookup-files/v1",
    "Creates a lookup file",
    "foundry_logscale",
    [
      {
        "maxLength": 36,
        "minLength": 36,
        "type": "string",
        "description": "Requester UUID.",
        "name": "X-CS-USERUUID",
        "in": "header"
      },
      {
        "type": "file",
        "description": "File to be uploaded",
        "name": "file",
        "in": "formData",
        "required": True
      },
      {
        "maxLength": 50,
        "minLength": 5,
        "type": "string",
        "description": "Name used to identify the file",
        "name": "name",
        "in": "formData",
        "required": True
      },
      {
        "maxLength": 255,
        "minLength": 5,
        "type": "string",
        "description": "File description",
        "name": "description",
        "in": "formData"
      },
      {
        "maxLength": 32,
        "minLength": 32,
        "type": "string",
        "description": "Unique identifier of the file being updated.",
        "name": "id",
        "in": "formData"
      },
      {
        "maxLength": 255,
        "minLength": 5,
        "type": "string",
        "description": "Name of repository or view to save the file",
        "name": "repo",
        "in": "formData"
      }
    ]
  ],
  [
    "UpdateFileV1",
    "PATCH",
    "/loggingapi/entities/lookup-files/v1",
    "Updates a lookup file",
    "foundry_logscale",
    [
      {
        "maxLength": 36,
        "minLength": 36,
        "type": "string",
        "description": "Requester UUID.",
        "name": "X-CS-USERUUID",
        "in": "header"
      },
      {
        "minLength": 32,
        "type": "string",
        "description": "Unique identifier of the file being updated.",
        "name": "id",
        "in": "formData",
        "required": True
      },
      {
        "maxLength": 255,
        "minLength": 5,
        "type": "string",
        "description": "File description",
        "name": "description",
        "in": "formData"
      },
      {
        "type": "file",
        "description": "File to be uploaded",
        "name": "file",
        "in": "formData"
      }
    ]
  ],
  [
    "CreateSavedSearchesDynamicExecuteV1",
    "POST",
    "/loggingapi/entities/saved-searches/execute-dynamic/v1",
    "Execute a dynamic saved search",
    "foundry_logscale",
    [
      {
        "type": "string",
        "description": "Application ID.",
        "name": "app_id",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Include generated schemas in the response",
        "name": "include_schema_generation",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Include test data when executing searches",
        "name": "include_test_data",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to try to infer data types in json event response instead of returning map[string]string",
        "name": "infer_json_types",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to validate search results against their schema",
        "name": "match_response_schema",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to include metadata in the response",
        "name": "metadata",
        "in": "query"
      },
      {
        "enum": [
          "sync",
          "async",
          "async_offload"
        ],
        "type": "string",
        "description": "Mode to execute the query under.",
        "name": "mode",
        "in": "query"
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetSavedSearchesExecuteV1",
    "GET",
    "/loggingapi/entities/saved-searches/execute/v1",
    "Get the results of a saved search",
    "foundry_logscale",
    [
      {
        "type": "string",
        "description": "Job ID for a previously executed async query",
        "name": "job_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Application ID.",
        "name": "app_id",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to try to infer data types in json event response instead of returning map[string]string",
        "name": "infer_json_types",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "If set to true, result rows are dropped from the response and only the job status is returned",
        "name": "job_status_only",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "string",
        "description": "Maximum number of records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to validate search results against their schema",
        "name": "match_response_schema",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to include metadata in the response",
        "name": "metadata",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "string",
        "description": "Starting pagination offset of records to return.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "CreateSavedSearchesExecuteV1",
    "POST",
    "/loggingapi/entities/saved-searches/execute/v1",
    "Execute a saved search",
    "foundry_logscale",
    [
      {
        "type": "string",
        "description": "Application ID.",
        "name": "app_id",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to include search field details",
        "name": "detailed",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Include test data when executing searches",
        "name": "include_test_data",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to try to infer data types in json event response instead of returning map[string]string",
        "name": "infer_json_types",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to validate search results against their schema",
        "name": "match_response_schema",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to include metadata in the response",
        "name": "metadata",
        "in": "query"
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "CreateSavedSearchesIngestV1",
    "POST",
    "/loggingapi/entities/saved-searches/ingest/v1",
    "Populate a saved search",
    "foundry_logscale",
    [
      {
        "type": "string",
        "description": "Application ID.",
        "name": "app_id",
        "in": "query"
      }
    ]
  ],
  [
    "GetSavedSearchesJobResultsDownloadV1",
    "GET",
    "/loggingapi/entities/saved-searches/job-results-download/v1",
    "Get the results of a saved search as a file",
    "foundry_logscale",
    [
      {
        "type": "string",
        "description": "Job ID for a previously executed async query",
        "name": "job_id",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Whether to try to infer data types in json event response instead of returning map[string]string",
        "name": "infer_json_types",
        "in": "query"
      },
      {
        "enum": [
          "json",
          "csv"
        ],
        "type": "string",
        "description": "Result Format",
        "name": "result_format",
        "in": "query"
      }
    ]
  ],
  [
    "ListViewV1",
    "GET",
    "/loggingapi/entities/views/v1",
    "List views",
    "foundry_logscale",
    [
      {
        "type": "boolean",
        "default": False,
        "description": "Include whether test data is present in the application repository",
        "name": "check_test_data",
        "in": "query"
      }
    ]
  ]
]
