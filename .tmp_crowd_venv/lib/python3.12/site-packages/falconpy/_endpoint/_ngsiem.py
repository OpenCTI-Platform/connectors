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

_ngsiem_endpoints = [
  [
    "UploadLookupV1",
    "POST",
    "/humio/api/v1/repositories/{repository}/files",
    "Upload file to NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of repository",
        "name": "repository",
        "in": "path",
        "required": True
      },
      {
        "type": "file",
        "description": "file to upload",
        "name": "file",
        "in": "formData",
        "required": True
      }
    ]
  ],
  [
    "GetLookupV1",
    "GET",
    "/humio/api/v1/repositories/{repository}/files/{filename}",
    "Download lookup file from NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of repository",
        "name": "repository",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "description": "name of lookup file",
        "name": "filename",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "GetLookupFromPackageWithNamespaceV1",
    "GET",
    "/humio/api/v1/repositories/{repository}/files/{namespace}/{package}/{filename}",
    "Download lookup file in namespaced package from NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of repository",
        "name": "repository",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "description": "name of namespace",
        "name": "namespace",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "description": "name of package",
        "name": "package",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "description": "name of lookup file",
        "name": "filename",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "GetLookupFromPackageV1",
    "GET",
    "/humio/api/v1/repositories/{repository}/files/{package}/{filename}",
    "Download lookup file in package from NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of repository",
        "name": "repository",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "description": "name of package",
        "name": "package",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "description": "name of lookup file",
        "name": "filename",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "StartSearchV1",
    "POST",
    "/humio/api/v1/repositories/{repository}/queryjobs",
    "Initiate search",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of repository",
        "name": "repository",
        "in": "path",
        "required": True
      },
      {
        "description": "Query Job JSON request body",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetSearchStatusV1",
    "GET",
    "/humio/api/v1/repositories/{repository}/queryjobs/{id}",
    "Get status of search",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of repository",
        "name": "repository",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "description": "id of query",
        "name": "id",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "StopSearchV1",
    "DELETE",
    "/humio/api/v1/repositories/{repository}/queryjobs/{id}",
    "Stop search",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of repository",
        "name": "repository",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "description": "id of query",
        "name": "id",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "GetDashboardTemplate",
    "GET",
    "/ngsiem-content/entities/dashboards-template/v1",
    "Retrieve Dashboard in NGSIEM as LogScale YAML Template",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "dashboard ID value",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, dashboards",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ],
  [
    "CreateDashboardFromTemplate",
    "POST",
    "/ngsiem-content/entities/dashboards-template/v1",
    "Create Dashboard from LogScale YAML Template in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party",
        "name": "search_domain",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "name of the dashboard",
        "name": "name",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "LogScale dashboard YAML template content, see schema at https://schemas.humio.com/",
        "name": "yaml_template",
        "in": "formData"
      }
    ]
  ],
  [
    "UpdateDashboardFromTemplate",
    "PATCH",
    "/ngsiem-content/entities/dashboards-template/v1",
    "Update Dashboard from LogScale YAML Template in NGSIEM. Please note a successful update will result in a "
    "new ID value being returned.",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party",
        "name": "search_domain",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "id of the dashboard",
        "name": "ids",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "LogScale dashboard YAML template content, see schema at https://schemas.humio.com/",
        "name": "yaml_template",
        "in": "formData"
      }
    ]
  ],
  [
    "DeleteDashboard",
    "DELETE",
    "/ngsiem-content/entities/dashboards/v1",
    "Delete Dashboard in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "dashboard ID value",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ],
  [
    "GetLookupFile",
    "GET",
    "/ngsiem-content/entities/lookupfiles/v1",
    "Retrieve Lookup File in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "lookup file filename",
        "name": "filename",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, dashboards, "
        "parsers-repository",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ],
  [
    "CreateLookupFile",
    "POST",
    "/ngsiem-content/entities/lookupfiles/v1",
    "Create Lookup File in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, parsers-repository",
        "name": "search_domain",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "Filename of the lookup file to create",
        "name": "filename",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "file content to upload",
        "name": "file",
        "in": "formData"
      }
    ]
  ],
  [
    "UpdateLookupFile",
    "PATCH",
    "/ngsiem-content/entities/lookupfiles/v1",
    "Update Lookup File in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, parsers-repository",
        "name": "search_domain",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "Filename of the lookup file to update",
        "name": "filename",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "file content to upload",
        "name": "file",
        "in": "formData"
      }
    ]
  ],
  [
    "DeleteLookupFile",
    "DELETE",
    "/ngsiem-content/entities/lookupfiles/v1",
    "Delete Lookup File in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "lookup file filename",
        "name": "filename",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, parsers-repository",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ],
  [
    "GetParserTemplate",
    "GET",
    "/ngsiem-content/entities/parsers-template/v1",
    "Retrieve Parser in NGSIEM as LogScale YAML Template",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "parser ID value",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of repository, options; parsers-repository",
        "name": "repository",
        "in": "query"
      }
    ]
  ],
  [
    "CreateParserFromTemplate",
    "POST",
    "/ngsiem-content/entities/parsers-template/v1",
    "Create Parser from LogScale YAML Template in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of repository, options; parsers-repository",
        "name": "repository",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "name of the parser",
        "name": "name",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "LogScale Parser YAML template content, see schema at https://schemas.humio.com/",
        "name": "yaml_template",
        "in": "formData"
      }
    ]
  ],
  [
    "GetParser",
    "GET",
    "/ngsiem-content/entities/parsers/v1",
    "Retrieve Parser in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "parser ID value",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of repository, options; parsers-repository",
        "name": "repository",
        "in": "query"
      }
    ]
  ],
  [
    "CreateParser",
    "POST",
    "/ngsiem-content/entities/parsers/v1",
    "Create Parser in NGSIEM",
    "ngsiem",
    [
      {
        "description": "create parser request",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateParser",
    "PATCH",
    "/ngsiem-content/entities/parsers/v1",
    "Update Parser in NGSIEM. Please note that name changes are not supported, but rather should be created as a new parser.",
    "ngsiem",
    [
      {
        "description": "update parser request",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteParser",
    "DELETE",
    "/ngsiem-content/entities/parsers/v1",
    "Delete Parser in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "parser ID value",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of repository, options; parsers-repository",
        "name": "repository",
        "in": "query"
      }
    ]
  ],
  [
    "GetSavedQueryTemplate",
    "GET",
    "/ngsiem-content/entities/savedqueries-template/v1",
    "Retrieve Saved Query in NGSIEM as LogScale YAML Template",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "saved query ID value",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, dashboards",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ],
  [
    "CreateSavedQuery",
    "POST",
    "/ngsiem-content/entities/savedqueries-template/v1",
    "Create Saved Query from LogScale YAML Template in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party",
        "name": "search_domain",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "LogScale Saved Query YAML template content, see schema at https://schemas.humio.com/",
        "name": "yaml_template",
        "in": "formData"
      }
    ]
  ],
  [
    "UpdateSavedQueryFromTemplate",
    "PATCH",
    "/ngsiem-content/entities/savedqueries-template/v1",
    "Update Saved Query from LogScale YAML Template in NGSIEM. Please note a successful update will result in "
    "a new ID value being returned.",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party",
        "name": "search_domain",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "id of the dashboard",
        "name": "ids",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "LogScale Saved Query YAML template content, see schema at https://schemas.humio.com/",
        "name": "yaml_template",
        "in": "formData"
      }
    ]
  ],
  [
    "DeleteSavedQuery",
    "DELETE",
    "/ngsiem-content/entities/savedqueries/v1",
    "Delete Saved Query in NGSIEM",
    "ngsiem",
    [
      {
        "type": "string",
        "description": "saved query ID value",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ],
  [
    "ListDashboards",
    "GET",
    "/ngsiem-content/queries/dashboards/v1",
    "List Dashboards in NGSIEM",
    "ngsiem",
    [
      {
        "pattern": "^\\d{1,4}$",
        "type": "string",
        "default": "50",
        "description": "maximum number of results to return",
        "name": "limit",
        "in": "query"
      },
      {
        "pattern": "^\\d{1,4}$",
        "type": "string",
        "default": "0",
        "description": "number of results to offset the returned results by",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter to apply to the name of the content, only currently support text match on "
        "name field: name:~'value'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, dashboards",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ],
  [
    "ListLookupFiles",
    "GET",
    "/ngsiem-content/queries/lookupfiles/v1",
    "List Lookup Files in NGSIEM",
    "ngsiem",
    [
      {
        "pattern": "^\\d{1,4}$",
        "type": "string",
        "default": "50",
        "description": "maximum number of results to return",
        "name": "limit",
        "in": "query"
      },
      {
        "pattern": "^\\d{1,4}$",
        "type": "string",
        "default": "0",
        "description": "number of results to offset the returned results by",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter to apply to the name of the content, only currently support text match on "
        "name field: name:~'value'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, dashboards, "
        "parsers-repository",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ],
  [
    "ListParsers",
    "GET",
    "/ngsiem-content/queries/parsers/v1",
    "List Parsers in NGSIEM",
    "ngsiem",
    [
      {
        "pattern": "^\\d{1,4}$",
        "type": "string",
        "default": "50",
        "description": "maximum number of results to return",
        "name": "limit",
        "in": "query"
      },
      {
        "pattern": "^\\d{1,4}$",
        "type": "string",
        "default": "0",
        "description": "number of results to offset the returned results by",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter to apply to the name of the content, only currently support text match on "
        "name field: name:~'value'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of repository, options; parsers-repository",
        "name": "repository",
        "in": "query"
      }
    ]
  ],
  [
    "ListSavedQueries",
    "GET",
    "/ngsiem-content/queries/savedqueries/v1",
    "Get Saved Queries in NGSIEM",
    "ngsiem",
    [
      {
        "pattern": "^\\d{1,4}$",
        "type": "string",
        "default": "50",
        "description": "maximum number of results to return",
        "name": "limit",
        "in": "query"
      },
      {
        "pattern": "^\\d{1,4}$",
        "type": "string",
        "default": "0",
        "description": "number of results to offset the returned results by",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter to apply to the name of the content, only currently support text match on "
        "name field: name:~'value'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "name of search domain (view or repo), options; all, falcon, third-party, dashboards",
        "name": "search_domain",
        "in": "query"
      }
    ]
  ]
]
