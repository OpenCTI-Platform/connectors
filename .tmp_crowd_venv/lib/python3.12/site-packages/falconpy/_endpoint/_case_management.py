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
# pylint: disable=C0302

_case_management_endpoints = [
  [
    "aggregates_file_details_post_v1",
    "POST",
    "/case-files/aggregates/file-details/v1",
    "Get file details aggregates as specified via json in the request body.",
    "case_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      },
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "combined_file_details_get_v1",
    "GET",
    "/case-files/combined/file-details/v1",
    "Query file details",
    "case_management",
    [
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "maximum": 10,
        "minimum": 1,
        "type": "integer",
        "description": "Page size",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Page offset",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "entities_file_details_get_v1",
    "GET",
    "/case-files/entities/file-details/v1",
    "Get file details by id",
    "case_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_file_details_patch_v1",
    "PATCH",
    "/case-files/entities/file-details/v1",
    "Update file details",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_files_bulk_download_post_v1",
    "POST",
    "/case-files/entities/files/bulk-download/v1",
    "Download multiple existing file from case as a ZIP",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_files_download_get_v1",
    "GET",
    "/case-files/entities/files/download/v1",
    "Download existing file from case",
    "case_management",
    [
      {
        "type": "string",
        "description": "Resource ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_files_upload_post_v1",
    "POST",
    "/case-files/entities/files/upload/v1",
    "Upload file for case",
    "case_management",
    [
      {
        "type": "file",
        "description": "Local file to Upload",
        "name": "file",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "Description of the file",
        "name": "description",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "Case ID for the file",
        "name": "case_id",
        "in": "formData",
        "required": True
      }
    ]
  ],
  [
    "entities_files_delete_v1",
    "DELETE",
    "/case-files/entities/files/v1",
    "Delete file details by id",
    "case_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_retrieve_rtr_file_post_v1",
    "POST",
    "/case-files/entities/retrieve-rtr-file/v1",
    "retrieves a file from host using RTR and adds it to a case",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "queries_file_details_get_v1",
    "GET",
    "/case-files/queries/file-details/v1",
    "Query for ids of file details",
    "case_management",
    [
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "maximum": 10,
        "minimum": 1,
        "type": "integer",
        "description": "Page size",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Page offset",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "aggregates_notification_groups_post_v1",
    "POST",
    "/casemgmt/aggregates/notification-groups/v1",
    "Get notification groups aggregations",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "aggregates_notification_groups_post_v2",
    "POST",
    "/casemgmt/aggregates/notification-groups/v2",
    "Get notification groups aggregations",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "aggregates_slas_post_v1",
    "POST",
    "/casemgmt/aggregates/slas/v1",
    "Get SLA aggregations",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "aggregates_templates_post_v1",
    "POST",
    "/casemgmt/aggregates/templates/v1",
    "Get templates aggregations",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_fields_get_v1",
    "GET",
    "/casemgmt/entities/fields/v1",
    "Get fields by ID",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_notification_groups_get_v1",
    "GET",
    "/casemgmt/entities/notification-groups/v1",
    "Get notification groups by ID",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_notification_groups_post_v1",
    "POST",
    "/casemgmt/entities/notification-groups/v1",
    "Create notification group",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_notification_groups_patch_v1",
    "PATCH",
    "/casemgmt/entities/notification-groups/v1",
    "Update notification group",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_notification_groups_delete_v1",
    "DELETE",
    "/casemgmt/entities/notification-groups/v1",
    "Delete notification groups by ID",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_notification_groups_get_v2",
    "GET",
    "/casemgmt/entities/notification-groups/v2",
    "Get notification groups by ID",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_notification_groups_post_v2",
    "POST",
    "/casemgmt/entities/notification-groups/v2",
    "Create notification group",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_notification_groups_patch_v2",
    "PATCH",
    "/casemgmt/entities/notification-groups/v2",
    "Update notification group",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_notification_groups_delete_v2",
    "DELETE",
    "/casemgmt/entities/notification-groups/v2",
    "Delete notification groups by ID",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_slas_get_v1",
    "GET",
    "/casemgmt/entities/slas/v1",
    "Get SLAs by ID",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_slas_post_v1",
    "POST",
    "/casemgmt/entities/slas/v1",
    "Create SLA",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_slas_patch_v1",
    "PATCH",
    "/casemgmt/entities/slas/v1",
    "Update SLA",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_slas_delete_v1",
    "DELETE",
    "/casemgmt/entities/slas/v1",
    "Delete SLAs",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_template_snapshots_get_v1",
    "GET",
    "/casemgmt/entities/template-snapshots/v1",
    "Get template snapshots",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Snapshot IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Retrieves the latest snapshot for all Template IDs",
        "name": "template_ids",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "integer"
        },
        "collectionFormat": "multi",
        "description": "Retrieve a specific version of the template from the parallel array template_ids. A "
        "value of zero will return the latest snapshot.",
        "name": "versions",
        "in": "query"
      }
    ]
  ],
  [
    "entities_templates_export_get_v1",
    "GET",
    "/casemgmt/entities/templates/export/v1",
    "Export templates to files in a zip archive",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Template IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "enum": [
          "yaml",
          "json"
        ],
        "type": "string",
        "default": "yaml",
        "description": "Export file format",
        "name": "format",
        "in": "query"
      }
    ]
  ],
  [
    "entities_templates_import_post_v1",
    "POST",
    "/casemgmt/entities/templates/import/v1",
    "Import a template from a file",
    "case_management",
    [
      {
        "type": "file",
        "description": "Local file",
        "name": "file",
        "in": "formData",
        "required": True
      },
      {
        "type": "boolean",
        "description": "Run validation only",
        "name": "dry_run",
        "in": "formData"
      }
    ]
  ],
  [
    "entities_templates_get_v1",
    "GET",
    "/casemgmt/entities/templates/v1",
    "Get templates by ID",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_templates_post_v1",
    "POST",
    "/casemgmt/entities/templates/v1",
    "Create template",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_templates_patch_v1",
    "PATCH",
    "/casemgmt/entities/templates/v1",
    "Update template",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_templates_delete_v1",
    "DELETE",
    "/casemgmt/entities/templates/v1",
    "Delete templates",
    "case_management",
    [
      {
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queries_fields_get_v1",
    "GET",
    "/casemgmt/queries/fields/v1",
    "Query fields",
    "case_management",
    [
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "maximum": 200,
        "minimum": 1,
        "type": "integer",
        "description": "Page size",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Page offset",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_notification_groups_get_v1",
    "GET",
    "/casemgmt/queries/notification-groups/v1",
    "Query notification groups",
    "case_management",
    [
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort expression",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 200,
        "minimum": 1,
        "type": "integer",
        "description": "Page size",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Page offset",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_notification_groups_get_v2",
    "GET",
    "/casemgmt/queries/notification-groups/v2",
    "Query notification groups",
    "case_management",
    [
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort expression",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 200,
        "minimum": 1,
        "type": "integer",
        "description": "Page size",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Page offset",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_slas_get_v1",
    "GET",
    "/casemgmt/queries/slas/v1",
    "Query SLAs",
    "case_management",
    [
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort expression",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 200,
        "minimum": 1,
        "type": "integer",
        "description": "Page size",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Page offset",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_template_snapshots_get_v1",
    "GET",
    "/casemgmt/queries/template-snapshots/v1",
    "Query template snapshots",
    "case_management",
    [
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "maximum": 200,
        "minimum": 1,
        "type": "integer",
        "description": "Page size",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Page offset",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_templates_get_v1",
    "GET",
    "/casemgmt/queries/templates/v1",
    "Query templates",
    "case_management",
    [
      {
        "type": "string",
        "description": "FQL filter expression",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort expression",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 200,
        "minimum": 1,
        "type": "integer",
        "description": "Page size",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Page offset",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "entities_alert_evidence_post_v1",
    "POST",
    "/cases/entities/alert-evidence/v1",
    "Adds the given list of alert evidence to the specified case.",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_case_tags_post_v1",
    "POST",
    "/cases/entities/case-tags/v1",
    "Adds the given list of tags to the specified case.",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_case_tags_delete_v1",
    "DELETE",
    "/cases/entities/case-tags/v1",
    "Removes the specified tags from the specified case.",
    "case_management",
    [
      {
        "type": "string",
        "description": "The ID of the case to remove tags from.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The tag to remove from the case.",
        "name": "tag",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_cases_put_v2",
    "PUT",
    "/cases/entities/cases/v2",
    "Creates the given Case",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_cases_post_v2",
    "POST",
    "/cases/entities/cases/v2",
    "Retrieves all Cases given their IDs.",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_cases_patch_v2",
    "PATCH",
    "/cases/entities/cases/v2",
    "Updates given fields on the specified case.",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_event_evidence_post_v1",
    "POST",
    "/cases/entities/event-evidence/v1",
    "Adds the given list of event evidence to the specified case.",
    "case_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "queries_cases_get_v1",
    "GET",
    "/cases/queries/cases/v1",
    "Retrieves all Cases IDs that match a given query.",
    "case_management",
    [
      {
        "maximum": 10000,
        "minimum": 0,
        "type": "integer",
        "description": "The maximum number of Cases to return in this response (default: 100; max: 10000). Use "
        "this parameter together with the offset parameter to manage pagination of the results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The first case to return, where 0 is the latest case. Use with the offset parameter to "
        "manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort parameter takes the form <field|direction>. Direction can be either asc "
        "(ascending) or desc (descending) order. For example: status|asc or status|desc.\n\nThe sorting fields can be "
        "any keyword field that is part of #domain.Case except for the text based fields. Most commonly used fields are "
        " status, cid, created_timestamp, updated_timestamp, assigned_to_name, assigned_to_userid, assigned_to_uuid, "
        "tags\nIf the fields are missing from the Cases, the service will fallback to its default ordering ",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter Cases using a query in Falcon Query Language (FQL).Filter fields can be any "
        "keyword field that is part of #domain.Case \nAn asterisk wildcard * includes all results.  \nEmpty value means "
        " to not filter on anything.\nMost commonly used filter fields that supports exact match: cid, id ...\nMost "
        "commonly used filter fields that supports wildcard (*): assigned_to_name, assigned_to_uuid...\nMost commonly "
        "filter fields that supports range comparisons (>, <, >=, <=): created_timestamp, updated_timestamp...\nAll "
        "filter fields and operations support negation (!).\n\n\nThe full list of valid filter options is extensive. "
        "Review it in our [documentation inside the Falcon "
        "console](https://falcon.crowdstrike.com/documentation/45/falcon-query-language-fql).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Search all Case metadata for the provided string",
        "name": "q",
        "in": "query"
      }
    ]
  ]
]
