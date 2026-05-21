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

_data_protection_configuration_endpoints = [
  [
    "entities_classification_get_v2",
    "GET",
    "/data-protection/entities/classifications/v2",
    "Gets the classifications that match the provided ids",
    "data_protection_configuration",
    [
      {
        "maxItems": 100,
        "minItems": 1,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of the classifications to get",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_classification_post_v2",
    "POST",
    "/data-protection/entities/classifications/v2",
    "Create classifications",
    "data_protection_configuration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_classification_patch_v2",
    "PATCH",
    "/data-protection/entities/classifications/v2",
    "Update classifications",
    "data_protection_configuration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_classification_delete_v2",
    "DELETE",
    "/data-protection/entities/classifications/v2",
    "Deletes classifications that match the provided ids",
    "data_protection_configuration",
    [
      {
        "maxItems": 100,
        "minItems": 1,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of the classifications to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_cloud_application_get",
    "GET",
    "/data-protection/entities/cloud-applications/v1",
    "Get a particular cloud-application",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The cloud application id(s) to get.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_cloud_application_create",
    "POST",
    "/data-protection/entities/cloud-applications/v1",
    "Persist the given cloud application for the provided entity instance",
    "data_protection_configuration",
    [
      {
        "description": "The cloud-application definition to create",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_cloud_application_patch",
    "PATCH",
    "/data-protection/entities/cloud-applications/v1",
    "Update a cloud application",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The cloud app id to update.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "description": "The new cloud-application definition",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_cloud_application_delete",
    "DELETE",
    "/data-protection/entities/cloud-applications/v1",
    "Delete cloud application",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The id of the cloud application to delete.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_content_pattern_get",
    "GET",
    "/data-protection/entities/content-patterns/v1",
    "Get a particular content-pattern(s)",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The content-pattern id(s) to get.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_content_pattern_create",
    "POST",
    "/data-protection/entities/content-patterns/v1",
    "Persist the given content pattern for the provided entity instance",
    "data_protection_configuration",
    [
      {
        "description": "Definition of content-pattern to create",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_content_pattern_patch",
    "PATCH",
    "/data-protection/entities/content-patterns/v1",
    "Update a content pattern",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The id of the content pattern to patch.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "description": "Definition of content-pattern to create",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_content_pattern_delete",
    "DELETE",
    "/data-protection/entities/content-patterns/v1",
    "Delete content pattern",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The id(s) of the content pattern to delete.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_enterprise_account_get",
    "GET",
    "/data-protection/entities/enterprise-accounts/v1",
    "Get a particular enterprise-account(s)",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The enterprise-account id(s) to get.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_enterprise_account_create",
    "POST",
    "/data-protection/entities/enterprise-accounts/v1",
    "Persist the given enterprise account for the provided entity instance",
    "data_protection_configuration",
    [
      {
        "description": "Definition of enterprise-account to create",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_enterprise_account_patch",
    "PATCH",
    "/data-protection/entities/enterprise-accounts/v1",
    "Update a enterprise account",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The id of the enterprise account to update.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "description": "Definition of enterprise-account to create",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_enterprise_account_delete",
    "DELETE",
    "/data-protection/entities/enterprise-accounts/v1",
    "Delete enterprise account",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The id of the enterprise account to delete.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_file_type_get",
    "GET",
    "/data-protection/entities/file-types/v1",
    "Get a particular file-type",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The file-type id(s) to get.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_sensitivity_label_get_v2",
    "GET",
    "/data-protection/entities/labels/v2",
    "Get sensitivity label matching the IDs (V2)",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The sensitivity label entity id(s) to get.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_sensitivity_label_create_v2",
    "POST",
    "/data-protection/entities/labels/v2",
    "Create new sensitivity label (V2)",
    "data_protection_configuration",
    [
      {
        "description": "Definition of sensitivity label to create",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_sensitivity_label_delete_v2",
    "DELETE",
    "/data-protection/entities/labels/v2",
    "Delete sensitivity labels matching the IDs (V2)",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The sensitivity label entity id(s) to delete.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_policy_get_v2",
    "GET",
    "/data-protection/entities/policies/v2",
    "Gets policies that match the provided ids",
    "data_protection_configuration",
    [
      {
        "maxItems": 100,
        "minItems": 1,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of the policies to get",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_policy_post_v2",
    "POST",
    "/data-protection/entities/policies/v2",
    "Create policies",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "platform name of the policies to update, either 'win' or 'mac'",
        "name": "platform_name",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_policy_patch_v2",
    "PATCH",
    "/data-protection/entities/policies/v2",
    "Update policies",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "platform name of the policies to update, either 'win' or 'mac'",
        "name": "platform_name",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_policy_delete_v2",
    "DELETE",
    "/data-protection/entities/policies/v2",
    "Deletes policies that match the provided ids",
    "data_protection_configuration",
    [
      {
        "maxItems": 100,
        "minItems": 1,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of the policies to delete",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "platform name of the policies to update, either 'win' or 'mac'",
        "name": "platform_name",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_web_location_get_v2",
    "GET",
    "/data-protection/entities/web-locations/v2",
    "Get web-location entities matching the provided ID(s)",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The web-location entity id(s) to get.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities_web_location_create_v2",
    "POST",
    "/data-protection/entities/web-locations/v2",
    "Persist the given web-locations",
    "data_protection_configuration",
    [
      {
        "description": "Definition of web-locations to create",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_web_location_patch_v2",
    "PATCH",
    "/data-protection/entities/web-locations/v2",
    "Update a web-location",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The web-location entity id to update.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "description": "Definition of updated web-location",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities_web_location_delete_v2",
    "DELETE",
    "/data-protection/entities/web-locations/v2",
    "Delete web-location",
    "data_protection_configuration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "The ids of the web-location to delete.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queries_classification_get_v2",
    "GET",
    "/data-protection/queries/classifications/v2",
    "Search for classifications that match the provided criteria",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "Filter results by specific attributes , allowed attributes are "
        "[properties.protection_mode properties.web_sources created_by modified_at properties.file_types "
        "properties.sensitivity_labels name created_at modified_by properties.content_patterns "
        "properties.evidence_duplication_enabled]",
        "name": "filter",
        "in": "query"
      },
      {
        "maximum": 10000,
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 500,
        "minimum": 0,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The property to sort by, allowed fields are :[name created_at modified_at]",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "queries_cloud_application_get_v2",
    "GET",
    "/data-protection/queries/cloud-applications/v2",
    "Get all cloud-application IDs matching the query with filter",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "Optional filter for searching cloud applications. Allowed filters are 'name' (string), "
        " 'type' (array of strings representing the tier, accepted values are: integrated, predefined, custom), "
        "'deleted' (boolean), supports_network_inspection (boolean) and 'application_group_id' (string)",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort instructions to order by on. Allowed values are 'name' (string), 'type' "
        "(array of strings representing the tier, accepted values are: integrated, predefined, custom), 'deleted' "
        "(boolean) and 'application_group_id' (string)",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from. Use with the limit parameter to manage "
        "pagination of results.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_content_pattern_get_v2",
    "GET",
    "/data-protection/queries/content-patterns/v2",
    "Get all content-pattern IDs matching the query with filter",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The filter to use when finding content patterns. Allowed filters are 'name', 'type', "
        "'category', 'region', 'example', 'created_at', 'updated_at' and 'deleted'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort instructions to order by on. Allowed values are 'name', 'type', 'category', "
        "'region', 'created_at', 'updated_at', 'example' and 'deleted'",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from. Use with the limit parameter to manage "
        "pagination of results.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_enterprise_account_get_v2",
    "GET",
    "/data-protection/queries/enterprise-accounts/v2",
    "Get all enterprise-account IDs matching the query with filter",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The filter to use when finding enterprise accounts. Allowed filters are 'name', "
        "'application_group_id', 'deleted', 'created_at' and 'updated_at'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort instructions to order by on. Allowed values are 'name', "
        "'application_group_id', 'deleted', 'created_at' and 'updated_at'",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from. Use with the limit parameter to manage "
        "pagination of results.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_file_type_get_v2",
    "GET",
    "/data-protection/queries/file-types/v2",
    "Get all file-type IDs matching the query with filter",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The filter to use when finding file types. Allowed filter is 'name', 'created_at' and 'updated_at'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort instructions to order by on. Allowed values are 'name', 'created_at' and 'updated_at'",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from. Use with the limit parameter to manage "
        "pagination of results.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_sensitivity_label_get_v2",
    "GET",
    "/data-protection/queries/labels/v2",
    "Get all sensitivity label IDs matching the query with filter",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The filter to use when finding sensitivity labels. The only allowed filters are "
        "'name', 'display_name', 'external_id' and 'deleted'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort instructions to order by on. Allowed values are 'name', 'display_name', "
        "'deleted', 'created_at' and 'updated_at'",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from. Use with the limit parameter to manage "
        "pagination of results.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "queries_policy_get_v2",
    "GET",
    "/data-protection/queries/policies/v2",
    "Search for policies that match the provided criteria",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "platform name of the policies to search, either 'win' or 'mac'",
        "name": "platform_name",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Filter results by specific attributes , allowed attributes are "
        "[properties.network_inspection_files_exceeding_size_limit properties.be_paste_timeout_duration_milliseconds "
        "properties.max_file_size_to_inspect created_at modified_by properties.min_confidence_level "
        "properties.max_file_size_to_inspect_unit properties.custom_block_notification "
        "properties.evidence_download_enabled properties.classifications properties.be_paste_timeout_response "
        "description properties.besplash_custom_message properties.be_paste_clipboard_min_size "
        "properties.be_paste_clipboard_max_size properties.evidence_storage_free_disk_perc is_enabled "
        "properties.similarity_detection properties.be_exclude_domains properties.evidence_storage_max_size "
        "properties.browsers_without_active_extension properties.unsupported_browsers_action "
        "properties.besplash_message_source properties.be_paste_clipboard_min_size_unit "
        "properties.be_paste_clipboard_max_size_unit precedence properties.block_all_data_access "
        "properties.enable_clipboard_inspection properties.allow_notifications properties.block_notifications "
        "properties.be_upload_timeout_duration_seconds properties.be_paste_clipboard_over_size_behaviour_block "
        "properties.enable_context_inspection properties.custom_allow_notification properties.besplash_enabled "
        "properties.be_upload_timeout_response created_by modified_at properties.enable_content_inspection "
        "properties.inspection_depth properties.similarity_threshold "
        "properties.enable_end_user_notifications_unsupported_browser properties.evidence_duplication_enabled_default "
        "properties.evidence_encrypted_enabled name is_default properties.enable_network_inspection]",
        "name": "filter",
        "in": "query"
      },
      {
        "maximum": 10000,
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 500,
        "minimum": 0,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The property to sort by, allowed fields are :[name precedence created_at modified_at]",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "queries_web_location_get_v2",
    "GET",
    "/data-protection/queries/web-locations/v2",
    "Get web-location IDs matching the query with filter",
    "data_protection_configuration",
    [
      {
        "type": "string",
        "description": "The filter to use when finding web locations. Allowed filters are 'name', 'type', "
        "'deleted', 'application_id', 'provider_location_id' and 'enterprise_account_id'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The type of entity to query. Allowed values are 'predefined' and 'custom'",
        "name": "type",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from. Use with the limit parameter to manage "
        "pagination of results.",
        "name": "offset",
        "in": "query"
      }
    ]
  ]
]
