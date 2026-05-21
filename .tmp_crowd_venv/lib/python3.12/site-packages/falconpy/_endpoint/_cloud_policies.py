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

_cloud_policies_endpoints = [
  [
    "GetRuleInputSchema",
    "GET",
    "/cloud-policies/combined/rules/input-schema/v1",
    "Get rule input schema for given resource type",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "domain",
        "name": "domain",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "subdomain",
        "name": "subdomain",
        "in": "query",
        "required": True
      },
      {
        "enum": [
          "aws",
          "azure",
          "gcp",
          "oci"
        ],
        "type": "string",
        "description": "Cloud service provider for the resource type",
        "name": "cloud_provider",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Selects the resource type for which to retrieve the rule input schema",
        "name": "resource_type",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ReplaceControlRules",
    "PUT",
    "/cloud-policies/entities/compliance/control-rule-assignments/v1",
    "Assign rules to a compliance control (full replace)",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "The UUID of the compliance control to assign rules to",
        "name": "ids",
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
    "GetComplianceControls",
    "GET",
    "/cloud-policies/entities/compliance/controls/v1",
    "Get compliance controls by ID",
    "cloud_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The uuids of compliance controls to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateComplianceControl",
    "POST",
    "/cloud-policies/entities/compliance/controls/v1",
    "Create a new custom compliance control",
    "cloud_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateComplianceControl",
    "PATCH",
    "/cloud-policies/entities/compliance/controls/v1",
    "Update a custom compliance control",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "The uuid of compliance control to update",
        "name": "ids",
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
    "DeleteComplianceControl",
    "DELETE",
    "/cloud-policies/entities/compliance/controls/v1",
    "Delete custom compliance controls",
    "cloud_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The uuids of compliance control to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "RenameSectionComplianceFramework",
    "PATCH",
    "/cloud-policies/entities/compliance/frameworks/section/v1",
    "Rename a section in a custom compliance framework",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "The uuid of compliance framework containing the section to rename",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The current name of the section to rename",
        "name": "sectionName",
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
    "GetComplianceFrameworks",
    "GET",
    "/cloud-policies/entities/compliance/frameworks/v1",
    "Get compliance frameworks by ID",
    "cloud_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The uuids of compliance frameworks to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateComplianceFramework",
    "POST",
    "/cloud-policies/entities/compliance/frameworks/v1",
    "Create a new custom compliance framework",
    "cloud_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateComplianceFramework",
    "PATCH",
    "/cloud-policies/entities/compliance/frameworks/v1",
    "Update a custom compliance framework",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "The uuids of compliance framework to update",
        "name": "ids",
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
    "DeleteComplianceFramework",
    "DELETE",
    "/cloud-policies/entities/compliance/frameworks/v1",
    "Delete a custom compliance framework and all associated controls and rule assignments",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "The uuids of compliance framework to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetEnrichedAsset",
    "GET",
    "/cloud-policies/entities/enriched-resources/v1",
    "Gets enriched assets that combine a primary resource with all its related resources",
    "cloud_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "List of asset IDs (maximum 100 IDs allowed).",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "GetEvaluationResult",
    "POST",
    "/cloud-policies/entities/evaluation/v1",
    "Gets evaluation results based on the provided rule",
    "cloud_policies",
    [
      {
        "enum": [
          "aws",
          "azure",
          "gcp",
          "oci"
        ],
        "type": "string",
        "description": "Cloud Service Provider of the provided IDs",
        "name": "cloud_provider",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Resource Type of the provided IDs",
        "name": "resource_type",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "List of assets to evaluate (maximum 100 IDs allowed).",
        "name": "ids",
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
    "GetRuleOverride",
    "GET",
    "/cloud-policies/entities/rule-overrides/v1",
    "Get a rule override",
    "cloud_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The uuids of rule overrides to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateRuleOverride",
    "POST",
    "/cloud-policies/entities/rule-overrides/v1",
    "Create a new rule override",
    "cloud_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateRuleOverride",
    "PATCH",
    "/cloud-policies/entities/rule-overrides/v1",
    "Update a rule override",
    "cloud_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteRuleOverride",
    "DELETE",
    "/cloud-policies/entities/rule-overrides/v1",
    "Delete a rule override",
    "cloud_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The uuids of rule overrides to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetRule",
    "GET",
    "/cloud-policies/entities/rules/v1",
    "Get a rule by id",
    "cloud_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The uuids of rules to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateRuleMixin0",
    "POST",
    "/cloud-policies/entities/rules/v1",
    "Create a new rule",
    "cloud_policies",
    [
      {
        "description": "For Custom Rule, logic is mandatory and parent_rule_id should not be specified.\nFor "
        "Managed Rule duplication, parent_rule_id is mandatory and logic should be not specified.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateRule",
    "PATCH",
    "/cloud-policies/entities/rules/v1",
    "Update a rule",
    "cloud_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteRuleMixin0",
    "DELETE",
    "/cloud-policies/entities/rules/v1",
    "Delete a rule",
    "cloud_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The uuids of rules to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "QueryComplianceControls",
    "GET",
    "/cloud-policies/queries/compliance/controls/v1",
    "Query for compliance controls by various parameters",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "FQL filter, allowed props: \n\t\n*compliance_control_name*\t\n*compliance_control_auth "
        "ority*\t\n*compliance_control_type*\t\n*compliance_control_section*\t\n*compliance_control_requirement*\t\n*co "
        "mpliance_control_benchmark_name*\t\n*compliance_control_benchmark_version*\t\n",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The maximum number of resources to return. The maximum allowed is 500.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "The number of results to skip before starting to return results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Field to sort on. Sortable fields: \n\t\n*compliance_control_name*\t\n*compliance_cont "
        "rol_authority*\t\n*compliance_control_type*\t\n*compliance_control_section*\t\n*compliance_control_requirement "
        "*\t\n*compliance_control_benchmark_name*\t\n*compliance_control_benchmark_version*\t\n \n\nUse the |asc or "
        "|desc suffix to specify sort direction.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "QueryComplianceFrameworks",
    "GET",
    "/cloud-policies/queries/compliance/frameworks/v1",
    "Query for compliance frameworks by various parameters",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "FQL filter, allowed properties: "
        "\n\t\n*compliance_framework_name*\t\n*compliance_framework_version*\t\n*compliance_framework_authority*\t\n",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The maximum number of resources to return. The maximum allowed is 500.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "The number of results to skip before starting to return results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Field to sort on. Sortable fields: "
        "\n\t\n*compliance_framework_name*\t\n*compliance_framework_version*\t\n*compliance_framework_authority*\t\n "
        "\n\nUse the |asc or |desc suffix to specify sort direction.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "QueryRule",
    "GET",
    "/cloud-policies/queries/rules/v1",
    "Query for rules by various parameters",
    "cloud_policies",
    [
      {
        "type": "string",
        "description": "FQL filter, allowed properties: \n\t\n*rule_origin*\t\n*rule_parent_uuid*\t\n*rule_nam "
        "e*\t\n*rule_description*\t\n*rule_domain*\t\n*rule_status*\t\n*rule_severity*\t\n*rule_short_code*\t\n*rule_se "
        "rvice*\t\n*rule_resource_type*\t\n*rule_provider*\t\n*rule_subdomain*\t\n*rule_auto_remediable*\t\n*rule_contr "
        "ol_requirement*\t\n*rule_control_section*\t\n*rule_compliance_benchmark*\t\n*rule_compliance_framework*\t\n*ru "
        "le_mitre_tactic*\t\n*rule_mitre_technique*\t\n*rule_created_at*\t\n*rule_updated_at*\t\n*rule_updated_by*\t\n  ",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The maximum number of resources to return. The maximum allowed is 500.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "The number of results to skip before starting to return results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Field to sort on. Sortable fields: \n\t\n*rule_origin*\t\n*rule_parent_uuid*\t\n*rule_"
        "name*\t\n*rule_description*\t\n*rule_domain*\t\n*rule_status*\t\n*rule_severity*\t\n*rule_short_code*\t\n*rule "
        "_service*\t\n*rule_resource_type*\t\n*rule_provider*\t\n*rule_subdomain*\t\n*rule_auto_remediable*\t\n*rule_co "
        "ntrol_requirement*\t\n*rule_control_section*\t\n*rule_compliance_benchmark*\t\n*rule_compliance_framework*\t\n "
        "*rule_mitre_tactic*\t\n*rule_mitre_technique*\t\n*rule_created_at*\t\n*rule_updated_at*\t\n*rule_updated_by*\t "
        "\n \n\nUse the |asc or |desc suffix to specify sort direction.",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
