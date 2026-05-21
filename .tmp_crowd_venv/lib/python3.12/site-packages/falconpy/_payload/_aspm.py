"""Internal payload handling library - ASPM.

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


def aspm_delete_tag_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted ASPM tag delete payload.

    {
        "entries": [
            {
                "isSensitive": boolean,
                "persistentSignature": "string",
                "value": "string"
            }
        ],
        "name": "string"
    }
    """
    keymap = {"is_sensitive": "isSensitive", "persistent_signature": "persistentSignature"}
    returned = {"entries": []}
    keys = ["is_sensitive", "persistent_signature", "value"]
    item = {}
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            keyset = key
            if key in keymap:
                keyset = keymap.get(key)
            item[keyset] = passed_keywords.get(key)
    returned["entries"].append(item)
    # Overrides individual keywords
    mainkeys = ["name", "entries"]
    for key in mainkeys:
        if passed_keywords.get(key, None):
            returned[key] = passed_keywords.get(key)

    return returned


def aspm_update_tag_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted ASPM tag update payload.

    {
        "entries": [
            {
                "isSensitive": true,
                "name": "string",
                "tag_type": "string",
                "value": "string"
            }
        ]
    }
    """
    keymap = {"is_sensitive": "isSensitive"}
    returned = {"entries": []}
    keys = ["is_sensitive", "persistent_signature", "value", "name"]
    item = {}
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            keyset = key
            if key in keymap:
                keyset = keymap.get(key)
            item[keyset] = passed_keywords.get(key)
    returned["entries"].append(item)
    # Overrides individual keywords
    if passed_keywords.get("entries", None):
        returned["entries"] = passed_keywords.get("entries")

    return returned


def aspm_violations_search_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted violations search payload.

    {
        "filter": {
            "order_by": {
                "by_field": "string",
                "direction": 0
            },
            "paginate": {
                "direction": "string",
                "limit": 0,
                "offset": 0,
                "orderBy": [
                    "string"
                ]
            }
        },
        "optionalTime": 0,
        "revisionId": 0
    }
    """
    returned = {}
    keymap = {"optional_time": "optionalTime", "revision_id": "revisionId"}
    keys = ["filter", "optional_time", "revision_id"]
    for key in keys:
        if passed_keywords.get(key, None):
            keyset = key
            if key in keymap:
                keyset = keymap.get(key)
            returned[keyset] = passed_keywords.get(key)

    return returned


def aspm_get_services_count_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted services count search payload.

    {
        "deploymentTupleFilters": [
            {
            "excludes": [
                {
                    "key": "string",
                    "value": "string"
                }
            ],
            "includes": [
                {
                    "key": "string",
                    "value": "string"
                }
            ]
            }
        ],
        "nestingLevel": integer,
        "onlyCount": boolean,
        "optionalTime": integer,
        "pagination": {
            "direction": "string",
            "limit": integer,
            "offset": integer,
            "order_by": [
                "string"
            ]
        },
        "persistentSignatures": [
            "string"
        ],
        "qlFilters": "string",
        "relatedEntities": [
            {
                "aggregation_type": integer,
                "entity_type": integer,
                "filters": {
                    "include_du_services": boolean,
                    "only_du_types": boolean,
                    "only_get_brokers": boolean
                },
                "groupByFields": {
                    "fields": [
                        "string"
                    ]
                }
            }
        ],
        "revisionId": integer,
        "rolesSignature": "string"
    }
    """
    returned = {}
    keymap = {
        "deployment_tuple_filters": "deploymentTupleFilters",
        "nesting_level": "nestingLevel",
        "only_count": "onlyCount",
        "optional_time": "optionalTime",
        "persistent_signatures": "persistentSignatures",
        "ql_filters": "qlFilters",
        "related_entities": "relatedEntities",
        "revision_id": "revisionId",
        "roles_signature": "rolesSignature"
    }
    keys = ["deployment_tuple_filters", "nesting-level", "only_count", "optional_time",
            "pagination", "persistent_signatures", "ql_filters", "related_entities", "revision_id",
            "roles_signatures"
            ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            keyset = key
            if key in keymap:
                keyset = keymap.get(key)
            returned[keyset] = passed_keywords.get(key)

    return returned


def aspm_query_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatting ASPM query payload.

    {
        "paginate": {
            "direction": "string",
            "limit": integer,
            "offset": integer,
            "orderBy": [
                "string"
            ]
        },
        "query": "string",
        "selectFields": {
            "fields": [
                "string"
            ],
            "serviceFields": [
                "string"
            ],
            "withoutServices": boolean
        },
        "timestamp": integer
    }
    """
    keys = ["paginate", "query", "select_fields", "timestamp"]
    keymap = {"select_fields": "selectFields"}
    returned = {}
    for key in keys:
        if passed_keywords.get(key, None):
            keyset = key
            if key in keymap:
                keyset = keymap.get(key)
            returned[keyset] = passed_keywords.get(key)

    return returned


def aspm_integration_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted integration update payload.

    {
        "integration": {
            "data": "string",
            "enabled": boolean,
            "id": integer,
            "integration_type": {
                "configured": boolean,
                "display_name": "string",
                "enabled": boolean,
                "id": integer,
                "name": "string"
            },
            "name": "string",
            "node": {
                "additional_header": "string",
                "current_aws_arn": "string",
                "dashboard_url": "string",
                "id": integer,
                "last_health_check": integer,
                "name": "string",
                "node_type": "string",
                "password": "string",
                "pod_settings": {
                    "imageAddress": "string",
                    "imagePullSecrets": [
                        "string"
                    ],
                    "podLabels": [
                        {
                            "key": "string",
                            "value": "string"
                        }
                    ]
                },
                "proxy_address": "string",
                "type": "string",
                "useJobs": boolean,
                "username": "string"
            },
            "type": {
                "configured": boolean,
                "display_name": "string",
                "enabled": boolean,
                "id": integer,
                "name": "string"
            },
            "update_time": integer
        },
        "overwriteFields": [
            "string"
        ]
    }
    """
    keys = ["integration", "overwrite_fields"]
    returned = {}
    for key in keys:
        if passed_keywords.get(key, None):
            keyset = key
            if key == "overwrite_fields":
                keyset = "overwriteFields"
            returned[keyset] = passed_keywords.get(key)

    return returned


def aspm_integration_task_payload(passed_keywords: dict) -> dict:
    """Craft a properly formated ASPM integration task.

    {
        "access_token": "string",
        "category": "string",
        "data": "string",
        "override": boolean,
        "scheduled": boolean,
        "task_id": integer,
        "integration_task": {
            "access_token": "string",
            "additional_header": "string",
            "business_application": "string",
            "data": "string",
            "enabled": true,
            "id": 0,
            "integration": {
            "data": "string",
            "enabled": true,
            "id": 0,
            "integration_type": {
                "configured": true,
                "display_name": "string",
                "enabled": true,
                "id": 0,
                "name": "string"
            },
            "name": "string",
            "node": {
                "additional_header": "string",
                "current_aws_arn": "string",
                "dashboard_url": "string",
                "id": 0,
                "last_health_check": 0,
                "name": "string",
                "node_type": "string",
                "password": "string",
                "pod_settings": {
                "imageAddress": "string",
                "imagePullSecrets": [
                    "string"
                ],
                "podLabels": [
                    {
                    "key": "string",
                    "value": "string"
                    }
                ]
                },
                "proxy_address": "string",
                "type": "string",
                "useJobs": true,
                "username": "string"
            },
            "type": {
                "configured": true,
                "display_name": "string",
                "enabled": true,
                "id": 0,
                "name": "string"
            },
            "update_time": 0
            },
            "integration_task_type": {
            "category": "string",
            "display_name": "string",
            "enabled": true,
            "id": 0,
            "name": "string",
            "required_integration_types": [
                {
                "configured": true,
                "display_name": "string",
                "enabled": true,
                "id": 0,
                "name": "string"
                }
            ]
            },
            "latest_task_run": {
            "create_time": {
                "nanos": 0,
                "seconds": 0
            },
            "events": [
                {
                "FlatData": {
                    "additionalProp1": "string",
                    "additionalProp2": "string",
                    "additionalProp3": "string"
                },
                "additional_data": "string",
                "data": {
                    "additional_info": "string",
                    "aws": {
                    "accountArn": "string",
                    "region": "string"
                    },
                    "azureSite": {
                    "location": "string",
                    "resourceGroup": "string",
                    "siteId": "string",
                    "siteKind": "string",
                    "siteName": "string",
                    "subscriptionId": "string"
                    },
                    "azureVm": {
                    "id": "string",
                    "region": "string",
                    "resourceGroup": "string",
                    "subscriptionId": "string",
                    "vmName": "string"
                    },
                    "cloud_function": {
                    "function_name": "string"
                    },
                    "crowdstrike_cloud_security": {
                    "baseUrl": "string",
                    "clientId": "string",
                    "cloudProvider": "string",
                    "iomID": "string",
                    "policyId": 0,
                    "resourceId": "string",
                    "resourceType": "string"
                    },
                    "ec2": {
                    "instance_id": "string",
                    "instance_name": "string"
                    },
                    "ecs": {
                    "clusterName": "string",
                    "collectionMethod": 0,
                    "resourceArn": "string",
                    "resourceName": "string",
                    "resourceType": "string"
                    },
                    "gcp": {
                    "project": "string",
                    "region": "string"
                    },
                    "host": {
                    "address": "string"
                    },
                    "k8s": {
                    "container": "string",
                    "namespace": "string",
                    "pod_name": "string"
                    },
                    "lambda": {
                    "lambdaArn": "string",
                    "lambdaName": "string"
                    },
                    "remedy": {
                    "content": "string",
                    "url": "string"
                    },
                    "snyk": {
                    "apiEndpointUrl": "string",
                    "appEndpointUrl": "string",
                    "groupId": "string"
                    },
                    "sonatype": {
                    "CVEId": "string",
                    "applicationPublicId": "string",
                    "componentNameVersion": "string",
                    "iqServerUrl": "string"
                    }
                },
                "flat_fields": [
                    "string"
                ],
                "id": 0,
                "message": "string",
                "object": "string",
                "object_type": "string",
                "send_time": {
                    "nanos": 0,
                    "seconds": 0
                },
                "status": 0
                }
            ],
            "id": 0,
            "latest_event": {
                "FlatData": {
                "additionalProp1": "string",
                "additionalProp2": "string",
                "additionalProp3": "string"
                },
                "additional_data": "string",
                "data": {
                "additional_info": "string",
                "aws": {
                    "accountArn": "string",
                    "region": "string"
                },
                "azureSite": {
                    "location": "string",
                    "resourceGroup": "string",
                    "siteId": "string",
                    "siteKind": "string",
                    "siteName": "string",
                    "subscriptionId": "string"
                },
                "azureVm": {
                    "id": "string",
                    "region": "string",
                    "resourceGroup": "string",
                    "subscriptionId": "string",
                    "vmName": "string"
                },
                "cloud_function": {
                    "function_name": "string"
                },
                "crowdstrike_cloud_security": {
                    "baseUrl": "string",
                    "clientId": "string",
                    "cloudProvider": "string",
                    "iomID": "string",
                    "policyId": 0,
                    "resourceId": "string",
                    "resourceType": "string"
                },
                "ec2": {
                    "instance_id": "string",
                    "instance_name": "string"
                },
                "ecs": {
                    "clusterName": "string",
                    "collectionMethod": 0,
                    "resourceArn": "string",
                    "resourceName": "string",
                    "resourceType": "string"
                },
                "gcp": {
                    "project": "string",
                    "region": "string"
                },
                "host": {
                    "address": "string"
                },
                "k8s": {
                    "container": "string",
                    "namespace": "string",
                    "pod_name": "string"
                },
                "lambda": {
                    "lambdaArn": "string",
                    "lambdaName": "string"
                },
                "remedy": {
                    "content": "string",
                    "url": "string"
                },
                "snyk": {
                    "apiEndpointUrl": "string",
                    "appEndpointUrl": "string",
                    "groupId": "string"
                },
                "sonatype": {
                    "CVEId": "string",
                    "applicationPublicId": "string",
                    "componentNameVersion": "string",
                    "iqServerUrl": "string"
                }
                },
                "flat_fields": [
                "string"
                ],
                "id": 0,
                "message": "string",
                "object": "string",
                "object_type": "string",
                "send_time": {
                "nanos": 0,
                "seconds": 0
                },
                "status": 0
            },
            "metadata": {
                "collected_objects": 0,
                "end_time": {
                "nanos": 0,
                "seconds": 0
                },
                "integration_task_id": 0,
                "integration_task_name": "string",
                "integration_task_type": {
                "category": "string",
                "display_name": "string",
                "enabled": true,
                "id": 0,
                "name": "string",
                "required_integration_types": [
                    {
                    "configured": true,
                    "display_name": "string",
                    "enabled": true,
                    "id": 0,
                    "name": "string"
                    }
                ]
                },
                "start_time": {
                "nanos": 0,
                "seconds": 0
                },
                "total_objects": 0
            },
            "progress": 0,
            "scheduled": true,
            "trace_uuid": "string"
            },
            "name": "string",
            "next_run": {
            "nanos": 0,
            "seconds": 0
            },
            "progress": 0,
            "schedule": {
            "every": 0,
            "every_unit": 0,
            "hour": 0,
            "minute": 0,
            "startTimeTimezoneOffsetMinutes": 0,
            "start_time": {
                "nanos": 0,
                "seconds": 0
            },
            "timezone": 0,
            "weekdays": [
                0
            ]
            },
            "schedule_every_unit_display_name": "string",
            "trigger": "string",
            "type": {
            "category": "string",
            "display_name": "string",
            "enabled": true,
            "id": 0,
            "name": "string",
            "required_integration_types": [
                {
                "configured": true,
                "display_name": "string",
                "enabled": true,
                "id": 0,
                "name": "string"
                }
            ]
            }
        }
    }
    """
    keys = ["access_token", "category", "data", "override", "scheduled", "task_id", "integration_task"]
    returned = {}
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned[key] = passed_keywords.get(key)

    return returned


def aspm_node_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted ASPM node payload.

    {
        "additional_header": "string",
        "current_aws_arn": "string",
        "dashboard_url": "string",
        "id": integer,
        "last_health_check": integer,
        "name": "string",
        "node_type": "string",
        "password": "string",
        "pod_settings": {
            "imageAddress": "string",
            "imagePullSecrets": [
                "string"
            ],
            "podLabels": [
                {
                    "key": "string",
                    "value": "string"
                }
            ]
        },
        "proxy_address": "string",
        "type": "string",
        "useJobs": boolean,
        "username": "string"
    }
    """
    returned = {}
    keys = ["additional_header", "current_aws_arn", "dashbaord_url", "id", "last_health_check",
            "name", "node_type", "password", "pod_settings", "proxy_address", "type", "use_jobs",
            "username"
            ]
    keymap = {"use_jobs": "useJobs"}
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            keyset = key
            if key in keymap:
                keyset = keymap.get(key)
            returned[keyset] = passed_keywords.get(key)

    return returned


def aspm_application_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted ASPM application payload.

    {
        "name": "string",
        "persistentSignatures": [
            "string"
        ]
    }
    """
    returned = {}
    keymap = {"persistent_signatures": "persistentSignatures"}
    keys = ["name", "persistent_signatures"]
    for key in keys:
        if passed_keywords.get(key, None):
            keyset = key
            if key in keymap:
                keyset = keymap.get(key)
            returned[keyset] = passed_keywords.get(key)

    return returned


def retrieve_relay_node_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted executor node relay retrieval payload.

    {
        "additional_header": "string",
        "current_aws_arn": "string",
        "dashboard_url": "string",
        "id": integer,
        "last_health_check": integer,
        "name": "string",
        "node_type": "string",
        "password": "string",
        "pod_settings": {
            "imageAddress": "string",
            "imagePullSecrets": [
                "string"
            ],
            "podLabels": [
                {
                    "key": "string",
                    "value": "string"
                }
            ]
        },
        "proxy_address": "string",
        "status": {
            "State": integer,
            "StateLastUpdated": integer,
            "StateReason": integer
        },
        "type": "string",
        "useJobs": boolean,
        "username": "string"
    }
    """
    returned = {}
    keys = ["additional_headers", "current_aws_arn", "dashboard_url", "id", "last_health_check",
            "name", "node_type", "password", "pod_settings", "proxy_address", "status", "type"
            "username"
            ]
    for key in keys:
        if passed_keywords.get(key, None):
            returned[key] = passed_keywords.get(key, None)
    if passed_keywords.get("use_jobs", None) is not None:
        returned["useJobs"] = passed_keywords.get("use_jobs", None)

    return returned
