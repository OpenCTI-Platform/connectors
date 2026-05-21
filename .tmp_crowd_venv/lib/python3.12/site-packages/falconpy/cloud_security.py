"""CrowdStrike Falcon CloudSecurity API interface class.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
-------'                         -------'

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
from typing import Dict, Union
from ._util import force_default, process_service_request, handle_single_argument
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._cloud_security import _cloud_security_endpoints as Endpoints
from ._payload._cloud_security import cloud_security_create_group_payload


class CloudSecurity(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials.
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py).
    - a valid token provided by the authentication service class (oauth2.py).
    """

    @force_default(defaults=["parameters"], default_types=["dict"])
    def combined_cloud_risks(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get cloud risks with full details based on filters and sort criteria.

        Keyword arguments:
        filter -- FQL string to filter results in Falcon Query Language (FQL). String.
            Supported fields:
                  account_id            account_name        asset_gcrn
                  asset_id              asset_name          asset_region
                  asset_type            cloud_group         cloud_provider
                  first_seen            last_seen           resolved_at
                  risk_factor           rule_id             rule_name
                  service_category      severity            status
                  suppressed_by         suppressed_reason   tags

        sort -- The field to sort on. Use |asc or |desc suffix to specify sort direction. String.
            Supported fields:
                account_id          account_name            asset_id
                asset_name          asset_region            asset_type
                cloud_provider      first_seen              last_seen
                resolved_at         rule_name               service_category
                severity            status
        limit -- The maximum number of items to return. When not specified or 0, 500 is used.
        When larger than 1000, 1000 is used. Integer.
        offset -- Offset returned risks. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/%2Fcloud-security-risks/combined-cloud-risks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="combined_cloud_risks",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_cloud_groups(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query Cloud Groups and returns entities.

        Keyword arguments:
        filter -- A valid FQL filter. String. Supports filtering groups by:
                  Group properties:
                    name            description
                    created_at      updated_at

                  Selector properties:
                    cloud_provider      account_id
                    region              cloud_provider_tag
                    image_registry      image_repository
                    image_tag

                  Group tags:
                    business_unit       business_impact
                    environment
        sort -- A valid sort string. String.
        offset -- The starting position of the list operation. Integer.
        limit -- The maximum number of cloud groups to retrieve. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-security/ListCloudGroupsExternal
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListCloudGroupsExternal",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_cloud_groups_by_id(self: object,
                                *args,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """List Cloud Groups By ID.

        Keyword arguments:
        ids -- Cloud Groups UUIDs. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-security/ListCloudGroupsByIDExternal
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListCloudGroupsByIDExternal",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_cloud_group(self: object,
                           body: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a Cloud Group. The created_by field will be set to the API client ID.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
             {
                    "business_impact": "high",
                    "business_unit": "string",
                    "description": "string",
                    "environment": "dev",
                    "name": "string",
                    "owners": [
                        "string"
                    ],
                    "selectors": {
                        "cloud_resources": [
                        {
                            "account_ids": [
                            "string"
                            ],
                            "cloud_provider": "aws",
                            "filters": {
                                "region": [
                                    "string"
                                ],
                                "tags": [
                                    "string"
                                ]
                            }
                        }
                        ],
                        "images": [
                        {
                            "filters": {
                                "repository": [
                                    "string"
                                ],
                                "tag": [
                                    "string"
                                ]
                            },
                            "registry": "string"
                        }
                        ]
                    }
                }
        business_impact -- String.
        business_unit -- String.
        description -- String.
        environment -- String.
        name -- String.
        owners -- List of strings.
        selectors -- Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-security/CreateCloudGroupExternal
        """
        if not body:
            body = cloud_security_create_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateCloudGroupExternal",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_cloud_group(self: object,
                           group: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Cloud Group.

        Keyword arguments:
        group -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "business_impact": "high",
                    "business_unit": "string",
                    "description": "string",
                    "environment": "dev",
                    "name": "string",
                    "owners": [
                        "string"
                    ],
                    "selectors": {
                        "cloud_resources": [
                        {
                            "account_ids": [
                            "string"
                            ],
                            "cloud_provider": "aws",
                            "filters": {
                                "region": [
                                    "string"
                                ],
                                "tags": [
                                    "string"
                                ]
                            }
                        }
                        ],
                        "images": [
                        {
                            "filters": {
                                "repository": [
                                    "string"
                                ],
                                "tag": [
                                    "string"
                                ]
                            },
                            "registry": "string"
                        }
                        ]
                    }
                }
        business_impact -- String.
        business_unit -- String.
        description -- String.
        environment -- String.
        name -- String.
        owners -- List of strings.
        selectors -- Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-security/UpdateCloudGroupExternal
        """
        if not group:
            group = cloud_security_create_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateCloudGroupExternal",
            body=group
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_cloud_groups(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete Cloud Groups in batch.

        Keyword arguments:
        ids -- Cloud Groups UUIDs to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-security/DeleteCloudGroupsExternal
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteCloudGroupsExternal",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_group_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query Cloud Groups and returns IDs.

        Keyword arguments:
        filter -- A valid FQL filter. String. Supports filtering groups by:
                  Group properties:
                    name            description
                    created_at      updated_at

                  Selector properties:
                    cloud_provider      account_id
                    region              cloud_provider_tag
                    image_registry      image_repository
                    image_tag

                  Group tags:
                    business_unit       business_impact
                    environment
        sort -- A valid sort string. String.
        offset -- The starting position of the list operation. Integer.
        limit -- The maximum number of cloud groups to retrieve. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-security/ListCloudGroupIDsExternal
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListCloudGroupIDsExternal",
            keywords=kwargs,
            params=parameters
            )

    combined_cloud_risks = combined_cloud_risks
    ListCloudGroupsExternal = list_cloud_groups
    ListCloudGroupsByIDExternal = list_cloud_groups_by_id
    CreateCloudGroupExternal = create_cloud_group
    UpdateCloudGroupExternal = update_cloud_group
    DeleteCloudGroupsExternal = delete_cloud_groups
    ListCloudGroupIDsExternal = list_group_ids
