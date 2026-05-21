"""CrowdStrike Falcon SaasSecurity API interface class.

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
from typing import Dict, Union
from ._util import force_default, process_service_request, handle_single_argument
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._saas_security import _saas_security_endpoints as Endpoints


class SaasSecurity(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py)
    - a valid token provided by the authentication service class (oauth2.py)
    """

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_metrics(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Metrics.

        Keyword arguments:
        status -- Exposure status. String.
                  Available values:
                    Passed      Failed
                    Dismissed   Pending
                    Can't Run   Stale
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results. Integer.
        integration_id -- Comma separated list of integration IDs. String.
        impact -- Impact. String.
                  Available values:
                    1   2   3
        compliance -- Compliance. Boolean.
        check_type -- Check Type. String.
                      Available values:
                        apps            devices
                        users           assets
                        permissions     Falcon Shield Security Check
                        custom
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetMetricsV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMetricsV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_alerts(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Alert by ID or GET Alerts.

        Keyword arguments:
        id -- Alert ID. String
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results. Integer.
        last_id -- The last id of the alert you want to get. String.
        type -- The type of alert you want to get. String.
                Available values:
                    configuration_drift     check_degraded
                    integration_failure     Threat
        integration_id -- Comma separated list of integration ID's of the alert you want to get. String
        from_date -- The start date of the alert you want to get (in YYYY-MM-DD format). String.
        to_date -- The end date of the alert you want to get (in YYYY-MM-DD format). String.
        ascending -- Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetAlertsV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAlertsV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_application_users(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Application Users.

        Keyword arguments:
        item_id -- Item ID in format: 'integration_id|||app_id' (item_id). String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'item_id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetAppInventoryUsers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAppInventoryUsers",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "item_id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_application_inventory(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Applications Inventory.

        Keyword arguments:
        type -- Comma separated list of app types. String.
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results Integer.
        status -- Comma separated list of application statuses. String.
                  Available values:
                    approved        in review
                    rejected        unclassified
        access_level -- Comma separated list of access levels. String.
        scopes -- Comma separated list of scopes. String.
        users -- Users. Format: 'is equal value' or 'contains value' or 'value' (implies 'is equal value'). String.
        groups -- Comma separated list of groups. String
        last_activity -- Last activity was within or was not within the last 'value' days. String.
        Format: 'was value' or 'was not value' or 'value' (implies 'was value'). 'value' is an integer
        integration_id -- Comma separated list of integration IDs. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetAppInventory
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAppInventory",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_security_check(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Security Check Affected.

        Keyword arguments:
        id -- Security Check ID. String.
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetSecurityCheckAffectedV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSecurityCheckAffectedV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def dismiss_affected_entity(self: object,
                                body: dict = None,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """POST Dismiss Affected Entity.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "entities": "string",
                    "reason": "string"
                }
        entities -- Entities. String.
        reason -- Reason for dismiss. String.
        id -- Security Check ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/DismissAffectedEntityV3
        """
        if not body:
            keys = ["entities", "reason"]
            for key in keys:
                if kwargs.get(key, None) is not None:
                    body[key] = kwargs.get(key, None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DismissAffectedEntityV3",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def dismiss_security_check(self: object,
                               body: dict = None,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """POST Dismiss Security Check by ID.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "reason": "string"
                }
        reason -- The reason for dismissal. String.
        id -- Security Check ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/DismissSecurityCheckV3
        """
        if not body:
            if kwargs.get("reason", None) is not None:
                body["reason"] = kwargs.get("reason", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DismissSecurityCheckV3",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_security_checks(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Security Check by ID or GET List Security Checks.

        Keyword arguments:
        id -- Security Check ID. String
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results. Integer.
        status -- Exposure status. String.
                  Available values:
                    Passsed         Failed
                    Dismissed       Pending
                    Can't Run       Stale
        integration_id -- Comma separated list of integration IDs. String.
        impact -- Impact. String.
                  Available values:
                    Low     Medium     High
        compliance -- Compliance. Boolean.
        check_type -- Check Type. String.
                      Available values:
                        apps            devices
                        users           assets
                        permissions     Falcon Shield Security Check
                        custom
        check_tags -- Comma separated list of check tags names or ids. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetSecurityChecksV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSecurityChecksV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_security_check_compliance(self: object,
                                      *args,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Compliance.

        Keyword arguments:
        id -- Security Check ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetSecurityCheckComplianceV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSecurityCheckComplianceV3",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def complete_integration_upload(self: object,
                                    *args,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """POST Data Upload Transaction Completion.

        Keyword arguments:
        id -- Integration ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/IntegrationBuilderEndTransactionV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="IntegrationBuilderEndTransactionV3",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def reset_integration_builder(self: object,
                                  *args,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Reset.

        Keyword arguments:
        id -- Integration ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/IntegrationBuilderResetV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="IntegrationBuilderResetV3",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_integration_builder_status(self: object,
                                       *args,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Status.

        Keyword arguments:
        id -- Integration ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/IntegrationBuilderGetStatusV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="IntegrationBuilderGetStatusV3",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def upload_integration_builder(self: object,
                                   body: dict = None,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """POST Upload.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "data": "string"
                }
        data -- String.
        id -- Integration ID. String.
        source_id -- Source ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/IntegrationBuilderUploadV3
        """
        if not body:
            if kwargs.get("data", None) is not None:
                body["data"] = kwargs.get("data", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="IntegrationBuilderUploadV3",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_asset_inventory(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Data Inventory.

        Keyword arguments:
        integration_id -- Comma separated list of integration IDs. String.
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results. Integer.
        resource_type -- Comma separated list of resource types. String.
        access_level -- Comma separated list of access levels. String.
        last_accessed -- Last accessed date was within or was not within the last 'value' days. String.
        Format: 'was value' or 'was not value' or 'value' (implies 'was value'). 'value' is an integer
        last_modified -- Last modified date was within or was not within the last 'value' days. String.
        Format: 'was value' or 'was not value' or 'value' (implies 'was value'). 'value' is an integer
        resource_name -- Resource name contains 'value' (case insensitive). String.
        password_protected -- Password protected. Boolean.
        resource_owner -- Resource owner contains 'value' (case insensitive). String.
        resource_owner_enabled -- Resource owner enabled. Boolean.
        unmanaged_domain -- Comma separated list of unmanaged domains. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetAssetInventoryV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAssetInventoryV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_device_inventory(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Device Inventory.

        Keyword arguments:
        integration_id -- Comma separated integration ID's. String.
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results. Integer.
        email -- Email. String.
        privileged_only -- Privileged Only. Boolean.
        unassociated_devices -- Unassociated Devices. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetDeviceInventoryV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDeviceInventoryV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_integrations(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Integrations.

        Keyword arguments:
        saas_id -- Comma separated SaaS ID's. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetIntegrationsV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIntegrationsV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_activity_monitor(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Activity Monitor.

        Keyword arguments:
        integration_id -- Integration ID. String.
        actor -- Actor. String.
        category -- Comma separated list of categories. String.
        projection -- Comma separated list of projections. String.
        from_date -- From Date. String.
        to_date -- To Date. String.
        limit -- Max number of logs to fetch. Integer.
        skip -- Number of logs to skip. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetActivityMonitorV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetActivityMonitorV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_supported_saas(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET Supported SaaS.

        Keyword arguments:
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetSupportedSaasV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSupportedSaasV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_system_logs(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET System Logs.

        Keyword arguments:
        from_date -- From Date (in YYYY-MM-DD format). String.
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results. Integer.
        to_date -- To Date (in YYYY-MM-DD format). String.
        total_count -- Fetch Total Count?. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetSystemLogsV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSystemLogsV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_system_users(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET System Users.

        Keyword arguments:
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetSystemUsersV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSystemUsersV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_inventory(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """GET User Inventory.

        Keyword arguments:
        integration_id -- Comma separated integration ID's. String.
        limit -- The maximum number of objects to return. Integer.
        offset -- The starting index of the results. Integer.
        email -- Email. String.
        privileged_only -- Privileged Only. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/saas-security/GetUserInventoryV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetUserInventoryV3",
            keywords=kwargs,
            params=parameters
            )

    GetMetricsV3 = get_metrics
    GetAlertsV3 = get_alerts
    GetAppInventoryUsers = get_application_users
    GetAppInventory = get_application_inventory
    GetSecurityCheckAffectedV3 = get_security_check
    DismissAffectedEntityV3 = dismiss_affected_entity
    DismissSecurityCheckV3 = dismiss_security_check
    GetSecurityChecksV3 = get_security_checks
    GetSecurityCheckComplianceV3 = get_security_check_compliance
    IntegrationBuilderEndTransactionV3 = complete_integration_upload
    IntegrationBuilderResetV3 = reset_integration_builder
    IntegrationBuilderGetStatusV3 = get_integration_builder_status
    IntegrationBuilderUploadV3 = upload_integration_builder
    GetAssetInventoryV3 = get_asset_inventory
    GetDeviceInventoryV3 = get_device_inventory
    GetIntegrationsV3 = get_integrations
    GetActivityMonitorV3 = get_activity_monitor
    GetSupportedSaasV3 = get_supported_saas
    GetSystemLogsV3 = get_system_logs
    GetSystemUsersV3 = get_system_users
    GetUserInventoryV3 = get_user_inventory
