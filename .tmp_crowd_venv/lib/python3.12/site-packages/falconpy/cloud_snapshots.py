"""CrowdStrike Cloud Snapshots API Interface Class.

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
from ._util import process_service_request, force_default, handle_single_argument
from ._payload import (
    snapshot_registration_payload,
    snapshot_launch_payload
    )
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._cloud_snapshots import _cloud_snapshots_endpoints as Endpoints


class CloudSnapshots(ServiceClass):
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
    def search_detections(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search IaC Detections using a query in Falcon Query Language.

        Keyword arguments:
        filter -- Search IaC detections using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    detection_uuid          file_name
                    last_detected           platform
                    project_name            project_owner
                    project_ref             provider
                    resource_name           rule_category
                    rule_name               rule_type
                    rule_uuid               service
                    severity
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- Fields to sort the records on. String
                Supported columns:
                    detection_uuid          file_name
                    last_detected           platform
                    project_name            project_owner
                    project_ref             provider
                    resource_name           rule_category
                    rule_name               rule_type
                    rule_uuid               service
                    severity
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cspg-iacapi/CombinedDetections
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedDetections",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_scan_jobs(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for snapshot jobs identified by the provided filter.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available sort fields:
                    account_id          region
                    asset_identifier    status
                    cloud_provider
        limit -- The upper-bound on the number of records to retrieve.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset from where to begin.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. last_behavior|asc).
                Available sort fields:
                account_id          last_updated_timestamp
                asset_identifier    region
                cloud_provider      status
                instance_type

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-snapshots/ReadDeploymentsCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDeploymentsCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_scan_jobs(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve snapshot jobs identified by the provided IDs.

        Keyword arguments:
        parameters -- full parameters payload, not required if using other keywords.
        ids -- ID(s) of the snapshots to retrieve. String or list of strings. Max: 100

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-snapshots/ReadDeploymentsEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDeploymentsEntities",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def launch_scan_job(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Launch a snapshot scan for a given cloud asset.

        Keyword arguments:
        account_id -- Cloud provider account ID. String.
        asset_identifier -- Cloud asset identifier. String.
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "resources": [
                       {
                           "account_id": "string",
                           "asset_identifier": "string",
                           "cloud_provider": "string",
                           "region": "string"
                       }
                   ]
               }
        cloud_provider -- Cloud provider ID. String.
        region -- Cloud provider region ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-snapshots/CreateDeploymentEntity
        """
        if not body:
            body = snapshot_launch_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateDeploymentEntity",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_scan_reports(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the scan report for an instance.

        Keyword arguments:
        parameters -- full parameters payload, not required if using other keywords.
        ids -- The instance identifiers to fetch reports for. String or list of strings. Max: 100

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-snapshots/GetScanReport
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetScanReport",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    def get_credentials(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the registry credentials.

        HTTP Method: GET

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-snapshots/GetCredentialsMixin0

        Keyword arguments
        ----
        This method does not accept keyword arguments.

        Arguments
        ----
        This method does not accept arguments.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetCredentialsMixin0"
            )

    def get_iac_credentials(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the registry credentials.

        HTTP Method: GET

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cspg-iacapi/GetCredentialsMixin0

        Keyword arguments
        ----
        This method does not accept keyword arguments.

        Arguments
        ----
        This method does not accept arguments.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetCredentialsIAC"
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def register_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create inventory from data received from a snapshot.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "aws_accounts": [
                       {
                           "account_number": "string",
                           "batch_regions": [
                               {
                                   "job_definition_name": "string",
                                   "job_queue": "string",
                                   "region": "string"
                               }
                           ],
                           "iam_external_id": "string",
                           "iam_role_arn": "string",
                           "kms_alias": "string",
                           "processing_account": "string"
                       }
                   ]
               }
        aws_accounts -- Complete list of AWS accounts to register. List of dictionaries.
                        Overrides any values specified below.
        account_number -- AWS account number. String
        batch_regions -- Region the batch is executed. List of dictionaries.
        iam_external_id -- The external ID of the IAM account used. String.
        iam_role_arn -- The AWS ARN for the IAM account used. String.
        kms_alias -- The KMS alias for the IAM account used. String.
        processing_account -- The name of the processing account. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-snapshots/RegisterCspmSnapshotAccount
        """
        if not body:
            body = snapshot_registration_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RegisterCspmSnapshotAccount",
            keywords=kwargs,
            body=body
            )

    # This method name aligns to the operation ID in the API but
    # does not conform to snake_case / PEP8 and is defined here
    # for backwards compatibility / ease of use purposes
    CombinedDetections = search_detections
    ReadDeploymentsCombined = search_scan_jobs
    ReadDeploymentsEntities = get_scan_jobs
    CreateDeploymentEntity = launch_scan_job
    GetScanReport = get_scan_reports
    GetCredentialsMixin0 = get_credentials
    GetCredentialsIAC = get_iac_credentials
    RegisterCspmSnapshotAccount = register_account
