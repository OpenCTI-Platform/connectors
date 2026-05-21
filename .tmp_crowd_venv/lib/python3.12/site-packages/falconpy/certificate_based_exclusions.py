"""CrowdStrike Falcon Certificate Based Exclusions API interface class.

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
from ._payload import certificate_based_exclusions_payload
from ._endpoint._certificate_based_exclusions import _certificate_based_exclusions_endpoints as Endpoints


class CertificateBasedExclusions(ServiceClass):
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
    def get_exclusions(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all exclusion IDs matching the query with filter.

        Keyword arguments:
        ids -- One or more exclusion IDs . String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/certificate-based-exclusions/cb-exclusions.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cb_exclusions_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create new Certificate Based Exclusions.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "exclusions": [
                        {
                            "applied_globally": true,
                            "certificate": {
                                "issuer": "string",
                                "serial": "string",
                                "subject": "string",
                                "thumbprint": "string",
                                "valid_from": "2024-07-17T16:55:01.502Z",
                                "valid_to": "2024-07-17T16:55:01.502Z"
                            },
                            "children_cids": [
                                "string"
                            ],
                            "comment": "string",
                            "created_by": "string",
                            "created_on": "2024-07-17T16:55:01.502Z",
                            "description": "string",
                            "host_groups": [
                                "string"
                            ],
                            "modified_by": "string",
                            "modified_on": "2024-07-17T16:55:01.502Z",
                            "name": "string",
                            "status": "string"
                        }
                    ]
                }

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/certificate-based-exclusions/cb-exclusions.create.v1
        """
        if not body:
            body = certificate_based_exclusions_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cb_exclusions_create_v1",
            body=body,
            keywords=kwargs
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_exclusions(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a set of exclusions by specifying their IDs.

        Keyword arguments:
        ids -- List of exclusion IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.
        comment - The comment why these exclusions were deleted. String.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/certificate-based-exclusions/cb-exclusions.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cb_exclusions_delete_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Certificate Based Exclusions.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "exclusions": [
                        {
                            "applied_globally": true,
                            "certificate": {
                                "issuer": "string",
                                "serial": "string",
                                "subject": "string",
                                "thumbprint": "string",
                                "valid_from": "2024-07-17T16:55:01.502Z",
                                "valid_to": "2024-07-17T16:55:01.502Z"
                            },
                            "children_cids": [
                                "string"
                            ],
                            "comment": "string",
                            "created_by": "string",
                            "created_on": "2024-07-17T16:55:01.502Z",
                            "description": "string",
                            "host_groups": [
                                "string"
                            ],
                            "modified_by": "string",
                            "modified_on": "2024-07-17T16:55:01.502Z",
                            "name": "string",
                            "status": "string"
                        }
                    ]
                }

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/certificate-based-exclusions/cb-exclusions.update.v1
        """
        if not body:
            body = certificate_based_exclusions_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cb_exclusions_update_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_certificates(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve vulnerability and package related info for this customer.

        Keyword arguments:
        ids - The SHA256 Hash of the file to retrieve certificate signing info for. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/certificate-based-exclusions/certificates.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="certificates_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_certificates(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for cert-based exclusions.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum records to return. [1-500]. Defaults to 100.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by (e.g. alias.desc or state.asc). FQL syntax.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/certificate-based-exclusions/cb-exclusions.query.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cb_exclusions_query_v1",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    cb_exclusions_get_v1 = get_exclusions
    cb_exclusions_create_v1 = create_exclusions
    cb_exclusions_delete_v1 = delete_exclusions
    cb_exclusions_update_v1 = update_exclusions
    certificates_get_v1 = get_certificates
    cb_exclusions_query_v1 = query_certificates
