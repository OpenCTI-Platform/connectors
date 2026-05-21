"""Falcon Quick Scan API Interface Class.

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
from ._payload import generic_payload_list, aggregate_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._quick_scan import _quick_scan_endpoints as Endpoints


class QuickScan(ServiceClass):
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

    @force_default(defaults=["body"], default_types=["dict"])
    def get_scans_aggregates(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get scans aggregations as specified via json in request body.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
                {
                    "date_ranges": [
                        {
                            "from": "string",
                            "to": "string"
                        }
                    ],
                    "field": "string",
                    "filter": "string",
                    "interval": "string",
                    "min_doc_count": 0,
                    "missing": "string",
                    "name": "string",
                    "q": "string",
                    "ranges": [
                        {
                            "From": 0,
                            "To": 0
                        }
                    ],
                    "size": 0,
                    "sort": "string",
                    "sub_aggregates": [
                        null
                    ],
                    "time_zone": "string",
                    "type": "string"
                }
        date_ranges -- List of dictionaries.
        field -- String.
        filter -- FQL syntax. String.
        interval -- String.
        min_doc_count -- Minimum number of documents required to match. Integer.
        missing -- String.
        name -- Scan name. String.
        q -- FQL syntax. String.
        ranges -- List of dictionaries.
        size -- Integer.
        sort -- FQL syntax. String.
        sub_aggregates -- List of strings.
        time_zone -- String.
        type -- String.

        This method only supports keywords for providing arguments.

        This method does not support body payload validation.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan/GetScansAggregates
        """
        if not body:
            body = aggregate_payload(submitted_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetScansAggregates",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_scans(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Check the status of a volume scan.

        Time required for analysis increases with the number of samples in a volume
        but usually it should take less than 1 minute.

        Keyword arguments:
        ids -- One or more remediation IDs. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan/GetScans
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetScans",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def scan_samples(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get scans aggregations as specified via json in request body.

        Keyword arguments:
        body -- full body payload, not required when samples keyword is provided.
                {
                    "samples": [
                        "string"
                    ]
                }
        samples -- SHA256(s) of the samples to scan. Must have been previously submitted using
                   SampleUploadV3 (SampleUploads class). String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'samples'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan/ScanSamples
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="samples"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ScanSamples",
            body=body,
            body_validator={"samples": list} if self.validate_payloads else None,
            body_required=["samples"] if self.validate_payloads else None
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_submissions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find IDs for submitted scans by providing an FQL filter and paging details.

        Returns a set of volume IDs that match your criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return. [integer, 1-5000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan/QuerySubmissionsMixin0
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QuerySubmissionsMixin0",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    GetScansAggregates = get_scans_aggregates
    GetScans = get_scans
    ScanSamples = scan_samples
    QuerySubmissionsMixin0 = query_submissions


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Quick_Scan = QuickScan  # pylint: disable=C0103
