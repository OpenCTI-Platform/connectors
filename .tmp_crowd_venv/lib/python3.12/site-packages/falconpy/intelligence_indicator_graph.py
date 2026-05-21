"""CrowdStrike Falcon IntelligenceIndicatorGraph API interface class.

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
from ._util import force_default, process_service_request
from ._payload import generic_payload_list
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._intelligence_indicator_graph import _intelligence_indicator_graph_endpoints as Endpoints


class IntelligenceIndicatorGraph(ServiceClass):
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

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def search(self: object,
               body: dict = None,
               parameters: dict = None,
               **kwargs
               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search indicators based on FQL filter.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                DEPRECATED: Please use query string parameters instead of the body payload for these arguments.
                {
                    "filter": "string",
                    "sort": [
                        {
                            "field": "string",
                            "order": "string"
                        }
                    ]
                }
        filter -- The filter expression that should be used to limit the results. String. FQL syntax.
                  Available values:
                    Type                            LastUpdated
                    KillChain                       MaliciousConfidence
                    MaliciousConfidenceValidatedTime
                    FirstSeen                       LastSeen
                    Adversaries.Name                Adversaries.Slug
                    Reports.Title                   Reports.Slug
                    Threats.FamilyName              Vulnerabilities.CVE
                    Sectors.Name                    FileDetails.SHA256
                    FileDetails.SHA1                FileDetails.MD5
                    DomainDetails.Detail            IPv4Details.IPv4
                    IPv6Details.IPv6                URLDetails.URL
        limit -- Returned record limit. Integer.
        offset -- Offset to start returning results. Integer.
        sort -- List of sort operations to perform on the returnset. String.

        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intelligence-indicator-graph/SearchIndicators
        """
        # Body payload parameters have been deprecated as of version 1.5.4
        # if not body:
        #     body = indicator_graph_payload(kwargs)
        if not body:
            body = {}
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="SearchIndicators",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def lookup(self: object,
               *args,
               body: dict = None,
               **kwargs
               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search indicators based on FQL filter.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "values": [
                        "example.com",
                        "1.2.3.4",
                        "7391279b68dd9ae643125aef4af41b87a17fc8cea669a6ffa709c8470236e25a",
                        "94e8020ce8836b9cae654af56eba25396e8ba9f0",
                        "86464cd07e4f924e33a5a1d1dcebdae6"
                    ]
                }
        values -- Values to look up. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'values'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intelligence-indicator-graph/LookupIndicators
        """
        if not kwargs and args:
            kwargs["values"] = args[0]

        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="values")

        # Convert comma-delimited strings to a properly formatted list
        if "values" in body:
            if isinstance(body["values"], str):
                body["values"] = body["values"].split(",")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="LookupIndicators",
            body=body
            )

    SearchIndicators = search
    LookupIndicators = lookup
