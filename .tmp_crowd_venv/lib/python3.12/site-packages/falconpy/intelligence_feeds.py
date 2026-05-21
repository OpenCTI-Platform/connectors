"""CrowdStrike Falcon IntelligenceFeeds API interface class.

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
from requests import Response
from ._util import force_default, process_service_request
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._intelligence_feeds import _intelligence_feeds_endpoints as Endpoints


class IntelligenceFeeds(ServiceClass):
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
    def download_feed(self: object,
                      parameters: dict = None,
                      **kwargs) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Download feed file contents as a zip archive.

        Keyword arguments:
        feed_item_id -- Feed object reference ID.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        stream -- Enable streaming download of the returned file. Boolean.

        This method only supports keywords for providing arguments.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL

        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DownloadFeedArchive",
            keywords=kwargs,
            params=parameters,
            stream=kwargs.get("stream", False)
            )

    def list_feeds(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """List the accessible feeds for a given customer.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL

        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListFeedTypes"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_feeds(self: object,
                    parameters: dict = None,
                    **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query the accessible feeds for a customer.

        Keyword arguments:
        feed_name -- Feed Name.
        feed_interval -- Feed interval must be one of: 'dump', 'daily', 'hourly' or 'minutely'.
        since -- Since is a valid timestamp in RFC3399 format.
                 Restrictions: minutely: now()-2h
                               hourly: now()-2d
                               daily: now()-5d
                               dump: now()-7d
                               any: Automatically combines the appropriate intervals
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL

        """
        # if kwargs.get("feed_name", None):
        #     kwargs["feed-name"] = kwargs.get("feed_name", None)

        # if kwargs.get("feed_interval", None):
        #     kwargs["feed-interval"] = kwargs.get("feed_interval", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryFeedArchives",
            keywords=kwargs,
            params=parameters
            )

    DownloadFeedArchive = download_feed
    ListFeedTypes = list_feeds
    QueryFeedArchives = query_feeds
