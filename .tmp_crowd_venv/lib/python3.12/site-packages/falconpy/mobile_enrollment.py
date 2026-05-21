"""Falcon Mobile Enrollment API Interface Class.

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
from ._util import process_service_request, force_default
from ._payload import mobile_enrollment_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._mobile_enrollment import _mobile_enrollment_endpoints as Endpoints


class MobileEnrollment(ServiceClass):
    """This class represents the CrowdStrike Falcon Mobile Enrollment service collection.

    The only requirement to instantiate an instance of this class is one of the following:
    - valid API credentials provided as the keywords `client_id` and `client_secret`
    - a `creds` dictionary containing valid credentials within the client_id and client_secret keys

          {
              "client_id": "CLIENT_ID_HERE",
              "client_secret": "CLIENT_SECRET_HERE"
          }
    - an `auth_object` containing a valid instance of the authentication service class (OAuth2)
    - a valid token provided by the token method of the authentication service class (OAuth2.token)
    """

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def device_enroll(self: object,
                      body: dict = None,
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Trigger on-boarding process for a mobile device.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mobile-enrollment/RequestDeviceEnrollmentV3

        Keyword arguments
        ----
        action_name : str
            Action to perform. Allowed values: enroll, re-enroll.
        body : dict
            Full body payload, not required if using `email_addresses` and `expires_at` keywords.
                {
                    "email_addresses": [
                        "string"
                    ],
                    "expires_at": "2022-08-07T02:37:16.797Z"
                }
        email_addresses : str or list[str] (required)
            Email addresses to use for enrollment.
        expires_at : str (required)
            Date enrollment expires. UTC date format.
        filter : str
            FQL filter.
        parameters : dict
            Full parameters payload, not required if using `action_name` keyword.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            body = mobile_enrollment_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RequestDeviceEnrollmentV3",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def device_enroll_v4(self: object,
                         body: dict = None,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Trigger on-boarding process for a mobile device.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mobile-enrollment/RequestDeviceEnrollmentV4

        Keyword arguments
        ----
        action_name : str
            Action to perform. Allowed values: enroll, re-enroll.
        body : dict
            Full body payload, not required if using `email_addresses` and `expires_at` keywords.
                {
                    "email_addresses": [
                        "string"
                    ],
                    "enrollment_type": "string",
                    "expires_at": "2022-08-07T02:37:16.797Z"
                }
        email_addresses : str or list[str] (required)
            Email addresses to use for enrollment.
        enrollment_type : str
            Mobile enrollment type.
        expires_at : str (required)
            Date enrollment expires. UTC date format.
        filter : str
            FQL filter.
        parameters : dict
            Full parameters payload, not required if using `action_name` keyword.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            body = mobile_enrollment_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RequestDeviceEnrollmentV4",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    # This method name aligns to the operation ID in the API but
    # does not conform to snake_case / PEP8 and is defined here for
    # backwards compatibility / ease of use purposes
    RequestDeviceEnrollmentV3 = device_enroll
    RequestDeviceEnrollmentV4 = device_enroll_v4


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Mobile_Enrollment = MobileEnrollment  # pylint: disable=C0103
