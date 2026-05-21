"""FalconPy utility module.

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
from ._auth import login_payloads, logout_payloads, review_provided_credentials
from ._functions import (
    validate_payload,
    generate_b64cred,
    handle_single_argument,
    force_default,
    service_request,
    perform_request,
    generate_error_result,
    generate_ok_result,
    get_default,
    args_to_params,
    process_service_request,
    confirm_base_url,
    confirm_base_region,
    return_preferred_default,
    base_url_regions,
    autodiscover_region,
    sanitize_dictionary,
    calc_content_return,
    log_class_startup,
    deprecated_operation,
    deprecated_class,
    params_to_keywords,
    _ALLOWED_METHODS
)
from ._service import service_override_payload
from ._uber import (
    create_uber_header_payload,
    handle_body_payload_ids,
    scrub_target,
    handle_container_operations,
    uber_request_keywords,
)

__all__ = ["create_uber_header_payload", "handle_body_payload_ids", "scrub_target",
           "handle_container_operations", "uber_request_keywords", "autodiscover_region",
           "validate_payload", "generate_b64cred", "handle_single_argument", "force_default",
           "service_request", "perform_request", "generate_error_result", "generate_ok_result",
           "get_default", "args_to_params", "process_service_request", "confirm_base_url",
           "confirm_base_region", "return_preferred_default", "base_url_regions",
           "_ALLOWED_METHODS", "login_payloads", "logout_payloads", "sanitize_dictionary",
           "calc_content_return", "log_class_startup", "service_override_payload",
           "deprecated_operation", "deprecated_class", "review_provided_credentials",
           "params_to_keywords"
           ]
