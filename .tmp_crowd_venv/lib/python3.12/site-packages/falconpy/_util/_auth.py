"""Internal authentication utilities library.

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
from typing import Dict, Optional
from json import loads
try:
    from simplejson import JSONDecodeError
except (ImportError, ModuleNotFoundError):  # Support import as a module
    from json.decoder import JSONDecodeError
from ._functions import generate_b64cred
from .._endpoint._oauth2 import _oauth2_endpoints as AuthEndpoints
from .._error import InvalidCredentialFormat


def login_payloads(creds: dict, base: str):
    """Craft the necessary payloads to generate a token.

    This method is intentionally generic and does not necessarily need to
    be used to generate the token currently being used for other API operations.
    """
    op_id = "oauth2AccessToken"
    target = f"{base}{[ep[2] for ep in AuthEndpoints if op_id in ep[0]][0]}"
    data = {
        'client_id': creds['client_id'],
        'client_secret': creds['client_secret']
    }
    if "member_cid" in creds:
        data["member_cid"] = creds["member_cid"]

    return op_id, target, data


def logout_payloads(creds: dict, base: str, token_val: str, client_id: str = None):
    """Craft the necessary payloads to revoke a token.

    This method is intentionally generic and does not necessarily need to
    be used to revoke the token currently being used for other API operations.
    """
    op_id = "oauth2RevokeToken"
    target = f"{base}{[ep[2] for ep in AuthEndpoints if op_id in ep[0]][0]}"
    b64cred = generate_b64cred(creds["client_id"], creds["client_secret"])
    headers = {"Authorization": f"basic {b64cred}"}
    data = {"token": f"{token_val}"}
    if client_id:
        data["client_id"] = client_id

    return op_id, target, data, headers


def review_provided_credentials(cid: Optional[str] = None,
                                csec: Optional[str] = None,
                                cdict: Optional[Dict[str, str]] = None,
                                mcid: Optional[str] = None
                                ):
    """Review the provided credential values and create a valid credential dictionary."""
    returned = {}
    returned_style = None
    if cid and csec and not cdict:
        cdict = {
            "client_id": cid,
            "client_secret": csec
        }
        # You must pass member_cid the same way you pass client_id / secret.
        # If you use a creds dictionary, pass the member_cid there instead.
        if mcid:
            cdict["member_cid"] = mcid
        returned_style = "DIRECT"
    elif not cdict:
        cdict = {}
    # Credential Authentication (also powers Direct Authentication).
    if isinstance(cdict, str):
        try:
            # Try and clean up any attempts to provide the dictionary as a string
            returned: Dict[str, str] = loads(cdict.replace("'", "\""))
            returned_style = "CREDENTIAL"
        except (TypeError, JSONDecodeError) as bad_cred_format:
            raise InvalidCredentialFormat from bad_cred_format
    elif isinstance(cdict, dict):
        returned: Dict[str, str] = cdict
        if not returned_style:
            returned_style = "CREDENTIAL"
    else:
        raise InvalidCredentialFormat

    return returned, returned_style
