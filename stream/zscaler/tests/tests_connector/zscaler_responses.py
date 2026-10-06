import json

import requests


def make_response(status_code=200, body=None, headers=None):
    """Build a real ``requests.Response`` so truthiness and ``ok`` behave as in production."""
    response = requests.Response()
    response.status_code = status_code
    response._content = json.dumps(body if body is not None else {}).encode()
    response.headers.update(headers or {})
    return response
