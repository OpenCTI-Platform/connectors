"""EXAMPLE package -- the API client and its models.

`TemplateClient` and `IPReputation` are the example described in
`api_client.py` and `models.py`. Rename this package and update the exports
below when you replace them.
"""

from template_client.api_client import TemplateClient
from template_client.models import IPReputation

__all__ = [
    "TemplateClient",
    "IPReputation",
]
