"""EXAMPLE package -- rewrite for your own API client and models.

`TemplateClient`, `CVE`, and `Report` are all part of the worked
example described in `api_client.py` and `models.py`. Rename this
package and update the exports below once you replace them with your own
client class and entity models.
"""

from template_client.api_client import TemplateClient
from template_client.models import CVE, Report

__all__ = [
    "TemplateClient",
    "CVE",
    "Report",
]
