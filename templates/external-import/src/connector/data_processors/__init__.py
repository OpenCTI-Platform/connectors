"""EXAMPLE package -- rewrite for your own connector's data processors.

`ReportsProcessor` and `VulnerabilitiesProcessor` are the two worked
examples described in `reports_processor.py` (non-paginated pattern) and
`vulnerabilities_processor.py` (paginated pattern). Replace them with one
processor per real data type your connector imports, and update the
exports below accordingly.
"""

from connector.data_processors.reports_processor import ReportsProcessor
from connector.data_processors.vulnerabilities_processor import VulnerabilitiesProcessor

__all__ = [
    "VulnerabilitiesProcessor",
    "ReportsProcessor",
]
