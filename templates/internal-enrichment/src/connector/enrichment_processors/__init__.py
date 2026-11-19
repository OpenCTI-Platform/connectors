"""EXAMPLE package -- the enrichment processors of the connector.

`IPv4Processor` is the example described in `ipv4_processor.py`. Replace it
with one processor per group of entity types your connector enriches, and
update the exports below.
"""

from connector.enrichment_processors.ipv4_processor import IPv4Processor

__all__ = [
    "IPv4Processor",
]
