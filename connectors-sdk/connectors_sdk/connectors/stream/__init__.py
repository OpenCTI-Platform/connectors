"""Building blocks for stream connectors.

This package provides the components shared by connectors of type ``STREAM``:

- ``deployment``: dissemination assurance (deployment write-back). Stream connectors
  report to OpenCTI whether each indicator they push is actually live on the
  security platform (``deployed-on`` relationship), reconcile that state with the
  vendor periodically and report detection hits.
"""
