# OpenCTI ExportReportPdf Connector

OpenCTI ExportReportPdf connector allows exporting PDF based reports for the following entities: Report (Analysis), Intrusion Set, and Threat Actor. The PDF may be useful for sharing threat intelligence with an external entity in a nice, well-groomed format.


#### Technical information

The connector uses weasyprint under the hood for report generation, where the `resources` directory contains all of the dependencies.
