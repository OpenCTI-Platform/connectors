# OpenCTI ExportReportPdf Connector

OpenCTI ExportReportPdf connector allows exporting PDF based reports for the following entities: Report (Analysis), Intrusion Set, and Threat Actor. The PDF may be useful for sharing threat intelligence with an external entity in a nice, well-groomed format.


#### Technical information

The connector uses weasyprint under the hood for report generation, where the `resources` directory contains all of the dependencies.

#### Windows limitation

If you’re having trouble starting the connector saying that a library of type “cairo” or something is missing, you need to download and install this on your computer:

https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases/tag/2022-01-04

Once it’s installed, don’t forget to restart your IDE.

If it’s still not working after that, you need to download Visual Studio Community and enable C++ development in the tools section.