# -*- coding: utf-8 -*-
"""VirusTotal connector main file."""

from virustotal import VirusTotalConnector


if __name__ == "__main__":
    connector = VirusTotalConnector()
    connector.start()
